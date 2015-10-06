#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>

#include "list.h"

#include <libct/libct.h>
#include <libct/libct-log-levels.h>

#include "apr_hash.h"
#include "apr_strings.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "unixd.h"

#include "mpm_common.h"

module AP_MODULE_DECLARE_DATA container_module;

static LIST_HEAD(containers);

static libct_session_t session;

struct container_config {
	struct list_head node;

	char *root;
	ct_handler_t ct;
	ct_process_t pr;
};

ct_handler_t host_ct;

static int write_file(char *fname, char *buf, int size)
{
	int fd;

	fd = open(fname, O_WRONLY);
	if (fd < 0) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			"Unable to open %s", fname);
		return -1;
	}
	if (write(fd, buf, size) < 0) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			"Unable to write into %s", fname);
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

static int __unshare_userns()
{
	char buf[1024];
	int size;
	uid_t uid = getuid();
	gid_t gid = getgid();

	if (unshare(CLONE_NEWUSER)) {
		ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
			"Unable to unshare userns");
		return -1;
	}

	if (write_file("/proc/self/setgroups", "deny", 5))
		return -1;
	size = snprintf(buf, sizeof(buf), "0 %d 1", uid);
	if (write_file("/proc/self/uid_map", buf, size))
		return -1;
	size = snprintf(buf, sizeof(buf), "0 %d 1", gid);
	if (write_file("/proc/self/gid_map", buf, size))
		return -1;

	return 0;
}

#define CONTAINER_USERNS_UNSHARED "container_userns_unshared"
static int unshare_userns(server_rec *s)
{
	void *unshared;

	apr_pool_userdata_get(&unshared, CONTAINER_USERNS_UNSHARED,
						  s->process->pool);
	if (unshared == NULL) {
		apr_pool_userdata_set((void *)1, CONTAINER_USERNS_UNSHARED,
				  apr_pool_cleanup_null, s->process->pool);
	} else
		goto out;

	if (setgid(ap_unixd_config.group_id) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                        "setgid: unable to set group id to Group %ld",
                        (long)ap_unixd_config.group_id);
            return -1;
        }
        if (setuid(ap_unixd_config.user_id) == -1) {
            ap_log_error(APLOG_MARK, APLOG_ALERT, errno, NULL,
                        "setgid: unable to set user id to User %ld",
                        (long)ap_unixd_config.user_id);
            return -1;
        }
	prctl(PR_SET_DUMPABLE, 1, 0, 0, 0);
	if (__unshare_userns())
		return -1;
out:
	ap_unixd_config.user_id = 0;
	ap_unixd_config.group_id = 0;
	return 0;
}
#undef CONTAINER_USERNS_UNSHARED

static int privileges_postconf(apr_pool_t *pconf, apr_pool_t *plog, apr_pool_t *ptemp, server_rec *s)
{
	struct container_config *cfg;
	ct_process_desc_t pd;
	int fd;

	fd = open("/var/log//libct.log", O_WRONLY | O_APPEND | O_CREAT, 0600);
	if (fd == -1) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, errno, s, "Unable to open libct log file");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	libct_log_init(fd, LOG_DEBUG);

	if (unshare_userns(s)) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, errno, s, "Unable to unshare userns");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	session = libct_session_open_local();
	if (libct_handle_is_err(session))
		return HTTP_INTERNAL_SERVER_ERROR;

	pd = libct_process_desc_create(session);
	if (libct_handle_is_err(pd))
		return HTTP_INTERNAL_SERVER_ERROR;
	libct_process_desc_set_pdeathsig(pd, SIGKILL);

	{
		ct_process_t pr;
		host_ct = libct_container_create(session, "host");
		if (libct_handle_is_err(host_ct))
			goto err;

		if (libct_container_set_option(host_ct, LIBCT_OPT_TASKLESS, 0))
			goto err;

		if (libct_container_set_nsmask(host_ct, CLONE_NEWNS | CLONE_NEWIPC))
			goto err;

		pr = libct_container_spawn_cb(host_ct, pd, NULL, NULL);
		if (libct_handle_is_err(pr)) {
			ap_log_error(APLOG_MARK, APLOG_CRIT, 0, 0, "Unable to start a container\n");
			goto err;
		}
	}

	list_for_each_entry(cfg, &containers, node) {
		static int id = 0;
		char buf[] = "XXXXXXXXXX";

		ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, 0, "Start a container with %s\n", cfg->root);

		snprintf(buf, sizeof(buf), "%d", id++);
		cfg->ct = libct_container_create(session, buf);
		if (libct_handle_is_err(cfg->ct))
			goto err;

		if (libct_container_set_option(cfg->ct, LIBCT_OPT_TASKLESS, 0))
			goto err;

		if (libct_container_set_nsmask(cfg->ct, CLONE_NEWNS))
			goto err;

		if (libct_fs_set_root(cfg->ct, cfg->root))
			goto err;

		cfg->pr = libct_container_spawn_cb(cfg->ct, pd, NULL, NULL);
		if (libct_handle_is_err(cfg->pr)) {
			ap_log_error(APLOG_MARK, APLOG_CRIT, 0, 0, "Unable to start a container %s\n", cfg->root);
			goto err;
		}
	}
	libct_process_desc_destroy(pd);
	return OK;
err:
	list_for_each_entry(cfg, &containers, node) {
		if (cfg->ct == NULL)
			continue;
		libct_container_kill(cfg->ct);
		libct_container_destroy(cfg->ct);
	}
	libct_process_desc_destroy(pd);
	libct_container_kill(host_ct);
	libct_container_destroy(host_ct);
	libct_session_close(session);
	return HTTP_INTERNAL_SERVER_ERROR;
}

static int
unixd_pre_config(apr_pool_t *pconf, apr_pool_t *plog,
                 apr_pool_t *ptemp)
{
	ap_sys_privileges_handlers(1);
	return OK;
}

static int enter_container_handler (request_rec * r)
{
	struct container_config *cfg;

	cfg = ap_get_module_config(r->per_dir_config, &container_module);;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, 0, "New request: %s\n", cfg->root);

	if (libct_container_switch(cfg->ct)) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, 0, 0, "Unable to switch into CT\n");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return DECLINED;
}

static int leave_container_handler (request_rec * r)
{
	struct container_config *cfg;

	cfg = ap_get_module_config(r->per_dir_config, &container_module);;

	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, 0, "Complete request: %s\n", cfg->root);

	if (libct_container_switch(host_ct)) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, 0, 0, "Unable to switch into the host CT\n");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return DECLINED;
}

static void register_hooks(apr_pool_t *pool)
{
	ap_hook_pre_config(unixd_pre_config,
                       NULL, NULL, APR_HOOK_FIRST);
	ap_hook_post_config(privileges_postconf, NULL, NULL,
						APR_HOOK_REALLY_FIRST);
	ap_hook_post_read_request(enter_container_handler, NULL, NULL,
						APR_HOOK_REALLY_FIRST);
	ap_hook_log_transaction(leave_container_handler, NULL, NULL,
						APR_HOOK_LAST);
}

static void *container_module_create_dir_config(apr_pool_t * p, char *dirspec)
{
	struct container_config *cfg;

	cfg = apr_pcalloc (p, sizeof(struct container_config));
	if (!cfg) {
		ap_log_error (APLOG_MARK, APLOG_ERR, OK, NULL,
				"not enough memory");
		return NULL;
	}

	list_add(&cfg->node, &containers);

	cfg->root = NULL;
	cfg->ct = NULL;

	return cfg;
}

static const char *set_root (cmd_parms * cmd, void *mcfg, const char *root)
{
	struct container_config *cfg;
	cfg = mcfg;
	if (root)
		cfg->root = apr_pstrdup(cmd->pool, root);
	return NULL;
}

static const char *
unixd_set_user(cmd_parms *cmd, void *dummy,
               const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_unixd_config.user_name = arg;
    ap_unixd_config.user_id = ap_uname2id(arg);
#if !defined (BIG_SECURITY_HOLE) && !defined (OS2)
    if (ap_unixd_config.user_id == 0) {
        return "Error:\tApache has not been designed to serve pages while\n"
                "\trunning as root.  There are known race conditions that\n"
                "\twill allow any local user to read any file on the system.\n"
                "\tIf you still desire to serve pages as root then\n"
                "\tadd -DBIG_SECURITY_HOLE to the CFLAGS env variable\n"
                "\tand then rebuild the server.\n"
                "\tIt is strongly suggested that you instead modify the User\n"
                "\tdirective in your httpd.conf file to list a non-root\n"
                "\tuser.\n";
    }
#endif

    return NULL;
}

static const char*
unixd_set_group(cmd_parms *cmd, void *dummy,
                                         const char *arg)
{
    const char *err = ap_check_cmd_context(cmd, GLOBAL_ONLY);
    if (err != NULL) {
        return err;
    }

    ap_unixd_config.group_name = arg;
    ap_unixd_config.group_id = ap_gname2id(arg);

    return NULL;
}
static command_rec container_module_directives[] = {
	AP_INIT_TAKE1("User", unixd_set_user, NULL, RSRC_CONF,
		  "Effective user id for this server"),
	AP_INIT_TAKE1("Group", unixd_set_group, NULL, RSRC_CONF,
		  "Effective group id for this server"),
	AP_INIT_TAKE1 ("ContainerRoot", set_root, NULL, ACCESS_CONF | RSRC_CONF, "Container Root"),
	{NULL}
};

module AP_MODULE_DECLARE_DATA   container_module =
{
    STANDARD20_MODULE_STUFF,
    container_module_create_dir_config,	/* Per-directory configuration handler */
    NULL,	/* Merge handler for per-directory configurations */
    NULL,	/* Per-server configuration handler */
    NULL,	/* Merge handler for per-server configurations */
    container_module_directives,	/* Any directives we may have for httpd */
    register_hooks   /* Our hook registering function */
};

