#include <stdio.h>

#include "list.h"

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

module AP_MODULE_DECLARE_DATA container_module;

static LIST_HEAD(containers);

struct container_config {
	struct list_head node;

	char *root;
};

static int privileges_postconf(apr_pool_t *pconf, apr_pool_t *plog,
                               apr_pool_t *ptemp, server_rec *s)
{
	struct container_config *cfg;

	ap_log_error(APLOG_MARK, APLOG_CRIT, 0, 0, "Start!");

	list_for_each_entry(cfg, &containers, node) {
		ap_log_error(APLOG_MARK, APLOG_CRIT, 0, 0, "-- %s\n", cfg->root);
	}
	return OK;
}

static int enter_container_handler (request_rec * r)
{
	struct container_config *cfg;

	cfg = ap_get_module_config(r->per_dir_config, &container_module);;

	ap_log_error(APLOG_MARK, APLOG_CRIT, 0, 0, "New request: %s\n", cfg->root);

	return DECLINED;
}

static int leave_container_handler (request_rec * r)
{
	struct container_config *cfg;

	cfg = ap_get_module_config(r->per_dir_config, &container_module);;

	ap_log_error(APLOG_MARK, APLOG_CRIT, 0, 0, "Complete request: %s\n", cfg->root);

	return DECLINED;
}

static void register_hooks(apr_pool_t *pool)
{
	ap_hook_post_config(privileges_postconf, NULL, NULL,
						APR_HOOK_REALLY_FIRST);
	ap_hook_handler(enter_container_handler, NULL, NULL,
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

static command_rec container_module_directives[] = {
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

