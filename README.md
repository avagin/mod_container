# mod_container
**mod_container** is an Apache module which can improve isolation and security of virtual hosts. Here we use the container technology to create isolated environments. A new mount namespace is constructed for each virtual host, that allows to specify which parts of the file system tree should be visible. All Apache processes are running under a non-root users in its own user namespace to get capability to operate namespaces. When a new request is received, a namespace set is switched to a proper one for a required virtual host.

Each process can switch namespaces, but for that it should raise capabilities and know which file descriptors are associated with namespaces. All this makes it harder to get access to other virtual hosts. For script languages we can deny *setns()* and *capset()* system calls.

##Install
The **unixd** module should be disabled.

[https://github.com/avagin/libct](https://github.com/avagin/libct)
