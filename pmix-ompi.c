#include <stdbool.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/time.h>
#include "pmix.h"

typedef
pmix_status_t (*init_fn_t)(pmix_proc_t *proc,
                           pmix_info_t info[], size_t ninfo);

typedef
pmix_status_t (*finalize_fn_t)(const pmix_info_t info[], size_t ninfo);

typedef
int (*initialized_fn_t)(void);

typedef
pmix_status_t (*abort_fn_t)(int status, const char msg[],
                                    pmix_proc_t procs[], size_t nprocs);

typedef
pmix_status_t (*put_fn_t)(pmix_scope_t scope,
                          const char key[], pmix_value_t *val);

typedef
pmix_status_t (*commit_fn_t)(void);

typedef
pmix_status_t (*fence_fn_t)(const pmix_proc_t procs[], size_t nprocs,
                            const pmix_info_t info[], size_t ninfo);

typedef
pmix_status_t (*fence_nb_fn_t)(const pmix_proc_t procs[], size_t nprocs,
                               const pmix_info_t info[], size_t ninfo,
                               pmix_op_cbfunc_t cbfunc, void *cbdata);

typedef
pmix_status_t (*get_fn_t)(const pmix_proc_t *proc, const char key[],
                          const pmix_info_t info[], size_t ninfo,
                          pmix_value_t **val);

typedef
pmix_status_t (*get_nb_fn_t)(const pmix_proc_t *proc, const char key[],
                             const pmix_info_t info[], size_t ninfo,
                             pmix_value_cbfunc_t cbfunc, void *cbdata);

typedef
pmix_status_t (*publish_fn_t)(const pmix_info_t info[], size_t ninfo);

typedef
pmix_status_t (*publish_nb_fn_t)(const pmix_info_t info[], size_t ninfo,
                                 pmix_op_cbfunc_t cbfunc, void *cbdata);

typedef
pmix_status_t (*lookup_fn_t)(pmix_pdata_t data[], size_t ndata,
                             const pmix_info_t info[], size_t ninfo);

typedef
pmix_status_t (*lookup_nb_fn_t)(char **keys,
                                const pmix_info_t info[], size_t ninfo,
                                pmix_lookup_cbfunc_t cbfunc, void *cbdata);

typedef
pmix_status_t (*unpublish_fn_t)(char **keys,
                                const pmix_info_t info[], size_t ninfo);

typedef
pmix_status_t (*unpublish_nb_fn_t)(char **keys,
                                   const pmix_info_t info[], size_t ninfo,
                                   pmix_op_cbfunc_t cbfunc, void *cbdata);

typedef
pmix_status_t (*spawn_fn_t)(const pmix_info_t job_info[], size_t ninfo,
                            const pmix_app_t apps[], size_t napps,
                            char nspace[]);

typedef
pmix_status_t (*spawn_nb_fn_t)(const pmix_info_t job_info[], size_t ninfo,
                               const pmix_app_t apps[], size_t napps,
                               pmix_spawn_cbfunc_t cbfunc, void *cbdata);

typedef
pmix_status_t (*connect_fn_t)(const pmix_proc_t procs[], size_t nprocs,
                              const pmix_info_t info[], size_t ninfo);

typedef
pmix_status_t (*connect_nb_fn_t)(const pmix_proc_t procs[], size_t nprocs,
                                 const pmix_info_t info[], size_t ninfo,
                                 pmix_op_cbfunc_t cbfunc, void *cbdata);

typedef
pmix_status_t (*disconnect_fn_t)(const pmix_proc_t procs[], size_t nprocs,
                                 const pmix_info_t info[], size_t ninfo);

typedef
pmix_status_t (*disconnect_nb_fn_t)(const pmix_proc_t ranges[], size_t nprocs,
                                    const pmix_info_t info[], size_t ninfo,
                                    pmix_op_cbfunc_t cbfunc, void *cbdata);

typedef
pmix_status_t (*resolve_peers_fn_t)(const char *nodename, const char *nspace,
                                    pmix_proc_t **procs, size_t *nprocs);

typedef
pmix_status_t (*resolve_nodes_fn_t)(const char *nspace, char **nodelist);

struct symbols {
    init_fn_t          init;
    finalize_fn_t      finalize;
    initialized_fn_t   initialized;
    abort_fn_t         abort;
    put_fn_t           put;
    commit_fn_t        commit;
    fence_fn_t         fence;
    fence_nb_fn_t      fence_nb;
    get_fn_t           get;
    get_nb_fn_t        get_nb;
    publish_fn_t       publish;
    publish_nb_fn_t    publish_nb;
    lookup_fn_t        lookup;
    lookup_nb_fn_t     lookup_nb;
    unpublish_fn_t     unpublish;
    unpublish_nb_fn_t  unpublish_nb;
    spawn_fn_t         spawn;
    spawn_nb_fn_t      spawn_nb;
    connect_fn_t       connect;
    connect_nb_fn_t    connect_nb;
    disconnect_fn_t    disconnect;
    disconnect_nb_fn_t disconnect_nb;
    resolve_peers_fn_t resolve_peers;
    resolve_nodes_fn_t resolve_nodes;
};

static struct symbols symbols;

static bool initialized = false;

#define FIND_SYMBOL(version, name)                                     \
    do {                                                               \
        char capname[256], fullname[256], *error;                      \
        strncpy(capname, #name, sizeof(capname) - 1);                  \
        capname[sizeof(capname) - 1] = '\0';                           \
        capname[0] = capname[0] - 'a' + 'A';                           \
        snprintf(fullname, sizeof(fullname),                           \
                 "OPAL_PMIX_PMIX%s_PMIx_%s", version, capname);        \
        dlerror();                                                     \
        *(void **)&symbols.name = dlsym(NULL, fullname);               \
        error = dlerror();                                             \
        if (error != NULL) {                                           \
            fprintf(stderr, "PMIx-OMPI dlsym error: %s\n", error);     \
            fflush(stderr);                                            \
            exit(1);                                                   \
        }                                                              \
    } while (0)

static void initialize(void)
{
    char *version;

    if (initialized) {
        return;
    }

    version = getenv("PMIX_OMPI_VERSION");
    if (NULL == version) {
        fprintf(stderr, "Set an environment variable PMIX_OMPI_VERSION!\n");
        exit(1);
    }

    FIND_SYMBOL(version, init);
    FIND_SYMBOL(version, finalize);
    FIND_SYMBOL(version, initialized);
    FIND_SYMBOL(version, abort);
    FIND_SYMBOL(version, put);
    FIND_SYMBOL(version, commit);
    FIND_SYMBOL(version, fence);
    FIND_SYMBOL(version, fence_nb);
    FIND_SYMBOL(version, get);
    FIND_SYMBOL(version, get_nb);
    FIND_SYMBOL(version, publish);
    FIND_SYMBOL(version, publish_nb);
    FIND_SYMBOL(version, lookup);
    FIND_SYMBOL(version, lookup_nb);
    FIND_SYMBOL(version, unpublish);
    FIND_SYMBOL(version, unpublish_nb);
    FIND_SYMBOL(version, spawn);
    FIND_SYMBOL(version, spawn_nb);
    FIND_SYMBOL(version, connect);
    FIND_SYMBOL(version, connect_nb);
    FIND_SYMBOL(version, disconnect);
    FIND_SYMBOL(version, disconnect_nb);
    FIND_SYMBOL(version, resolve_peers);
    FIND_SYMBOL(version, resolve_nodes);

    initialized = true;
}

pmix_status_t PMIx_Init(pmix_proc_t *proc,
                        pmix_info_t info[], size_t ninfo)
{
    initialize();
    return symbols.init(proc, info, ninfo);
}

pmix_status_t PMIx_Finalize(const pmix_info_t info[], size_t ninfo)
{
    initialize();
    return symbols.finalize(info, ninfo);
}

int PMIx_Initialized(void);

pmix_status_t PMIx_Abort(int status, const char msg[],
                         pmix_proc_t procs[], size_t nprocs)
{
    initialize();
    return symbols.abort(status, msg, procs, nprocs);
}

pmix_status_t PMIx_Put(pmix_scope_t scope,
                       const char key[], pmix_value_t *val)
{
    initialize();
    return symbols.put(scope, key, val);
}

pmix_status_t PMIx_Commit(void)
{
    initialize();
    return symbols.commit();
}

pmix_status_t PMIx_Fence(const pmix_proc_t procs[], size_t nprocs,
                         const pmix_info_t info[], size_t ninfo)
{
    initialize();
    return symbols.fence(procs, nprocs, info, ninfo);
}

pmix_status_t PMIx_Fence_nb(const pmix_proc_t procs[], size_t nprocs,
                            const pmix_info_t info[], size_t ninfo,
                            pmix_op_cbfunc_t cbfunc, void *cbdata)
{
    initialize();
    return symbols.fence_nb(procs, nprocs, info, ninfo, cbfunc, cbdata);
}

pmix_status_t PMIx_Get(const pmix_proc_t *proc, const char key[],
                       const pmix_info_t info[], size_t ninfo,
                       pmix_value_t **val)
{
    initialize();
    return symbols.get(proc, key, info, ninfo, val);
}

pmix_status_t PMIx_Get_nb(const pmix_proc_t *proc, const char key[],
                          const pmix_info_t info[], size_t ninfo,
                          pmix_value_cbfunc_t cbfunc, void *cbdata)
{
    initialize();
    return symbols.get_nb(proc, key, info, ninfo, cbfunc, cbdata);
}

pmix_status_t PMIx_Publish(const pmix_info_t info[], size_t ninfo)
{
    initialize();
    return symbols.publish(info, ninfo);
}

pmix_status_t PMIx_Publish_nb(const pmix_info_t info[], size_t ninfo,
                              pmix_op_cbfunc_t cbfunc, void *cbdata)
{
    initialize();
    return symbols.publish_nb(info, ninfo, cbfunc, cbdata);
}

pmix_status_t PMIx_Lookup(pmix_pdata_t data[], size_t ndata,
                          const pmix_info_t info[], size_t ninfo)
{
    initialize();
    return symbols.lookup(data, ndata, info, ninfo);
}

pmix_status_t PMIx_Lookup_nb(char **keys,
                             const pmix_info_t info[], size_t ninfo,
                             pmix_lookup_cbfunc_t cbfunc, void *cbdata)
{
    initialize();
    return symbols.lookup_nb(keys, info, ninfo, cbfunc, cbdata);
}

pmix_status_t PMIx_Unpublish(char **keys,
                              const pmix_info_t info[], size_t ninfo)
{
    initialize();
    return symbols.unpublish(keys, info, ninfo);
}

pmix_status_t PMIx_Unpublish_nb(char **keys,
                                const pmix_info_t info[], size_t ninfo,
                                pmix_op_cbfunc_t cbfunc, void *cbdata)
{
    initialize();
    return symbols.unpublish_nb(keys, info, ninfo, cbfunc, cbdata);
}

pmix_status_t PMIx_Spawn(const pmix_info_t job_info[], size_t ninfo,
                         const pmix_app_t apps[], size_t napps,
                         char nspace[])
{
    initialize();
    return symbols.spawn(job_info, ninfo, apps, napps, nspace);
}

pmix_status_t PMIx_Spawn_nb(const pmix_info_t job_info[], size_t ninfo,
                            const pmix_app_t apps[], size_t napps,
                            pmix_spawn_cbfunc_t cbfunc, void *cbdata)
{
    initialize();
    return symbols.spawn_nb(job_info, ninfo, apps, napps, cbfunc, cbdata);
}

pmix_status_t PMIx_Connect(const pmix_proc_t procs[], size_t nprocs,
                           const pmix_info_t info[], size_t ninfo)
{
    initialize();
    return symbols.connect(procs, nprocs, info, ninfo);
}

pmix_status_t PMIx_Connect_nb(const pmix_proc_t procs[], size_t nprocs,
                              const pmix_info_t info[], size_t ninfo,
                              pmix_op_cbfunc_t cbfunc, void *cbdata)
{
    initialize();
    return symbols.connect_nb(procs, nprocs, info, ninfo, cbfunc, cbdata);
}

pmix_status_t PMIx_Disconnect(const pmix_proc_t procs[], size_t nprocs,
                              const pmix_info_t info[], size_t ninfo)
{
    initialize();
    return symbols.disconnect(procs, nprocs, info, ninfo);
}

pmix_status_t PMIx_Disconnect_nb(const pmix_proc_t ranges[], size_t nprocs,
                                 const pmix_info_t info[], size_t ninfo,
                                 pmix_op_cbfunc_t cbfunc, void *cbdata)
{
    initialize();
    return symbols.disconnect_nb(ranges, nprocs, info, ninfo, cbfunc, cbdata);
}

pmix_status_t PMIx_Resolve_peers(const char *nodename, const char *nspace,
                                 pmix_proc_t **procs, size_t *nprocs)
{
    initialize();
    return symbols.resolve_peers(nodename, nspace, procs, nprocs);
}

pmix_status_t PMIx_Resolve_nodes(const char *nspace, char **nodelist)
{
    initialize();
    return symbols.resolve_nodes(nspace, nodelist);
}
