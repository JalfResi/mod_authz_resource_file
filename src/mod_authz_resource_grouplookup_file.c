#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_lib.h" /* apr_isspace */

#include <mod_authz_resource_grouplookup.h>

typedef struct {
    char *groupfile;
    int authoritative;
} authz_resource_groupfile_config_rec;

static void *create_authz_resource_groupfile_dir_config(apr_pool_t *p, char *d)
{
    authz_resource_groupfile_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->groupfile = NULL;
    conf->authoritative = 1; /* keep the fortress secure by default */
    return conf;
}

static const char *set_authz_resource_groupfile_slot(cmd_parms *cmd, void *offset, const char *f,
                                 const char *t)
{
    if (t && strcmp(t, "standard")) {
        return apr_pstrcat(cmd->pool, "Invalid auth file type: ", t, NULL);
    }

    return ap_set_file_slot(cmd, offset, f);
}

static const command_rec authz_groupfile_cmds[] =
{
    AP_INIT_TAKE12("AuthResourceGroupFile", set_authz_resource_groupfile_slot,
                   (void *)APR_OFFSETOF(authz_resource_groupfile_config_rec, groupfile),
                   OR_AUTHCFG,
                   "text file containing group names and member user IDs"),
    {NULL}
};

module AP_MODULE_DECLARE_DATA authz_resource_grouplookup_file_module;

static apr_status_t *get_groups_by_username(request_rec *r, apr_table_t ** out)
{
    authz_resource_groupfile_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authz_resource_grouplookup_file_module);
    ap_configfile_t *f;
    apr_table_t *grps = apr_table_make(r->pool, 15);
    apr_pool_t *sp;
    char l[MAX_STRING_LEN];
    const char *group_name, *ll, *w;
    apr_status_t status;
    apr_size_t group_len;

    /* If there is no group file - then we are not
     * configured. So decline.
     */
    if (!(conf->groupfile)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
					  "GroupFile directive not configured");    
        return DECLINED;
    }

    /* If there's no user, it's a misconfiguration */
    if (!r->user) {
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    if ((status = ap_pcfg_openfile(&f, r->pool, conf->groupfile)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
					  "Could not open group file: %s",
					  conf->groupfile);
		return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_pool_create(&sp, r->pool);

    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        if ((l[0] == '#') || (!l[0])) {
            continue;
        }
        ll = l;
        apr_pool_clear(sp);

        group_name = ap_getword(sp, &ll, ':');
        group_len = strlen(group_name);

        while (group_len && apr_isspace(*(group_name + group_len - 1))) {
            --group_len;
        }

        while (ll[0]) {
            w = ap_getword_conf(sp, &ll);
            if (!strcmp(w, r->user)) {
                apr_table_setn(grps, apr_pstrmemdup(r->pool, group_name, group_len),
                               "in");
                break;
            }
        }
    }
    ap_cfg_closefile(f);
    apr_pool_destroy(sp);

    *out = grps;
    return APR_SUCCESS;
}

static const authz_resource_grouplookup_provider authz_resource_grouplookup_bob_provider =
{
    &get_groups_by_username,
};

static void provider_test_bob_register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AUTHZ_RESOURCE_GROUPLOOKUP_PROVIDER_GROUP, "dbd", "0",
                         &authz_resource_grouplookup_bob_provider);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA authz_resource_grouplookup_file_module = {
    STANDARD20_MODULE_STUFF, 
    create_authz_resource_groupfile_dir_config,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    authz_groupfile_cmds,             /* table of config file commands       */
    provider_test_bob_register_hooks  /* register hooks                      */
};
