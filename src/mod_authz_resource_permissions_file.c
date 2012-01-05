#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include "apr_strings.h"
#include "apr_tables.h"
#include "apr_lib.h" /* apr_isspace */

#include <mod_authz_resource_permissions.h>

typedef struct {
    char *permissionsfile;
    int authoritative;
} authz_resource_permissions_config_rec;

static void *create_authz_resource_permissions_dir_config(apr_pool_t *p, char *d)
{
    authz_resource_permissions_config_rec *conf = apr_palloc(p, sizeof(*conf));

    conf->permissionsfile = NULL;
    conf->authoritative = 1; /* keep the fortress secure by default */
    return conf;
}

static resource_permissions_t *create_resource_permission(apr_pool_t *p)
{
	resource_permissions_t *resPerms;
	resPerms = (resource_permissions_t *) apr_palloc(p, sizeof(resource_permissions_t));

	resPerms->owner = (char *) apr_palloc(p, sizeof(15));
	resPerms->group = (char *) apr_palloc(p, sizeof(15));

	resPerms->ownerPerms = apr_table_make(p, 15);
	resPerms->groupPerms = apr_table_make(p, 15);
	resPerms->worldPerms = apr_table_make(p, 15);
	return resPerms;
}

module AP_MODULE_DECLARE_DATA authz_resource_permissions_file_module;

static apr_status_t *get_permissions_by_uri(request_rec *r, resource_permissions_t ** out)
{
    authz_resource_permissions_config_rec *conf = ap_get_module_config(r->per_dir_config,
                                                      &authz_resource_permissions_file_module);
    ap_configfile_t *f;
    apr_pool_t *sp;
    char l[MAX_STRING_LEN];
    char *permissionsFilename;
    const char *setting_name, *ll, *w;
    apr_status_t status;
    apr_size_t setting_len;

	resource_permissions_t *resPerms = create_resource_permission(r->pool);

	/* if theres no request filename, error! */
	if (!r->filename) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r,
					  "Missing request filename");
        return HTTP_INTERNAL_SERVER_ERROR;
	}
	ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r,
					  "Filename: %s", r->filename);
	permissionsFilename = apr_pstrcat(r->pool, r->filename, ".permissions");
	ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r,
					  "Permissions Filename: %s", permissionsFilename);

    /* If there's no user, it's a misconfiguration */
    /*
    if (!r->user) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r,
					  "Missing user");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    */

    if ((status = ap_pcfg_openfile(&f, r->pool, permissionsFilename)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, status, r,
					  "Could not open permissions file: %s",
					  permissionsFilename);
		return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_pool_create(&sp, r->pool);

    while (!(ap_cfg_getline(l, MAX_STRING_LEN, f))) {
        if ((l[0] == '#') || (!l[0])) { // Comment or blank, skip it
            continue;
        }
        ll = l;
        apr_pool_clear(sp);

        setting_name = ap_getword(sp, &ll, ':');
        setting_len = strlen(setting_name);

        while (setting_len && apr_isspace(*(setting_name + setting_len - 1))) {
            --setting_len;
        }

        while (ll[0]) {
            w = ap_getword_conf(sp, &ll);
			ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r,
					  "W: %s Setting: %s", w, setting_name);
            
            if (!strcmp(setting_name, "owner")) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r,
					  "Owner: %s", w);
            	resPerms->owner = apr_pstrdup(r->pool, w);
            } else if (!strcmp(setting_name, "group")) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r,
					  "Group: %s", w);
            	resPerms->group = apr_pstrdup(r->pool, w);
            } else {
            	if (!strcmp(setting_name, "ownerPerms")) {
					ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r,
					  "OwnerPerms: %s", w);
	                apr_table_setn(resPerms->ownerPerms, apr_pstrdup(r->pool, w),
                               "in");
            	} else if (!strcmp(setting_name, "groupPerms")) {
					ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r,
					  "GroupPerms: %s", w);
                    apr_table_setn(resPerms->groupPerms, apr_pstrdup(r->pool, w),
                               "in");
	        	} else if (!strcmp(setting_name, "worldPerms")) {
					ap_log_rerror(APLOG_MARK, APLOG_ERR, NULL, r,
					  "WorldPerms: %s", w);
    	            apr_table_setn(resPerms->worldPerms, apr_pstrdup(r->pool, w),
                               "in");
    	            //apr_table_setn(resPerms->worldPerms, apr_pstrmemdup(r->pool, setting_name, setting_len),
                    //           "in");
                }
            }
            /*
            if (!strcmp(w, r->user)) {
                apr_table_setn(resPerms->ownerPerms, apr_pstrmemdup(r->pool, setting_name, setting_len),
                               "in");
                break;
            }
            */
        }
    }
    ap_cfg_closefile(f);
    apr_pool_destroy(sp);

    *out = resPerms;
    return APR_SUCCESS;
}

static const authz_resource_permissions_provider authz_resource_permissions_bob_provider =
{
    &get_permissions_by_uri,
};

static void provider_test_bob_register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AUTHZ_RESOURCE_PERMISSIONS_PROVIDER_GROUP, "file-test", "0",
                         &authz_resource_permissions_bob_provider);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA authz_resource_permissions_file_module = {
    STANDARD20_MODULE_STUFF, 
    create_authz_resource_permissions_dir_config,                  /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    NULL,             /* table of config file commands       */
    provider_test_bob_register_hooks  /* register hooks                      */
};
