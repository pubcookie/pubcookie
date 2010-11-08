/*
 * Copyright (C) 2010 Vitki <vitki@vitki.net>
 *
 * Based on ngx_http_auth_pam_module.c by Sergio Talens-Oliag
 *
 * SVN Id: $Id$
 */

#define OPENSSL_IN_DIR
#undef  HAVE_CONFIG_H
#define pool ngx_pool_t

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#ifdef OPENSSL_IN_DIR
#  include <openssl/pem.h>
#  include <openssl/des.h>
#  include <openssl/rand.h>
#  include <openssl/err.h>
#else
#  include <pem.h>
#  include <des.h>
#  include <rand.h>
#  include <err.h>
#endif

#include <ctype.h>

/* pubcookie stuff */

#include "pbc_logging.h"
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "security.h"

#define DONE NGX_DONE

#define libpbc_config_getstring(p,n,v) pbc_get_cfg_str(r,n,v)

/* Cookies are secure except for execptional cases */
#ifdef PORT80_TEST
static char *secure_cookie = "";
#else
static char *secure_cookie = " secure";
#endif

static ngx_str_t pbc_content_type = ngx_string("text/html; charset=utf-8");

#define BASIC_REALM_C "Basic realm=\""

#define SET_C_LETTER(c,a,b) (*(c)++ = '%', *(c)++ = (a), *(c)++ = (b))

#define ngx_pubcookie_module ngx_http_auth_pubcookie_module

#define pc_req_log(r,args...) ngx_log_error_core(NGX_LOG_WARN,(r)->connection->log,0,args)
#define pc_cf_log(c,args...) ngx_log_error_core(NGX_LOG_WARN,(c)->log,0,args)

#define ngx_str_assign(a,s) do { u_char *_p = (u_char *)(s); (a).len = ngx_strlen(_p); (a).data = _p; } while(0)

static ngx_str_t blank_str = ngx_string("");

/* Module configuration struct */
typedef struct {
    /* === config list === */
    /*table *configlist; //table?*/
    ngx_str_t login_uri;
    ngx_str_t enterprise_domain;
    ngx_str_t keydir;
    ngx_str_t granting_cert_file;
    ngx_str_t ssl_key_file;
    ngx_str_t ssl_cert_file;
    ngx_str_t crypt_key;
    ngx_str_t egd_socket;
    /* === server part === */
    int dirdepth;
    int noblank;
    int catenate;		/* Added by ddj@cmu.edu on 2006/05/01 */
    int no_clean_creds;
    ngx_str_t login;
    ngx_str_t appsrvid;
    int use_post;
    ngx_str_t post_reply_url;
    security_context *sectext;
    unsigned crypt_alg;
    int vitki_behind_proxy;
    /* === location part === */
    ngx_str_t	realm;		/* http basic auth realm */
    int inact_exp;
    int hard_exp;
    int non_ssl_ok;
    ngx_str_t oldappid; /* Added by ddj@cmu.edu on 2006/05/10 */
    ngx_str_t appid;
    ngx_str_t end_session;
    int session_reauth;
    ngx_str_t addl_requests;
    int strip_realm;
    ngx_str_t accept_realms;
    int noprompt;
    int dummy;
} ngx_pubcookie_loc_conf_t;

typedef struct
{
    int failed;
    int redir_reason_no;
    int has_granting;
    ngx_str_t user;
    ngx_str_t user_name;
    char creds;
    pbc_cookie_data *cookie_data;
    ngx_str_t stop_message;
    ngx_str_t cred_transfer;
    ngx_str_t passwd;
    /*table *hdr_out; //table?*/
    /*table *hdr_err; //table?*/
    ngx_str_t msg;
    ngx_str_t app_path;
    ngx_str_t server_name;
} ngx_pubcookie_req_rec;

static struct {
    const char *name;
    size_t offset;
} pbc_cfg_str_fields[] = {
    { "enterprise_domain", offsetof(ngx_pubcookie_loc_conf_t, enterprise_domain) },
    { NULL, 0 }
};

/* Module handler */
static ngx_int_t ngx_pubcookie_authz_handler(ngx_http_request_t *r);

/* Function that authenticates the user -- is the only function that uses Pubcookie */
static ngx_int_t ngx_pubcookie_authenticate (ngx_http_request_t *r, ngx_pubcookie_req_rec *rr, void *conf);

static ngx_int_t ngx_pubcookie_set_realm (ngx_http_request_t *r, ngx_str_t *realm);

static void *ngx_pubcookie_create_loc_conf (ngx_conf_t *cf);

static char *ngx_pubcookie_merge_loc_conf (ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_pubcookie_init (ngx_conf_t *cf);

static char *ngx_pubcookie_post_handler_proc (ngx_conf_t *cf, void *post, void *data);

static ngx_conf_post_handler_pt  ngx_pubcookie_p = ngx_pubcookie_post_handler_proc;


static char *pubcookie_set_inact_exp (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *pubcookie_set_hard_exp (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *pubcookie_set_login (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *pubcookie_set_domain (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *pubcookie_set_method (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *pubcookie_set_crypt (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *pubcookie_set_appid (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *pubcookie_set_appsrvid (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *pubcookie_set_noprompt (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static char pubcookie_auth_type (ngx_http_request_t * r);

static int pubcookie_user (ngx_http_request_t * r, ngx_pubcookie_loc_conf_t *conf, ngx_pubcookie_req_rec *rr);
static int pubcookie_user_hook (ngx_http_request_t * r);

/**************************************
 * Initialization
 */

static ngx_command_t  ngx_pubcookie_commands[] = {
    /* "Set the inactivity expire time for PubCookies." */
    { ngx_string("pubcookie_inactive_expire"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      pubcookie_set_inact_exp,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, inact_exp),
      NULL },

    /* "Set the hard expire time for PubCookies." */
    { ngx_string("pubcookie_hard_expire"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      pubcookie_set_hard_exp,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, hard_exp),
      NULL },

    /* "Set the login page for PubCookies." */
    { ngx_string("pubcookie_login"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      pubcookie_set_login,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, login_uri),
      NULL },

    /* "Set the domain for PubCookies." */
    { ngx_string("pubcookie_domain"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      pubcookie_set_domain,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, enterprise_domain),
      NULL },

    /* "Set the location of PubCookie encryption keys." */
    { ngx_string("pubcookie_key_dir"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, keydir),
      NULL },

    /* "Set the name of the certfile for Granting PubCookies." */
    { ngx_string("pubcookie_granting_cert_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, granting_cert_file),
      NULL },

    /* "Set the name of the keyfile for Session PubCookies." */
    { ngx_string("pubcookie_session_key_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, ssl_key_file),
      NULL },

    /* "Set the name of the certfile for Session PubCookies." */
    { ngx_string("pubcookie_session_cert_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, ssl_cert_file),
      NULL },

    /* "Set the name of the encryption keyfile for PubCookies." */
    { ngx_string("pubcookie_crypt_key_file"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, crypt_key),
      NULL },

    /* "Set the name of the EGD Socket if needed for randomness." */
    { ngx_string("pubcookie_egd_device"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, egd_socket),
      NULL },

    /* "Set login method (GET/POST). Def = GET" */
    { ngx_string("pubcookie_login_method"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      pubcookie_set_method,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, use_post),
      NULL },

    /* "Set encryption method (AES/DES)." */
    { ngx_string("pubcookie_encryption"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      pubcookie_set_crypt,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, crypt_alg),
      NULL },

    /* "Set the name of the application." */
    { ngx_string("pubcookie_app_id"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      pubcookie_set_appid,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, appid),
      NULL },

    /* "Set the name of the server(cluster)." */
    { ngx_string("pubcookie_app_srv_id"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      pubcookie_set_appsrvid,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, appsrvid),
      NULL },

    /* "Do not prompt for id and password if not already logged in." */
    { ngx_string("pubcookie_no_prompt"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      pubcookie_set_noprompt,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, noprompt),
      NULL },

#if 0
    /* "Do not blank cookies.". DEPRECATED in favour of pubcookie_no_obscure_cookies */
    { ngx_string("pubcookie_no_blank"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      pubcookie_set_no_blank,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, noblank),
      NULL },

    /* "Do not obscure Pubcookie cookies." */
    { ngx_string("pubcookie_no_obscure_cookies"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      pubcookie_set_no_obscure,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, noblank),
      NULL },

    /* Added by ddj@cmu.edu on 2006/05/01 to address security issue at CMU. */
    /* "Determines whether a new AppID replaces or is catenated to the old App ID." */
    { ngx_string("pubcookie_catenate_app_ids"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      pubcookie_set_catenate_appids,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, catenate),
      NULL },
    /* End of ddj@cmu.edu's change. */

    /* "Specify the Directory Depth for generating default AppIDs." */
    { ngx_string("pubcookie_dir_depth_for_app_id"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      pubcookie_set_dirdepth,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, dirdepth),
      NULL },

    /* "Force reauthentication for new sessions with specified timeout" */
    { ngx_string("pubcookie_session_cause_reauth"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      set_session_reauth,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, session_reauth),
      NULL },

    /* "End application session and possibly login session" */
    { ngx_string("pubcookie_end_session"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE/*AP_INIT_RAW_ARGS*/,
      set_end_session,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, end_session),
      NULL },

    /* "Send the following options to the login server along with authentication requests" */
    { ngx_string("pubcookie_add_request"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE/*AP_INIT_ITERATE*/,
      pubcookie_add_request_iterate,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, addl_requests),
      NULL },

    /* "Only accept realms in this list" */
    { ngx_string("pubcookie_accept_realm"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE/*AP_INIT_ITERATE*/,
      pubcookie_accept_realms_iterate,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, accept_realms),
      NULL },

    /* "Strip the realm (and set the REMOTE_REALM envirorment variable)" */
    { ngx_string("pubcookie_strip_realm"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      pubcookie_strip_realm,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, strip_realm),
      NULL },

    /* "Specify on-demand pubcookie directives." */
    { ngx_string("pubcookie_on_demand"),
      NGX_HTTP_LOC_CONF|NGX_CONF_2MORE/*AP_INIT_ITERATE2*/,
      pubcookie_set_keyed_directive_iterate2,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, dummy),
      NULL },

    /* "Set post response URL. Def = /PubCookie.reply" */
    { ngx_string("pubcookie_post_url"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      pubcookie_set_post_url,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, post_reply_url),
      NULL },

    /* "Deprecated, do not use" */
    { ngx_string("pubcookie_super_debug"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE/*AP_INIT_ITERATE*/,
      pubcookie_set_super_debug_iterate,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, dummy),
      NULL },

    /* "Set to leave credentials in place after cleanup" */
    { ngx_string("pubcookie_no_clean_creds"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      pubcookie_set_no_clean_creds,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, no_clean_creds),
      NULL },

    /* "Set to ignore non-standard server port" */
    { ngx_string("pubcookie_vitki_behind_proxy"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      pubcookie_set_vitki_behind_proxy,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_conf_t, vitki_behind_proxy),
      NULL },
#endif

    ngx_null_command
};

static ngx_http_module_t  ngx_pubcookie_module_ctx = {
    NULL,                             /* preconfiguration */
    ngx_pubcookie_init,               /* postconfiguration */

    NULL,                             /* create main configuration */
    NULL,                             /* init main configuration */

    NULL,                             /* create server configuration */
    NULL,                             /* merge server configuration */

    ngx_pubcookie_create_loc_conf,    /* create location configuration */
    ngx_pubcookie_merge_loc_conf      /* merge location configuration */
};

ngx_module_t ngx_pubcookie_module = {
    NGX_MODULE_V1,
    &ngx_pubcookie_module_ctx,             /* module context */
    ngx_pubcookie_commands,                /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


/**************************************
 * Utilities
 */

static void
ngx_str_assign_copy (ngx_pool_t *p, ngx_str_t *dst, u_char *src)
{
    ngx_str_t tmp;
    tmp.data = (u_char *) src;
    tmp.len = ngx_strlen(tmp.data);
    dst->data = ngx_pstrdup(p, &tmp);
    dst->len = tmp.len;
}

static char *
getword_white_nc (ngx_pool_t *pool, char **line)
{
    char *p = *line;
    int len;
    char *res;

    while (!isspace(*p) && *p)
        ++p;

    len = p - *line;
    res = ngx_pnalloc(pool, len + 1);
    ngx_memcpy(res, *line, len);
    res[len] = 0;

    while (isspace(*p))
        ++p;

    *line = p;
    return res;
}
 
static int
ngx_strcat3 (ngx_pool_t *pool, ngx_str_t *res, ngx_str_t *s1, ngx_str_t *s2, ngx_str_t *s3)
{
    u_char *p;
    int n, n1, n2, n3;
    n1 = s1 == NULL || s1->data == NULL ? 0 : s1->len == (unsigned)-1 ? ngx_strlen(s1->data) : s1->len;
    n2 = s2 == NULL || s2->data == NULL ? 0 : s2->len == (unsigned)-1 ? ngx_strlen(s2->data) : s2->len;
    n3 = s3 == NULL || s3->data == NULL ? 0 : s3->len == (unsigned)-1 ? ngx_strlen(s3->data) : s3->len;
    n = n1 + n2 + n3 + 1;
    p = ngx_pnalloc(pool, n);
    if (p == NULL) {
        return NGX_ERROR;
    }
    if (n1 > 0) {
        ngx_memcpy(p, s1->data, n1);
    }
    if (n2 > 0) {
        ngx_memcpy(p + n1, s2->data, n2);
    }
    if (n3 > 0) {
        ngx_memcpy(p + n1 + n2, s3->data, n3);
    }
    p[n1+n2+n3] = '\0';
    res->data = p;
    res->len = n;
    return NGX_OK;
}

static char *
nswrap (ngx_pool_t *pool, ngx_str_t *nsp)
{
    ngx_str_t q = ngx_string("\"");
    ngx_str_t res;
    if (NULL == nsp || NULL == nsp->data) {
        return "(NIL)";
    }
    ngx_strcat3(pool, &res, &q, nsp, &q);
    return (char *) res.data;
}

static void
dump_loc_rec(ngx_http_request_t *r, ngx_pubcookie_loc_conf_t *c)
{
    ngx_pool_t *p = r->pool;
    pc_req_log(r, "+--- dump_loc_req ---");
    pc_req_log(r, "| login_uri=%s domain=%s", nswrap(p,&c->login_uri), nswrap(p,&c->enterprise_domain));
    pc_req_log(r, "| keydir=%s grant_cf=%s ssl_keyf=%s ssl_cf=%s", nswrap(p,&c->keydir), nswrap(p,&c->granting_cert_file), nswrap(p,&c->ssl_key_file), nswrap(p,&c->ssl_cert_file));
    pc_req_log(r, "| crypt_key=%s egd_socket=%s", nswrap(p,&c->crypt_key), nswrap(p, &c->egd_socket));
    pc_req_log(r, "| login=%s oldappid=%s appid=%s appsrvid=%s", nswrap(p,&c->login), nswrap(p,&c->oldappid), nswrap(p,&c->appid), nswrap(p,&c->appsrvid));
    pc_req_log(r, "| post_reply_url=%s realm=%s end_session=%s addl_requests=%s accept_realms=%s", nswrap(p,&c->post_reply_url), nswrap(p,&c->realm), nswrap(p,&c->end_session), nswrap(p,&c->addl_requests), nswrap(p,&c->accept_realms));
    pc_req_log(r, "| dirdepth=%d noblank=%d catenate=%d no_clean_creds=%d use_post=%d behind_proxy=%d", c->dirdepth, c->noblank, c->catenate, c->no_clean_creds, c->use_post, c->vitki_behind_proxy);
    pc_req_log(r, "| crypt_alg=%d inact_exp=%d hard_exp=%d non_ssl_ok=%d session_reauth=%d", c->crypt_alg, c->inact_exp, c->hard_exp, c->non_ssl_ok, c->session_reauth);
    pc_req_log(r, "| strip_realm=%d noprompt=%d", c->strip_realm, c->noprompt);
    pc_req_log(r, "+----------------------------------");
}

/**************************************
 * Configuration
 */

static const char *
pbc_get_cfg_str(ngx_http_request_t *r, const char *name, const char *defval)
{
    ngx_pubcookie_loc_conf_t *cfg = ngx_http_get_module_loc_conf(r, ngx_pubcookie_module);
    int i;

    if (NULL == cfg) {
        pc_req_log(r, "PUBCOOKIE: local configuration not found for \"%s\"", name);
        return defval;
    }

    for (i = 0; pbc_cfg_str_fields[i].name != NULL; i++) {
        if (0 == strcmp(pbc_cfg_str_fields[i].name, name)) {
            ngx_str_t *nsp = (ngx_str_t *) ((char *)cfg + pbc_cfg_str_fields[i].offset);
            const char * val = NULL == nsp->data ? defval : (const char *) nsp->data;
            pc_req_log(r, "PUBCOOKIE: value of \"%s\" is \"%s\"", name, val);
            return val;
        }
    }
    /* not found */
    pc_req_log(r, "PUBCOOKIE: field \"%s\" not found !!", name);
    return defval;
}

static char *
pubcookie_set_inact_exp (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_conf_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;

    if ((cfg->inact_exp = ngx_atoi (value[1].data, value[1].len)) == NGX_ERROR) {
        return "PUBCOOKIE: Could not convert inactivity expire parameter to nonnegative number.";
    }

    /* how to turn off inactivity checking */
    if (cfg->inact_exp == -1) {
        return NGX_CONF_OK;
    }

    /* check for valid range */
    if (cfg->inact_exp < PBC_MIN_INACT_EXPIRE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "PUBCOOKIE: inactivity expire parameter less then allowed minimum of %d, requested %d.",
            PBC_MIN_INACT_EXPIRE, cfg->inact_exp);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
pubcookie_set_hard_exp (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_conf_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;

    if ((cfg->hard_exp = ngx_atoi(value[1].data, value[1].len)) == NGX_ERROR) {
        return "PUBCOOKIE: PubcookieHardExpire should be nonnegative integer.";
    } else if (cfg->hard_exp > PBC_MAX_HARD_EXPIRE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "PUBCOOKIE: Hard expire parameter greater then allowed maximium of %d, requested %d.",
            PBC_MAX_HARD_EXPIRE, cfg->hard_exp);
        return NGX_CONF_ERROR;
    } else if (cfg->hard_exp < PBC_MIN_HARD_EXPIRE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "PUBCOOKIE: Hard expire parameter less then allowed minimum of %d, requested %d.",
            PBC_MIN_HARD_EXPIRE, cfg->hard_exp);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
pubcookie_set_login (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_conf_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;

    ngx_str_t schema = ngx_string("https://");
    ngx_str_t path = ngx_string("/");
    ngx_str_t host;
    u_char *p;

    if (ngx_strncmp(value[1].data, "http://", 7) && ngx_strncmp(value[1].data, "https://", 8)) {
        return "PUBCOOKIE: PubCookieLogin must start with http:// or https://";
    }

    host.data = value[1].data + 7;
    host.len = value[1].len - 7;
    if (value[1].data[4] == 's') {
        host.data++;
        host.len--;
    }

    p = ngx_strnstr(host.data, "/", host.len);
    if (NULL == p) {
        p = ngx_strnstr(host.data, "?", host.len);
    }
    if (NULL != p) {
        path.data = p;
        path.len = host.len - (int)(p - host.data);
        host.len = (int)(p - host.data);
    }

    ngx_strcat3(cf->pool, &cfg->login_uri, &schema, &host, &path);

    return NGX_CONF_OK;
}

/**
 *  handle the PubCookieDomain directive
 */
static char *
pubcookie_set_domain (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_conf_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;

    if (value[1].data[0] == '.') {
        cfg->enterprise_domain = value[1];
    } else {
        static ngx_str_t the_dot = ngx_string(".");
        ngx_strcat3(cf->pool, &cfg->enterprise_domain, &the_dot, &value[1], NULL);
    }

    return NGX_CONF_OK;
}

static char *
pubcookie_set_method (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_conf_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;

    if (0 == ngx_strcasecmp(value[1].data, (u_char *) "get")) {
        cfg->use_post = 0;
    } else if (0 == ngx_strcasecmp(value[1].data, (u_char *) "post")) {
        cfg->use_post = 1;
    } else {
        return "Invalid pubcookie login method";
    }

    return NGX_OK;
}

static char *
pubcookie_set_crypt (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_conf_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;

    if (0 == ngx_strcasecmp(value[1].data, (u_char *) "des")) {
        cfg->crypt_alg = PBC_CRYPT_DES;
    } else if (0 == ngx_strcasecmp(value[1].data, (u_char *) "aes")) {
        cfg->crypt_alg = PBC_CRYPT_AES;
    } else if (0 == ngx_strcasecmp(value[1].data, (u_char *) "aes+domain")) {
        cfg->crypt_alg = PBC_CRYPT_AES_D;
    } else {
        return "Invalid encryption method";
    }

    return NGX_CONF_OK;
}

static char *
pubcookie_set_appid (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_conf_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;
    u_char *c;
    u_int i;

    cfg->appid.data = ngx_pnalloc (cf->pool, value[1].len * 3 + 1);
    c = cfg->appid.data;
    for (i = 0; i < value[1].len; ++i) {
        switch (value[1].data[i]) {
        case ' ': *c++ = '+'; break;
        case '%': SET_C_LETTER(c,'2','5'); break;
        case '&': SET_C_LETTER(c,'2','6'); break;
        case '+': SET_C_LETTER(c,'2','B'); break;
        case ':': SET_C_LETTER(c,'3','A'); break;
        case ';': SET_C_LETTER(c,'3','B'); break;
        case '=': SET_C_LETTER(c,'3','D'); break;
        case '?': SET_C_LETTER(c,'3','F'); break;
        default:  *c++ = value[1].data[i]; break;
        }
    }
    *c = '\0';
    cfg->appid.len = (int)(c - cfg->appid.data);

    return NGX_CONF_OK;
}

static char *
pubcookie_set_appsrvid (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_conf_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;
    u_char *c;
    u_int i;

    cfg->appsrvid.data = ngx_pnalloc (cf->pool, value[1].len * 3 + 1);
    c = cfg->appsrvid.data;
    for (i = 0; i < value[1].len; ++i) {
        switch (value[1].data[i]) {
        case ' ': *c++ = '+'; break;
        case '%': SET_C_LETTER(c,'2','5'); break;
        case '&': SET_C_LETTER(c,'2','6'); break;
        case '+': SET_C_LETTER(c,'2','B'); break;
        case ':': SET_C_LETTER(c,'3','A'); break;
        case ';': SET_C_LETTER(c,'3','B'); break;
        case '=': SET_C_LETTER(c,'3','D'); break;
        case '?': SET_C_LETTER(c,'3','F'); break;
        default:  *c++ = value[1].data[i]; break;
        }
    }
    *c = '\0';
    cfg->appsrvid.len = (int)(c - cfg->appsrvid.data);

    return NGX_CONF_OK;
}

static char *
pubcookie_set_noprompt (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_conf_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;

    if (0 == ngx_strcasecmp(value[1].data, (u_char *) "on")) {
        cfg->noprompt = 1;
    } else if (0 == ngx_strcasecmp(value[1].data, (u_char *) "off")) {
        cfg->noprompt = -1;
    } else {
        return "Invalid value in pubcookie_noprompt";
    }

    return NGX_CONF_OK;
}


static void *
ngx_pubcookie_create_loc_conf(ngx_conf_t *cf)
{
    ngx_pubcookie_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_pubcookie_loc_conf_t));
    if (NULL == conf) {
        return NGX_CONF_ERROR;
    }

    conf->dirdepth = NGX_CONF_UNSET;
    conf->noblank = NGX_CONF_UNSET;
    conf->catenate = NGX_CONF_UNSET;
    conf->no_clean_creds = NGX_CONF_UNSET;
    conf->use_post = NGX_CONF_UNSET;
    conf->vitki_behind_proxy = NGX_CONF_UNSET;

    conf->inact_exp = NGX_CONF_UNSET;
    conf->hard_exp = NGX_CONF_UNSET;
    conf->non_ssl_ok = NGX_CONF_UNSET;
    conf->session_reauth = NGX_CONF_UNSET;
    conf->strip_realm = NGX_CONF_UNSET;
    conf->noprompt = NGX_CONF_UNSET;

    conf->crypt_alg = NGX_CONF_UNSET_UINT;

    return conf;
}

static char *
ngx_pubcookie_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_pubcookie_loc_conf_t  *prev = parent;
    ngx_pubcookie_loc_conf_t  *conf = child;

    ngx_conf_merge_value(conf->dirdepth, prev->dirdepth, PBC_DEFAULT_DIRDEPTH);
    ngx_conf_merge_value(conf->noblank, prev->noblank, 0);
    ngx_conf_merge_value(conf->catenate, prev->catenate, 0);
    ngx_conf_merge_value(conf->no_clean_creds, prev->no_clean_creds, 0);
    ngx_conf_merge_value(conf->use_post, prev->use_post, 0);
    ngx_conf_merge_uint_value(conf->crypt_alg, prev->crypt_alg, PBC_DEF_CRYPT);
    ngx_conf_merge_value(conf->vitki_behind_proxy, prev->vitki_behind_proxy, 0);

    ngx_conf_merge_value(conf->inact_exp, prev->inact_exp, PBC_DEFAULT_INACT_EXPIRE);
    ngx_conf_merge_value(conf->hard_exp, prev->hard_exp, PBC_DEFAULT_HARD_EXPIRE);
    ngx_conf_merge_value(conf->non_ssl_ok, prev->non_ssl_ok, 0);
    ngx_conf_merge_value(conf->session_reauth, prev->session_reauth, 0);
    ngx_conf_merge_value(conf->strip_realm, prev->strip_realm, 0);
    ngx_conf_merge_value(conf->noprompt, prev->noprompt, 0);

    if (conf->login.data == NULL) {
        conf->login = prev->login;
    }

    if (conf->appsrvid.data == NULL) {
        conf->appsrvid = prev->appsrvid;
    }

    if (conf->post_reply_url.data == NULL) {
        conf->post_reply_url = prev->post_reply_url;
        if (conf->post_reply_url.data == NULL) {
            static ngx_str_t def_post_reply_url = ngx_string("PubCookie.reply");
            conf->post_reply_url = def_post_reply_url;
        }
    }

    /***
     * Okay.  We might need to catenate app IDs.  We'll know at
     * request time.  So, let's make sure the "appid" is set assuming
     * we *won't* have to, and into "oldappid" goes the stuff we'll
     * need to include if we *do* have to.  Then we will have all the
     * data we need to go either way at request time.
     *
     * ddj@cmu.edu 2006/05/10
     */

    /* Did the parent have an app ID? */
    if (prev->appid.data != NULL) {
        /* Yes.  Did the parent also have an *old* app ID? */
        if (prev->oldappid.data != NULL) {
	        /* Yes.  Glue them together and store as "old app ID". */
	        ngx_strcat3(cf->pool, &conf->oldappid, &prev->oldappid, &prev->appid, NULL);
        } else {
            /* No.  The parent's app ID is now the "old app ID". */
            conf->oldappid = prev->appid;
        }
    }

    /* life is much easier if the default value is zero or NULL */
    if (conf->appid.data == NULL) {
        conf->appid = prev->appid;
    }

    if (conf->end_session.data == NULL) {
        conf->end_session = prev->end_session;
    }

    if (prev->addl_requests.data != NULL) {
        if (conf->addl_requests.data != NULL) {
	        ngx_strcat3(cf->pool, &conf->addl_requests, &prev->addl_requests, &conf->addl_requests, NULL);
        } else {
            conf->addl_requests = prev->addl_requests;
        }
    }

    return NGX_CONF_OK;
}


/**************************************
 *  Handler
 */

static u_char *
ap_get_server_name (ngx_http_request_t *r)
{
    ngx_pubcookie_req_rec *rr = ngx_http_get_module_ctx(r, ngx_pubcookie_module);

    if (NULL == rr->server_name.data) {
        ngx_strcat3(r->pool, &rr->server_name, &r->headers_in.server, NULL, NULL);
    }
    return rr->server_name.data;
}

/*
 * Send headers - so we can send direct content.  If we're 
 * doing the deferred method, append any headers we've accumulated
 * to the real header list.
 */
static int
flush_headers (ngx_http_request_t *r)
{
#if 0 && defined(PBC_DEFERRED_HEADERS)
    ngx_pubcookie_req_rec *rr = ngx_http_get_module_ctx(r, ngx_pubcookie_module);
    if (rr) {
        ap_log_rerror (PC_LOG_DEBUG, r, "pubcookie flush headers: merging %d output headers",
                       apr_table_elts(rr->hdr_out)->nelts);
        append_to_table(r, r->headers_out, rr->hdr_out);
        append_to_table(r, r->err_headers_out, rr->hdr_err);
    }
#endif
    return ngx_http_send_header(r);
}

static inline ngx_http_request_t *
main_rrec (ngx_http_request_t * r)
{
    return r->main;
}

static u_char *
ap_make_dirstr_prefix(u_char *d, u_char *s, int n)
{
    if (n < 1) {
        *d = '/';
        *++d = '\0';
        return (d);
    }

    for (;;) {
        if (*s == '\0' || (*s == '/' && (--n) == 0)) {
            *d = '/';
            break;
        }
        *d++ = *s++;
    }
    *++d = 0;

    return (d);
}

static u_char *
ap_make_dirstr_parent (ngx_pool_t *p, u_char *s)
{
    u_char *d;
    int l;

    if (!*s) {
        return ngx_pstrdup(p, &blank_str);
    }

    d = s + ngx_strlen(s) - 1;
    while (d != s && *d != '/')
        d--;

    if (*d != '/') {
        return ngx_pstrdup(p, &blank_str);
    }
    l = (d - s) + 1;
    d = ngx_pnalloc(p, l + 1);
    ngx_memcpy(d, s, l);
    d[l] = 0;
    return (d);
}

static int 
ap_count_dirs (u_char *path)
{
    register int x, n;
    for (x = 0, n = 0; path[x]; x++)
        if (path[x] == '/')
            n++;
    return n;
}

/*
 */
static u_char *
get_app_path (ngx_http_request_t * r, u_char *path)
{
    ngx_pool_t *p = r->pool;
    ngx_pubcookie_loc_conf_t *cfg = ngx_http_get_module_loc_conf(r, ngx_pubcookie_module);
    u_char *path_out;
    int truncate;
    u_char *a;

    if (cfg->dirdepth) {
        if (cfg->dirdepth < ap_count_dirs(path))
            truncate = cfg->dirdepth;
        else
            truncate = ap_count_dirs(path);
        path_out = ngx_pnalloc(p, ngx_strlen(path) + 1);
        ap_make_dirstr_prefix(path_out, path, truncate);
    } else {
        path_out = ap_make_dirstr_parent(p, path);
    }

    for (a = path_out; *a; a++) {
        if (*a != '/' && !isalnum(*a))
            *a = '_';
    }

    return (u_char *) path_out;
}

/*
 * figure out the appid
 */
static u_char *
appid (ngx_http_request_t * r)
{
    ngx_pool_t *p = r->pool;
    ngx_pubcookie_loc_conf_t *cfg = ngx_http_get_module_loc_conf(r, ngx_pubcookie_module);
    ngx_pubcookie_req_rec *rr = ngx_http_get_module_ctx(r, ngx_pubcookie_module);
    ngx_str_t res;

    if (NULL == rr->app_path.data) {
        ngx_http_request_t *rmain = main_rrec(r);
        u_char *main_uri_path = (u_char *) nswrap(p, &rmain->uri);
        rr->app_path.data = get_app_path(r, main_uri_path);
    }

    /* Added by ddj@cmu.edu on 2006/05/10. */
    if (cfg->catenate) {	/* Catenate app IDs? */
        /* Yeah. Anything to catenate? 4 possibilities. */
        if (cfg->appid.data && cfg->oldappid.data) {
	        /* Old and new are both set. */
            /* Glue the default, old, and new together. */
            ngx_strcat3(p, &res, &rr->app_path, &cfg->oldappid, &cfg->appid);
            return res.data;
        } else if (cfg->appid.data) {
            /* Just the new one is set. */
            /* Glue the default and the new one together. */
            ngx_strcat3(p, &res, &rr->app_path, &cfg->appid, NULL);
            return res.data;
        } else if (cfg->oldappid.data) {
            /* Just the old one is set. */
            /* Glue the default and the old one together. */
            ngx_strcat3(p, &res, &rr->app_path, &cfg->oldappid, NULL);
            return res.data;
        } else {
            /* None were ever set.  Just use the default. */
            return rr->app_path.data;
        }
    } else {
        /* No, don't catenate.  Use the 3.3.0a logic verbatim. */
        return cfg->appid.data ? cfg->appid.data : rr->app_path.data;
    }
}

/*
 * figure out the appsrvid
 */
static u_char *
appsrvid (ngx_http_request_t * r)
{
    ngx_pubcookie_loc_conf_t *cfg = ngx_http_get_module_loc_conf(r, ngx_pubcookie_module);

    if (cfg->appsrvid.data) {
        return (cfg->appsrvid.data);
    } else {
        /* because of multiple passes through don't use r->hostname() */
        return ap_get_server_name(r);
    }
}


static int
add_set_cookie (ngx_http_request_t *r, u_char *value)
{
    ngx_str_t temp;
    ngx_table_elt_t *cookie;

    cookie = ngx_list_push(&r->headers_out.headers);
    if (NULL == cookie) {
        return NGX_ERROR;
    }

    temp.data = value;
    temp.len = ngx_strlen(value);

    cookie->hash = 1;
    ngx_str_set(&cookie->key, "Set-Cookie");
    cookie->value.len = temp.len;
    cookie->value.data = ngx_pstrdup(r->pool, &temp);
    if (NULL == cookie->value.data) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

/*
 * clear granting cookie
 */
static int
clear_granting_cookie (ngx_http_request_t * r)
{
    ngx_pubcookie_loc_conf_t *cfg = ngx_http_get_module_loc_conf(r, ngx_pubcookie_module);
    u_char new_cookie[200];

    if (cfg->use_post)
        ngx_sprintf(new_cookie, "%s=; path=/; expires=%s;%s",
                                  PBC_G_COOKIENAME,
                                  EARLIEST_EVER, secure_cookie);
    else
        ngx_sprintf(new_cookie, "%s=; domain=%s; path=/; expires=%s;%s",
                         PBC_G_COOKIENAME, PBC_ENTRPRS_DOMAIN,
                         EARLIEST_EVER, secure_cookie);

    pc_req_log(r,
               "clear_granting_cookie: setting cookie: %s",
               new_cookie);
    return add_set_cookie(r, new_cookie);
}

/*
 * clear cred transfer cookie
 */
static int
clear_transfer_cookie (ngx_http_request_t * r)
{
    u_char new_cookie[200];

    ngx_sprintf(new_cookie,
                              "%s=; domain=%s; path=/; expires=%s;%s",
                              PBC_CRED_TRANSFER_COOKIENAME,
                              PBC_ENTRPRS_DOMAIN,
                              EARLIEST_EVER, secure_cookie);

    return add_set_cookie(r, new_cookie);
}

/*
 * clear pre session cookie
 */
static int
clear_pre_session_cookie (ngx_http_request_t * r)
{
    u_char new_cookie[200];

    ngx_sprintf(new_cookie,
                              "%s=; path=/; expires=%s;%s",
                              PBC_PRE_S_COOKIENAME,
                              EARLIEST_EVER, secure_cookie);

    return add_set_cookie(r, new_cookie);
}

static int
clear_session_cookie (ngx_http_request_t * r)
{
    ngx_pubcookie_req_rec *rr = ngx_http_get_module_ctx(r, ngx_pubcookie_module);
    u_char new_cookie[200];

    if (NULL == rr)
        return NGX_OK;

    ngx_sprintf(new_cookie,
                              "%s=%s; path=/; expires=%s;%s",
                              make_session_cookie_name (r->pool,
                                                        PBC_S_COOKIENAME,
                                                        appid(r)),
                              PBC_CLEAR_COOKIE, EARLIEST_EVER,
                              secure_cookie);

    if (add_set_cookie(r, new_cookie) != NGX_OK)
        return NGX_ERROR;

    if (NULL != rr->cred_transfer.data) {
        /* extra cookies (need cookie extensions) */
        ngx_sprintf(new_cookie,
                                  "%s=%s; path=/; expires=%s;%s",
                                  make_session_cookie_name (r->pool,
                                                            PBC_CRED_COOKIENAME,
                                                            appid(r)),
                                  PBC_CLEAR_COOKIE,
                                  EARLIEST_EVER, secure_cookie);

        if (add_set_cookie(r, new_cookie) != NGX_OK)
            return NGX_ERROR;
    }

    return NGX_OK;
}

/**
 * give an error message and stop the transaction, i.e. don't loop
 * @param r request_rec
 * @return OK
 * this is kinda bogus since it looks like a successful request but isn't
 * but it's far less bogus than looping between the WLS and AS forever ...
 *
 * Called from the check user hook.
 */
static const char * stop_html = "<html><body><h1>stop</h1></body></html>"; /*FIXME*/

static int
stop_the_show (ngx_http_request_t *r, ngx_pubcookie_loc_conf_t *cfg, ngx_pubcookie_req_rec *rr)
{
    u_char *msg, *admin;

    pc_req_log(r, "stop_the_show: hello");

    clear_granting_cookie(r);
    clear_pre_session_cookie(r);
    clear_session_cookie(r);
    set_no_cache_headers(r);

    msg = rr->stop_message.data ?: (u_char *) "";
    admin = (u_char *) "postmaster@this.server";
    rr->msg.data = ngx_pnalloc(r->pool, ngx_strlen(stop_html) + ngx_strlen(admin) + ngx_strlen(msg) + 10);
    if (NULL != rr->msg.data) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_sprintf(rr->msg.data, stop_html, admin, msg);

    return NGX_OK;
}

/* User authentication */

static int
pubcookie_user_hook (ngx_http_request_t * r)
{
    ngx_pubcookie_loc_conf_t *cfg = ngx_http_get_module_loc_conf(r, ngx_pubcookie_module);
    ngx_pubcookie_req_rec *rr = ngx_http_get_module_ctx(r, ngx_pubcookie_module);

    int s;
    int first_time_in_session = 0;
    char creds;

    /* pass if the request is for our post-reply */
    if (0 == ngx_strcasecmp (r->uri.data + 1, cfg->post_reply_url.data))
        return NGX_OK;

    /* get pubcookie creds or bail if not a pubcookie auth_type */
    if ((creds = pubcookie_auth_type (r)) == PBC_CREDS_NONE)
        return NGX_DECLINED;

    /* pass if the request is for favicon.ico */
    if (0 == ngx_strncasecmp (r->uri.data, (u_char *) "/favicon.ico", 12))
        return NGX_OK;

    rr->creds = creds;
    s = pubcookie_user (r, cfg, rr);
    if (rr->failed) {
        pc_req_log(r, " .. user_hook: user failed");
        if (rr->failed == PBC_BAD_G_STATE) {
            pc_req_log(r, " .. user_hook: Can't use Granting cookie");
            stop_the_show(r, cfg, rr);
            return DONE;
        } else if (rr->failed == PBC_BAD_USER) {
            static ngx_str_t unauth_user = ngx_string("Unauthorized user.");
            pc_req_log(r, " .. user_hook: bad user");
            rr->msg.data = ngx_pstrdup(r->pool, &unauth_user);
            return DONE;
        }
        auth_failed_handler(r, cfg, rr);
        return DONE;
    }
    pc_req_log(r, " .. user_hook: user '%s'OK", rr->user_name.data);

    if (rr->has_granting) {
        pc_req_log(r, " .. user_hook: new session");
        first_time_in_session = 1;
        rr->has_granting = 0;
    }

    if (check_end_session(r) & PBC_END_SESSION_REDIR) {
        do_end_session_redirect(r, cfg);
        return DONE;
    } else if (check_end_session(r) & PBC_END_SESSION_ANY) {
        clear_session_cookie(r);
        rr->user_name = blank_str;        /* rest of apache needs a user if there's an authtype */
    } else if (cfg->inact_exp > 0 || first_time_in_session) {
        if ((!first_time_in_session) && (!rr->cookie_data)) {
            pc_req_log(r, " .. user_hook: not first and no data! (sub?)");
        } else {
            set_session_cookie(r, cfg, rr, first_time_in_session);
        }
    }

    /* Since we've done something any "if-modified"s must be cancelled
       to prevent "not modified" responses.  There may be other "if"s
       (see: http_protocol.c:ap_meets_conditions) that we are not
       considering as they have not yet come up. */

    if (NULL != r->headers_in.if_modified_since) {
        pc_req_log(r, " .. user_hook: removing if-modified = %s",
                    nswrap(r->pool, &r->headers_in.if_modified_since->value));
        r->headers_in.if_modified_since = NULL;
    }

    pc_req_log(r, " .. user_hook exit");
    
    return (s);
}

/* Check user id                                                              */
static int
pubcookie_user(ngx_http_request_t * r, ngx_pubcookie_loc_conf_t *cfg, ngx_pubcookie_req_rec *rr)
{
    char *cookie;
    char *isssl = NULL;
    pbc_cookie_data *cookie_data;
    pool *p = r->pool;
    char *sess_cookie_name;
    int cred_from_trans;
    int pre_sess_from_cookie;
    int gcnt = 0;
    int scnt = 0;

    /* get defaults for unset args */
    pubcookie_loc_defaults(cfg);

    pc_req_log(r, "pubcookie_user: going to check uri: %s creds: %c", r->uri, rr->creds);

    /* maybe dump the directory and server recs */
    dump_loc_rec(r, cfg);

    sess_cookie_name = make_session_cookie_name(p, PBC_S_COOKIENAME, appid(r));

    /* force SSL */

    isssl = "on"; /*FIXME*/

    if (!isssl)
    {
        pc_req_log(r, "Not SSL; uri: %s appid: %s", r->uri, appid (r));
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_NOGORS_CODE;
        return NGX_OK;
    }

    /* before we check if they hav a valid S or G cookie see if it's a logout */
    if (check_end_session (r) & PBC_END_SESSION_ANY) {
        return NGX_OK;
    }

    pc_req_log(r,
               "pubcookie_user: about to look for some cookies; current uri: %s",
               r->uri);

    /* check if we hav a granting cookie's and a pre-session cookie.
       when using GET method we need the pair (pre sess and granting), but 
       when using POST method there is no pre-session cookie used.  
       if the granting cookie fails to decrypt (unbundle) we move on to look 
       at the session cookie(s).  The assumption is that graning cookies that 
       fail to decrypt aren't for our app server.  In cases where the crypt
       key is incorrect on the app server this will cause looping */
    cookie_data = NULL;
    while ((cookie = get_cookie(r, PBC_G_COOKIENAME, gcnt))
        && (cfg->use_post || get_cookie(r, PBC_PRE_S_COOKIENAME, 0))) {
        cookie_data = libpbc_unbundle_cookie(p, cfg->sectext, cookie,
                                             (char *) ap_get_server_name(r), 1, cfg->crypt_alg);
        if (cookie_data)
            break;
        pc_req_log(r,
                   "can't unbundle G cookie, it's probably not for us; uri: %s\n",
                   r->uri);
        gcnt++;
        clear_granting_cookie(r);
    }

    /* If no valid granting cookie, check session cookie  */
    if (NULL == cookie_data
        || ngx_strncasecmp ((u_char *) appid(r),
                            (u_char *) cookie_data->broken.
                            appid,
                            sizeof(cookie_data->broken.appid) - 1) != 0)
    {
        char *ckfix;
        while (NULL != (cookie = get_cookie(r, sess_cookie_name, scnt))) {
            int cookie_len = strlen(cookie);
            cookie_data =
                libpbc_unbundle_cookie (p, cfg->sectext, cookie, ME(r), 0,
                                        cfg->crypt_alg);

            if (cookie_data)
                break;

            /* try 'fixing' the cookie */
            pc_req_log(r,
                       "retring failed unbundle of S cookie; uri: %s\n",
                       r->uri);
            ckfix = ngx_pnalloc(p, cookie_len + 3);
            strcpy(ckfix, cookie);
            strcat(ckfix, "==");
            cookie_data = libpbc_unbundle_cookie (p, cfg->sectext, ckfix, ME(r), 0, cfg->crypt_alg);
            if (cookie_data)
                break;

            pc_req_log(r,
                       "still can't unbundle S cookie; uri: %s\n",
                       r->uri);
            scnt++;
        }

        if (cookie_data) {

            rr->cookie_data = cookie_data;

            /* we tell everyone what authentication check we did */
            ngx_str_assign_copy(p, &rr->user_name, cookie_data->broken.user);

            /* save the full user/realm for later */
            ngx_str_assign_copy(p, &rr->user, cookie_data->broken.user);

            /* check for acceptable realms and strip realm */
            if (cfg->strip_realm == 1 || cfg->accept_realms.data != NULL) {
                ngx_str_t tmpstr;
                char *tmprealm, *tmpuser;
                ngx_str_assign_copy(p, &tmpstr, cookie_data->broken.user);
                tmpuser = (char *) tmpstr.data;
                tmprealm = index (tmpuser, '@');
                if (tmprealm) {
                    tmprealm[0] = 0;
                    tmprealm++;
                    /*FIXME ap_table_set (r->subprocess_env, "REMOTE_REALM", tmprealm);*/
                }

                if (cfg->strip_realm == 1) {
                    ngx_str_assign(rr->user_name, tmpuser);
                } else {
                    ngx_str_assign_copy(p, &rr->user_name, cookie_data->broken.user);
                }

                if (cfg->accept_realms.data != NULL) {
                    int realmmatched = 0;
                    char *thisrealm;
                    char *okrealms = (char *) ngx_pstrdup(p, &cfg->accept_realms);

                    if (tmprealm == NULL) {
                        /* no realm to check !?!? */
                        pc_req_log(r, "no realm in userid: %s returning UNAUTHORIZED",
                                   cookie_data->broken.user);
                        return NGX_HTTP_UNAUTHORIZED;
                    }

                    while (*okrealms && !realmmatched &&
                           (thisrealm = getword_white_nc(p, &okrealms))) {
                        if (strcmp (thisrealm, tmprealm) == 0) {
                            realmmatched++;
                        }
                    }
                    if (realmmatched == 0) {
                        return NGX_HTTP_UNAUTHORIZED;
                    }
                }
            }

            if (libpbc_check_exp(p, cookie_data->broken.create_ts, cfg->hard_exp) == PBC_FAIL) {
                pc_req_log(r,
                           "S cookie hard expired; user: %s cookie timestamp: %d timeout: %d now: %d uri: %s\n",
                           cookie_data->broken.user,
                           cookie_data->broken.create_ts,
                           cfg->hard_exp, pbc_time (NULL), r->uri);
                rr->failed = PBC_BAD_AUTH;
                rr->redir_reason_no = PBC_RR_SHARDEX_CODE;
                return NGX_OK;
            }

            if (cfg->inact_exp != -1 &&
                libpbc_check_exp(p, cookie_data->broken.last_ts,
                                  cfg->inact_exp) == PBC_FAIL) {
                pc_req_log(r,
                           "S cookie inact expired; user: %s cookie timestamp %d timeout: %d now: %d uri: %s\n",
                           cookie_data->broken.user,
                           cookie_data->broken.last_ts,
                           cfg->inact_exp, pbc_time (NULL), r->uri);
                rr->failed = PBC_BAD_AUTH;
                rr->redir_reason_no = PBC_RR_SINAEX_CODE;
                return NGX_OK;
            }

            pc_req_log(r,
                       "S cookie chk reauth=%d, tok=%d",
                       cfg->session_reauth,
                       cookie_data->broken.pre_sess_token);
            if ((cfg->session_reauth >= 0)
                && (cookie_data->broken.pre_sess_token == 23)) {
                pc_req_log(r,
                           "S cookie new force reauth");
                rr->failed = PBC_BAD_AUTH;
                rr->redir_reason_no = PBC_RR_NEW_REAUTH;
                return NGX_OK;
            }

            /* Check if we're switching from noprompt to prompt */
            pc_req_log(r,
                       "S cookie chk nop: user=%s, nop=%d", rr->user_name.data,
                       cfg->noprompt);
            if (cfg->noprompt <= 0 && !*rr->user_name.data) {
                pc_req_log(r,
                           "S cookie noprompt to prompt");
                rr->failed = PBC_BAD_AUTH;
                rr->redir_reason_no = PBC_RR_NOGORS_CODE;
                return NGX_OK;
            }

        } else {                /* hav S cookie */

            pc_req_log(r,
                       "No G or S cookie; uri: %s appid: %s sess_cookie_name: %s",
                       r->uri, appid (r), sess_cookie_name);
            rr->failed = PBC_BAD_AUTH;
            rr->redir_reason_no = PBC_RR_NOGORS_CODE;
            return NGX_OK;

        }                       /* end if session cookie */

    } else {

        rr->has_granting = 1;

        clear_granting_cookie (r);
        if (!cfg->use_post)
            clear_pre_session_cookie (r);

        pc_req_log(r,
                   "pubcookie_user: has granting; current uri is: %s",
                   r->uri);

        /* If GET, check pre_session cookie */
        if (!cfg->use_post) {
            pre_sess_from_cookie = get_pre_s_from_cookie (r);
            pc_req_log(r, "pubcookie_user: ret from get_pre_s_from_cookie");
            if (cookie_data->broken.pre_sess_token !=
                pre_sess_from_cookie) {
                pc_req_log(r, "pubcookie_user, pre session tokens mismatched, uri: %s",
                           r->uri);
                pc_req_log(r, "pubcookie_user, pre session from G: %d PRE_S: %d, uri: %s",
                           cookie_data->broken.pre_sess_token,
                           pre_sess_from_cookie, r->uri);
                rr->failed = PBC_BAD_AUTH;
                #define STOP_MESSAGE_FMT_1 "Couldn't decode pre-session cookie. (from G: %d from PRE_S: %d)"
                rr->stop_message.data = ngx_pnalloc(r->pool, sizeof(STOP_MESSAGE_FMT_1) + 6 + 6);
                ngx_sprintf(rr->stop_message.data, STOP_MESSAGE_FMT_1,
                            cookie_data->broken.pre_sess_token, pre_sess_from_cookie);
                rr->redir_reason_no = PBC_RR_BADPRES_CODE;
                return NGX_OK;
            }
        }

        /* the granting cookie gets blanked too early and another login */
        /* server loop is required, this just speeds up that loop */
        if (strncmp (cookie, PBC_X_STRING, PBC_XS_IN_X_STRING) == 0) {
            pc_req_log(r,
                       "pubcookie_user: 'speed up that loop' logic; uri is: %s\n",
                       r->uri);

            rr->failed = PBC_BAD_AUTH;
            rr->redir_reason_no = PBC_RR_DUMMYLP_CODE;
            return NGX_OK;
        }

        ngx_str_assign_copy(p, &rr->user_name, cookie_data->broken.user);

        /* Make sure we really got a user (unless noprompt) */
        if (!*rr->user_name.data && cfg->noprompt <= 0) {
            pc_req_log(r, "No user and not a noprompt");
            rr->stop_message.data = (u_char *) "Required user login didn't happen";
            rr->failed = PBC_BAD_G_STATE;
            return (DONE);
        }

        pc_req_log(r, "pubcookie_user: set user (%s)", rr->user_name.data);

        /* save the full user/realm for later */
        ngx_str_assign_copy(p, &rr->user, cookie_data->broken.user);

        /* check for acceptable realms and strip realm */
        if (*rr->user.data) {
            ngx_str_t tmps;
            char *tmprealm, *tmpuser;
            ngx_str_assign_copy(p, &tmps, cookie_data->broken.user);
            tmpuser = (char *) tmps.data;
            tmprealm = index (tmpuser, '@');
            if (tmprealm) {
                tmprealm[0] = 0;
                tmprealm++;
                /*FIXME: ap_table_set (r->subprocess_env, "REMOTE_REALM", tmprealm);*/
            }

            if (cfg->strip_realm == 1) {
                ngx_str_assign(rr->user_name, tmpuser);
            } else {
                ngx_str_assign_copy(p, &rr->user_name, cookie_data->broken.user);
            }

            if (cfg->accept_realms.data != NULL) {
                int realmmatched = 0;
                char *thisrealm;
                char *okrealms = (char *) ngx_pstrdup(p, &cfg->accept_realms);
                while (*okrealms && !realmmatched &&
                       (thisrealm = getword_white_nc(p, &okrealms))) {
                    if (strcmp (thisrealm, tmprealm) == 0) {
                        realmmatched++;
                    }
                }
                if (realmmatched == 0) {
                    return NGX_HTTP_UNAUTHORIZED;
                }
            }
        }

        /* make sure force reauth requests actually get a reauth */
        if ( cfg->session_reauth > 0 
             && cookie_data->broken.version[3] == PBC_VERSION_REAUTH_NO ) {
        
            pc_req_log(r,
                       "Force reauth didn't get a re-auth: %c", cookie_data->broken.version[3]);
            /* Send out bad session_reauth error */
            rr->stop_message.data = (u_char *) "Required Session Reauthentication didn't happen";
            rr->failed = PBC_BAD_G_STATE;
            return (DONE);
        }

        if (libpbc_check_exp(p, cookie_data->broken.create_ts, PBC_GRANTING_EXPIRE) == PBC_FAIL) {
            pc_req_log(r,
                       "pubcookie_user: G cookie expired by %ld; user: %s create: %ld uri: %s",
                       pbc_time(NULL) - cookie_data->broken.create_ts -
                       PBC_GRANTING_EXPIRE, cookie_data->broken.user,
                       cookie_data->broken.create_ts, r->uri);
            rr->failed = PBC_BAD_AUTH;
            rr->redir_reason_no = PBC_RR_GEXP_CODE;
            return NGX_OK;
        }

    }

    /* check appid */
    if (ngx_strncasecmp(appid(r),
                         cookie_data->broken.appid,
                         sizeof(cookie_data->broken.appid) - 1) != 0) {
        pc_req_log(r,
                   "pubcookie_user: wrong appid; current: %s cookie: %s uri: %s",
                   appid (r), cookie_data->broken.appid, r->uri);
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_WRONGAPPID_CODE;
        return NGX_OK;
    }

    /* check appsrv id */
    if (ngx_strncasecmp (appsrvid(r),
                     cookie_data->broken.appsrvid,
                     sizeof(cookie_data->broken.appsrvid) - 1) != 0) {
        pc_req_log(r,
                   "pubcookie_user: wrong app server id; current: %s cookie: %s uri: %s",
                   appsrvid (r), cookie_data->broken.appsrvid,
                   r->uri);
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_WRONGAPPSRVID_CODE;
        return NGX_OK;
    }

    /* check version id */
    if (libpbc_check_version(p, cookie_data) == PBC_FAIL) {
        pc_req_log(r,
                   "pubcookie_user: wrong version id; module: %d cookie: %d uri: %s",
                   PBC_VERSION, cookie_data->broken.version);
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_WRONGVER_CODE;
        return NGX_OK;
    }

    /* check creds */
    if (rr->creds != cookie_data->broken.creds) {
        pc_req_log(r,
                   "pubcookie_user: wrong creds; required: %c cookie: %c uri: %s",
                   rr->creds, cookie_data->broken.creds, r->uri);
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_WRONGCREDS_CODE;
        return NGX_OK;
    }

    /* extensions */

    /* transcred */
    cookie = get_cookie (r, PBC_CRED_TRANSFER_COOKIENAME, 0);
    cred_from_trans = 1;
    if (!cookie) {
        char *mycookie;

        /* try a locally scoped cookie */
        mycookie = make_session_cookie_name (p, PBC_CRED_COOKIENAME,
                                             appid (r));

        cred_from_trans = 0;    /* not transferring creds */
        cookie = get_cookie (r, mycookie, 0);
    }

    if (cookie) {
        char *blob = ngx_palloc (p, strlen(cookie));
        int bloblen;
        char *plain = NULL;
        int plainlen;
        char *krb5ccname;
        ngx_file_t f;
        int res = 0;

        /* base64 decode cookie */
        if (!libpbc_base64_decode(p, (u_char *) cookie, (u_char *) blob, &bloblen)) {
            pc_req_log(r, "credtrans: libpbc_base64_decode() failed");
            res = -1;
        }

        /* decrypt cookie. if credtrans is set, then it's from login server
           to me. otherwise it's from me to me. */
        if (!res && libpbc_rd_priv(p, cfg->sectext, cred_from_trans ?
                                    ap_get_server_name(r) : NULL,
                                    cred_from_trans ? 1 : 0,
                                    blob, bloblen, &plain, &plainlen,
                                    cfg->crypt_alg)) {
            pc_req_log(r,
                       "credtrans: libpbc_rd_priv() failed");
            res = -1;
        }

        if (!res && plain) {
            /* sigh, copy it into the memory pool */
            rr->cred_transfer.data = ngx_pnalloc(p, plainlen);
            ngx_memcpy(rr->cred_transfer.data, plain, plainlen);
            rr->cred_transfer.len = plainlen;
        }

        /* set a random KRB5CCNAME */
        krb5ccname = ngx_pnalloc(p, 64);
        ngx_snprintf(krb5ccname, 64, "/tmp/k5cc_%d_%s", getpid(), rr->user.data);
        f.fd = NGX_INVALID_FILE;
        f.sys_offset = 0;
        if (!res) {
            /* save these creds in that file */
            f.fd = ngx_open_file (krb5ccname, NGX_FILE_RDWR,
                                  NGX_FILE_CREATE_OR_OPEN | NGX_FILE_TRUNCATE,
                                  0640);
            if (f.fd == NGX_INVALID_FILE) {
                pc_req_log(r, "credtrans: setenv() failed");
                res = -1;
            }
        }
        if (!res && ngx_write_file (&f, rr->cred_transfer.data,
                                    rr->cred_transfer.len, 0) == NGX_ERROR) {
            pc_req_log(r, "credtrans: setenv() failed");
            res = -1;
        }

        if (f.fd != NGX_INVALID_FILE) {
            ngx_close_file (f.fd);
        }

        if (cred_from_trans) {
            clear_transfer_cookie(r);
        }
    }

    pc_req_log(r,
               "pubcookie_user: everything is o'tay; current uri is: %s",
               r->uri);

    return NGX_OK;
}

static ngx_int_t
ngx_pubcookie_authz_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_pool_t *p = r->pool;
    ngx_pubcookie_loc_conf_t *conf = ngx_http_get_module_loc_conf(r, ngx_pubcookie_module);
    ngx_pubcookie_req_rec *rr = ngx_http_get_module_ctx(r, ngx_pubcookie_module);

    /* get pubcookie creds or bail if not a pubcookie auth_type */
    if (pubcookie_auth_type(r) == PBC_CREDS_NONE) {
        return NGX_DECLINED;
    }

    if (r != r->main) {
        /* subrequest */
        return NGX_OK;
    }

    if (0 == ngx_strncasecmp(r->uri.data, (u_char *) "/favicon.ico", 12)) {
        return NGX_OK;
    }

    /* pass if the request is our post-reply */
    if (0 == ngx_strcasecmp(r->uri.data + 1, conf->post_reply_url.data)) {
        return NGX_OK;
    }

    if (NULL == rr) {
        rr = ngx_pcalloc(p, sizeof(ngx_pubcookie_req_rec));
        if (NULL == rr) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        ngx_http_set_ctx(r, rr, ngx_pubcookie_module);
        rr->user_name = blank_str;
    }

    /* User authentication */
    rc = pubcookie_user_hook(r);

    if (NULL != rr->msg.data) {
        u_char *msg = rr->msg.data;
        ngx_buf_t *b;
        ngx_chain_t out;
        int len;

        r->headers_out.content_type = pbc_content_type;
        r->headers_out.content_type_len = pbc_content_type.len;
        flush_headers(r);
        len = ngx_strlen(msg);
        b = ngx_create_temp_buf(r->pool, len);
        if (NULL == b) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        b->last = ngx_cpymem(b->last, msg, len);
        b->last_buf = 1;
        out.buf = b;
        out.next = NULL;
        rc = ngx_http_output_filter(r, &out);
    }

    return rc;
}

/* OLD STUFF */
#if 0
    /* a failed noprompt login is all we check for */
    if (!*rr->user_name && cfg->noprompt > 0) {
        pc_req_log(r, "pubcookie_authz: is a nouser noprompt");
        return NGX_OK;
    }

    pc_req_log(r, "authorizing this place");
    return NGX_DECLINED;

    if (rr) {
        pc_req_log(r, "ngx_pubcookie_handler: found ctx");
        return ngx_pubcookie_authenticate(r, rr, conf);
    }

    /* Decode http auth user and passwd, leaving values on the request */
    pc_req_log(r, "ngx_pubcookie_handler: auth basic user");
    rc = ngx_http_auth_basic_user(r);

    if (rc == NGX_DECLINED) {
        return ngx_pubcookie_set_realm(r, &conf->realm);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Check user & password using PAM */
    return ngx_pubcookie_authenticate(r, rr, conf);
}
#endif


#if 0
static ngx_int_t
ngx_pubcookie_authenticate (ngx_http_request_t *r, ngx_pubcookie_req_rec *rr, void *conf)
{
    ngx_int_t   rc;
    ngx_pubcookie_loc_conf_t  *alcf = conf;

    /* try to authenticate user, log error on failure */
    pc_req_log(r, "ngx_pubcookie_authenticate");
    /*return NGX_HTTP_INTERNAL_SERVER_ERROR;*/
  	return ngx_pubcookie_set_realm(r, &alcf->realm);

    /*return NGX_HTTP_OK;*/
}

static ngx_int_t
ngx_pubcookie_set_realm(ngx_http_request_t *r, ngx_str_t *realm)
{
    ngx_table_elt_t *auth = ngx_list_push(&r->headers_out.headers);
    r->headers_out.www_authenticate = auth;
    if (NULL == auth) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    auth->hash = 1;
    auth->key.len = sizeof("WWW-Authenticate") - 1;
    auth->key.data = (u_char *) "WWW-Authenticate";
    auth->value = *realm;

    return NGX_HTTP_UNAUTHORIZED;
}
#endif

/*
 * converts an authtype name to a pubcookie credential number
 */
static char
pubcookie_auth_type (ngx_http_request_t * r)
{
    ngx_pubcookie_loc_conf_t  *conf = ngx_http_get_module_loc_conf(r, ngx_pubcookie_module);

    if (NULL == conf || NULL == conf->appid.data) {
        return PBC_CREDS_NONE;
    }

    return '1';
    /* return libpbc_get_credential_id (p, auth_type); */
}

/*
 *  ngx_pubcookie_init - inject into access phase chain
 */
static ngx_int_t
ngx_pubcookie_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (NULL == h) {
        return NGX_ERROR;
    }

    *h = ngx_pubcookie_authz_handler;

    return NGX_OK;
}

/*
 *  POST handler
 */
static char *
ngx_pubcookie_post_handler_proc(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *realm = data;

    size_t   len;
    u_char  *basic, *p;

    if (ngx_strcmp(realm->data, "off") == 0) {
        realm->len = 0;
        realm->data = blank_str.data;

        return NGX_CONF_OK;
    }

    len = sizeof(BASIC_REALM_C) - 1 + realm->len + 1;

    if (NULL == (basic = ngx_palloc(cf->pool, len))) {
        return NGX_CONF_ERROR;
    }

    p = ngx_cpymem(basic, BASIC_REALM_C, sizeof(BASIC_REALM_C) - 1);
    p = ngx_cpymem(p, realm->data, realm->len);
    *p = '"';

    realm->len = len;
    realm->data = basic;

    return NGX_CONF_OK;
}

/* SVN Id: $Id$ */

