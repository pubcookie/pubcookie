/*
 * Copyright (C) 2010 Vitki <vitki@vitki.net>
 *
 * Based on ngx_http_auth_pubcookie_module.c by Sergio Talens-Oliag
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

/* pubcookie stuff */

#include "pbc_logging.h"
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "security.h"

#define BASIC_REALM_C "Basic realm=\""

#define ngx_pubcookie_module ngx_http_auth_pubcookie_module

#define pc_req_log(r,args...) ngx_log_error_core(NGX_LOG_WARN,(r)->connection->log,0,args)
#define pc_cf_log(c,args...) ngx_log_error_core(NGX_LOG_WARN,(c)->log,0,args)

/* Module context data */
typedef struct {
    ngx_str_t  passwd;
} ngx_pubcookie_ctx_t;

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
    /*table *keydirs; //table?*/
    int noprompt;
} ngx_pubcookie_loc_conf_t;

typedef struct
{
    int failed;
    int redir_reason_no;
    int has_granting;
    ngx_str_t user;
    char creds;
    pbc_cookie_data *cookie_data;
    ngx_str_t stop_message;
    ngx_str_t cred_transfer;
    int cred_transfer_len;
    /*table *hdr_out; //table?*/
    /*table *hdr_err; //table?*/
} ngx_pubcookie_req_rec;

/* Module handler */
static ngx_int_t ngx_pubcookie_handler(ngx_http_request_t *r);

/* Function that authenticates the user -- is the only function that uses Pubcookie */
static ngx_int_t ngx_pubcookie_authenticate (ngx_http_request_t *r, ngx_pubcookie_ctx_t *ctx, ngx_str_t *passwd, void *conf);

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

/**************************************
 * Initialization
 */

static ngx_command_t  ngx_pubcookie_commands[] = {

    /* "Set the inactivity expire time for PubCookies." */
    { ngx_string("pubcookie_inactive_expire"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      pubcookie_set_inact_exp,
      0, 0, NULL },

    /* "Set the hard expire time for PubCookies." */
    { ngx_string("pubcookie_hard_expire"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      pubcookie_set_hard_exp,
      0, 0, NULL },

    /* "Set the login page for PubCookies." */
    { ngx_string("pubcookie_login"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      pubcookie_set_login,
      0, 0, NULL },

    /* "Set the domain for PubCookies." */
    { ngx_string("pubcookie_domain"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      pubcookie_set_domain,
      0, 0, NULL },

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
      0, 0, NULL },

    /* "Set encryption method (AES/DES)." */
    { ngx_string("pubcookie_encryption"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      pubcookie_set_crypt,
      0, 0, NULL },

    /* "Set the name of the application." */
    { ngx_string("pubcookie_app_id"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      pubcookie_set_appid,
      0, 0, NULL },

    /* "Set the name of the server(cluster)." */
    { ngx_string("pubcookie_app_srv_id"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1 |NGX_HTTP_LOC_CONF,
      pubcookie_set_appsrvid,
      0, 0, NULL },

#if 0
    /* "Do not blank cookies.". DEPRECATED in favour of pubcookie_no_obscure_cookies */
    { ngx_string("pubcookie_no_blank"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      pubcookie_set_no_blank,
      0, 0, NULL },

    /* "Do not obscure Pubcookie cookies." */
    { ngx_string("pubcookie_no_obscure_cookies"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      pubcookie_set_no_obscure,
      0, 0, NULL },

    /* Added by ddj@cmu.edu on 2006/05/01 to address security issue at CMU. */
    /* "Determines whether a new AppID replaces or is catenated to the old App ID." */
    { ngx_string("pubcookie_catenate_app_ids"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      pubcookie_set_catenate_appids,
      0, 0, NULL },
    /* End of ddj@cmu.edu's change. */

    /* "Specify the Directory Depth for generating default AppIDs." */
    { ngx_string("pubcookie_dir_depth_for_app_id"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      pubcookie_set_dirdepth,
      0, 0, NULL },

    /* "Force reauthentication for new sessions with specified timeout" */
    { ngx_string("pubcookie_session_cause_reauth"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      set_session_reauth,
      0, 0, NULL },

    /* "End application session and possibly login session" */
    { ngx_string("pubcookie_end_session"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE/*AP_INIT_RAW_ARGS*/,
      set_end_session,
      0, 0, NULL },

    /* "Send the following options to the login server along with authentication requests" */
    { ngx_string("pubcookie_add_request"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE/*AP_INIT_ITERATE*/,
      pubcookie_add_request_iterate,
      0, 0, NULL },

    /* "Only accept realms in this list" */
    { ngx_string("pubcookie_accept_realm"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE/*AP_INIT_ITERATE*/,
      pubcookie_accept_realms_iterate,
      0, 0, NULL },

    /* "Strip the realm (and set the REMOTE_REALM envirorment variable)" */
    { ngx_string("pubcookie_strip_realm"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      pubcookie_strip_realm,
      0, 0, NULL },

    /* "Specify on-demand pubcookie directives." */
    { ngx_string("pubcookie_on_demand"),
      NGX_HTTP_LOC_CONF|NGX_CONF_2MORE/*AP_INIT_ITERATE2*/,
      pubcookie_set_keyed_directive_iterate2,
      0, 0, NULL },

    /* "Do not prompt for id and password if not already logged in." */
    { ngx_string("pubcookie_no_prompt"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      pubcookie_set_noprompt,
      0, 0, NULL },

    /* "Set post response URL. Def = /PubCookie.reply" */
    { ngx_string("pubcookie_post_url"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      pubcookie_set_post_url,
      0, 0, NULL },

    /* "Deprecated, do not use" */
    { ngx_string("pubcookie_super_debug"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE/*AP_INIT_ITERATE*/,
      pubcookie_set_super_debug_iterate,
      0, 0, NULL },

    /* "Set to leave credentials in place after cleanup" */
    { ngx_string("pubcookie_no_clean_creds"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      pubcookie_set_no_clean_creds,
      0, 0, NULL },

    /* "Set to ignore non-standard server port" */
    { ngx_string("pubcookie_vitki_behind_proxy"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      pubcookie_set_vitki_behind_proxy,
      0, 0, NULL },
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
    &ngx_pubcookie_module_ctx,   /* module context */
    ngx_pubcookie_commands,      /* module directives */
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
 * Configuration
 */

static int
ngx_str_cat (ngx_pool_t *pool, ngx_str_t *res, ngx_str_t *s1, ngx_str_t *s2)
{
    u_char *p;
    int n, n1, n2;
    n1 = s1->data == NULL ? 0 : s1->len;
    n2 = s2->data == NULL ? 0 : s2->len;
    n = n1 + n2 + 1;
    p = ngx_pcalloc(pool, n);
    if (p == NULL) {
        return NGX_ERROR;
    }
    if (n1 > 0) {
        ngx_memcpy(p, s1->data, n1);
    }
    if (n2 > 0) {
        ngx_memcpy(p + n1, s2->data, n2);
    }
    p[n1 + n2] = '\0';
    res->data = p;
    res->len = n;
    return NGX_OK;
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
    int len;

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

    len = schema.len + host.len + path.len;
    p = ngx_pnalloc(cf->pool, len + 1);
    if (NULL == p) {
        return "PUBCOOKIE: not enough memory";
    }

    ngx_memcpy(p, schema.data, schema.len);
    ngx_memcpy(p + schema.len, host.data, host.len);
    ngx_memcpy(p + schema.len + host.len, path.data, path.len);
    p[len] = '\0';

    cfg->login_uri.data = p;
    cfg->login_uri.len = len;

    return NULL;
}

/**
 *  handle the PubCookieDomain directive
 */
static char *
pubcookie_set_domain (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_conf_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;

    u_char *p;
    int len;

    if (value[1].data[0] == '.') {
        len = value[1].len;
        p = ngx_pstrdup(cf->pool, &value[1]);
    } else {
        len = value[1].len + 1;
        p = ngx_pnalloc(cf->pool, len);
        if (NULL != p) {
            p[0] = '.';
            ngx_memcpy(p + 1, value[1].data, value[1].len);
        }
    }
    if (NULL == p) {
        return "PUBCOOKIE: not enough memory";
    }

    cfg->enterprise_domain.data = p;
    cfg->enterprise_domain.len = len;

    return NULL;
}

static char *
pubcookie_set_method (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_conf_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;

    pc_cf_log(cf,"set_method cfg=0x%p", (unsigned)cfg);
    if (!ngx_strncasecmp (value[1].data, (u_char *) "get", value[1].len)) {
    pc_cf_log(cf,"is get");
        cfg->use_post = 0;
    } else if (!ngx_strncasecmp (value[1].data, (u_char *) "post", value[1].len)) {
    pc_cf_log(cf,"is post");
        cfg->use_post = 1;
    } else {
        return "Invalid pubcookie login method";
    }
    pc_cf_log(cf,"null");
    return NULL;
}

static char *
pubcookie_set_crypt (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_conf_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;

    if (!ngx_strncasecmp (value[1].data, (u_char *) "des", value[1].len)) {
        cfg->crypt_alg = PBC_CRYPT_DES;
    } else if (!ngx_strncasecmp (value[1].data, (u_char *) "aes", value[1].len)) {
        cfg->crypt_alg = PBC_CRYPT_AES;
    } else if (!ngx_strncasecmp (value[1].data, (u_char *) "aes+domain", value[1].len)) {
        cfg->crypt_alg = PBC_CRYPT_AES_D;
    } else {
        return "Invalid encryption method";
    }
    return NULL;
}

#define SET_C_LETTER(c,a,b) (*(c)++ = '%', *(c)++ = (a), *(c)++ = (b))

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

static void *
ngx_pubcookie_create_loc_conf(ngx_conf_t *cf)
{
    ngx_pubcookie_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_pubcookie_loc_conf_t));
    if (NULL == conf) {
        return NGX_CONF_ERROR;
    }

    pc_cf_log(cf,"ngx_pubcookie_create_loc_conf");

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

    pc_cf_log(cf,"ngx_pubcookie_merge_loc_conf");

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
	        ngx_str_cat(cf->pool, &conf->oldappid, &prev->oldappid, &prev->appid);
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
	        ngx_str_cat(cf->pool, &conf->addl_requests, &prev->addl_requests, &conf->addl_requests);
        } else {
            conf->addl_requests = prev->addl_requests;
        }
    }

    return NGX_CONF_OK;
}


/**************************************
 *  Handler
 */

static ngx_int_t
ngx_pubcookie_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;
    ngx_pubcookie_ctx_t  *ctx;
    ngx_pubcookie_loc_conf_t  *alcf;

    alcf = ngx_http_get_module_loc_conf(r, ngx_pubcookie_module);

    if (alcf->realm.len == 0) {
        return NGX_DECLINED;
    }
    pc_req_log(r, "ngx_pubcookie_handler: realm len <> 0 !!!");

    ctx = ngx_http_get_module_ctx(r, ngx_pubcookie_module);

    if (ctx) {
        pc_req_log(r, "ngx_pubcookie_handler: found ctx");
        return ngx_pubcookie_authenticate(r, ctx, &ctx->passwd, alcf);
    }

    /* Decode http auth user and passwd, leaving values on the request */
    pc_req_log(r, "ngx_pubcookie_handler: auth basic user");
    rc = ngx_http_auth_basic_user(r);

    if (rc == NGX_DECLINED) {
        return ngx_pubcookie_set_realm(r, &alcf->realm);
    }

    if (rc == NGX_ERROR) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    /* Check user & password using PAM */
    return ngx_pubcookie_authenticate(r, ctx, &ctx->passwd, alcf);
}

static ngx_int_t
ngx_pubcookie_authenticate (ngx_http_request_t *r, ngx_pubcookie_ctx_t *ctx, ngx_str_t *passwd, void *conf)
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

    *h = ngx_pubcookie_handler;
    //pc_cf_log(cf,"ngx_pubcookie_init !!!");

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
        realm->data = (u_char *) "";

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

/* SVN Id: $Id*/

