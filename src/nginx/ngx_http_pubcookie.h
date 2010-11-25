/*
 * Copyright (C) 2010 Vitki <vitki@vitki.net>
 *
 * SVN Id: $Id$
 */

#define OPENSSL_IN_DIR
#undef  HAVE_CONFIG_H

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


/*************************
 * Pubcookie library hooks
 */

typedef ngx_http_request_t pool;
#define PBC_NGINX 1

#include "pbc_logging.h"
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "security.h"
#include "html.h"

/***********************************
 * Logging
 */

extern int pubcookie_super_debug;

#define pc_any_log(l,v,args...) \
        do { \
            int _v = (v); \
            ngx_log_t *_l = (l); \
            _v = pubcookie_super_debug ? NGX_LOG_WARN : NGX_LOG_DEBUG; \
            if (_l->log_level >= _v) \
                ngx_log_error_core(_v, _l, 0, args); \
        } while(0)

#define pc_req_log(r,args...) pc_any_log((r)->connection->log,0,args)
#define pc_pool_log(p,args...) pc_any_log((p)->log,0,args)
#define pc_cf_log(c,args...) pc_any_log((c)->log,0,args)
#define pc_log_log(l,args...) pc_any_log((l),0,args)

#define pbc_log_activity(p,l,args...) pc_any_log(log_of(p),0,args);
#define pbc_vlog_activity(p,l,f,va) pc_any_log(log_of(p),0,"libpbc: %s",f);

#define ap_log_rerror(v,r,args...) pc_any_log((r)->connection->log,0,args)

/***********************************
 * APR helpers
 */

#define request_rec ngx_http_request_t
#define ap_palloc ngx_palloc

static inline char *
str2charp (ngx_pool_t *pool, ngx_str_t *ns)
{
    u_char *dst;
    int len;
    if (NULL == ns)
        return NULL;
    if ((len = ns->len) < 0) {
        if (NULL == ns->data)
            return NULL;
        len = ngx_strlen((u_char *) ns->data);
    }
    if (NULL == (dst = ngx_pnalloc(pool, len + 1)))
        return NULL;
    if (len > 0)
        ngx_memcpy(dst, ns->data, len);
    dst[len] = '\0';
    return (char *) dst;
}

static inline char *
__ap_pstrdup (ngx_pool_t *pool, const char *src)
{
    ngx_str_t ns;
    ns.data = (u_char *) src;
    ns.len = -1;
    return str2charp(pool, &ns);
}

#define ap_pstrdup(p,s) __ap_pstrdup(p,s)

/***********************************
 * Definitions
 */

#define DONE NGX_DONE
#define OK NGX_OK

#define ME(r) ap_get_server_name(r)

#define MAX_POST_DATA 10485760

#define SET_C_LETTER(c,a,b) (*(c)++ = '%', *(c)++ = (a), *(c)++ = (b))

#define ngx_pubcookie_module ngx_http_pubcookie_module

#define ngx_str_assign(a,s)     ({ \
        u_char *_p = (u_char *)(s); \
        (a).len = ngx_strlen(_p); \
        (a).data = _p; \
    })

#define main_rrec(r)    ((r)->main)
#define top_rrec(r)     ((r)->main)

#undef PBC_ENTRPRS_DOMAIN
#define PBC_ENTRPRS_DOMAIN (libpbc_config_getstring(r,"enterprise_domain",".washington.edu"))

/***********************************
 * Data types
 */

/* Module configuration struct */
typedef struct {
    uint32_t signature;
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
} ngx_pubcookie_loc_t;

typedef struct
{
    uint32_t signature;
    ngx_log_t *log;
    ngx_pool_t *pool;
    security_context *sectext;
    int locations;
    /* === config list === */
    ngx_str_t enterprise_domain;
    ngx_str_t keydir;
    ngx_str_t granting_key_file;
    ngx_str_t granting_cert_file;
    ngx_str_t ssl_key_file;
    ngx_str_t ssl_cert_file;
    ngx_str_t crypt_key;
    ngx_str_t egd_socket;
    ngx_str_t login;
    /* === server part === */
    ngx_str_t post_url;
    ngx_str_t appsrvid;
    int dirdepth;
    int noblank;
    int catenate;		/* Added by ddj@cmu.edu on 2006/05/01 */
    int no_clean_creds;
    int use_post;
    unsigned crypt_alg;
    int behind_proxy;
} ngx_pubcookie_srv_t;

typedef struct
{
    int failed;
    int redir_reason_no;
    int has_granting;
    ngx_str_t user;
    ngx_str_t user_name;
    char creds;
    pbc_cookie_data *cookie_data;
    char *stop_message;
    int status;
    int no_cache_set;
    ngx_str_t msg;
    ngx_str_t cred_transfer;
    ngx_str_t app_path;
    ngx_str_t server_name_tmp;
    ngx_str_t uri_tmp;
    ngx_array_t notes;
} ngx_pubcookie_req_t;

/*
 * Helpers for libpbc library
 */

#define PBC_LOC_SIGNATURE 0x0B100C10
#define PBC_SRV_SIGNATURE 0x0B200C20

static inline ngx_log_t *
log_of (void *p)
{
    return (NULL == p ? NULL :
            (*(uint32_t *)p == PBC_SRV_SIGNATURE)
                ? ((ngx_pubcookie_srv_t *)p)->log
                : ((ngx_http_request_t *)p)->connection->log);
}

static inline ngx_pool_t *
pool_of (void *p)
{
    return (NULL == p ? NULL :
            (*(uint32_t *)p == PBC_SRV_SIGNATURE)
                ? ((ngx_pubcookie_srv_t *)p)->pool
                : ((ngx_http_request_t *)p)->pool);
}

/* SVN Id: $Id$ */

