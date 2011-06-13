/*
 * Copyright (C) 2010 Vitki <vitki@vitki.net>
 *
 * SVN Id: $Id$
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

/*************************
 * Pubcookie library hooks
 */

#define PBC_NGINX 1
#define OPENSSL_IN_DIR
#undef  HAVE_CONFIG_H

typedef ngx_http_request_t pool;

#include "pbc_logging.h"
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "security.h"
#include "html.h"

#undef PBC_ENTRPRS_DOMAIN
#define PBC_ENTRPRS_DOMAIN (libpbc_config_getstring(r,"enterprise_domain",".washington.edu"))

/***********************************
 * Data types
 */

#define PBC_LOC_SIGNATURE 0x0B100C10
#define PBC_SRV_SIGNATURE 0x0B200C20

/* Module configuration struct */
typedef struct {
    uint32_t signature;
    ngx_flag_t marked;
    ngx_str_t location;
    ngx_int_t inact_exp;
    ngx_int_t hard_exp;
    ngx_flag_t non_ssl_ok;
    ngx_str_t oldappid; /* Added by ddj@cmu.edu on 2006/05/10 */
    ngx_str_t appid;
    ngx_str_t end_session;
    ngx_int_t session_reauth;
    ngx_flag_t strip_realm;
    char * accept_realms;
    char * addl_requests;
    ngx_flag_t noprompt;
    ngx_array_t *keydirs;
    ngx_flag_t set_remote_user;
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
    ngx_str_t granting_cert_file;
    ngx_str_t ssl_key_file;
    ngx_str_t ssl_cert_file;
    ngx_str_t crypt_key;
    ngx_str_t egd_socket;
    ngx_str_t login;
    /* === server part === */
    ngx_str_t post_reply_url;
    ngx_str_t appsrvid;
    ngx_int_t dirdepth;
    ngx_flag_t noblank;
    ngx_flag_t catenate;		/* Added by ddj@cmu.edu on 2006/05/01 */
    ngx_flag_t no_clean_creds;
    ngx_int_t use_post;
    ngx_uint_t crypt_alg;
    ngx_flag_t vitki_behind_proxy;
    ngx_flag_t dummy_flag;
    ngx_str_t  dummy_str;
} ngx_pubcookie_srv_t;

typedef struct
{
    char *user;
    char *auth_type;
    int failed;
    int redir_reason_no;
    int has_granting;
    char creds;
    pbc_cookie_data *cookie_data;
    char *stop_message;
    int status;
    int nocache_sent;
    char * cred_transfer;
    int cred_transfer_len;
    ngx_str_t msg;
    ngx_str_t app_path;
    ngx_array_t *notes;
    char *server_name_tmp;
    ngx_table_elt_t *basic_auth_elt;
} ngx_pubcookie_req_t;

/***********************************
 * Logging
 */

extern int pubcookie_super_debug;

#define PC_LOG_EMERG   NGX_LOG_EMERG
#define PC_LOG_ERR     NGX_LOG_ERR
#define PC_LOG_INFO    NGX_LOG_INFO
#define PC_LOG_WARNING NGX_LOG_WARN
#define PC_LOG_DEBUG   NGX_LOG_DEBUG

#undef  PBC_LOG_ERROR
#undef  PBC_LOG_DEBUG_LOW
#undef  PBC_LOG_DEBUG_VERBOSE
#undef  PBC_LOG_DEBUG_OUTPUT
#undef  PBC_LOG_AUDIT

#define PBC_LOG_ERROR         NGX_LOG_ERR
#define PBC_LOG_DEBUG_LOW     NGX_LOG_DEBUG
#define PBC_LOG_DEBUG_VERBOSE NGX_LOG_DEBUG
#define PBC_LOG_DEBUG_OUTPUT  NGX_LOG_DEBUG
#define PBC_LOG_AUDIT         NGX_LOG_DEBUG

#define PBC_SUPER_LOG_LEVEL   NGX_LOG_WARN

#define pbc_ngx_log(log,verb,args...) \
        do { \
            ngx_uint_t _verb = (verb); \
            ngx_log_t *_log = (log); \
            if (pubcookie_super_debug && _verb > PBC_SUPER_LOG_LEVEL) \
                _verb = PBC_SUPER_LOG_LEVEL; \
            if (pubcookie_super_debug || _verb <= _log->log_level) \
                ngx_log_error_core(_verb, _log, 0, args); \
        } while(0)

/***********************************
 * APR helpers
 */

static inline char *
str2charp (ngx_pool_t *pool, ngx_str_t *ns)
{
    u_char *dst;
    int len;
    if (! ns)  return NULL;
    if ((len = ns->len) < 0) {
        if (! ns->data)  return NULL;
        len = ngx_strlen((u_char *) ns->data);
    }
    if (! (dst = ngx_pnalloc(pool, len + 1)))  return NULL;
    if (len > 0)  ngx_memcpy(dst, ns->data, len);
    dst[len] = '\0';
    return (char *) dst;
}

static inline char *
__ap_pstrdup (ngx_pool_t *pool, const char *src)
{
    ngx_str_t ns = { -1, (u_char *) src };
    return str2charp(pool, &ns);
}

/* SVN Id: $Id$ */

