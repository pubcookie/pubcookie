/* ========================================================================
 * Copyright 2008 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

/** @file mod_pubcookie.c
 * Apache pubcookie module
 *
 * $Id: mod_pubcookie.c,v 1.223 2009/09/18 21:24:51 fox Exp $
 */

#define MAX_POST_DATA 10485760
#define CONTENT_TYPE "text/html; charset=utf-8"

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#include "pbc_time.h"

#ifdef APACHE2
#undef HAVE_CONFIG_H
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#endif

extern int errno;

/* apache includes */
#include "httpd.h"
#include "http_config.h"
#define CORE_PRIVATE
#include "http_core.h"
#include "http_log.h"
#include "http_main.h"
#include "http_protocol.h"
#include "util_script.h"
#ifdef APACHE2
#include "ap_mpm.h"
#endif

/* ssleay lib stuff */

#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
# include <openssl/des.h>
# include <openssl/rand.h>
# include <openssl/err.h>
#else
# include <pem.h>
# include <des.h>
# include <rand.h>
# include <err.h>
#endif /* OPENSSL_IN_DIR */

#ifdef APACHE2
typedef apr_pool_t pool;
typedef apr_table_t table;
#endif

/* pubcookie stuff */
#include "pbc_apacheconfig.h"
#include "pbc_myconfig.h"
#include "pbc_logging.h"
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"
#include "security.h"
#include "mod_pubcookie.h"
#include "pbc_configure.h"
#include "html.h"

/* system stuff */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif /* HAVE_SYS_STAT_H */

#ifdef APACHE2

#include "apr_strings.h"

#define PC_LOG_DEBUG  APLOG_MARK,APLOG_DEBUG,0
#define PC_LOG_WARNING   APLOG_MARK,APLOG_WARNING,0
#define PC_LOG_NOTICE APLOG_MARK,APLOG_NOTICE,0
#define PC_LOG_INFO   APLOG_MARK,APLOG_INFO,0
#define PC_LOG_ERR    APLOG_MARK,APLOG_ERR,0
#define PC_LOG_EMERG  APLOG_MARK,APLOG_EMERG,0
#define USER user
#define AUTH_TYPE ap_auth_type

#define ap_palloc apr_palloc
#define ap_pcalloc apr_pcalloc
#define ap_make_array apr_array_make
#define ap_push_array apr_array_push
#define ap_make_table apr_table_make
#define ap_table_add apr_table_add
#define ap_table_get apr_table_get
#define ap_table_set apr_table_set
#define ap_table_setn apr_table_setn
#define ap_table_merge apr_table_merge
#define ap_table_unset apr_table_unset
#define ap_overlay_tables apr_table_overlay
#define ap_psprintf apr_psprintf
#define ap_snprintf apr_snprintf
#define ap_pstrcat apr_pstrcat
#define ap_pstrdup apr_pstrdup
#define ap_pstrndup apr_pstrndup
#define ap_parse_uri_components apr_uri_parse
#define ap_unparse_uri_components apr_uri_unparse
#define uri_components apr_uri_t
typedef apr_pool_t ap_pool;
#define ap_send_http_header(r) ;

#include "apr_optional.h"
APR_DECLARE_OPTIONAL_FN (char *, ssl_var_lookup, (apr_pool_t *,
                                                  server_rec *, conn_rec *,
                                                  request_rec *, char *));
static APR_OPTIONAL_FN_TYPE (ssl_var_lookup) * lookup_ssl_var = NULL;


#else /* is apache 1.3 */

#define PC_LOG_DEBUG  APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO
#define PC_LOG_WARNING   APLOG_MARK,APLOG_WARNING|APLOG_NOERRNO
#define PC_LOG_NOTICE APLOG_MARK,APLOG_NOTICE|APLOG_NOERRNO
#define PC_LOG_INFO   APLOG_MARK,APLOG_INFO|APLOG_NOERRNO
#define PC_LOG_ERR    APLOG_MARK,APLOG_ERR
#define PC_LOG_EMERG  APLOG_MARK,APLOG_EMERG|APLOG_NOERRNO
#define USER connection->user
#define AUTH_TYPE connection->ap_auth_type
#define APR_SUCCESS HTTP_OK
#define AP_RAW_ARGS func
#define AP_TAKE1 func
#define AP_FLAG func
typedef unsigned short apr_port_t;

#endif /* which apache */

/* Cookies are secure except for execptional cases */
#ifdef PORT80_TEST
static char *secure_cookie = "";
#else
char *secure_cookie = " secure";
#endif

#define ME(r) ap_get_server_name(r)
static char *encode_get_args (request_rec *r, char *in, int ec);

void dump_server_rec (request_rec * r, pubcookie_server_rec * scfg)
{
    ap_log_rerror (PC_LOG_DEBUG, r, "dump_server_rec:\n\
		dirdepth: %d\n\
		noblank: %d\n\
		login: %s\n\
		appsrvid: %s\n\
		authtype_names: %s\n\
		use_post: %d\n\
        no_clean_creds: %d\n", scfg->dirdepth, scfg->noblank, (scfg->login == NULL ? "" : scfg->login), (scfg->appsrvid == NULL ? "" : (char *) scfg->appsrvid), (scfg->authtype_names == NULL ? "" : (char *) scfg->authtype_names), scfg->use_post, scfg->no_clean_creds);

}

void dump_dir_rec (request_rec * r, pubcookie_dir_rec * cfg)
{
    ap_log_rerror (PC_LOG_DEBUG, r, "dump_dir_rec:\n\
		inact_exp: %d\n\
                hard_exp: %d\n\
                non_ssl_ok: %d\n\
		appid: %s\n\
                end_session: %s\n\
                session_reauth: %d\n\
                noprompt: %d", cfg->inact_exp, cfg->hard_exp, cfg->non_ssl_ok, (cfg->appid == NULL ? "" : (char *) cfg->appid), (cfg->end_session == NULL ? "" : (char *) cfg->end_session), cfg->session_reauth, cfg->noprompt);

}

void dump_req_rec (request_rec * r, pubcookie_req_rec * rr)
{
    ap_log_rerror (PC_LOG_DEBUG, r, "dump_req_rec:\n\
                failed: %d\n\
                has_granting: %d\n\
                creds: %c\n\
                redir_reason_no: %d\n\
                stop_message: %s", rr->failed, rr->has_granting, rr->creds, rr->redir_reason_no, (rr->stop_message == NULL ? "" : (char *) rr->stop_message));

}

/* Apache 2.2.x headers must be accumulated and set in the output filter.
   Apache 2.0.49+ also supports the filters as well.
   In Apache 1.3.x and lesser 2.0.x we write the headers directly. */

#if defined(APACHE2) && AP_MODULE_MAGIC_AT_LEAST(20020903,6)
#define PBC_DEFERRED_HEADERS
#endif

#ifdef PBC_DEFERRED_HEADERS
#define HDRS_OUT rr->hdr_out
#define HDRS_ERR rr->hdr_err
#else
#define HDRS_OUT r->headers_out
#define HDRS_ERR r->err_headers_out
#endif


/* Recover the currect request or server rec from a pool.
   Note that either of these can return NULL.
   */

#ifdef APACHE1_3
/* In apache 1.3, which handles only one request at a time, we 
   just store the record pointers. */

static server_rec *current_server_rec = NULL;
static request_rec *current_request_rec = NULL;

server_rec *find_server_from_pool (pool * p)
{
    return (current_server_rec);
}

request_rec *find_request_from_pool (pool * p)
{
    return (current_request_rec);
}

#else /* APACHE 2 */

/* In apache 2.x, which can be threaded and handle several requests
   at a time, we store the pointers in each pool's userdata table. */

#define PBC_SERVER_REC_KEY "pbc_server_rec_key"
#define PBC_REQUEST_REC_KEY "pbc_request_rec_key"

server_rec *find_server_from_pool (pool * p)
{
    void *vs;
    apr_pool_userdata_get (&vs, PBC_SERVER_REC_KEY, p);
    return ((server_rec *) vs);
}

request_rec *find_request_from_pool (pool * p)
{
    void *vr;
    apr_pool_userdata_get (&vr, PBC_REQUEST_REC_KEY, p);
    return ((request_rec *) vr);
}

#endif /* which apache */


#ifdef PBC_DEFERRED_HEADERS
/* Append add the entries in 'src' to the 'dest' table */
static void append_to_table(request_rec *r, apr_table_t *dest, apr_table_t *src)
{
   const apr_array_header_t *srce = apr_table_elts(src);
   int i;
 
   for (i=0; i<srce->nelts; i++) {
      apr_table_entry_t *ent = &((apr_table_entry_t *) (srce->elts))[i];
      ap_log_rerror (PC_LOG_DEBUG, r, " .. adding header %s", ent->key);
      apr_table_add(dest, ent->key, ent->val);
   }
}
#endif

/* Send headers - so we can send direct content.  If we're 
   doing the deferred method, append any headers we've accumulated
   to the real header list. */
static void flush_headers(request_rec *r)
{
#ifdef PBC_DEFERRED_HEADERS
    pubcookie_req_rec *rr;
    rr = (pubcookie_req_rec *) ap_get_module_config (r->request_config,
                                                     &pubcookie_module);
    if ( rr ) {
        ap_log_rerror (PC_LOG_DEBUG, r, "pubcookie flush headers: merging %d output headers",
                   apr_table_elts(rr->hdr_out)->nelts);
        append_to_table(r, r->headers_out, rr->hdr_out);
        append_to_table(r, r->err_headers_out, rr->hdr_err);
    }
#endif
    ap_send_http_header (r);
}


/**
 * get the post stuff 
 * @param r reuquest_rec
 * @return int 
 */

char *get_post_data (request_rec * r, int post_len)
{
    char *buffer;
    char *bp;
    int rem = post_len;

    if (rem <= 0)
        return (ap_pstrdup (r->pool, ""));

    buffer = (char *) ap_palloc (r->pool, post_len + 1);
    *buffer = '\0';
    bp = buffer;
    if (ap_setup_client_block (r, REQUEST_CHUNKED_ERROR))
        return (buffer);

    if (ap_should_client_block (r)) {
        int len;

#ifdef APACHE1_3
        ap_hard_timeout ("copy script args", r);
#endif
        while ((len = ap_get_client_block (r, bp, rem)) > 0) {
#ifdef APACHE1_3
            ap_reset_timeout (r);
#endif
            bp += len;
            rem -= len;
        }
#ifdef APACHE1_3
        ap_kill_timeout (r);
#endif
    }
    *bp = '\0';
    return (buffer);

}

/**
 * get a random int used to bind the granting cookie and pre-session
 * @returns random int or -1 for error
 * but, what do we do about that error?
 */
int get_pre_s_token (request_rec * r)
{
    int i;
    pool *p = r->pool;

    if ((i = libpbc_random_int (p)) == -1) {
        ap_log_rerror (PC_LOG_EMERG, r, "get_pre_s_token: OpenSSL error");
    }

    ap_log_rerror (PC_LOG_DEBUG, r, "get_pre_s_token: token is %d", i);
    return (i);

}

/*                                                                            */
unsigned char *get_app_path (request_rec * r, const char *path)
{
    char *path_out;
    int truncate;
    pool *p = r->pool;
    pubcookie_server_rec *scfg;
    char *a;

    scfg =
        (pubcookie_server_rec *) ap_get_module_config (r->server->
                                                       module_config,
                                                       &pubcookie_module);

    if (scfg->dirdepth) {
        if (scfg->dirdepth < ap_count_dirs (path))
            truncate = scfg->dirdepth;
        else
            truncate = ap_count_dirs (path);
        path_out = ap_palloc (p, strlen (path) + 1);
        ap_make_dirstr_prefix (path_out, path, truncate);
    } else {
        path_out = ap_make_dirstr_parent (p, path);
    }

    for (a = path_out; *a; a++)
        if (*a != '/' && !isalnum (*a))
            *a = '_';
    return (unsigned char *) path_out;

}

int check_end_session (request_rec * r)
{
    int ret = 0;
    const char *end_session;
    char *word;
    pool *p = r->pool;
    pubcookie_dir_rec *cfg;

    cfg = (pubcookie_dir_rec *) ap_get_module_config (r->per_dir_config,
                                                      &pubcookie_module);

    end_session = cfg->end_session;

    /* check list of end session args */
    while (end_session != NULL && *end_session != '\0' &&
           (word = ap_getword_white (p, &end_session))) {

        if (strcasecmp (word, PBC_END_SESSION_ARG_REDIR) == 0) {
            ret = ret | PBC_END_SESSION_REDIR;
        }
        if (strcasecmp (word, PBC_END_SESSION_ARG_CLEAR_L) == 0) {
            ret = ret | PBC_END_SESSION_CLEAR_L | PBC_END_SESSION_REDIR;
        } else if (strcasecmp (word, PBC_END_SESSION_ARG_ON) == 0) {
            ret = ret | PBC_END_SESSION_ONLY;
        } else if (strcasecmp (word, PBC_END_SESSION_ARG_OFF) == 0) {
            /* off means off, nothing else */
            return (PBC_END_SESSION_NOPE);
        }
    }

    return (ret);

}

/* converts an authtype name to a pubcookie credential number */
char pubcookie_auth_type (request_rec * r)
{
    pubcookie_server_rec *scfg;
    pubcookie_dir_rec *cfg;
    pool *p = r->pool;
    const char *auth_type;
    const char *type_names;
    char *word;
    int i;

    scfg =
        (pubcookie_server_rec *) ap_get_module_config (r->server->
                                                       module_config,
                                                       &pubcookie_module);
    cfg =
        (pubcookie_dir_rec *) ap_get_module_config (r->per_dir_config,
                                                    &pubcookie_module);
    type_names = scfg->authtype_names;
    auth_type = ap_auth_type (r);

    /* check list of pubcookie auth_types */
    /* xxx this only works if the credential id is '0', '1', ..., '9'  */
    i = 1;
    while (type_names != NULL && *type_names != '\0' &&
           (word = ap_getword_conf (p, &type_names))) {
        if (strcasecmp (word, auth_type) == 0)
            return (i + '0');
        i++;
    }

    /* ok, check the list in libpubcookie */
    return libpbc_get_credential_id (p, auth_type);
}

request_rec *main_rrec (request_rec * r)
{
    request_rec *mr = r;
    while (mr->main)
        mr = mr->main;
    return mr;
}

/* figure out the appid                                                      */
unsigned char *appid (request_rec * r)
{
    pubcookie_server_rec *scfg;
    pubcookie_dir_rec *cfg;
    request_rec *rmain = main_rrec (r);
    pool *p = r->pool;

    cfg = (pubcookie_dir_rec *) ap_get_module_config (r->per_dir_config,
                                                      &pubcookie_module);
    scfg =
        (pubcookie_server_rec *) ap_get_module_config (r->server->
                                                       module_config,
                                                       &pubcookie_module);

    /* Added by ddj@cmu.edu on 2006/05/10. */
    if (scfg->catenate) {	/* Catenate app IDs? */
      /* Yeah. Anything to catenate? 4 possibilities. */
      if (cfg->appid && cfg->oldappid) {
	/* Old and new are both set. */
	/* Glue the default, old, and new together. */
	return (unsigned char *) ap_pstrcat(p,
			  get_app_path (r, rmain->parsed_uri.path),
			  cfg->oldappid,
			  cfg->appid,
			  NULL);
      } else if (cfg->appid) {
	/* Just the new one is set. */
	/* Glue the default and the new one together. */
	return (unsigned char *) ap_pstrcat(p,
			  get_app_path (r, rmain->parsed_uri.path),
			  cfg->appid,
			  NULL);
      } else if (cfg->oldappid) {
	/* Just the old one is set. */
	/* Glue the default and the old one together. */
	return (unsigned char *) ap_pstrcat(p,
			  get_app_path (r, rmain->parsed_uri.path),
			  cfg->oldappid,
			  NULL);
      } else {
	/* None were ever set.  Just use the default. */
	return get_app_path (r, rmain->parsed_uri.path);
      }
    } else {
      /* No, don't catenate.  Use the 3.3.0a logic verbatim. */
      if (cfg->appid)
	return (cfg->appid);
      else
	return get_app_path (r, rmain->parsed_uri.path);
    }
}

/* figure out the appsrvid                                                   */
unsigned char *appsrvid (request_rec * r)
{
    pubcookie_server_rec *scfg;
    pubcookie_dir_rec *cfg;
    pool *p = r->pool;

    cfg = (pubcookie_dir_rec *) ap_get_module_config (r->per_dir_config,
                                                      &pubcookie_module);
    scfg =
        (pubcookie_server_rec *) ap_get_module_config (r->server->
                                                       module_config,
                                                       &pubcookie_module);

    if (scfg->appsrvid)
        return (scfg->appsrvid);
    else
        /* because of multiple passes through don't use r->hostname() */
        return (unsigned char *) ap_pstrdup (p, ap_get_server_name (r));

}

/* make sure agents don't cache the redirect */
void set_no_cache_headers (request_rec * r)
{
    pubcookie_req_rec *rr;
    pool *p = r->pool;
#ifdef APACHE2
    char *datestr;
#endif

    rr = (pubcookie_req_rec *) ap_get_module_config (r->request_config,
                                                     &pubcookie_module);
#ifdef APACHE2
    datestr = apr_palloc (p, APR_RFC822_DATE_LEN);
    apr_rfc822_date (datestr, r->request_time);
    ap_table_set (HDRS_OUT, "Expires", datestr);
    ap_table_set (HDRS_ERR, "Expires", datestr);
#else
    ap_table_set (HDRS_OUT, "Expires", ap_gm_timestr_822 (r->pool,
                                                                r->
                                                                request_time));
    ap_table_set (HDRS_ERR, "Expires", ap_gm_timestr_822 (r->pool,
                                                                r->
                                                                request_time));
#endif
    ap_table_set (HDRS_OUT, "Cache-Control",
                  "no-store, no-cache, must-revalidate");
    ap_table_set (HDRS_ERR, "Cache-Control",
                  "no-store, no-cache, must-revalidate");
    ap_table_set (HDRS_OUT, "Pragma", "no-cache");
    ap_table_set (HDRS_ERR, "Pragma", "no-cache");

}

/* set or reset the session cookie.
   Called from the user hook.  */
static void set_session_cookie (request_rec * r,
                                pubcookie_server_rec * scfg,
                                pubcookie_dir_rec * cfg,
                                pubcookie_req_rec * rr, int firsttime)
{
    char *new_cookie;
    unsigned char *cookie;
    pool *p = r->pool;

    if (firsttime != 1) {
        /* just update the idle timer */
        /* xxx it would be nice if the idle timeout has been disabled
           to avoid recomputing and resigning the cookie? */
        cookie =
            libpbc_update_lastts (p, scfg->sectext, rr->cookie_data, ME(r),
                                  0, scfg->crypt_alg);
    } else {
        /* create a brand new cookie, initialized with the present time */
        cookie = libpbc_get_cookie (p,
                                    scfg->sectext,
                                    (unsigned char *) rr->user,
                                    (unsigned char *) PBC_VERSION,
                                    PBC_COOKIE_TYPE_S,
                                    rr->creds,
                                    (cfg->session_reauth < 0) ? 23 : 24,
                                    (unsigned char *) appsrvid (r),
                                    appid (r), ME (r), 0, scfg->crypt_alg);
    }

    new_cookie = ap_psprintf (p, "%s=%s; path=%s;%s",
                              make_session_cookie_name (p,
                                                        PBC_S_COOKIENAME,
                                                        appid (r)),
                              cookie, "/", secure_cookie);

    ap_table_add (HDRS_OUT, "Set-Cookie", new_cookie);

    if (firsttime && rr->cred_transfer) {
        char *blob = NULL;
        int bloblen;
        char *base64 = NULL;
        int res = 0;

        /* save the transfer creds in a cookie; we only need to do this
           the first time since our cred cookie doesn't expire (which is poor
           and why we need cookie extensions) */
        /* encrypt */
        if (libpbc_mk_priv (p, scfg->sectext, ME (r), 0, rr->cred_transfer,
                            rr->cred_transfer_len, &blob, &bloblen,
                            scfg->crypt_alg)) {
            ap_log_rerror (PC_LOG_ERR, r,
                           "credtrans: libpbc_mk_priv() failed");
            res = -1;
        }

        /* base 64 */
        if (!res) {
            base64 = ap_palloc (p, (bloblen + 3) / 3 * 4 + 1);
            if (!libpbc_base64_encode (p, (unsigned char *) blob,
                                       (unsigned char *) base64,
                                       bloblen)) {
                ap_log_rerror (PC_LOG_ERR, r,
                               "credtrans: libpbc_base64_encode() failed");
                res = -1;
            }
        }

        /* set */
        new_cookie = ap_psprintf (p, "%s=%s; path=%s;%s",
                                  make_session_cookie_name (p,
                                                            PBC_CRED_COOKIENAME,
                                                            appid (r)),
                                  base64, "/", secure_cookie);
        ap_table_add (HDRS_OUT, "Set-Cookie", new_cookie);

        /* xxx eventually when these are just cookie extensions, they'll
           automatically be copied from the granting cookie to the 
           session cookies and from session cookie to session cookie */
    }
}

/** clear granting cookie */
void clear_granting_cookie (request_rec * r)
{
    char *new_cookie;
    pool *p = r->pool;
    pubcookie_server_rec *scfg;
    pubcookie_req_rec *rr;

    scfg =
        (pubcookie_server_rec *) ap_get_module_config (r->server->
                                                       module_config,
                                                       &pubcookie_module);
    rr = (pubcookie_req_rec *) ap_get_module_config (r->request_config,
                                                     &pubcookie_module);

    if (scfg->use_post)
        new_cookie = ap_psprintf (p, "%s=; path=/; expires=%s;%s",
                                  PBC_G_COOKIENAME,
                                  EARLIEST_EVER, secure_cookie);
    else
        new_cookie =
            ap_psprintf (p, "%s=; domain=%s; path=/; expires=%s;%s",
                         PBC_G_COOKIENAME, PBC_ENTRPRS_DOMAIN,
                         EARLIEST_EVER, secure_cookie);

    ap_log_rerror (PC_LOG_DEBUG, r,
                   "clear_granting_cookie: setting cookie: %s",
                   new_cookie);
    ap_table_add (HDRS_OUT, "Set-Cookie", new_cookie);
}

/* clear cred transfer cookie */
void clear_transfer_cookie (request_rec * r)
{
    char *new_cookie;
    pool *p = r->pool;
    pubcookie_req_rec *rr;

    rr = (pubcookie_req_rec *) ap_get_module_config (r->request_config,
                                                     &pubcookie_module);

    new_cookie = ap_psprintf (p,
                              "%s=; domain=%s; path=/; expires=%s;%s",
                              PBC_CRED_TRANSFER_COOKIENAME,
                              PBC_ENTRPRS_DOMAIN,
                              EARLIEST_EVER, secure_cookie);

    ap_table_add (HDRS_OUT, "Set-Cookie", new_cookie);
}

/** clear pre session cookie */
void clear_pre_session_cookie (request_rec * r)
{
    char *new_cookie;
    pool *p = r->pool;
    pubcookie_req_rec *rr;

    rr = (pubcookie_req_rec *) ap_get_module_config (r->request_config,
                                                     &pubcookie_module);

    new_cookie = ap_psprintf (p,
                              "%s=; path=/; expires=%s;%s",
                              PBC_PRE_S_COOKIENAME,
                              EARLIEST_EVER, secure_cookie);

    ap_table_add (HDRS_OUT, "Set-Cookie", new_cookie);

}

void clear_session_cookie (request_rec * r)
{
    char *new_cookie;
    pubcookie_req_rec *rr;
    pool *p = r->pool;

    rr = (pubcookie_req_rec *) ap_get_module_config (r->request_config,
                                                     &pubcookie_module);

    if (!rr)
        return;

    new_cookie = ap_psprintf (p,
                              "%s=%s; path=/; expires=%s;%s",
                              make_session_cookie_name (p,
                                                        PBC_S_COOKIENAME,
                                                        appid (r)),
                              PBC_CLEAR_COOKIE, EARLIEST_EVER,
                              secure_cookie);

    ap_table_add (HDRS_OUT, "Set-Cookie", new_cookie);

    if (rr->cred_transfer) {
        /* extra cookies (need cookie extensions) */
        new_cookie = ap_psprintf (p,
                                  "%s=%s; path=/; expires=%s;%s",
                                  make_session_cookie_name (p,
                                                            PBC_CRED_COOKIENAME,
                                                            appid (r)),
                                  PBC_CLEAR_COOKIE,
                                  EARLIEST_EVER, secure_cookie);

        ap_table_add (HDRS_OUT, "Set-Cookie", new_cookie);
    }
}


/**
 * process end session redirects
 * @param r the apache request rec
 * @return OK to let Apache know to finish the request
 *
 * Called from the check user hook 
 */
static int do_end_session_redirect (request_rec * r,
                                    pubcookie_server_rec * scfg,
                                    pubcookie_dir_rec * cfg)
{
    char *refresh;
    pool *p = r->pool;

    ap_log_rerror (PC_LOG_DEBUG, r, "do_end_session_redirect: hello");

    r->content_type = CONTENT_TYPE;
    clear_granting_cookie (r);
    clear_pre_session_cookie (r);
    clear_session_cookie (r);
    set_no_cache_headers (r);

    flush_headers (r);

    refresh = ap_psprintf (p, "%d;URL=%s?%s=%d&%s=%s&%s=%s",
                           PBC_REFRESH_TIME,
                           scfg->login,
                           PBC_GETVAR_LOGOUT_ACTION,
                           (check_end_session (r) & PBC_END_SESSION_CLEAR_L
                            ? LOGOUT_ACTION_CLEAR_L :
                            LOGOUT_ACTION_NOTHING), PBC_GETVAR_APPID,
                           appid (r), PBC_GETVAR_APPSRVID, appsrvid (r));

    ap_rprintf (r, redirect_html, refresh);

    return (OK);
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
static int stop_the_show (request_rec * r, pubcookie_server_rec * scfg,
                          pubcookie_dir_rec * cfg, pubcookie_req_rec * rr)
{

    ap_log_rerror (PC_LOG_DEBUG, r, "stop_the_show: hello");

    r->content_type = CONTENT_TYPE;
    clear_granting_cookie (r);
    clear_pre_session_cookie (r);
    clear_session_cookie (r);
    set_no_cache_headers (r);

    flush_headers (r);

    ap_rprintf (r, stop_html, r->server->server_admin,
                rr->stop_message ? rr->stop_message : "");

    return (OK);

}

request_rec *top_rrec (request_rec * r)
{
    request_rec *mr = r;

    for (;;) {
        while (mr->main)
            mr = mr->main;
        while (mr->prev)
            mr = mr->prev;
        if (!mr->main)
            break;
    }
    return mr;
}

/* URL encode a base64 (deal with '+') */
static char *fix_base64_for_url(pool *p, char *b64)
{
   int n;
   char *np;
   char *n64;
   for (n=0, np=b64; *np; np++) if (*np=='+') n++;
   if (n>0) {
       n64 = ap_pcalloc (p, (strlen (b64) + 4*n));
       for (np=n64; *b64; b64++) {
          if (*b64=='+') {
             *np++ = '%';
             *np++ = '2';
             *np++ = 'B';
          } else *np++ = *b64;
       }
       *np++ = '\0';
   } else n64 = b64;
   return (n64);
}


/* Herein we deal with the redirect of the request to the login server        */
/*    if it was only that simple ...                                          */
static int auth_failed_handler (request_rec * r,
                                pubcookie_server_rec * scfg,
                                pubcookie_dir_rec * cfg,
                                pubcookie_req_rec * rr)
{
    pool *p = r->pool;
    char *refresh = ap_palloc (p, PBC_1K);
    char *pre_s = ap_palloc (p, PBC_1K);
    char *pre_s_cookie = ap_palloc (p, PBC_1K);
    char *g_req_cookie = ap_palloc (p, PBC_4K);
    char *g_req_contents = ap_palloc (p, PBC_4K);
    char *e_g_req_contents;
    const char *tenc = ap_table_get (r->headers_in, "Transfer-Encoding");
    const char *ctype = ap_table_get (r->headers_in, "Content-type");
    const char *lenp = ap_table_get (r->headers_in, "Content-Length");
    char *host = NULL;
    char *args;
    char *refresh_e;
    request_rec *mr = top_rrec (r);
    char misc_flag = '0';
    char *file_to_upld = NULL;
    const char *referer;
    int pre_sess_tok;
    apr_port_t port;
    char *post_data;
    char vstr[4];
    char *b64uri;

    ap_log_rerror (PC_LOG_DEBUG, r, "auth_failed_handler: hello");

    if (r->main) {
        ap_log_rerror (PC_LOG_DEBUG, r,
                       " .. in subrequest: retuning noauth");
        return (HTTP_UNAUTHORIZED);
    }

    if (cfg->noprompt > 0)
        misc_flag = 'Q';

    /* reset these dippy flags */
    rr->failed = 0;

    /* acquire any GET args */
    if (r->args) {
        char *argst;
        /* error out if length of GET args would cause a problem */
        if (strlen (r->args) > PBC_MAX_GET_ARGS) {
            rr->stop_message =
                ap_psprintf (p,
                             "GET arguments longer than supported.  (args length: %d)",
                             strlen (r->args));
            stop_the_show (r, scfg, cfg, rr);
            return (OK);
        }

        argst = ap_pcalloc (p, (strlen (r->args) + 3) / 3 * 4 + 1);
        libpbc_base64_encode (p, (unsigned char *) r->args,
                              (unsigned char *) argst, strlen (r->args));
        ap_log_rerror (PC_LOG_DEBUG, r,
                       "GET args before encoding length %d, string: %s",
                       strlen (r->args), r->args);
        args = fix_base64_for_url(p, argst);
        ap_log_rerror (PC_LOG_DEBUG, r,
                       "GET args after encoding length %d, string: %s",
                       strlen (args), args);
    } else
        args = ap_pstrdup (p, "");

    r->content_type = CONTENT_TYPE;

    /* if there is a non-standard port number just tack it onto the hostname  */
    /* the login server just passes it through and the redirect works         */
    port = ap_get_server_port (r);
    if ((port != 80) && (port != 443)) {
        /* because of multiple passes through don't use r->hostname() */
        host = ap_psprintf (p, "%s:%d", ap_get_server_name (r), port);
    }

    if (!host)
        /* because of multiple passes through on www don't use r->hostname() */
        host = ap_pstrdup (p, ap_get_server_name (r));

    /* To knit the referer history together */
    referer = ap_table_get (r->headers_in, "Referer");

    if ((pre_sess_tok = get_pre_s_token (r)) == -1) {
        /* this is weird since we're already in a handler */
        rr->stop_message =
            ap_pstrdup (p,
                        "Couldn't get pre session token. (Already in handler)");
        stop_the_show (r, scfg, cfg, rr);
        return (OK);
    }

    /* make the granting request */
    /* the granting request is a cookie that we set  */
    /* that gets sent up to the login server cgi, it */
    /* is our main way of communicating with it      */
    /* If we're doing compatibility encryption, send the */
    /* compatibility version string. */

    sprintf (vstr, "%-2.2s%c", PBC_VERSION,
             scfg->crypt_alg == 'd' ? '\0' : scfg->crypt_alg);

    if (scfg->use_post) {
        b64uri = ap_pcalloc (p, (strlen (mr->uri) + 3) / 3 * 4 + 1);
        libpbc_base64_encode (p, (unsigned char *) mr->uri,
                              (unsigned char *) b64uri, strlen (mr->uri));
        ap_log_rerror (PC_LOG_DEBUG, r,
                       "Post URI before encoding length %d, string: %s",
                       strlen (mr->uri), mr->uri);
        ap_log_rerror (PC_LOG_DEBUG, r,
                       "Post URI after encoding length %d, string: %s",
                       strlen (b64uri), b64uri);
    } else b64uri = ap_pstrdup(p, mr->uri);

    ap_snprintf (g_req_contents, PBC_4K - 1,
                 "%s=%s&%s=%s&%s=%c&%s=%s&%s=%s&%s=%s&%s=%s&%s=%s&%s=%s&%s=%d&%s=%s&%s=%s&%s=%d&%s=%d&%s=%c",
                 PBC_GETVAR_APPSRVID,
                 appsrvid (r),
                 PBC_GETVAR_APPID,
                 appid (r),
                 PBC_GETVAR_CREDS,
                 rr->creds,
                 PBC_GETVAR_VERSION,
                 vstr,
                 PBC_GETVAR_METHOD,
                 r->method,
                 PBC_GETVAR_HOST,
                 host,
                 PBC_GETVAR_URI,
                 b64uri,
                 PBC_GETVAR_ARGS,
                 args,
                 PBC_GETVAR_REAL_HOST,
                 r->server->server_hostname,
                 PBC_GETVAR_APPSRV_ERR,
                 rr->redir_reason_no,
                 PBC_GETVAR_FILE_UPLD,
                 (file_to_upld ? file_to_upld : ""),
                 PBC_GETVAR_REFERER,
                 referer,
                 PBC_GETVAR_SESSION_REAUTH,
                 (cfg->session_reauth == PBC_UNSET_SESSION_REAUTH ?
                  PBC_SESSION_REAUTH_NO : cfg->session_reauth),
                 PBC_GETVAR_PRE_SESS_TOK,
                 pre_sess_tok, PBC_GETVAR_FLAG, misc_flag);

    if (cfg->addl_requests) {
        ap_log_rerror (PC_LOG_DEBUG, r,
                       "auth_failed_handler: adding %s",
                       cfg->addl_requests);

        g_req_contents = ap_pstrcat (p, g_req_contents,
                                     cfg->addl_requests, NULL);
    }

    ap_log_rerror (PC_LOG_DEBUG, r,
                   "g_req before encoding length %d, string: %s",
                   strlen (g_req_contents), g_req_contents);

    /* setup the client pull */
    ap_snprintf (refresh, PBC_1K - 1, "%d;URL=%s", PBC_REFRESH_TIME,
                 scfg->login);


    /* the redirect for requests with POST args are  */
    /* different then reqs with only GET args        */
    /* for GETs:                                     */
    /*   granting request is sent in a cookie and    */
    /*   a simple redirect is used to get the user   */
    /*   to the login server                         */
    /* for POSTs or (POST and GET args)              */
    /*   granting request is still sent in a cookie  */
    /*   redirect is done with javascript in the     */
    /*   body or a button if the user has javascript */
    /*   turned off.  the POST info is in a FORM in  */
    /*   the body of the redirect                    */

    e_g_req_contents =
        ap_palloc (p, (strlen (g_req_contents) + 3) / 3 * 4 + 1);
    libpbc_base64_encode (p, (unsigned char *) g_req_contents,
                          (unsigned char *) e_g_req_contents,
                          strlen (g_req_contents));

    /* The GET method requires a pre-session cookie */

    if (!scfg->use_post) {
        ap_log_rerror (PC_LOG_DEBUG, r, "making a pre-session ckookie");
        pre_s = (char *) libpbc_get_cookie (p,
                                            scfg->sectext,
                                            (unsigned char *) "presesuser",
                                            (unsigned char *) PBC_VERSION,
                                            PBC_COOKIE_TYPE_PRE_S,
                                            PBC_CREDS_NONE,
                                            pre_sess_tok,
                                            (unsigned char *) appsrvid (r),
                                            appid (r), ME (r), 0,
                                            scfg->crypt_alg);

        pre_s_cookie = ap_psprintf (p,
                                    "%s=%s; path=%s;%s",
                                    PBC_PRE_S_COOKIENAME,
                                    pre_s, "/", secure_cookie);

        ap_table_add (HDRS_OUT, "Set-Cookie", pre_s_cookie);
    }

    /* load and send the header */

    set_no_cache_headers (r);

    /* multipart/form-data is not supported */
    if (ctype
        && !strncmp (ctype, "multipart/form-data",
                     strlen ("multipart/form-data"))) {
        rr->stop_message =
            ap_pstrdup (p, "multipart/form-data not allowed");
        stop_the_show (r, scfg, cfg, rr);
        return (OK);
    }

    /* we handle post data unless it is too large, in which */
    /* case we treat it much like multi-part form data. */

    post_data = ap_pstrdup (p, "");
    if (lenp) {
        int post_data_len;
        if (((post_data_len = strtol (lenp, NULL, 10)) <= 0) ||
            (post_data_len > MAX_POST_DATA) ||
            (!(post_data = get_post_data (r, post_data_len)))) {
            rr->stop_message =
                ap_psprintf (p,
                             "Invalid POST data. (POST data length: %d)",
                             post_data_len);
            stop_the_show (r, scfg, cfg, rr);
            return (OK);
        }
    }


    if (!scfg->use_post) {
        /* GET method puts granting request in a cookie */
        ap_snprintf (g_req_cookie, PBC_4K - 1,
                     "%s=%s; domain=%s; path=/;%s",
                     PBC_G_REQ_COOKIENAME,
                     e_g_req_contents, PBC_ENTRPRS_DOMAIN, secure_cookie);

        ap_log_rerror (PC_LOG_DEBUG, r,
                       "g_req length %d cookie: %s", strlen (g_req_cookie),
                       g_req_cookie);
        ap_table_add (HDRS_OUT, "Set-Cookie", g_req_cookie);

        refresh_e = ap_os_escape_path (p, refresh, 0);

#ifdef REDIRECT_IN_HEADER
        /* warning, this will break some browsers */
        if (!(tenc || lenp))
            ap_table_add (HDRS_OUT, "Refresh", refresh_e);
#endif

    }

    flush_headers (r);

    /* If we're using the post method, just bundle everything
       in a post to the login server. */

    if (scfg->use_post) {
        char cp[24];
        if (port == 80 || port == 443)
            cp[0] = '\0';
        else
            sprintf (cp, ":%d", port);
        ap_rprintf (r, post_request_html, scfg->login,
                    e_g_req_contents, encode_get_args(r, post_data, 1),
                    ap_get_server_name (r), cp, scfg->post_reply_url);

    } else if (ctype && (tenc || lenp || r->method_number == M_POST)) {

        ap_rprintf (r, get_post_request_html, scfg->login,
                    encode_get_args(r, post_data, 1), scfg->login, PBC_WEBISO_LOGO,
                    PBC_POST_NO_JS_BUTTON);

    } else {
#ifdef REDIRECT_IN_HEADER
/* warning, this will break some browsers */
        ap_rprintf (r, nullpage_html);
#else
        ap_rprintf (r, redirect_html, refresh);
#endif
    }

    ap_log_rerror (PC_LOG_DEBUG, r,
                   "auth_failed_handler: redirect sent. uri: %s reason: %d",
                   mr->uri, rr->redir_reason_no);

    return (OK);

}


/* figure out the session cookie name                                         */
char *make_session_cookie_name (pool * p, char *cookiename,
                                unsigned char *_appid)
{
    /* 
       we now use JimB style session cookie names
       session cookie names are PBC_S_COOKIENAME_appid 
     */

    char *ptr;
    char *name;

    name = ap_pstrcat (p, cookiename, "_", _appid, NULL);

    ptr = name;
    while (*ptr) {
        if (*ptr == '/')
            *ptr = '_';
        ptr++;
    }

    return name;
}

/*
 * Since we blank out cookies, they're stashed in the notes table.
 * blank_cookie only stashes in the topmost request's notes table, so
 * that's where we'll look.
 *
 * We don't bother with using the topmost request when playing with the
 * headers because only the pointer is copied, anyway.
 */
char *get_cookie (request_rec * r, char *name, int n)
{
    const char *cookie_header;
    char *chp;
    char *cookie, *ptr;
    request_rec *mr = top_rrec (r);
    char *name_w_eq;
    pool *p = r->pool;
    pubcookie_server_rec *scfg;
    int i;

    scfg =
        (pubcookie_server_rec *) ap_get_module_config (r->server->
                                                       module_config,
                                                       &pubcookie_module);

    ap_log_rerror (PC_LOG_DEBUG, r, "get_cookie: %s (%d)", name, n);

    /* get cookies */
    if ((n==0) && (cookie_header = ap_table_get (mr->notes, name))&&(*cookie_header)) {
        ap_log_rerror (PC_LOG_DEBUG, r, " .. by cache: %s", cookie_header);
        return ap_pstrdup (p, cookie_header);
    }
    if (!(cookie_header = ap_table_get (r->headers_in, "Cookie")))
        return NULL;

    /* add an equal on the end */
    name_w_eq = ap_pstrcat (p, name, "=", NULL);

    /* find the one that's pubcookie */
    for (chp=(char*)cookie_header,i=0;i<=n;i++) {
       if (!(chp = strstr(chp, name_w_eq))) return NULL;
       chp += strlen (name_w_eq);
    }

    cookie = ap_pstrdup (p, chp);

    ptr = cookie;
    while (*ptr) {
        if (*ptr == ';')
            *ptr = 0;
        ptr++;
    }

    /* cache and blank cookie */
    ptr = ap_pstrdup (mr->pool, cookie);
    ap_table_set (mr->notes, name, ptr);

    if (!scfg->noblank) {
       for (ptr=chp; *ptr&&*ptr!=';'; ptr++) *ptr = PBC_X_CHAR;
       ap_table_set (r->headers_in, "Cookie", cookie_header);
    }

    if (*cookie) {
        ap_log_rerror (PC_LOG_DEBUG, r, " .. return: %s", cookie);
        return cookie;
    }
    return (NULL);

}

#ifdef APACHE2
#define AP2LZ 0,
#else
#define AP2LZ
#endif
static void mylog (pool * p, int logging_level, const char *msg)
{
    int apri = APLOG_INFO;
    server_rec *s;
    request_rec *r;

    /* convert pubcookie error level to apache error level */

    if (logging_level == PBC_LOG_ERROR)
        apri = APLOG_ERR | APLOG_NOERRNO;
    else if (logging_level == PBC_LOG_DEBUG_LOW ||
             logging_level == PBC_LOG_DEBUG_VERBOSE ||
             logging_level == PBC_LOG_DEBUG_OUTPUT)
        apri = APLOG_DEBUG | APLOG_NOERRNO;

    /* log as request if we can, else server, else pool */

    if (r = find_request_from_pool (p)) {
        ap_log_rerror (APLOG_MARK, apri, AP2LZ r, "%s", msg);
    } else if (s = find_server_from_pool (p)) {
        ap_log_error (APLOG_MARK, apri, AP2LZ s, "%s", msg);
#ifdef APACHE2
    } else {
        ap_log_perror (APLOG_MARK, apri, AP2LZ p, "%s", msg);
#endif
    }
}


/* Initialize after config file commands have been processed */

#ifdef APACHE2
#define PC_INIT_FAIL return HTTP_INTERNAL_SERVER_ERROR
#define PC_INIT_OK   return OK
static int pubcookie_init (pool * pconf, pool * plog, pool * ptemp,
                           server_rec * main_s)
#else /* apache 2 */
#define PC_INIT_FAIL exit (1);
#define PC_INIT_OK   return
static void pubcookie_init (server_rec * main_s, pool * pconf)
#endif
{
    server_rec *s;
    pubcookie_server_rec *scfg;
    pool *p = pconf;

#ifdef APACHE1_3
    current_server_rec = main_s;
#else
    apr_pool_userdata_setn (main_s, PBC_SERVER_REC_KEY, NULL, p);
#endif
    ap_log_error (PC_LOG_DEBUG, main_s, "pubcookie_init: hello");

    pbc_configure_init (p, "mod_pubcookie",
                        NULL,
                        NULL,
                        &libpbc_apacheconfig_getint,
                        &libpbc_apacheconfig_getlist,
                        &libpbc_apacheconfig_getstring,
                        &libpbc_apacheconfig_getswitch);

    pbc_log_init (p, "mod_pubcookie", NULL, &mylog, NULL, NULL);

    ap_add_version_component (
#ifdef APACHE2
                                 p,
#endif
                                 ap_pstrcat (p, "mod_pubcookie/",
                                             PBC_VERSION_STRING, NULL));

    /* initialize each virtual server */

    for (s = main_s; s != NULL; s = s->next) {

#ifdef APACHE1_3
        current_server_rec = s;
#else
        apr_pool_userdata_setn (s, PBC_SERVER_REC_KEY, NULL, p);
#endif
        scfg =
            (pubcookie_server_rec *) ap_get_module_config (s->
                                                           module_config,
                                                           &pubcookie_module);
        /* bail if PubcookieAuthTypes not set */
        if (scfg->authtype_names == NULL) {
            ap_log_error (PC_LOG_EMERG, s,
                          "PubCookieAuthTypeNames configuration directive must be set!");
            PC_INIT_FAIL;
        }

        if (ap_table_get (scfg->configlist, "ssl_key_file") == NULL) {
            ap_log_error (PC_LOG_EMERG, s,
                          "PubCookieSessionKeyFile configuration directive must be set!");
            PC_INIT_FAIL;
        }
        if (ap_table_get (scfg->configlist, "ssl_cert_file") == NULL) {
            ap_log_error (PC_LOG_EMERG, s,
                          "PubCookieSessionCertFile configuration directive must be set!");
            PC_INIT_FAIL;
        }

        if (ap_table_get (scfg->configlist, "granting_cert_file") == NULL) {
            ap_log_error (PC_LOG_EMERG, s,
                          "PubCookieGrantingCertFile configuration directive not set, using %s/%s",
                          PBC_KEY_DIR, "pubcookie_granting.cert");
        }

        /* libpubcookie initialization */
        ap_log_error (PC_LOG_DEBUG, s, "pubcookie_init: libpbc");
        if ( libpbc_pubcookie_init (p, &scfg->sectext) != PBC_OK ) {
            ap_log_error (PC_LOG_EMERG, s,
                          "pubcookie_init: libpbc_pubcookie_init failed.");
            PC_INIT_FAIL;
        }

        if (!scfg->login) {
            /* if the user didn't explicitly configure a login server,
               let's default to PBC_LOGIN_URI */
            scfg->login = ap_pstrcat (p, PBC_LOGIN_URI, NULL);
            ap_log_error (PC_LOG_DEBUG, s,
                          "pubcookie_init(): login from PBC_LOGIN_URI: %s",
                          scfg->login);
        }

        if (!scfg->post_reply_url)
            scfg->post_reply_url = "PubCookie.reply";

        if (!scfg->crypt_alg)
            scfg->crypt_alg = PBC_DEF_CRYPT;


    }                           /* end of per-server loop */

#ifdef APACHE2
    /* Get mod_ssl's var finder */
    lookup_ssl_var = APR_RETRIEVE_OPTIONAL_FN (ssl_var_lookup);
#endif

    ap_log_error (PC_LOG_DEBUG, s, "pubcookie_init: bye");
    PC_INIT_OK;

}

/*                                                                            */
static void *pubcookie_server_create (pool * p, server_rec * s)
{
    pubcookie_server_rec *scfg;
    scfg =
        (pubcookie_server_rec *) ap_pcalloc (p,
                                             sizeof
                                             (pubcookie_server_rec));

    scfg->configlist = ap_make_table (p, CONFIGLISTGROWSIZE);
    scfg->dirdepth = PBC_DEFAULT_DIRDEPTH;
    scfg->authtype_names = NULL;
    scfg->use_post = 0;
    scfg->post_reply_url = NULL;
    scfg->crypt_alg = 0;

    return (void *) scfg;
}

/*                                                                            */
static void *pubcookie_dir_create (pool * p, char *dirspec)
{
    pubcookie_dir_rec *cfg;
    cfg = (pubcookie_dir_rec *) ap_pcalloc (p, sizeof (pubcookie_dir_rec));

    cfg->inact_exp = PBC_UNSET_INACT_EXPIRE;
    cfg->hard_exp = PBC_UNSET_HARD_EXPIRE;
    cfg->session_reauth = PBC_UNSET_SESSION_REAUTH;
    cfg->addl_requests = NULL;

    return (void *) cfg;

}

/*                                                                            */
static void *pubcookie_server_merge (pool * p, void *parent, void *newloc)
{
    pubcookie_server_rec *scfg;
    pubcookie_server_rec *pscfg = (pubcookie_server_rec *) parent;
    pubcookie_server_rec *nscfg = (pubcookie_server_rec *) newloc;

    scfg =
        (pubcookie_server_rec *) ap_pcalloc (p,
                                             sizeof
                                             (pubcookie_server_rec));

    scfg->login = (nscfg->login != NULL) ? nscfg->login : pscfg->login;
    scfg->appsrvid = (nscfg->appsrvid != NULL) ?
        nscfg->appsrvid : pscfg->appsrvid;
    scfg->dirdepth = nscfg->dirdepth ? nscfg->dirdepth : pscfg->dirdepth;
    scfg->noblank = nscfg->noblank ? nscfg->noblank : pscfg->noblank;
    /* the following added by ddj@cmu.edu on 2006/05/01 */
    scfg->catenate = nscfg->catenate ? nscfg->catenate : pscfg->catenate;
    scfg->no_clean_creds =
        nscfg->no_clean_creds ? nscfg->no_clean_creds : pscfg->no_clean_creds;
    scfg->authtype_names = nscfg->authtype_names ?
        nscfg->authtype_names : pscfg->authtype_names;
    scfg->use_post = nscfg->use_post ? nscfg->use_post : pscfg->use_post;
    scfg->post_reply_url = nscfg->post_reply_url ?
        nscfg->post_reply_url : pscfg->post_reply_url;
    scfg->configlist = ap_overlay_tables (p, nscfg->configlist,
                                          pscfg->configlist);
    scfg->crypt_alg =
        nscfg->crypt_alg ? nscfg->crypt_alg : pscfg->crypt_alg;

    return (void *) scfg;
}

/*                                                                            */
static void *pubcookie_dir_merge (pool * p, void *parent, void *newloc)
{
    pubcookie_dir_rec *cfg;
    pubcookie_dir_rec *pcfg = (pubcookie_dir_rec *) parent;
    pubcookie_dir_rec *ncfg = (pubcookie_dir_rec *) newloc;

    cfg = (pubcookie_dir_rec *) ap_pcalloc (p, sizeof (pubcookie_dir_rec));

    cfg->inact_exp = (ncfg->inact_exp == PBC_UNSET_INACT_EXPIRE)
        ? pcfg->inact_exp : ncfg->inact_exp;
    cfg->hard_exp = (ncfg->hard_exp == PBC_UNSET_HARD_EXPIRE)
        ? pcfg->hard_exp : ncfg->hard_exp;

    cfg->session_reauth =
        (ncfg->session_reauth == PBC_UNSET_SESSION_REAUTH)
        ? pcfg->session_reauth : ncfg->session_reauth;

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
    if (pcfg->appid) {
      /* Yes.  Did the parent also have an *old* app ID? */
      if (pcfg->oldappid) {
	/* Yes.  Glue them together and store as "old app ID". */
	cfg->oldappid = (unsigned char *) ap_pstrcat(p, pcfg->oldappid, pcfg->appid, NULL);
      } else {
	/* No.  The parent's app ID is now the "old app ID". */
	cfg->oldappid = pcfg->appid;
      }
    }

    /* life is much easier if the default value is zero or NULL */
    cfg->appid = ncfg->appid ? ncfg->appid : pcfg->appid;

    cfg->end_session = ncfg->end_session ?
        ncfg->end_session : pcfg->end_session;

    if (pcfg->addl_requests) {
        if (ncfg->addl_requests) {
            cfg->addl_requests =
                (unsigned char *) ap_pstrcat (p, pcfg->addl_requests,
                                              ncfg->addl_requests, NULL);
        } else {
            cfg->addl_requests = pcfg->addl_requests;
        }
    } else {
        cfg->addl_requests = ncfg->addl_requests;
    }

    cfg->strip_realm = ncfg->strip_realm ?
        ncfg->strip_realm : pcfg->strip_realm;

    if (ncfg->accept_realms) {
        cfg->accept_realms = ap_pstrdup (p, ncfg->accept_realms);
    } else if (pcfg->accept_realms) {
        cfg->accept_realms = ap_pstrdup (p, pcfg->accept_realms);
    } else {
        cfg->accept_realms = NULL;
    }

    cfg->keydirs = ncfg->keydirs ?
        (pcfg->
         keydirs ? ap_overlay_tables (p, ncfg->keydirs,
                                      pcfg->keydirs) : ncfg->
         keydirs) : pcfg->keydirs;

    cfg->noprompt = ncfg->noprompt ? ncfg->noprompt : pcfg->noprompt;

    return (void *) cfg;

}

/* the bestest way to deal with default values for things that go thru the    */
/* create/merge gauntlet is to wait until you're ready to use them and then   */
/* see if they've been explicitly set                                         */
void pubcookie_dir_defaults (pubcookie_dir_rec * cfg)
{

    if (cfg->inact_exp == PBC_UNSET_INACT_EXPIRE)
        cfg->inact_exp = PBC_DEFAULT_INACT_EXPIRE;
    if (cfg->hard_exp == PBC_UNSET_HARD_EXPIRE)
        cfg->hard_exp = PBC_DEFAULT_HARD_EXPIRE;
}

/* when there is stuff in the server rec with non-zero defaults put them here */
void pubcookie_server_defaults (pubcookie_server_rec * scfg)
{

}

int get_pre_s_from_cookie (request_rec * r)
{
    pubcookie_dir_rec *cfg;
    pubcookie_server_rec *scfg;
    pbc_cookie_data *cookie_data = NULL;
    char *cookie = NULL;
    pool *p = r->pool;
    int ccnt = 0;

    cfg = (pubcookie_dir_rec *) ap_get_module_config (r->per_dir_config,
                                                      &pubcookie_module);
    scfg =
        (pubcookie_server_rec *) ap_get_module_config (r->server->
                                                       module_config,
                                                       &pubcookie_module);

    ap_log_rerror (PC_LOG_DEBUG, r, "retrieving a pre-session ckookie");
    while (cookie = get_cookie (r, PBC_PRE_S_COOKIENAME, ccnt)) {
        cookie_data = libpbc_unbundle_cookie (p, scfg->sectext,
                                              cookie, ME (r), 0,
                                              scfg->crypt_alg);
        if (cookie_data) break;
        ap_log_rerror (PC_LOG_INFO, r,
                       "get_pre_s_from_cookie: can't unbundle pre_s cookie uri: %s\n",
                       r->uri);
        ccnt++;
    }
    if (!cookie_data) {
        ap_log_rerror (PC_LOG_INFO, r,
                       "get_pre_s_from_cookie: no pre_s cookie, uri: %s\n",
                       r->uri);
        return (-1);
    }

    return ((*cookie_data).broken.pre_sess_token);

}

/* User authentication */

static int pubcookie_user_hook (request_rec * r)
{
    int s;
    pubcookie_server_rec *scfg;
    pubcookie_dir_rec *cfg;
    pubcookie_req_rec *rr;
    int first_time_in_session = 0;
    char creds;
    const char *ifms;

    scfg =
        (pubcookie_server_rec *) ap_get_module_config (r->server->
                                                       module_config,
                                                       &pubcookie_module);
    cfg =
        (pubcookie_dir_rec *) ap_get_module_config (r->per_dir_config,
                                                    &pubcookie_module);
    rr = (pubcookie_req_rec *) ap_get_module_config (r->request_config,
                                                     &pubcookie_module);

    ap_log_rerror (PC_LOG_DEBUG, r,
                   "pubcookie_user_hook: uri: %s auth_type: %s", r->uri,
                   ap_auth_type (r));

    if (!ap_auth_type (r))
        return DECLINED;

    /* pass if the request is for our post-reply */
    if (!strcasecmp (r->unparsed_uri + 1, scfg->post_reply_url))
        return OK;

    /* if it's basic auth then it's not pubcookie */
/*
    if( strcasecmp(ap_auth_type(r), "basic") == 0 ) return DECLINED;
 */

    /* get pubcookie creds or bail if not a pubcookie auth_type */
    if ((creds = pubcookie_auth_type (r)) == PBC_CREDS_NONE)
        return DECLINED;

    /* pass if the request is for favicon.ico */
    if (!strncasecmp (r->unparsed_uri, "/favicon.ico", 12))
        return OK;


    /* If this is a subrequest we either already have a user or we don't. */
    if (!rr) {
        request_rec *mr = r->main;
        ap_log_rerror (PC_LOG_DEBUG, r, "  .. user_hook: sub: %x, user=%s",
                       mr, mr ? mr->USER : "");
        if (mr && mr->USER && *mr->USER) {
#ifdef APACHE2
            /* AP2 keeps user in request rec, AP13 in the shared conn rec */
            /* r->AUTH_TYPE = ap_pstrdup(r->pool, mr->AUTH_TYPE); */
            r->USER = ap_pstrdup (r->pool, mr->USER);
#endif
            return OK;
        }
        if (cfg->noprompt>0) {
            r->USER = ap_pstrdup (r->pool, "");
            return OK;
        }
        return HTTP_UNAUTHORIZED;
    }

    rr->creds = creds;
    s = pubcookie_user (r, scfg, cfg, rr);
    if (rr->failed) {
        ap_log_rerror (PC_LOG_DEBUG, r, " .. user_hook: user failed");
        if (rr->failed == PBC_BAD_G_STATE) {
            ap_log_rerror (PC_LOG_DEBUG, r,
                           " .. user_hook: Can't use Granting cookie");
            stop_the_show (r, scfg, cfg, rr);
            return DONE;
        } else if (rr->failed == PBC_BAD_USER) {
            ap_log_rerror (PC_LOG_DEBUG, r, " .. user_hook: bad user");
            r->content_type = CONTENT_TYPE;
            flush_headers (r);
            ap_rprintf (r, "Unauthorized user.");
            return DONE;
        }
        auth_failed_handler (r, scfg, cfg, rr);
        return DONE;
    }
    ap_log_rerror (PC_LOG_DEBUG, r, " .. user_hook: user '%s'OK", r->USER);

    if (rr->has_granting) {
        ap_log_rerror (PC_LOG_DEBUG, r, " .. user_hook: new session");
        first_time_in_session = 1;
        rr->has_granting = 0;
    }

    if (check_end_session (r) & PBC_END_SESSION_REDIR) {
        do_end_session_redirect (r, scfg, cfg);
        return DONE;
    } else if (check_end_session (r) & PBC_END_SESSION_ANY) {
        clear_session_cookie (r);
        r->USER = "";           /* rest of apache needs a user if there's an authtype */
    } else if (cfg->inact_exp > 0 || first_time_in_session) {
        if ((!first_time_in_session) && (!rr->cookie_data)) {
            ap_log_rerror (PC_LOG_DEBUG, r,
                           " .. user_hook: not first and no data! (sub?)");
        } else
            set_session_cookie (r, scfg, cfg, rr, first_time_in_session);
    }

    /* Since we've done something any "if-modified"s must be cancelled
       to prevent "not modified" responses.  There may be other "if"s
       (see: http_protocol.c:ap_meets_conditions) that we are not
       considering as they have not yet come up. */

    ifms = ap_table_get (r->headers_in, "If-Modified-Since");
    if (ifms) {
        ap_log_rerror (PC_LOG_DEBUG, r, " .. user_hook: removing if-modified = %s", ifms);
        ap_table_unset(r->headers_in, "If-Modified-Since");
    }

    ap_log_rerror (PC_LOG_DEBUG, r,
                   " .. user_hook exit: user '%s', type '%s'", r->USER,
                   r->AUTH_TYPE);
    
    return (s);
}

/* Check user id                                                              */
int pubcookie_user (request_rec * r, pubcookie_server_rec * scfg,
                    pubcookie_dir_rec * cfg, pubcookie_req_rec * rr)
{
    char *cookie;
    char *isssl = NULL;
    pbc_cookie_data *cookie_data;
    pool *p = r->pool;
    char *sess_cookie_name;
    char *new_cookie = ap_palloc (p, PBC_1K);
    int cred_from_trans;
    int pre_sess_from_cookie;
    int gcnt = 0;
    int scnt = 0;

    /* get defaults for unset args */
    pubcookie_dir_defaults (cfg);
    pubcookie_server_defaults (scfg);

    ap_log_rerror (PC_LOG_DEBUG, r,
                   "pubcookie_user: going to check uri: %s creds: %c",
                   r->uri, rr->creds);

    /* maybe dump the directory and server recs */
    dump_server_rec (r, scfg);
    dump_dir_rec (r, cfg);

    sess_cookie_name =
        make_session_cookie_name (p, PBC_S_COOKIENAME, appid (r));

    /* force SSL */

#ifdef APACHE2
    if (lookup_ssl_var) {
        char *s = NULL;
        /* 'lookup_ssl_var' doesn't work until 2.0.49. Assume ssl before then */
        if (atoi (AP_SERVER_MINORVERSION AP_SERVER_PATCHLEVEL) < 49)
            isssl = "on";
        else {
            s = lookup_ssl_var (p, r->server, r->connection, r, "HTTPS");
            ap_log_rerror (PC_LOG_DEBUG, r,
                           "pubcookie_user: have ssl_var: %s", s);
            if (!strcmp (s, "on"))
                isssl = "on";
        }
    }
    if (!isssl)
#else /* apache 1.3 */
    if (ap_hook_call ("ap::mod_ssl::var_lookup", &isssl, p, r->server,
                      r->connection, r, "HTTPS") && isssl
        && strcmp (isssl, "on"))
#endif
    {

        ap_log_rerror (PC_LOG_DEBUG, r,
                       "Not SSL; uri: %s appid: %s", r->uri, appid (r));
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_NOGORS_CODE;
        return OK;
    }

    /* before we check if they hav a valid S or G cookie see if it's a logout */
    if (check_end_session (r) & PBC_END_SESSION_ANY) {
        return OK;
    }

    ap_log_rerror (PC_LOG_DEBUG, r,
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
    while ((cookie = get_cookie (r, PBC_G_COOKIENAME, gcnt))
        && (scfg->use_post || get_cookie (r, PBC_PRE_S_COOKIENAME, 0))) {
        cookie_data =
            libpbc_unbundle_cookie (p, scfg->sectext, cookie,
                                    ap_get_server_name (r), 1,
                                    scfg->crypt_alg);
        if (cookie_data) break;
        ap_log_rerror (PC_LOG_INFO, r,
                       "can't unbundle G cookie, it's probably not for us; uri: %s\n",
                       r->uri);
        gcnt++;
        clear_granting_cookie (r);
    }

    /* If no valid granting cookie, check session cookie  */
    if (!cookie_data || strncasecmp ((const char *) appid (r),
                                     (const char *) cookie_data->broken.
                                     appid,
                                     sizeof (cookie_data->broken.appid) -
                                     1) != 0) {
        char *ckfix;
        while (cookie = get_cookie (r, sess_cookie_name, scnt)) {
            cookie_data =
                libpbc_unbundle_cookie (p, scfg->sectext, cookie, ME(r), 0,
                                        scfg->crypt_alg);

            if (cookie_data) break;

            /* try 'fixing' the cookie */
            ap_log_rerror (PC_LOG_INFO, r,
                           "retring failed unbundle of S cookie; uri: %s\n",
                           r->uri);
            ckfix = ap_pstrcat(p, cookie, "==");
            cookie_data = libpbc_unbundle_cookie (p, scfg->sectext, ckfix, ME(r), 0,
                                        scfg->crypt_alg);
            if (cookie_data) break;

            ap_log_rerror (PC_LOG_INFO, r,
                           "still can't unbundle S cookie; uri: %s\n",
                           r->uri);
            scnt++;
        }

        if (cookie_data) {

            rr->cookie_data = cookie_data;

            /* we tell everyone what authentication check we did */
            r->AUTH_TYPE = ap_pstrdup (p, ap_auth_type (r));
            r->USER = ap_pstrdup (p, (char *) (*cookie_data).broken.user);

            /* save the full user/realm for later */
            rr->user = ap_pstrdup (p, (char *) (*cookie_data).broken.user);

            /* check for acceptable realms and strip realm */
            if ((cfg->strip_realm == 1) || (cfg->accept_realms != NULL)) {
                char *tmprealm, *tmpuser;
                tmpuser =
                    ap_pstrdup (p, (char *) (*cookie_data).broken.user);
                tmprealm = index (tmpuser, '@');
                if (tmprealm) {
                    tmprealm[0] = 0;
                    tmprealm++;
                    ap_table_set (r->subprocess_env, "REMOTE_REALM",
                                  tmprealm);
                }

                if (cfg->strip_realm == 1) {
                    r->USER = tmpuser;
                } else {
                    r->USER =
                        ap_pstrdup (p,
                                    (char *) (*cookie_data).broken.user);
                }

                if (cfg->accept_realms != NULL) {
                    int realmmatched = 0;
                    char *thisrealm;
                    char *okrealms = ap_pstrdup (p, cfg->accept_realms);

                    if (tmprealm == NULL) {
                        /* no realm to check !?!? */
                        ap_log_rerror (PC_LOG_ERR, r,
                                       "no realm in userid: %s returning UNAUTHORIZED",
                                       (char *) (*cookie_data).broken.
                                       user);
                        return HTTP_UNAUTHORIZED;
                    }

                    while (*okrealms && !realmmatched &&
                           (thisrealm =
                            ap_getword_white_nc (p, &okrealms))) {
                        if (strcmp (thisrealm, tmprealm) == 0) {
                            realmmatched++;
                        }
                    }
                    if (realmmatched == 0) {
                        return HTTP_UNAUTHORIZED;
                    }
                }
            }

            if (libpbc_check_exp
                (p, (*cookie_data).broken.create_ts,
                 cfg->hard_exp) == PBC_FAIL) {
                ap_log_rerror (PC_LOG_INFO, r,
                               "S cookie hard expired; user: %s cookie timestamp: %d timeout: %d now: %d uri: %s\n",
                               (*cookie_data).broken.user,
                               (*cookie_data).broken.create_ts,
                               cfg->hard_exp, pbc_time (NULL), r->uri);
                rr->failed = PBC_BAD_AUTH;
                rr->redir_reason_no = PBC_RR_SHARDEX_CODE;
                return OK;
            }

            if (cfg->inact_exp != -1 &&
                libpbc_check_exp (p, (*cookie_data).broken.last_ts,
                                  cfg->inact_exp) == PBC_FAIL) {
                ap_log_rerror (PC_LOG_INFO, r,
                               "S cookie inact expired; user: %s cookie timestamp %d timeout: %d now: %d uri: %s\n",
                               (*cookie_data).broken.user,
                               (*cookie_data).broken.last_ts,
                               cfg->inact_exp, pbc_time (NULL), r->uri);
                rr->failed = PBC_BAD_AUTH;
                rr->redir_reason_no = PBC_RR_SINAEX_CODE;
                return OK;
            }

            ap_log_rerror (PC_LOG_INFO, r,
                           "S cookie chk reauth=%d, tok=%d",
                           cfg->session_reauth,
                           (*cookie_data).broken.pre_sess_token);
            if ((cfg->session_reauth >= 0)
                && ((*cookie_data).broken.pre_sess_token == 23)) {
                ap_log_rerror (PC_LOG_INFO, r,
                               "S cookie new force reauth");
                rr->failed = PBC_BAD_AUTH;
                rr->redir_reason_no = PBC_RR_NEW_REAUTH;
                return OK;
            }

            /* Check if we're switching from noprompt to prompt */
            ap_log_rerror (PC_LOG_INFO, r,
                           "S cookie chk nop: user=%s, nop=%d", r->USER,
                           cfg->noprompt);
            if ((cfg->noprompt <= 0) && !*r->USER) {
                ap_log_rerror (PC_LOG_INFO, r,
                               "S cookie noprompt to prompt");
                rr->failed = PBC_BAD_AUTH;
                rr->redir_reason_no = PBC_RR_NOGORS_CODE;
                return OK;
            }

        } else {                /* hav S cookie */

            ap_log_rerror (PC_LOG_DEBUG, r,
                           "No G or S cookie; uri: %s appid: %s sess_cookie_name: %s",
                           r->uri, appid (r), sess_cookie_name);
            rr->failed = PBC_BAD_AUTH;
            rr->redir_reason_no = PBC_RR_NOGORS_CODE;
            return OK;

        }                       /* end if session cookie */

    } else {

        rr->has_granting = 1;

        clear_granting_cookie (r);
        if (!scfg->use_post)
            clear_pre_session_cookie (r);

        ap_log_rerror (PC_LOG_DEBUG, r,
                       "pubcookie_user: has granting; current uri is: %s",
                       r->uri);

        /* If GET, check pre_session cookie */
        if (!scfg->use_post) {
            pre_sess_from_cookie = get_pre_s_from_cookie (r);
            ap_log_rerror (PC_LOG_DEBUG, r,
                           "pubcookie_user: ret from get_pre_s_from_cookie");
            if ((*cookie_data).broken.pre_sess_token !=
                pre_sess_from_cookie) {
                ap_log_rerror (PC_LOG_INFO, r,
                               "pubcookie_user, pre session tokens mismatched, uri: %s",
                               r->uri);
                ap_log_rerror (PC_LOG_DEBUG, r,
                               "pubcookie_user, pre session from G: %d PRE_S: %d, uri: %s",
                               (*cookie_data).broken.pre_sess_token,
                               pre_sess_from_cookie, r->uri);
                rr->failed = PBC_BAD_AUTH;
                rr->stop_message =
                    ap_psprintf (p,
                                 "Couldn't decode pre-session cookie. (from G: %d from PRE_S: %d)",
                                 (*cookie_data).broken.pre_sess_token,
                                 pre_sess_from_cookie);
                rr->redir_reason_no = PBC_RR_BADPRES_CODE;
                return OK;
            }
        }

        /* the granting cookie gets blanked too early and another login */
        /* server loop is required, this just speeds up that loop */
        if (strncmp (cookie, PBC_X_STRING, PBC_XS_IN_X_STRING) == 0) {
            ap_log_rerror (PC_LOG_DEBUG, r,
                           "pubcookie_user: 'speed up that loop' logic; uri is: %s\n",
                           r->uri);

            rr->failed = PBC_BAD_AUTH;
            rr->redir_reason_no = PBC_RR_DUMMYLP_CODE;
            return OK;
        }

        r->AUTH_TYPE = ap_pstrdup (p, ap_auth_type (r));
        r->USER = ap_pstrdup (p, (char *) (*cookie_data).broken.user);

        /* Make sure we really got a user (unless noprompt) */
        if ((!*r->USER) && (cfg->noprompt<=0)) {
            ap_log_rerror (PC_LOG_INFO, r,
                               "No user and not a noprompt");
            rr->stop_message = ap_pstrdup (p, "Required user login didn't happen");
            rr->failed = PBC_BAD_G_STATE;
            return (DONE);
        }

        ap_log_rerror (PC_LOG_DEBUG, r,
                       "pubcookie_user: set type (%s) and user (%s)",
                       r->AUTH_TYPE, r->USER);

        /* save the full user/realm for later */
        rr->user = ap_pstrdup (p, (char *) (*cookie_data).broken.user);

        /* check for acceptable realms and strip realm */
        if (*rr->user) {
            char *tmprealm, *tmpuser;
            tmpuser = ap_pstrdup (p, (char *) (*cookie_data).broken.user);
            tmprealm = index (tmpuser, '@');
            if (tmprealm) {
                tmprealm[0] = 0;
                tmprealm++;
                ap_table_set (r->subprocess_env, "REMOTE_REALM", tmprealm);
            }

            if (cfg->strip_realm == 1) {
                r->USER = tmpuser;
            } else {
                r->USER =
                    ap_pstrdup (p, (char *) (*cookie_data).broken.user);
            }

            if (cfg->accept_realms != NULL) {
                int realmmatched = 0;
                char *thisrealm;
                char *okrealms = ap_pstrdup (p, cfg->accept_realms);
                while (*okrealms && !realmmatched &&
                       (thisrealm = ap_getword_white_nc (p, &okrealms))) {
                    if (strcmp (thisrealm, tmprealm) == 0) {
                        realmmatched++;
                    }
                }
                if (realmmatched == 0) {
                    return HTTP_UNAUTHORIZED;
                }
            }
        }

        /* make sure force reauth requests actually get a reauth */
        if ( cfg->session_reauth > 0 
             && (*cookie_data).broken.version[3] == PBC_VERSION_REAUTH_NO ) {
        
            ap_log_rerror (PC_LOG_INFO, r,
                               "Force reauth didn't get a re-auth: %c", (*cookie_data).broken.version[3]);
            /* Send out bad session_reauth error */
            rr->stop_message = ap_pstrdup (p, "Required Session Reauthentication didn't happen");
            rr->failed = PBC_BAD_G_STATE;
            return (DONE);
        }

        if (libpbc_check_exp
            (p, (*cookie_data).broken.create_ts,
             PBC_GRANTING_EXPIRE) == PBC_FAIL) {
            ap_log_rerror (PC_LOG_INFO, r,
                           "pubcookie_user: G cookie expired by %ld; user: %s create: %ld uri: %s",
                           pbc_time (NULL) - (*cookie_data).broken.create_ts -
                           PBC_GRANTING_EXPIRE, (*cookie_data).broken.user,
                           (*cookie_data).broken.create_ts, r->uri);
            rr->failed = PBC_BAD_AUTH;
            rr->redir_reason_no = PBC_RR_GEXP_CODE;
            return OK;
        }

    }

    /* check appid */
    if (strncasecmp ((const char *) appid (r),
                     (const char *) (*cookie_data).broken.appid,
                     sizeof ((*cookie_data).broken.appid) - 1) != 0) {
        ap_log_rerror (PC_LOG_INFO, r,
                       "pubcookie_user: wrong appid; current: %s cookie: %s uri: %s",
                       appid (r), (*cookie_data).broken.appid, r->uri);
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_WRONGAPPID_CODE;
        return OK;
    }

    /* check appsrv id */
    if (strncasecmp ((const char *) appsrvid (r),
                     (const char *) (*cookie_data).broken.appsrvid,
                     sizeof ((*cookie_data).broken.appsrvid) - 1) != 0) {
        ap_log_rerror (PC_LOG_INFO, r,
                       "pubcookie_user: wrong app server id; current: %s cookie: %s uri: %s",
                       appsrvid (r), (*cookie_data).broken.appsrvid,
                       r->uri);
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_WRONGAPPSRVID_CODE;
        return OK;
    }

    /* check version id */
    if (libpbc_check_version (p, cookie_data) == PBC_FAIL) {
        ap_log_rerror (PC_LOG_INFO, r,
                       "pubcookie_user: wrong version id; module: %d cookie: %d uri: %s",
                       PBC_VERSION, (*cookie_data).broken.version);
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_WRONGVER_CODE;
        return OK;
    }

    /* check creds */
    if (rr->creds != cookie_data->broken.creds) {
        ap_log_rerror (PC_LOG_INFO, r,
                       "pubcookie_user: wrong creds; required: %c cookie: %c uri: %s",
                       rr->creds, (*cookie_data).broken.creds, r->uri);
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_WRONGCREDS_CODE;
        return OK;
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
        char *blob = ap_palloc (p, strlen (cookie));
        int bloblen;
        char *plain = NULL;
        int plainlen;
        char *krb5ccname;
#ifdef APACHE2
        apr_file_t *f = NULL;
        apr_size_t nb;
#else
        FILE *f = NULL;
#endif
        int res = 0;

        /* base64 decode cookie */
        if (!libpbc_base64_decode (p, (unsigned char *) cookie,
                                   (unsigned char *) blob, &bloblen)) {
            ap_log_rerror (PC_LOG_ERR, r,
                           "credtrans: libpbc_base64_decode() failed");
            res = -1;
        }

        /* decrypt cookie. if credtrans is set, then it's from login server
           to me. otherwise it's from me to me. */
        if (!res && libpbc_rd_priv (p, scfg->sectext, cred_from_trans ?
                                    ap_get_server_name (r) : NULL,
                                    cred_from_trans ? 1 : 0,
                                    blob, bloblen, &plain, &plainlen,
                                    scfg->crypt_alg)) {
            ap_log_rerror (PC_LOG_ERR, r,
                           "credtrans: libpbc_rd_priv() failed");
            res = -1;
        }

        if (!res && plain) {
            /* sigh, copy it into the memory pool */
            rr->cred_transfer = ap_palloc (p, plainlen);
            memcpy (rr->cred_transfer, plain, plainlen);
            rr->cred_transfer_len = plainlen;
        }

        /* set a random KRB5CCNAME */
        krb5ccname =
            ap_psprintf (p, "/tmp/k5cc_%d_%s", getpid (), rr->user);
        if (!res) {
            /* save these creds in that file */
#ifdef APACHE2
            apr_file_open (&f, krb5ccname,
                           APR_CREATE | APR_WRITE | APR_TRUNCATE,
                           APR_UREAD | APR_UWRITE | APR_GREAD, p);
#else
            f = ap_pfopen (p, krb5ccname, "w");
            chmod (krb5ccname, S_IRUSR | S_IWUSR);
#endif
            if (!f) {
                ap_log_rerror (PC_LOG_ERR, r,
                               "credtrans: setenv() failed");
                res = -1;
            }
        }
        if (!res &&
#ifdef APACHE2
            (nb = rr->cred_transfer_len,
             apr_file_write (f, rr->cred_transfer, &nb) != APR_SUCCESS)
#else
            (fwrite (rr->cred_transfer, rr->cred_transfer_len, 1, f) != 1)
#endif
            ) {
            ap_log_rerror (PC_LOG_ERR, r, "credtrans: setenv() failed");
            res = -1;
        }

        if (f) {
#ifdef APACHE2
            apr_file_close (f);
#else
            ap_pfclose (p, f);
#endif
        }

        if (cred_from_trans) {
            clear_transfer_cookie (r);
        }
    }

    ap_log_rerror (PC_LOG_DEBUG, r,
                   "pubcookie_user: everything is o'tay; current uri is: %s",
                   r->uri);

    return OK;

}

/* Check authz */

static int pubcookie_authz_hook (request_rec * r)
{
    int s;
    pubcookie_server_rec *scfg;
    pubcookie_dir_rec *cfg;

    scfg =
        (pubcookie_server_rec *) ap_get_module_config (r->server->
                                                       module_config,
                                                       &pubcookie_module);
    cfg =
        (pubcookie_dir_rec *) ap_get_module_config (r->per_dir_config,
                                                    &pubcookie_module);

    if (!ap_auth_type (r))
        return DECLINED;

    /* get pubcookie creds or bail if not a pubcookie auth_type */
    if (pubcookie_auth_type (r) == PBC_CREDS_NONE)
        return DECLINED;

    /* pass if the request is for favicon.ico */
    if (!strncasecmp (r->unparsed_uri, "/favicon.ico", 12))
        return OK;

    /* pass if the request is our post-reply */
    if (!strcasecmp (r->unparsed_uri + 1, scfg->post_reply_url))
        return OK;

    /* a failed noprompt login is all we check for */
    if ((!*r->USER) && (cfg->noprompt > 0)) {
        ap_log_rerror (PC_LOG_DEBUG, r,
                       "pubcookie_authz: is a nouser noprompt");
        return OK;
    }

    return (DECLINED);
}


/* Set any additional environment variables for the client */
static int pubcookie_fixups (request_rec * r)
{
    pubcookie_dir_rec *cfg;
    pubcookie_req_rec *rr;
    table *e = r->subprocess_env;
    pool *p = r->pool;

    cfg = (pubcookie_dir_rec *) ap_get_module_config (r->per_dir_config,
                                                      &pubcookie_module);
    rr = (pubcookie_req_rec *) ap_get_module_config (r->request_config,
                                                     &pubcookie_module);

    if (!rr)
        return OK;              /* subrequest */

    if (rr->cred_transfer) {
        char *krb5ccname =
            ap_psprintf (p, "/tmp/k5cc_%d_%s", (int) getpid (),
                         rr->user);

        ap_table_setn (e, "KRB5CCNAME", krb5ccname);
    }

    /* Clear the null user from noprompt */
    if ((rr->creds != PBC_CREDS_NONE) && r->USER && !*r->USER) {
        ap_log_rerror (PC_LOG_DEBUG, r, "pubcookie_fixup: clear authtype");
        r->AUTH_TYPE = NULL;
        r->USER = NULL;
    }

    return OK;
}

/* See if we should augment the directives */

static int pubcookie_hparse (request_rec * r)
{
    char *cookies;
    char *nextcookie;
    pool *p = r->pool;

    ap_log_rerror (PC_LOG_DEBUG, r, "pubcookie_hparse: main=%x", r->main);

    if (!(cookies = (char *) ap_table_get (r->headers_in, "Cookie")))
        return OK;
    cookies = ap_pstrdup (p, cookies);

    nextcookie = cookies;
    while (nextcookie) {
        char *c = nextcookie;

        nextcookie = strchr (c, ';');
        if (nextcookie != 0) {
            *nextcookie++ = '\0';
            while (*nextcookie && *nextcookie == ' ')
                ++nextcookie;
        }

        /* Look for the directive key cookie */
        if (!strncasecmp (c, PBC_ODKEY_COOKIENAME,
                          sizeof (PBC_ODKEY_COOKIENAME) - 1)) {
            char *s = strchr (c, '=');
            int ret;
            if (s && (ret = load_keyed_directives (r, s + 1)))
                return (ret);
        }

    }

    return OK;
}

/* First look at a request. 
   Save the request record info
   Initialize the per-request config  */

static int pubcookie_post_read (request_rec * r)
{
    pubcookie_req_rec *rr =
        ap_pcalloc (r->pool, sizeof (pubcookie_req_rec));
    pubcookie_server_rec *scfg =
        (pubcookie_server_rec *) ap_get_module_config (r->server->
                                                       module_config,
                                                       &pubcookie_module);

    ap_log_rerror (PC_LOG_DEBUG, r,
                   "pubcookie_post_read: sr=%x", r->server);

#ifdef APACHE1_3
    current_request_rec = r;
    current_server_rec = r->server;
#else
    apr_pool_userdata_setn (r, PBC_REQUEST_REC_KEY, NULL, r->pool);
#endif

    ap_set_module_config (r->request_config, &pubcookie_module, rr);

    if (scfg->use_post && *r->uri == '/' &&
        !strcmp (r->uri + 1, scfg->post_reply_url)) {
        r->handler = "pubcookie-post-reply";
    }

#ifdef PBC_DEFERRED_HEADERS
    /* Add headers tables */
    rr->hdr_out = ap_make_table(r->pool, 5);
    rr->hdr_err = ap_make_table(r->pool, 5);

    /* If this is a forwarded request, copy our headers from the parent */

    if (r->prev) {
       int nprro;
       int nprre;
       pubcookie_req_rec *prr = (pubcookie_req_rec *) ap_get_module_config (r->prev->request_config,
                                                     &pubcookie_module);

       if (prr) {
          nprro = apr_table_elts(prr->hdr_out)->nelts;
          nprre = apr_table_elts(prr->hdr_err)->nelts;
          ap_log_rerror (PC_LOG_DEBUG, r, "pbc of: forwarding %d output headers to redirect request", nprro);
          if (nprro) append_to_table(r, rr->hdr_out, prr->hdr_out);
          ap_log_rerror (PC_LOG_DEBUG, r, "pbc of: forwarding %d error headers to redirect request", nprre);
          if (nprre) append_to_table(r, rr->hdr_err, prr->hdr_err);
       }
    }
#endif

    return DECLINED;
}

/*                                                                            */
static const char *pubcookie_set_inact_exp (cmd_parms * cmd, void *mconfig,
                                            const char *v)
{
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;
    char *err_string;

    if ((cfg->inact_exp = atoi (v)) < 0 && cfg->inact_exp != -1) {
        return
            "PUBCOOKIE: Could not convert inactivity expire parameter to nonnegative number.";
    }

    /* how to turn off inactivity checking */
    if (cfg->inact_exp == -1) {
        return NULL;
    }

    /* check for valid range */
    if (cfg->inact_exp < PBC_MIN_INACT_EXPIRE) {
        err_string =
            ap_psprintf (cmd->pool,
                         "PUBCOOKIE: inactivity expire parameter less then allowed minimum of %d, requested %d.",
                         PBC_MIN_INACT_EXPIRE, cfg->inact_exp);
        return (err_string);
    }

    return NULL;
}

/**
 *  handle the PubCookieHardExpire directive
 *  does some range checking
 */
const char *pubcookie_set_hard_exp (cmd_parms * cmd, void *mconfig,
                                    const char *v)
{
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;
    char *err_string;

    if ((cfg->hard_exp = atoi (v)) <= 0) {
        return
            ("PUBCOOKIE: PubcookieHardExpire should be nonnegative integer.");
    } else if (cfg->hard_exp > PBC_MAX_HARD_EXPIRE) {
        err_string =
            ap_psprintf (cmd->pool,
                         "PUBCOOKIE: Hard expire parameter greater then allowed maximium of %d, requested %d.",
                         PBC_MAX_HARD_EXPIRE, cfg->hard_exp);
        return (err_string);
    } else if (cfg->hard_exp < PBC_MIN_HARD_EXPIRE) {
        err_string =
            ap_psprintf (cmd->pool,
                         "PUBCOOKIE: Hard expire parameter less then allowed minimum of %d, requested %d.",
                         PBC_MIN_HARD_EXPIRE, cfg->hard_exp);
        return (err_string);
    }

    return NULL;
}

/**
 *  handle the PubCookieLogin directive
 *  we do a little checking to make sure the url is correctly formatted.
 */
const char *pubcookie_set_login (cmd_parms * cmd, void *mconfig,
                                 const char *v)
{
    server_rec *s = cmd->server;
    uri_components uptr;
    char *err_string;
    pubcookie_server_rec *scfg = (pubcookie_server_rec *)
        ap_get_module_config (s->module_config,
                              &pubcookie_module);

    if (ap_parse_uri_components (cmd->pool, v, &uptr) != APR_SUCCESS) {
        err_string =
            ap_psprintf (cmd->pool,
                         "PUBCOOKIE: PubCookieLogin not correctly formatted URL.");
        return (err_string);
    }
#ifdef PORT80_TEST
    if (uptr.scheme == NULL || strncmp (uptr.scheme, "http", 4) != 0) {
        err_string =
            ap_psprintf (cmd->pool,
                         "PUBCOOKIE: PubCookieLogin must start with http:// or https://");
        return (err_string);
    }
#else
    /* force ssl */
    if (uptr.scheme == NULL || strcmp (uptr.scheme, "https") != 0) {
        uptr.scheme = ap_pstrdup (cmd->pool, "https");
    }
#endif

    /* if the url has no path add a '/' */
    if (uptr.path == NULL)
        uptr.path = ap_pstrdup (cmd->pool, "/");

    scfg->login = ap_unparse_uri_components (cmd->pool, &uptr, 0);
    ap_table_set (scfg->configlist, "login_uri", (char *) &uptr);

    return NULL;
}

/**
 *  handle the PubCookieDomain directive
 */
const char *pubcookie_set_domain (cmd_parms * cmd, void *mconfig,
                                  const char *v)
{
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg = (pubcookie_server_rec *)
        ap_get_module_config (s->module_config,
                              &pubcookie_module);
    char *temp;

    if (*v != '.')
        temp = ap_pstrcat (cmd->pool, ".", v, NULL);
    else
        temp = ap_pstrdup (cmd->pool, v);

    ap_table_set (scfg->configlist, "enterprise_domain", temp);

    return NULL;
}

/**
 *  handle the PubCookieKeyDir directive
 */
const char *pubcookie_set_keydir (cmd_parms * cmd, void *mconfig,
                                  const char *v)
{
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg = (pubcookie_server_rec *)
        ap_get_module_config (s->module_config,
                              &pubcookie_module);
    ap_table_set (scfg->configlist, "keydir", v);
    return NULL;
}

/*                                                                            */
const char *pubcookie_set_appid (cmd_parms * cmd, void *mconfig,
                                 const char *v)
{
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;
    unsigned char *c;

    cfg->appid = ap_palloc (cmd->pool, strlen ((const char *) v) * 3 + 1);
    for (c = cfg->appid; *v; ++v) {
        switch (*v) {
        case ' ':
            *c++ = '+';
            break;
        case '%':
            *c++ = '%';
            *c++ = '2';
            *c++ = '5';
            break;
        case '&':
            *c++ = '%';
            *c++ = '2';
            *c++ = '6';
            break;
        case '+':
            *c++ = '%';
            *c++ = '2';
            *c++ = 'B';
            break;
        case ':':
            *c++ = '%';
            *c++ = '3';
            *c++ = 'A';
            break;
        case ';':
            *c++ = '%';
            *c++ = '3';
            *c++ = 'B';
            break;
        case '=':
            *c++ = '%';
            *c++ = '3';
            *c++ = 'D';
            break;
        case '?':
            *c++ = '%';
            *c++ = '3';
            *c++ = 'F';
            break;
        default:
            *c++ = *v;
            break;
        }
    }
    *c = '\0';
    return NULL;
}

const char *pubcookie_add_request (cmd_parms * cmd,
                                   void *mconfig, const char *v)
{
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;
    pubcookie_dir_rec *cfg;

    cfg = (pubcookie_dir_rec *) mconfig;
    scfg = (pubcookie_server_rec *) ap_get_module_config (s->module_config,
                                                          &pubcookie_module);

    if (!scfg)
        return "pubcookie_add_request(): scfg is NULL ?!";

    ap_log_error (PC_LOG_DEBUG, s, "pubcookie_add_request(): %s", v);
    cfg->addl_requests = (unsigned char *) ap_pstrcat (cmd->pool,
                                                       cfg->
                                                       addl_requests ?
                                                       cfg->
                                                       addl_requests
                                                       : (unsigned char *)
                                                       "", "&", v, NULL);
    return NULL;

}

const char *pubcookie_accept_realms (cmd_parms * cmd,
                                     void *mconfig, const char *v)
{
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;
    pubcookie_dir_rec *cfg;

    cfg = (pubcookie_dir_rec *) mconfig;
    scfg = (pubcookie_server_rec *) ap_get_module_config (s->module_config,
                                                          &pubcookie_module);

    if (!scfg)
        return "pubcookie_accept_realms(): scfg is NULL ?!";

    ap_log_error (PC_LOG_DEBUG, s, "pubcookie_accept_realms(): %s", v);
    cfg->accept_realms = ap_pstrcat (cmd->pool,
                                     cfg->accept_realms ? cfg->
                                     accept_realms : "", " ", v, NULL);
    return NULL;
}

const char *pubcookie_strip_realm (cmd_parms * cmd, void *mconfig,
                                   const int f)
{
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;

    if (f != 0) {
        cfg->strip_realm = 1;
    } else {
        cfg->strip_realm = 0;
    }
    return NULL;
}


/*                                                                            */
const char *pubcookie_set_appsrvid (cmd_parms * cmd, void *mconfig,
                                    const char *v)
{
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;
    unsigned char *c;

    scfg = (pubcookie_server_rec *) ap_get_module_config (s->module_config,
                                                          &pubcookie_module);

    scfg->appsrvid =
        ap_palloc (cmd->pool, strlen ((const char *) v) * 3 + 1);
    for (c = scfg->appsrvid; *v; ++v) {
        switch (*v) {
        case ' ':
            *c++ = '+';
            break;
        case '%':
            *c++ = '%';
            *c++ = '2';
            *c++ = '5';
            break;
        case '&':
            *c++ = '%';
            *c++ = '2';
            *c++ = '6';
            break;
        case '+':
            *c++ = '%';
            *c++ = '2';
            *c++ = 'B';
            break;
        case ':':
            *c++ = '%';
            *c++ = '3';
            *c++ = 'A';
            break;
        case ';':
            *c++ = '%';
            *c++ = '3';
            *c++ = 'B';
            break;
        case '=':
            *c++ = '%';
            *c++ = '3';
            *c++ = 'D';
            break;
        case '?':
            *c++ = '%';
            *c++ = '3';
            *c++ = 'F';
            break;
        default:
            *c++ = *v;
            break;
        }
    }
    *c = '\0';
    return NULL;
}

/*                                                                            */
const char *pubcookie_set_dirdepth (cmd_parms * cmd, void *mconfig,
                                    const char *v)
{
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;

    scfg = (pubcookie_server_rec *) ap_get_module_config (s->module_config,
                                                          &pubcookie_module);

    if ((scfg->dirdepth = atoi ((const char *) v)) < 0) {
        return
            "PUBCOOKIE: Could not convert Directory Depth for AppID parameter to nonnegative number.";
    }

    /* externally we count directories but internally we cound slashes
       external    internal
       /            == 0          1
       /blah/       == 1          2
       /blah/blong/ == 2          3
       and internally zero is 'unset'
     */
    (scfg->dirdepth)++;

    return NULL;
}

/**
 *  handle the PubCookieGrantingCertFile directive
 */
const char *pubcookie_set_g_certf (cmd_parms * cmd, void *mconfig,
                                   const char *v)
{

    pubcookie_server_rec *scfg = (pubcookie_server_rec *)
        ap_get_module_config (cmd->server->module_config,
                              &pubcookie_module);

    ap_table_set (scfg->configlist, "granting_cert_file", v);
    return NULL;
}

/**
 *  handle the PubCookieSessionKeyFile directive
 */
const char *pubcookie_set_s_keyf (cmd_parms * cmd, void *mconfig,
                                  const char *v)
{

    pubcookie_server_rec *scfg = (pubcookie_server_rec *)
        ap_get_module_config (cmd->server->module_config,
                              &pubcookie_module);

    ap_table_set (scfg->configlist, "ssl_key_file", v);
    return NULL;
}

/**
 *  handle the PubCookieSessionCertFile directive
 */
const char *pubcookie_set_s_certf (cmd_parms * cmd, void *mconfig,
                                   const char *v)
{
    pubcookie_server_rec *scfg = (pubcookie_server_rec *)
        ap_get_module_config (cmd->server->module_config,
                              &pubcookie_module);

    ap_table_set (scfg->configlist, "ssl_cert_file", v);
    return NULL;
}

/**
 *  handle the PubCookieCryptKeyFile directive
 *
 *  I don't think this is actually used anywhere.  I think it always uses
 *  keydir/hostname instead. 
 */
const char *pubcookie_set_crypt_keyf (cmd_parms * cmd, void *mconfig,
                                      const char *v)
{
    pubcookie_server_rec *scfg = (pubcookie_server_rec *)
        ap_get_module_config (cmd->server->module_config,
                              &pubcookie_module);

    ap_table_set (scfg->configlist, "crypt_key", v);
    return NULL;
}

/** 
 * handle the PubCookieEgdDevice directive
 */

const char *pubcookie_set_egd_device (cmd_parms * cmd, void *mconfig,
                                      const char *v)
{
    pubcookie_server_rec *scfg = (pubcookie_server_rec *)
        ap_get_module_config (cmd->server->module_config,
                              &pubcookie_module);

    ap_table_set (scfg->configlist, "egd_socket", v);
    return NULL;
}

/*                                                                            */
const char *set_session_reauth (cmd_parms * cmd, void *mconfig,
                                const char *v)
{
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;

    if (!v)
        cfg->session_reauth = 0;
    else if (!strcasecmp (v, "on"))
        cfg->session_reauth = 1;
    else if (!strcasecmp (v, "off"))
        cfg->session_reauth = 0;
    else
        cfg->session_reauth = atoi ((const char *) v);
    if (cfg->session_reauth < 0)
        cfg->session_reauth = 1;

    return NULL;
}

/* sets flag to remove session cookie                                         */
/*  can also set the action to redirecto the login server                     */
const char *set_end_session (cmd_parms * cmd, void *mconfig, const char *v)
{
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;

    cfg->end_session = ap_pstrdup (cmd->pool, v);

    return NULL;

}


/* allow admin to set a "dont blank the cookie" mode for proxy with pubcookie */
/* DEPRECATED in favour of PubcookieNoObscureCookie                          */
const char *pubcookie_set_no_blank (cmd_parms * cmd, void *mconfig,
                                    const char *v)
{
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;
    ap_pool *p = cmd->pool;

    scfg = (pubcookie_server_rec *) ap_get_module_config (s->module_config,
                                                          &pubcookie_module);

    ap_log_error (PC_LOG_WARNING, s,
                  "PubcookieNoBlank deprecated directive (use PubcookieNoObscureCookie instead");

    scfg->noblank = 1;

    return NULL;

}

/* allow to set a "don't obscure the cookie" mode for proxy with pubcookie */
const char *pubcookie_set_no_obscure (cmd_parms * cmd, void *mconfig,
                                      int flag)
{
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;
    ap_pool *p = cmd->pool;

    scfg = (pubcookie_server_rec *) ap_get_module_config (s->module_config,
                                                          &pubcookie_module);

    scfg->noblank = flag;

    return NULL;

}

/**
 * Determine whether setting the AppID replaces the current AppID or
 * appends its value to the current AppID.
 *
 * Added by ddj@cmu.edu on 2006/05/01 to address a security issue with
 * people stealing cookies from other apps.
 */
const char *pubcookie_set_catenate_appids(cmd_parms *cmd, void *mconfig,
					  int flag)
{
  server_rec *s = cmd->server;
  pubcookie_server_rec *scfg;
  ap_pool *p = cmd->pool;

  scfg = (pubcookie_server_rec *) ap_get_module_config (s->module_config,
							&pubcookie_module);

  scfg->catenate = flag;

  return NULL;
}

/**
 * used to give more debugging, does nothing now
 * @param cmd - command record
 * @param mconfig - module configuration
 * @param f - int
 * @returns NULL 
 */
const char *set_super_debug (cmd_parms * cmd, void *mconfig, int f)
{
    server_rec *s = cmd->server;

    ap_log_error (PC_LOG_EMERG, s,
                  "PubcookieSuperDebug deprecated, please remove.");

    return NULL;

}

const char *set_no_clean_creds (cmd_parms * cmd, void *mconfig, int flag)
{
  server_rec *s = cmd->server;
  pubcookie_server_rec *scfg;
  ap_pool *p = cmd->pool;

  scfg = (pubcookie_server_rec *) ap_get_module_config (s->module_config,
							&pubcookie_module);

  scfg->no_clean_creds = flag;

  return NULL;
}

/*                                                                            */
const char *pubcookie_set_no_ssl_ok (cmd_parms * cmd, void *mconfig,
                                     char *v)
{
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;

    cfg->non_ssl_ok = 1;

    return NULL;

}

/**
 * sets the text names for auth types
 * @param cmd - command record
 * @param mconfig - module configuration
 * @param args - aguments for directive
 * @returns NULL 
 */
const char *set_authtype_names (cmd_parms * cmd, void *mconfig,
                                const char *args)
{
    server_rec *s = cmd->server;
    pubcookie_server_rec *scfg;
    ap_pool *p = cmd->pool;

    scfg = (pubcookie_server_rec *) ap_get_module_config (s->module_config,
                                                          &pubcookie_module);

    scfg->authtype_names = ap_pstrdup (cmd->pool, args);

    return NULL;

}

/* Add an on-demand directive */
const char *set_keyed_directive (cmd_parms * cmd, void *mconfig,
                                 const char *k, const char *v)
{
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;

    if (!cfg->keydirs)
        cfg->keydirs = ap_make_table (cmd->pool, 5);
    ap_table_merge (cfg->keydirs, k, v);
    ap_log_error (PC_LOG_DEBUG, cmd->server, "keydirs: %s=%s", k, v);


    return NULL;
}

/* Set the noprompt option */
const char *set_noprompt (cmd_parms * cmd, void *mconfig, const int f)
{
    pubcookie_dir_rec *cfg = (pubcookie_dir_rec *) mconfig;

    cfg->noprompt = f ? 1 : -1;
    ap_log_error (PC_LOG_DEBUG, cmd->server,
                  "Noprompt set to %d", cfg->noprompt);

    return NULL;
}

static const char *pubcookie_set_method (cmd_parms * cmd,
                                         void *mconfig, const char *v)
{
    pubcookie_server_rec *scfg =
        (pubcookie_server_rec *) ap_get_module_config (cmd->server->
                                                       module_config,
                                                       &pubcookie_module);

    if (!strcasecmp (v, "get"))
        scfg->use_post = 0;
    else if (!strcasecmp (v, "post"))
        scfg->use_post = 1;
    else
        return ("Invalid pubcookie login method");
    return NULL;
}

static const char *pubcookie_set_crypt (cmd_parms * cmd,
                                        void *mconfig, const char *v)
{
    pubcookie_server_rec *scfg =
        (pubcookie_server_rec *) ap_get_module_config (cmd->server->
                                                       module_config,
                                                       &pubcookie_module);

    if (!strcasecmp (v, "des"))
        scfg->crypt_alg = PBC_CRYPT_DES;
    else if (!strcasecmp (v, "aes"))
        scfg->crypt_alg = PBC_CRYPT_AES;
    else if (!strcasecmp (v, "aes+domain"))
        scfg->crypt_alg = PBC_CRYPT_AES_D;
    else
        return ("Invalid encryption method");
    return NULL;
}

static const char *pubcookie_set_post_url (cmd_parms * cmd,
                                           void *mconfig, const char *v)
{
    pubcookie_server_rec *scfg =
        (pubcookie_server_rec *) ap_get_module_config (cmd->server->
                                                       module_config,
                                                       &pubcookie_module);

    scfg->post_reply_url = ap_pstrdup (cmd->pool, v);
    if (*scfg->post_reply_url == '/')
        scfg->post_reply_url++;
    return NULL;
}

/*                                                                            */
#ifdef APACHE1_3
#define AP_INIT_TAKE1(d,f,c,w,h) { d,f,c,w,TAKE1,h}
#define AP_INIT_RAW_ARGS(d,f,c,w,h) { d,f,c,w,RAW_ARGS,h}
#define AP_INIT_ITERATE(d,f,c,w,h) { d,f,c,w,ITERATE,h}
#define AP_INIT_FLAG(d,f,c,w,h) { d,f,c,w,FLAG,h}
#define AP_INIT_ITERATE2(d,f,c,w,h) { d,f,c,w,ITERATE2,h}
#endif

static const command_rec pubcookie_commands[] = {
    AP_INIT_TAKE1 ("PubCookieInactiveExpire",
                   pubcookie_set_inact_exp,
                   NULL, OR_AUTHCFG,
                   "Set the inactivity expire time for PubCookies."),
    AP_INIT_TAKE1 ("PubCookieHardExpire",
                   pubcookie_set_hard_exp,
                   NULL, OR_AUTHCFG,
                   "Set the hard expire time for PubCookies."),
    AP_INIT_TAKE1 ("PubCookieLogin",
                   pubcookie_set_login,
                   NULL, RSRC_CONF,
                   "Set the login page for PubCookies."),
    AP_INIT_TAKE1 ("PubCookieDomain",
                   pubcookie_set_domain,
                   NULL, RSRC_CONF,
                   "Set the domain for PubCookies."),
    AP_INIT_TAKE1 ("PubCookieKeyDir",
                   pubcookie_set_keydir,
                   NULL, RSRC_CONF,
                   "Set the location of PubCookie encryption keys."),

    AP_INIT_TAKE1 ("PubCookieGrantingCertfile",
                   pubcookie_set_g_certf,
                   NULL, RSRC_CONF,
                   "Set the name of the certfile for Granting PubCookies."),
    AP_INIT_TAKE1 ("PubCookieSessionKeyfile",
                   pubcookie_set_s_keyf,
                   NULL, RSRC_CONF,
                   "Set the name of the keyfile for Session PubCookies."),
    AP_INIT_TAKE1 ("PubCookieSessionCertfile",
                   pubcookie_set_s_certf,
                   NULL, RSRC_CONF,
                   "Set the name of the certfile for Session PubCookies."),
    AP_INIT_TAKE1 ("PubCookieCryptKeyfile",
                   pubcookie_set_crypt_keyf,
                   NULL, RSRC_CONF,
                   "Set the name of the encryption keyfile for PubCookies."),
    AP_INIT_TAKE1 ("PubCookieEgdDevice",
                   pubcookie_set_egd_device,
                   NULL, RSRC_CONF,
                   "Set the name of the EGD Socket if needed for randomness."),

    /* DEPRECATED in favour of PubcookieNoObscureCookie  */
    AP_INIT_TAKE1 ("PubCookieNoBlank",
                   pubcookie_set_no_blank,
                   NULL, RSRC_CONF,
                   "Do not blank cookies."),
    AP_INIT_FLAG ("PubCookieNoObscureCookies",
                  pubcookie_set_no_obscure,
                  NULL, RSRC_CONF,
                  "Do not obscure Pubcookie cookies."),
    AP_INIT_RAW_ARGS ("PubCookieAuthTypeNames",
                      set_authtype_names,
                      NULL, RSRC_CONF,
                      "Sets the text names for authtypes."),

    /* Added by ddj@cmu.edu on 2006/05/01 to address security
       issue at CMU. */
    AP_INIT_FLAG ("PubCookieCatenateAppIDs",
		  pubcookie_set_catenate_appids,
		  NULL, RSRC_CONF|ACCESS_CONF,
		  "Determines whether a new AppID replaces or is catenated "
		  "to the old App ID."),
    /* End of ddj@cmu.edu's change. */

    AP_INIT_TAKE1 ("PubCookieAppID",
                   pubcookie_set_appid,
                   NULL, OR_AUTHCFG,
                   "Set the name of the application."),
    AP_INIT_TAKE1 ("PubCookieAppSrvID",
                   pubcookie_set_appsrvid,
                   NULL, RSRC_CONF,
                   "Set the name of the server(cluster)."),
    AP_INIT_TAKE1 ("PubCookieDirDepthforAppID",
                   pubcookie_set_dirdepth,
                   NULL, RSRC_CONF,
                   "Specify the Directory Depth for generating default AppIDs."),

    AP_INIT_TAKE1 ("PubcookieSessionCauseReAuth",
                   set_session_reauth,
                   NULL, OR_AUTHCFG,
                   "Force reauthentication for new sessions with specified timeout"),
    AP_INIT_RAW_ARGS ("PubcookieEndSession",
                      set_end_session,
                      NULL, OR_AUTHCFG,
                      "End application session and possibly login session"),
    AP_INIT_ITERATE ("PubCookieAddlRequest",
                     pubcookie_add_request,
                     NULL, OR_AUTHCFG,
                     "Send the following options to the login server along with authentication requests"),
    AP_INIT_ITERATE ("PubCookieAcceptRealm",
                     pubcookie_accept_realms,
                     NULL, OR_OPTIONS | OR_AUTHCFG,
                     "Only accept realms in this list"),
    AP_INIT_FLAG ("PubCookieStripRealm",
                  pubcookie_strip_realm,
                  NULL, OR_OPTIONS | OR_AUTHCFG,
                  "Strip the realm (and set the REMOTE_REALM envirorment variable)"),
    AP_INIT_ITERATE2 ("PubCookieOnDemand",
                      set_keyed_directive,
                      NULL, OR_AUTHCFG,
                      "Specify on-demand pubcookie directives."),
    AP_INIT_FLAG ("PubCookieNoPrompt",
                  set_noprompt,
                  NULL, OR_AUTHCFG,
                  "Do not prompt for id and password if not already logged in."),
    AP_INIT_TAKE1 ("PubCookieLoginMethod",
                   pubcookie_set_method,
                   NULL, RSRC_CONF,
                   "Set login method (GET/POST).  Def = GET"),
    AP_INIT_TAKE1 ("PubCookieEncryption",
                   pubcookie_set_crypt,
                   NULL, RSRC_CONF,
                   "Set encryption method (AES/DES)."),
    AP_INIT_TAKE1 ("PubCookiePostURL",
                   pubcookie_set_post_url,
                   NULL, RSRC_CONF,
                   "Set post response URL.  Def = /PubCookie.reply"),
    AP_INIT_FLAG ("PubCookieSuperDebug",
                  set_super_debug,
                  NULL, OR_AUTHCFG,
                  "Deprecated, do not use"),
    AP_INIT_FLAG ("PubCookieNoCleanCreds",
                  set_no_clean_creds,
                  NULL, RSRC_CONF,
                  "Set to leave credentials in place after cleanup"),

/* maybe for future exploration
    AP_INIT_TAKE1("PubCookieNoSSLOK",
         pubcookie_set_no_ssl_ok,
         NULL, OR_AUTHCFG,
         "Allow session to go non-ssl."
    ),
*/
    {NULL}
};

/* Check for and load any keyed directives.  Return true if any found.
   Only a few directives can be invoked this way:
      "authtype", "require", and the following from pubcookie */

static char *odpc_dirs[] = {
    "PubCookieInactiveExpire",
    "PubCookieHardExpire",
    "PubCookieAppID",
    "PubCookieSessionCauseReAuth",
    "PubCookieEndSession",
    "PubCookieNoPrompt",
    NULL
};

static int load_keyed_directives (request_rec * r, char *key)
{
    pubcookie_dir_rec *cfg;
    pubcookie_req_rec *rr;
    pool *p = r->pool;
    const char *k, *c;
    char *s;
    int freq = 1;
    char *dirs;
    char *ret = NULL;

    cfg = (pubcookie_dir_rec *) ap_get_module_config (r->per_dir_config,
                                                      &pubcookie_module);
    rr = (pubcookie_req_rec *) ap_get_module_config (r->request_config,
                                                     &pubcookie_module);
    if (!rr)
        return 0;               /* subrequest */

    ap_log_rerror (PC_LOG_DEBUG, r,
                   "load_keyed_directives: hello, keydirs=%x, uri=%s",
                   cfg->keydirs, r->uri);

    if (!cfg->keydirs)
        return (0);
    for (s = key; *s && !isspace (*s); s++);
    c = ap_pstrndup (p, key, s - key);
    ap_log_rerror (PC_LOG_DEBUG, r, "ckd: key=%s", c);
    if (!(k = ap_table_get (cfg->keydirs, c)))
        return (0);
    ap_log_rerror (PC_LOG_DEBUG, r, "ckd: dir=%s", k);

    /* we have directives (k) */

    ap_table_set (r->subprocess_env, PBC_ODKEY_ENVNAME, c);

    dirs = ap_pstrdup (p, k);
    while (*dirs) {
        c = ap_get_token (p, (const char **) &dirs, 1); /* get next directive */
        if (*dirs)
            dirs++;
        s = ap_get_token (p, (const char **) &c, 0);

        /* authtype overrides authtype directive */
        if (!strcasecmp (s, "authtype")) {
            core_dir_config *ccfg = (core_dir_config *)
                ap_get_module_config (r->per_dir_config, &core_module);
            ccfg->ap_auth_type = ap_pstrdup (p, c);
            rr->creds = pubcookie_auth_type (r);
            ap_log_rerror (PC_LOG_DEBUG, r, "ckd: authtype; %s (%c)", c,
                           rr->creds);

            /* require overrides location require lines */
        } else if (!strcasecmp (s, "Require")) {
            core_dir_config *ccfg = (core_dir_config *)
                ap_get_module_config (r->per_dir_config, &core_module);
            require_line *rl;
            if (freq) {
                ccfg->ap_requires =
                    ap_make_array (p, 2, sizeof (require_line));
                ap_log_rerror (PC_LOG_DEBUG, r,
                               "ckd: created require array");
            }
            freq = 0;
            rl = (require_line *) ap_push_array (ccfg->ap_requires);
            rl->requirement = ap_pstrdup (p, c);
            rl->method_mask = (-1);
            ap_log_rerror (PC_LOG_DEBUG, r, "ckd: add require; %s", c);

            /* Do pubcookie '.htaccess' directives by normal methods */
        } else {
            const command_rec *cmd = pubcookie_commands;
            char **pc;
            const char *ret = "Unknown on-demand directive";
            char *w;
            int f = 1;
            cmd_parms parms;

            /* Setup dummy cmd_parms struct */
            memset (&parms, 0, sizeof (parms));
            parms.pool = p;     /* this is all we really use */
            parms.temp_pool = p;
            parms.server = r->server;

            /* Look for and process valid commands */
            for (pc = odpc_dirs; ret && *pc; pc++) {
                if (strcasecmp (s, *pc))
                    continue;
                for (cmd = pubcookie_commands; cmd->name; cmd++) {
                    if (strcasecmp (cmd->name, s))
                        continue;
                    if (!(cmd->req_override & OR_AUTHCFG)) {
                        ap_log_rerror (PC_LOG_DEBUG, r,
                                       "ckd: \"%s\" not allowed here", s);
                        return (HTTP_INTERNAL_SERVER_ERROR);
                    }
                    /* We only need these three for now */
                    switch (cmd->args_how) {
                    case RAW_ARGS:
                        ret = cmd->AP_RAW_ARGS (&parms, (void *) cfg, c);
                        break;
                    case TAKE1:
                        w = ap_getword_conf (parms.pool, &c);
                        ret = cmd->AP_TAKE1 (&parms, (void *) cfg, w);
                        break;
                    case FLAG:
                        if (!strcmp (c, "off"))
                            f = 0;
                        ret = cmd->AP_FLAG (&parms, (void *) cfg, f);
                        break;
                    default:
                        ap_log_rerror (PC_LOG_DEBUG, r,
                                       "ckd: \"%s\" unsupported here", s);
                        return (HTTP_INTERNAL_SERVER_ERROR);
                    }
                    break;
                }
            }
            if (ret)
                return (HTTP_INTERNAL_SERVER_ERROR);
        }
    }
    return (0);
}

static int pubcookie_cleanup (request_rec * r)
{
    pubcookie_req_rec *rr;
    pubcookie_server_rec *scfg;
    table *e = r->subprocess_env;

    ap_log_rerror (PC_LOG_DEBUG, r, "cleanup");

    rr = (pubcookie_req_rec *) ap_get_module_config (r->request_config,
                                                     &pubcookie_module);
    scfg = (pubcookie_server_rec *) ap_get_module_config (r->server->
                                                     module_config,
                                                     &pubcookie_module);

    if (!rr)
        return OK;

    if (rr->cred_transfer && !scfg->no_clean_creds) {
        struct stat sb;
        const char *krb5ccname = ap_table_get (e, "KRB5CCNAME");

        if (!krb5ccname || stat (krb5ccname, &sb) == -1) {
            ap_log_rerror (PC_LOG_DEBUG, r,
                           "pubcookie_cleanup: missing credential cache [%s]",
                           krb5ccname);
        } else {
            if (unlink (krb5ccname) == -1) {
                ap_log_rerror (PC_LOG_ERR, r,
                               "pubcookie_cleanup: cannot destroy credential cache [%s]",
                               krb5ccname);
            } else {
                ap_log_rerror (PC_LOG_DEBUG, r,
                               "deleted credential cache %s", krb5ccname);
            }
        }
    }

    return OK;
}

/* If apache2 add our headers in the output filter */

#ifdef PBC_DEFERRED_HEADERS

static void set_output_filter(request_rec *r)
{
   if (r->main) ap_log_rerror (PC_LOG_DEBUG, r, "pubcookie skipping output filter (sub)");
   else {
      ap_log_rerror (PC_LOG_DEBUG, r, "pubcookie adding output filter");
      ap_add_output_filter("PBC_HEADERS_OUT", NULL, r, r->connection);
   }
}

static void set_error_filter(request_rec *r)
{
   if (r->main) ap_log_rerror (PC_LOG_DEBUG, r, "pubcookie skipping error filter (sub)");
   else {
      ap_log_rerror (PC_LOG_DEBUG, r, "pubcookie adding error filter");
      ap_add_output_filter("PBC_HEADERS_ERR", NULL, r, r->connection);
   }
}

static apr_status_t do_output_filter(ap_filter_t *f,
                                             apr_bucket_brigade *in)
{
    request_rec *r = f->r;
    pubcookie_req_rec *rr;
    rr = (pubcookie_req_rec *) ap_get_module_config (r->request_config,
                                                     &pubcookie_module);

    if ( rr ) {
        ap_log_rerror (PC_LOG_DEBUG, r, "pubcookie output_filter: merging %d output headers",
                   apr_table_elts(rr->hdr_out)->nelts);
        append_to_table(r, r->headers_out, rr->hdr_out);
    }

    /* remove ourselves from the filter chain */
    ap_remove_output_filter(f);

    /* send the data up the stack */
    return ap_pass_brigade(f->next,in);
}

static apr_status_t do_error_filter(ap_filter_t *f,
                                             apr_bucket_brigade *in)
{
    request_rec *r = f->r;
    pubcookie_req_rec *rr;
    rr = (pubcookie_req_rec *) ap_get_module_config (r->request_config,
                                                     &pubcookie_module);

    if ( rr ) {
        ap_log_rerror (PC_LOG_DEBUG, r, "error_filter: merging %d error headers",
                   apr_table_elts(rr->hdr_err)->nelts);
        append_to_table(r, r->err_headers_out, rr->hdr_err);
    }

    /* remove ourselves from the filter chain */
    ap_remove_output_filter(f);

    /* send the data up the stack */
    return ap_pass_brigade(f->next,in);
}

#endif /* PBC_DEFERRED_HEADERS */


/* Handle the post-method reply from the login server.
   Activated by:
       <Location /PubCookie.reply>
         SetHandler pubcookie-post-reply
       </Location>
  */


/* Encode the args */

static char *encode_get_args (request_rec *r, char *in, int ec)
{
    int na = 0;
    char *enc, *s;

    for (s=in; s&&*s; s++) {
        if ( (*s=='"') ||
             (*s == '<') ||
             (*s == '>') ||
             (*s == '(') ||
             (*s == ')') ||
             (*s == ':') ||
             (*s == ';') ||
             (*s == '\n') ||
             (*s == '\r') ) na++;
    }
    if (!na) return (in);

    enc = (char*) ap_palloc (r->pool, strlen(in)+(na*5));
    for (s=enc; in&&*in; in++) {
        switch (*in) { 

            case '"':  strcpy(s, "%22"); s+=3; break;
            case '<':  strcpy(s, "%3C"); s+=3; break;
            case '>':  strcpy(s, "%3E"); s+=3; break;
            case '(':  strcpy(s, "%28"); s+=3; break;
            case ')':  strcpy(s, "%29"); s+=3; break;
            case ':':  if (ec) {
                           strcpy(s, "%3A"); s+=3;
                       } else *s++ = *in;
                       break;
            case ';':  strcpy(s, "%3B"); s+=3; break;
            case '\n': strcpy(s, "&#10;"); s+=5; break;
            case '\r': strcpy(s, "&#13;"); s+=5; break;
            default: *s++ = *in;
        }
    }
    *s = '\0';

    return (enc);
}

/* entity encode some post data */

static char *encode_data (request_rec *r, char *in)
{
    int na = 0;
    char *enc, *s;

    for (s=in; s&&*s; s++) {
        if ( (*s=='"') ||
             (*s == '\'') ||
             (*s == '<') ||
             (*s == '>') ||
             (*s == ':') ||
             (*s == '\n') ||
             (*s == '\r') ) na++;
    }
    if (!na) return (in);

    enc = (char*) ap_palloc (r->pool, strlen(in)+(na*5));
    for (s=enc; in&&*in; in++) {
        switch (*in) { 

            case '"':  strcpy(s, "&quot;"); s+=6; break;
            case '<':  strcpy(s, "&lt;"); s+=4; break;
            case '>':  strcpy(s, "&gt;"); s+=4; break;
            case '\n': strcpy(s, "&#10;"); s+=5; break;
            case '\r': strcpy(s, "&#13;"); s+=5; break;
            default: *s++ = *in;
        }
    }
    *s = '\0';

    return (enc);
}

/* decode an arg string */

static char *decode_data(char *in)
{
   char *s;
   char *v;
   long int k;
   char hex[4];
   char *e;

   if ((!in)||!*in) return ("");
   for (v=in,s=in; *s; s++) {
      switch (*s) {
        case '+': *v++ = ' ';
                  break;
        case '%': hex[0] = *++s;
                  hex[1] = *++s;
                  hex[2] = '\0';
                  k = strtol(hex,0,16);
                  *v++ = (char)k;
                  break;
        default:  *v++ = *s;
      }
   }
   *v = '\0';

   for (v=in,s=in; *s; s++) {
      switch (*s) {
        case '&': if (*(s+1)=='#') {
                     s += 2;
                     if ((*s=='x')||(*s=='X')) k = strtol(s+1, &e, 16);
                     else k = strtol(s, &e, 10);
                     *v++ = (char)k;
                     if (*e==';') s = e;
                     else s = e-1;
                  } else *v++ = '&';
                  break; 
        default:  *v++ = *s;
      }
   }
   *v = '\0';

   return (in);
}

/* Read and parse query_string args. 
   Check validity and add to argtbl. */

static void scan_args (request_rec *r, table *argtbl, char *arg)
{
    char *p, *q, *s;

    p = arg;

    while (p) {
        if (q = strchr (p, '&')) *q++ = '\0';
        if (s = strchr (p, '=')) *s++ = '\0';
        else s = "";

        decode_data (s);
        ap_table_set (argtbl, p, s);
        p = q;
    }
    return;
}

/* verify the url. return the url if OK.
   We are mostly checking for characters that
   could introduce javascript xss code. 

   If we're not encoding colons - the GET case - then
   we will also decode any encoded ones from the login server. */

static char *verify_url(request_rec *r, char *in, int ec)
{
    int n;
    char *sa, *e, *enc;
    char *s = in;
    char *dpath;
    int dpathl, sl;

    if (!s) return (NULL);

    ap_log_rerror (PC_LOG_DEBUG, r, "verify-url in: %s", in);

    /* check protocol */
    if (!strncmp(s, "http://", 7)) s+=7;
    else if (!strncmp(s, "https://", 8)) s += 8;
    else return (NULL);

    /* check hostname ( letters, digits, dash )*/
    while (isalnum(*s) || (*s=='-') || (*s=='.')) s++;
    if (*s=='\0') return (in);
  
    /* port? */
    if (*s==':') {
       s++;
       while (isdigit(*s)) s++;
    }
    if (*s=='\0') return (in);
    if (*s++!='/') return (NULL);

    /* decode the path */
    
    sl = strlen(s);
    dpath = ap_palloc (r->pool, sl);
    dpathl = strlen(s);
    /* the login may have turned our pluses to spaces */
    for (e=s; *e; e++) if (*e==' ') *e = '+';
    ap_log_rerror (PC_LOG_DEBUG, r, "verify-url decoding: %s", s);
    if (!libpbc_base64_decode (r->pool, (unsigned char *) s,
                                 (unsigned char *) dpath, &dpathl)) {
          ap_log_rerror (PC_LOG_ERR, r,
                         "DEC path: libpbc_base64_decode() failed");
    }
    if (*dpath=='/') dpath++;
    strncpy(s, dpath, sl);
    ap_log_rerror (PC_LOG_DEBUG, r, "verify-url path is: %s", s);
    

    /* see if we have to encode anything in the path */

    sa = s;
    n = 0;
    for (; s&&*s; s++) {
        if ( (*s=='"') ||
             (*s == '<') ||
             (*s == '>') ||
             (*s == ':') ||
             (*s == ';') ||
             (*s == '?') ||
             (*s == '%') ||
             (*s == '=') ) n++;
    }
    if (n==0) return (in);  /* nothing to do */

    /* else have some 'coding to do */
    enc = (char*) ap_palloc (r->pool, strlen(in)+(n*4));
    strncpy(enc, in, sa-in);
    for (s=enc+(sa-in); sa&&*sa; sa++) {
        switch (*sa) { 

            case '"':  strcpy(s, "%22"); s+=3; break;
            case '<':  strcpy(s, "%3C"); s+=3; break;
            case '>':  strcpy(s, "%3E"); s+=3; break;
            case ':':  if (ec) {
                           strcpy(s, "%3A"); s+=3;
                       } else *s++ = *sa;
                       break;
            case ';':  strcpy(s, "%3B"); s+=3; break;
            case '?':  strcpy(s, "%3F"); s+=3; break;
            case '=':  strcpy(s, "%3D"); s+=3; break;
            case '%':  if (ec || strncmp(sa,"%3A",3)) *s++ = *sa;
                       else *s++=':',sa+=2;
                       break;
            default: *s++ = *sa;
        }
    }
    *s = '\0';

    ap_log_rerror (PC_LOG_DEBUG, r, "verify-url out: %s", enc);

    return (enc);
}


/* verify a base64 string. return 1 on OK, Truncate at error. */

static int verify_base64(request_rec *r, char *in)
{
    char *s;
    for (s=in; s && *s; s++) {
       if (isalnum(*s)) continue;
       if ((*s=='+')||(*s=='/')||(*s=='=')) continue;
       *s++ = '\0';
       if (!*s) break; /* newline at end */
       ap_log_rerror (PC_LOG_ERR, r, "verify-base64 truncated: %s", in);
       return (0);  
    }
    return (1);
}

/* Handle the granting reply */
static int login_reply_handler (request_rec * r)
{
    pubcookie_server_rec *scfg;
    pubcookie_dir_rec *cfg;
    pubcookie_req_rec *rr;
    table *args = ap_make_table (r->pool, 5);
    const char *greply, *creply, *pdata;
    char *arg;
    char *a;
    const char *lenp = ap_table_get (r->headers_in, "Content-Length");
    char *post_data;
    char *gr_cookie, *cr_cookie;
    const char *r_url;
    pool *p = r->pool;

    scfg =
        (pubcookie_server_rec *) ap_get_module_config (r->server->
                                                       module_config,
                                                       &pubcookie_module);

    cfg = (pubcookie_dir_rec *) ap_get_module_config (r->per_dir_config,
                                                      &pubcookie_module);

    rr = (pubcookie_req_rec *) ap_get_module_config (r->request_config,
                                                     &pubcookie_module);

#ifdef APACHE2
    if (strcmp (r->handler, "pubcookie-post-reply"))
        return DECLINED;
#endif

    ap_log_rerror (PC_LOG_DEBUG, r, "login_reply_handler: hello");

    r->content_type = CONTENT_TYPE;
    set_no_cache_headers (r);

    /* Get the request data */

    if (r->args) {
        arg = ap_pstrdup (p, r->args);
        scan_args (r, args, arg);
    }
    if (lenp) {
        int post_data_len;
        if (((post_data_len = strtol (lenp, NULL, 10)) > 0) &&
            ((post_data = get_post_data (r, post_data_len)))) {
            scan_args (r, args, post_data);
        }
    }

    greply = ap_table_get (args, PBC_G_COOKIENAME);
    if (!greply) {
        /* Send out bad call error */
        rr->stop_message = ap_pstrdup (p, "No granting reply");
        stop_the_show (r, scfg, cfg, rr);
        return (OK);
    }
    verify_base64(r, (char*)greply);

    /* see if we do GET or POST */
    pdata = ap_table_get (args, PBC_GETVAR_POST_STUFF);
    if (!pdata) pdata = "";

    if (!(r_url=verify_url(r, (char*)ap_table_get (args, "redirect_url"), (*pdata)?1:0))) {
        /* Send out bad call error */
        ap_log_rerror (PC_LOG_ERR, r,
                       "bad redirect url: %s", r_url);
        rr->stop_message = ap_pstrdup (p, "Invalid relay URL");
        stop_the_show (r, scfg, cfg, rr);
        return (OK);
    }

    creply = ap_table_get (args, PBC_CRED_TRANSFER_COOKIENAME);
    verify_base64(r, (char*)creply);

    /* Build the redirection */

    gr_cookie = ap_psprintf (p, "%s=%s; path=/;%s",
                             PBC_G_COOKIENAME, greply, secure_cookie);
    ap_table_add (HDRS_OUT, "Set-Cookie", gr_cookie);

    if (creply) {
        cr_cookie = ap_psprintf (p, "%s=%s; domain=%s; path=/;%s",
                                 PBC_CRED_TRANSFER_COOKIENAME, creply,
                                 PBC_ENTRPRS_DOMAIN, secure_cookie);
        ap_table_add (HDRS_OUT, "Set-Cookie", cr_cookie);
    }

    /* get the query string */
    a = (char*) ap_table_get (args, "get_args");

    if (a && *a) {
        arg = ap_psprintf (p, "%s?%s", r_url, encode_get_args(r, (char*)a, 0));
    } else {
        arg = (char*) r_url;
    }
    /* make sure there are no newlines in the redirect location */
    if (a=strchr(arg,'\n')) *a = '\0';
    if (a=strchr(arg,'\r')) *a = '\0';


    if (*pdata) {
        char *v, *t;
        int needclick = 0;

        flush_headers (r);

        post_data = ap_pstrdup (p, pdata);
        if (strstr (post_data, "submit=")) needclick = 1;
        ap_log_rerror (PC_LOG_DEBUG, r,
                       "relay is post, click=%d", needclick);

        /* send post form with original elements */
        ap_rprintf (r, post_reply_1_html,
                    needclick ? POST_REPLY_CLICK : POST_REPLY_SUBMIT,
                    arg);

        while (post_data) {
            if (a = strchr (post_data, '&')) *a++ = '\0';
            if (*post_data) {
                int na;

                if (v = strchr (post_data, '=')) *v++ = '\0';
                for (t = v; t&&*t; t++) if (*t == '+') *t = ' ';
                decode_data (post_data);
                decode_data (v);

                ap_rprintf (r, post_reply_arg_html, encode_data(r, post_data), encode_data(r, v)); 

            }
            post_data = a;
        }

        ap_rprintf (r, post_reply_2_html);

    } else {                    /* do a get */

        /* Apache uses the error headers when we return a redirect */
        ap_table_add (HDRS_ERR, "Set-Cookie", gr_cookie);
        if (creply) ap_table_add (HDRS_ERR, "Set-Cookie", cr_cookie);
        ap_table_add (HDRS_OUT, "Location", arg);
        ap_table_add (HDRS_ERR, "Location", arg);
        return (HTTP_MOVED_TEMPORARILY);

    }

    return (OK);
}


#ifdef APACHE1_3
handler_rec pubcookie_handlers[] = {
    {"pubcookie-post-reply", login_reply_handler}
    ,
    {NULL}
};

module pubcookie_module = {
    STANDARD_MODULE_STUFF,
    pubcookie_init,             /* initializer */
    pubcookie_dir_create,       /* dir config creater */
    pubcookie_dir_merge,        /* dir merger --- default is to override */
    pubcookie_server_create,    /* server config */
    pubcookie_server_merge,     /* merge server config */
    pubcookie_commands,         /* command table */
    pubcookie_handlers,         /* handlers */
    NULL,                       /* filename translation */
    pubcookie_user_hook,        /* check authentication */
    pubcookie_authz_hook,       /* check authorization */
    NULL,                       /* check access */
    NULL,                       /*pubcookie_typer, *//* type_checker */
    pubcookie_fixups,           /* fixups */
    pubcookie_cleanup,          /* logger */
    pubcookie_hparse,           /* header parser */
    NULL,                       /* child init */
    NULL,                       /* exit/cleanup */
    pubcookie_post_read         /* post read request */
};

#else /* apache 2 */

static void register_hooks (pool * p)
{
#ifdef PBC_DEFERRED_HEADERS
    ap_register_output_filter("PBC_HEADERS_OUT", do_output_filter,
                              NULL, AP_FTYPE_CONTENT_SET);
    ap_hook_insert_filter(set_output_filter, NULL, NULL, APR_HOOK_LAST);

    ap_register_output_filter("PBC_HEADERS_ERR", do_error_filter,
                              NULL, AP_FTYPE_CONTENT_SET);
    ap_hook_insert_error_filter(set_error_filter, NULL, NULL, APR_HOOK_LAST);
#endif

    ap_hook_post_config (pubcookie_init, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_check_user_id (pubcookie_user_hook, NULL, NULL,
                           APR_HOOK_FIRST);
    ap_hook_auth_checker (pubcookie_authz_hook, NULL, NULL,
                          APR_HOOK_FIRST);

    ap_hook_fixups (pubcookie_fixups, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_header_parser (pubcookie_hparse, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_log_transaction (pubcookie_cleanup, NULL, NULL,
                             APR_HOOK_MIDDLE);
    ap_hook_post_read_request (pubcookie_post_read, NULL, NULL,
                               APR_HOOK_MIDDLE);
    ap_hook_handler (login_reply_handler, NULL, NULL, APR_HOOK_FIRST);
}
module AP_MODULE_DECLARE_DATA pubcookie_module = {
    STANDARD20_MODULE_STUFF,
    pubcookie_dir_create,
    pubcookie_dir_merge,
    pubcookie_server_create,
    pubcookie_server_merge,
    pubcookie_commands,
    register_hooks,
};
#endif /* apache */
