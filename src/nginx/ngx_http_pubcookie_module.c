/*
 * Copyright (C) 2010 Vitki <vitki@vitki.net>
 *
 * Based on ngx_http_auth_pam_module.c by Sergio Talens-Oliag
 *
 * SVN Id: $Id$
 */

#include "ngx_http_pubcookie.h"
#include <ctype.h>


/***********************************
 * Definitions
 */


/* Feature macros */
#undef DEBUG_DUMP_RECS
#undef REDIRECT_IN_HEADER
#undef PORT80_TEST

/*
 * ap_psprintf() by default allocates 4K buffers
 * mostly they are deallocated almost immediately
 * thus compacting reallocation is not needed
 */
#define AP_PSPRINTF_COMPACT_STRINGS 0


#define DONE NGX_DONE
#define OK   NGX_OK

#define ME(r) ap_get_server_name(r)

#define MAX_POST_DATA PBC_4K

#define ngx_pubcookie_module ngx_http_pubcookie_module

#define ngx_str_assign(a,s)     ({ \
        u_char *_p = (u_char *)(s); \
        (a).len = ngx_strlen(_p); \
        (a).data = _p; \
    })

#define ngx_strcmp_c(ns,cs) ((ns).len == sizeof(cs)-1 && \
                            ! ngx_strncmp((ns).data, (u_char*)(cs), sizeof(cs)-1))
#define ngx_strcasecmp_c(ns,cs) ((ns).len == sizeof(cs)-1 && \
                            ! ngx_strncasecmp((ns).data, (u_char*)(cs), sizeof(cs)-1))

#define ngx_strcmp_eq(ns1,ns2) ((ns1).len == (ns2).len && \
                            ! ngx_strncmp((ns1).data, (ns2).data, (ns1).len))

#define get_hdr_in(R,H) (R->headers_in.H ? str2charp(R->pool, &R->headers_in.H->value) : NULL)

#define main_rrec(r)    ((r)->main)
#define top_rrec(r)     ((r)->main)

#define pc_req_log(r,args...)  pbc_ngx_log((r)->connection->log,PC_LOG_DEBUG,args)
#define pc_pool_log(p,args...) pbc_ngx_log((p)->log,PC_LOG_DEBUG,args)
#define pc_cf_log(c,args...)   pbc_ngx_log((c)->log,PC_LOG_DEBUG,args)
#define pc_log_log(l,args...)  pbc_ngx_log((l),PC_LOG_DEBUG,args)


/***********************************
 * Globals
 */

int pubcookie_super_debug = 0;

/* Cookies are secure except for exceptional cases */
#ifdef PORT80_TEST
static char *secure_cookie = "";
#else
static char *secure_cookie = " secure";
#endif

static ngx_str_t pbc_content_type = ngx_string("text/html; charset=utf-8");

static ngx_str_t blank_str = ngx_string("");

extern ngx_module_t ngx_pubcookie_module;


/***********************************
 * Prototypes
 */

#define pubcookie_set_realm(r,realm)   add_out_header(r,"WWW-Authenticate",realm,0)

static int ngx_strcat3 (ngx_pool_t *pool, ngx_str_t *res, ngx_str_t *s1, ngx_str_t *s2, ngx_str_t *s3);

static char *encode_get_args (ngx_http_request_t *r, char *in, int ec);
static char *get_post_data (ngx_http_request_t * r, int post_len);

static ngx_int_t pubcookie_post_handler (ngx_http_request_t *r);
static ngx_int_t ngx_pubcookie_authz_handler(ngx_http_request_t *r);

static void *ngx_pubcookie_create_loc_conf (ngx_conf_t *cf);
static char *ngx_pubcookie_merge_loc_conf (ngx_conf_t *cf, void *parent, void *child);
static void *ngx_pubcookie_create_srv_conf (ngx_conf_t *cf);
static char *ngx_pubcookie_merge_srv_conf (ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_pubcookie_init (ngx_conf_t *cf);

static char pubcookie_auth_type (ngx_http_request_t * r);

static int pubcookie_user (ngx_http_request_t * r, ngx_pubcookie_loc_t *cfg, ngx_pubcookie_srv_t *scfg, ngx_pubcookie_req_t *rr);
static int pubcookie_user_hook (ngx_http_request_t * r);

static void dump_recs(ngx_http_request_t *r, ngx_pubcookie_loc_t *c, ngx_pubcookie_srv_t *s);
static void dump_cookie_data(ngx_http_request_t *r, const char *prefix, pbc_cookie_data *cookie_data);

const char * libpbc_config_getstring(pool *ptr, const char *name, const char *defval);


/**************************************
 * Apache/APR compatibility
 */

#define ap_log_error(v,r,args...)   pbc_ngx_log((r)->connection->log,v,args)
#define ap_log_rerror(v,r,args...)  pbc_ngx_log((r)->connection->log,v,args)

#define ap_pstrdup(p,s) __ap_pstrdup(p,s)
#define ap_palloc(p,n)  ngx_palloc(p,n)
#define ap_pfree(p,v)   ngx_pfree(p,v)

#define ap_table_add(tbl,hdr,val) add_out_header(r,hdr,val,1)

typedef ngx_http_request_t request_rec;
typedef ngx_array_t table;


static table *
ap_make_table (ngx_pool_t *p, int n)
{
    return ngx_array_create(p, n, sizeof(ngx_hash_key_t));
}

static inline ngx_hash_key_t *
__ap_table_find (table *t, const char *key)
{
    ngx_hash_key_t *d = t->elts;
    ngx_uint_t i, n = strlen(key);
    for (i = 0; i < t->nelts; i++)
        if (d[i].key.len == n && 0 == strncmp((char *) d[i].key.data, key, n))
            return &d[i];
    return NULL;
}

static ngx_int_t
ap_table_set (table *t, const char *key, const char *value)
{
    ngx_hash_key_t *data = __ap_table_find(t, key);
    if (NULL == data && NULL == (data = ngx_array_push(t)))
        return NGX_ERROR;
    data->key.data = (u_char *) key;
    data->key.len = strlen(key);
    data->key_hash = 1;
    data->value = (void *) value;
    return NGX_OK;
}

static char *
ap_table_get (table *t, const char *key)
{
    ngx_hash_key_t *data = __ap_table_find(t, key);
    return data ? data->value : NULL;
}

static char *
ap_psprintf(ngx_pool_t *p, const char *fmt, ...)
{
    u_char *s, *e;
    va_list args;
    const int m = PBC_4K;

    if (NULL == (s = ngx_pnalloc(p, m)))
        return NULL;

    va_start(args, fmt);
    e = ngx_vslprintf(s, s + m - 1, fmt, args);
    va_end(args);
    *e = '\0';

#if AP_PSPRINTF_COMPACT_STRINGS
    if ((int)(e - s) < m / 2) {
        u_char *d = (u_char *) ap_pstrdup(p, (char *) s);
        if (NULL != d) {
            ap_pfree(p, s);
            s = d;
        }
    }
#endif /* AP_PSPRINTF_COMPACT_STRINGS */

    return (char *) s;
}

static char *
ap_rprintf(ngx_http_request_t *r, const char *fmt, ...)
{
    ngx_pubcookie_req_t *rr = ngx_http_get_module_ctx(r, ngx_pubcookie_module);
    u_char *s, *e, *d;
    int m, n;
    va_list args;

    if (NULL == (s = rr->msg.data)) {
        m = n = 0;
    } else {
        n = ngx_strlen(s);
        m = rr->msg.len;
    }

    if (m - n < PBC_1K) {
        m = n + PBC_4K;
        if (NULL == (d = ngx_pnalloc(r->pool, m)))
            return NULL;
        if (n > 0)
            ngx_memcpy(d, s, n);
        s = d;
    }

    va_start(args, fmt);
    e = ngx_vslprintf(s + n, s + (n + m - 1), fmt, args);
    va_end(args);
    *e = '\0';

    rr->msg.data = s;
    rr->msg.len = m;

    return (char *) e;
}

static char *
ap_getword_white (ngx_pool_t *pool, char **line)
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

static char *
ap_get_server_name (ngx_http_request_t *r)
{
    ngx_pubcookie_req_t *rr = ngx_http_get_module_ctx(r, ngx_pubcookie_module);
    if (! rr->server_name_tmp) {
        ngx_http_core_srv_conf_t *core_scf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
        rr->server_name_tmp = str2charp(r->pool, &core_scf->server_name);
    }
    return rr->server_name_tmp;
}

static int
ap_get_server_port (ngx_http_request_t *r)
{
    ngx_uint_t            port;
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    if (ngx_connection_local_sockaddr(r->connection, NULL, 0) != NGX_OK)
        return NGX_ERROR;

    switch (r->connection->local_sockaddr->sa_family) {
#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) r->connection->local_sockaddr;
        port = ntohs(sin6->sin6_port);
        break;
#endif
    default: /* AF_INET */
        sin = (struct sockaddr_in *) r->connection->local_sockaddr;
        port = ntohs(sin->sin_port);
        break;
    }

    return (port > 0 && port < 65536) ? (int) port : NGX_ERROR;
}

static char *
ap_make_dirstr_prefix(char *d, const char *s, int n)
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

static char *
ap_make_dirstr_parent (ngx_pool_t *p, const char *s)
{
    char *d;
    int l;

    if (!s || !*s) {
        return ap_pstrdup(p, "");
    }

    d = (char *) s + strlen(s) - 1;
    while (d != s && *d != '/')
        d--;

    if (*d != '/') {
        return ap_pstrdup(p, "");
    }
    l = (d - s) + 1;
    d = ngx_pnalloc(p, l + 1);
    ngx_memcpy(d, s, l);
    d[l] = 0;
    return (d);
}

static int 
ap_count_dirs (const char *path)
{
    register int x, n;
    for (x = 0, n = 0; path[x]; x++)
        if (path[x] == '/')
            n++;
    return n;
}


#if defined(REDIRECT_IN_HEADER)
/* c2x takes an unsigned, and expects the caller has guaranteed that
 * 0 <= what < 256... which usually means that you have to cast to
 * unsigned char first, because (unsigned)(char)(x) first goes through
 * signed extension to an int before the unsigned cast.
 *
 * The reason for this assumption is to assist gcc code generation --
 * the unsigned char -> unsigned extension is already done earlier in
 * both uses of this code, so there's no need to waste time doing it
 * again.
 */
static const char c2x_table[] = "0123456789abcdef";

static unsigned char *
c2x (unsigned what, unsigned char prefix, unsigned char *where)
{
    *where++ = prefix;
    *where++ = c2x_table[what >> 4];
    *where++ = c2x_table[what & 0xf];
    return where;
}

static char *
ap_os_escape_path (ngx_pool_t *p, const char *path, int partial)
{
    char *copy = (char *) ngx_pnalloc(p, 3 * strlen(path) + 3);
    const unsigned char *s = (const unsigned char *)path;
    unsigned char *d = (unsigned char *)copy;
    unsigned c;
    
    if (!partial) {
        const char *colon = strchr(path, ':');
        const char *slash = strchr(path, '/');
    
        if (colon && (!slash || colon < slash)) {
            *d++ = '.';
            *d++ = '/';
        }
    }
    while ((c = *s)) {
        if (!isalnum(c) && !strchr("$-_.+!*'(),:@&=/~", c)) {
            /* T_OS_ESCAPE_PATH */
            d = c2x(c, '%', d);
        } else {
            *d++ = c;
        }
        ++s;
    }
    *d = '\0';
    return copy;
}
#endif                                                                                          


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

static int
ngx_strcat3 (ngx_pool_t *pool, ngx_str_t *res, ngx_str_t *s1, ngx_str_t *s2, ngx_str_t *s3)
{
    u_char *p;
    int n, n1, n2, n3;
    n1 = s1 == NULL || s1->data == NULL ? 0 : s1->len == (size_t)-1 ? ngx_strlen(s1->data) : s1->len;
    n2 = s2 == NULL || s2->data == NULL ? 0 : s2->len == (size_t)-1 ? ngx_strlen(s2->data) : s2->len;
    n3 = s3 == NULL || s3->data == NULL ? 0 : s3->len == (size_t)-1 ? ngx_strlen(s3->data) : s3->len;
    n = n1 + n2 + n3 + 1;
    p = ngx_pnalloc(pool, n);
    if (p == NULL)
        return NGX_ERROR;
    if (n1)  ngx_memcpy(p, s1->data, n1);
    if (n2)  ngx_memcpy(p + n1, s2->data, n2);
    if (n3)  ngx_memcpy(p + n1 + n2, s3->data, n3);
    p[n1+n2+n3] = '\0';
    if (res == s1)
        ngx_pfree(pool, s1->data);
    else if (res == s2)
        ngx_pfree(pool, s2->data);
    else if (res == s3)
        ngx_pfree(pool, s3->data);
    res->data = p;
    res->len = n - 1;
    return NGX_OK;
}

static char *
ap_pstrcat3 (ngx_pool_t *pool, const char *s1, const char *s2, const char *s3)
{
    u_char *p;
    int n, n1, n2, n3;
    n1 = s1 ? strlen(s1) : 0;
    n2 = s2 ? strlen(s2) : 0;
    n3 = s3 ? strlen(s3) : 0;
    n = n1 + n2 + n3 + 1;
    p = ngx_pnalloc(pool, n);
    if (NULL == p)
        return NULL;
    if (n1)  ngx_memcpy(p, s1, n1);
    if (n2)  ngx_memcpy(p + n1, s2, n2);
    if (n3)  ngx_memcpy(p + n1 + n2, s3, n3);
    p[n1+n2+n3] = '\0';
    return (char *) p;
}

/**************************************
 * Requests
 */

static ngx_pubcookie_req_t *
pubcookie_setup_request (ngx_http_request_t *r)
{
    ngx_pubcookie_srv_t *scfg = ngx_http_get_module_srv_conf(r, ngx_pubcookie_module);
    ngx_pubcookie_req_t *rr = ngx_http_get_module_ctx(r, ngx_pubcookie_module);

    scfg->log = r->connection->log;
    scfg->pool = r->pool;

    if (NULL == rr) {
        if (NULL == (rr = ngx_pcalloc(r->pool, sizeof(ngx_pubcookie_req_t))))
            return NULL;
        if (NULL == (rr->notes = ap_make_table(r->pool, 4)))
            return NULL;
        ngx_http_set_ctx(r, rr, ngx_pubcookie_module);
        rr->user_name = blank_str;
        rr->user_full = blank_str;
    }

    return rr;
}

static ngx_int_t
pubcookie_finish_request (ngx_http_request_t *r)
{
    ngx_pubcookie_req_t *rr = ngx_http_get_module_ctx(r, ngx_pubcookie_module);
    ngx_buf_t *b;
    ngx_chain_t out;
    u_char *msg;
    int len;

    if (NULL == rr || NULL == rr->msg.data)
        return NGX_DECLINED;

    msg = rr->msg.data;
    len = ngx_strlen(msg);

    r->headers_out.status = rr->status ? rr->status : NGX_HTTP_OK;
    r->headers_out.content_length_n = len;
    r->headers_out.last_modified_time = r->start_sec;

    r->headers_out.content_type = pbc_content_type;
    r->headers_out.content_type_len = pbc_content_type.len;

    ngx_http_send_header(r);

    if (NULL == (b = ngx_create_temp_buf(r->pool, len)))
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    b->last = ngx_cpymem(b->last, msg, len);
    b->last_buf = 1;
    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

/**************************************
 *
 *           Main stuff
 *
 **************************************/

/**
 * get the post stuff 
 * @param r reuquest_rec
 * @return int 
 */
static void dummy_body_handler (ngx_http_request_t *r) {}

static
char *get_post_data (request_rec * r, int post_len)
{
    char *buffer;
    char *bp;
    ngx_int_t rc;
    ngx_chain_t *chain;
    int len;

    post_len = r->headers_in.content_length_n;
    if (post_len <= 0)
        return ap_pstrdup(r->pool, "");

    r->request_body_in_file_only = 0;
    r->request_body_in_single_buf = 1;
    rc = ngx_http_read_client_request_body(r, dummy_body_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
        return NULL;
    }

    if (NULL == (bp = buffer = (char *) ngx_pnalloc (r->pool, post_len + 1))) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    for (chain = r->request_body->bufs; NULL != chain; chain = chain->next) {
        if (chain->buf->in_file) {
            pc_req_log(r, "ERROR: please increase client_buffer_size");
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NULL;
        }
        len = chain->buf->last - chain->buf->pos;
        if (len > 0) {
            ngx_memcpy(bp, chain->buf->pos, len);
            bp += len;
        }
    }

    *bp = '\0';
    return (buffer);
}

/**
 * get a random int used to bind the granting cookie and pre-session
 * @returns random int or -1 for error
 * but, what do we do about that error?
 */
static
int get_pre_s_token (request_rec * r)
{
    int i;

    if ((i = libpbc_random_int(r)) == -1) {
        pc_req_log (r, "EMERG: get_pre_s_token: OpenSSL error");
    }

    ap_log_rerror (PC_LOG_DEBUG, r, "get_pre_s_token: token is %d", i);
    return (i);
}

/*                                                                            */
static
unsigned char *get_app_path (request_rec * r, const char *path)
{
    char *path_out;
    int truncate;
    ngx_pool_t *p = r->pool;
    ngx_pubcookie_srv_t *scfg = ngx_http_get_module_srv_conf(r, ngx_pubcookie_module);
    char *a;

    if (scfg->dirdepth) {
        if (scfg->dirdepth < ap_count_dirs(path))
            truncate = scfg->dirdepth;
        else
            truncate = ap_count_dirs (path);
        path_out = ap_palloc(p, strlen (path) + 1);
        ap_make_dirstr_prefix (path_out, path, truncate);
    } else {
        path_out = ap_make_dirstr_parent (p, path);
    }

    for (a = path_out; *a; a++)
        if (*a != '/' && !isalnum(*a))
            *a = '_';
    return (unsigned char *) path_out;
}

/*
 * URL encode a base64 (deal with '+')
 */
static char *
fix_base64_for_url (ngx_pool_t *p, char *b64)
{
   int n;
   char *np;
   char *n64;
   for (n=0, np=b64; *np; np++) if (*np=='+') n++;
   if (n>0) {
       n64 = ngx_pcalloc (p, (strlen (b64) + 4*n));
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

/*
 * figure out the appid
 */
static u_char *
appid (ngx_http_request_t * r)
{
    ngx_pool_t *p = r->pool;
    ngx_pubcookie_loc_t *cfg = ngx_http_get_module_loc_conf(r, ngx_pubcookie_module);
    ngx_pubcookie_srv_t *scfg = ngx_http_get_module_srv_conf(r, ngx_pubcookie_module);
    ngx_pubcookie_req_t *rr = ngx_http_get_module_ctx(r, ngx_pubcookie_module);
    ngx_str_t res;

    if (NULL == rr->app_path.data) {
        char *main_uri_path = str2charp(r->pool, &(main_rrec(r)->uri));
        rr->app_path.data = get_app_path(r, main_uri_path);
    }

    /* Added by ddj@cmu.edu on 2006/05/10. */
    if (scfg->catenate) {	/* Catenate app IDs? */
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
        return (cfg->appid.data ? cfg->appid.data : rr->app_path.data);
    }
}

/*
 * figure out the appsrvid
 */
static u_char *
appsrvid (ngx_http_request_t * r)
{
    ngx_pubcookie_srv_t *scfg = ngx_http_get_module_srv_conf(r, ngx_pubcookie_module);

    if (scfg->appsrvid.data) {
        return scfg->appsrvid.data;
    } else {
        /* because of multiple passes through don't use r->hostname() */
        return (u_char *) ap_get_server_name(r);
    }
}

/*
 * figure out the session cookie name
 */
static char *
make_session_cookie_name (ngx_pool_t * p, char *cookiename, u_char *_appid)
{
    /* 
       we now use JimB style session cookie names
       session cookie names are PBC_S_COOKIENAME_appid 
     */

    char *ptr;
    char *name;

    name = (char *) ngx_pnalloc(p, strlen(cookiename) + strlen((char *)_appid) + 2);
    strcpy(name, cookiename);
    strcat(name, "_");
    strcat(name, (const char *) _appid);

    ptr = name;
    while (*ptr) {
        if (*ptr == '/')
            *ptr = '_';
        ptr++;
    }

    return name;
}

/*
 * ?
 */
static int
check_end_session (ngx_http_request_t * r)
{
    ngx_pubcookie_loc_t *cfg = ngx_http_get_module_loc_conf(r, ngx_pubcookie_module);
    ngx_pool_t *p = r->pool;
    int ret = 0;
    char *end_session = str2charp(p, &cfg->end_session);
    char *word;

    /* check list of end session args */
    while (end_session != NULL && *end_session != '\0' &&
           (word = ap_getword_white(p, &end_session))) {

        if (strcasecmp(word, PBC_END_SESSION_ARG_REDIR) == 0) {
            ret = ret | PBC_END_SESSION_REDIR;
        }
        if (strcasecmp(word, PBC_END_SESSION_ARG_CLEAR_L) == 0) {
            ret = ret | PBC_END_SESSION_CLEAR_L | PBC_END_SESSION_REDIR;
        } else if (strcasecmp (word, PBC_END_SESSION_ARG_ON) == 0) {
            ret = ret | PBC_END_SESSION_ONLY;
        } else if (strcasecmp(word, PBC_END_SESSION_ARG_OFF) == 0) {
            /* off means off, nothing else */
            return (PBC_END_SESSION_NOPE);
        }
    }

    return (ret);
}

/*
 * push another cookie to client
 */
static int
add_out_header (ngx_http_request_t *r, const char *name, const char *value, int free_value)
{
    ngx_table_elt_t *hdr;

    if (NULL == (hdr = ngx_list_push(&r->headers_out.headers))) {
        pc_req_log(r, "cannot allocate memory for header structure");
        return NGX_ERROR;
    }
    hdr->hash = 1;
    hdr->key.data = (u_char *) name;
    hdr->key.len = ngx_strlen((u_char *) name);

    if (NULL == (hdr->value.data = (u_char *) ap_pstrdup(r->pool, (char *) value))) {
        pc_req_log(r, "cannot allocate memory for header value");
        return NGX_ERROR;
    }
    hdr->value.len = strlen(value);

    pc_req_log(r, "out_header[%s]:\"%s\"", name, value);
    if (free_value)
        ap_pfree(r->pool, (void *) value);

    return NGX_OK;
}

/*
 * make sure agents don't cache the redirect
 */
static void
set_no_cache_headers (ngx_http_request_t * r)
{
    ngx_pubcookie_req_t *rr = ngx_http_get_module_ctx(r, ngx_pubcookie_module);
    if (! rr->no_cache_set) {
        char buf[32];
        *( ngx_http_time((u_char *) buf, r->start_sec) ) = '\0';
        add_out_header (r, "Expires", buf, 0);
        add_out_header (r, "Cache-Control", "no-store, no-cache, must-revalidate", 0);
        add_out_header (r, "Pragma", "no-cache", 0);
        rr->no_cache_set = 1;
    }
}

/*
 * set or reset the session cookie.
 * Called from the user hook.
 */
static void
set_session_cookie (ngx_http_request_t * r,
                    ngx_pubcookie_loc_t * cfg, ngx_pubcookie_srv_t * scfg,
                    ngx_pubcookie_req_t * rr, int firsttime)
{
    ngx_pool_t *p = r->pool;
    char *new_cookie;
    u_char *cookie;

    if (firsttime != 1) {
        /* just update the idle timer */
        /* xxx it would be nice if the idle timeout has been disabled
           to avoid recomputing and resigning the cookie? */
        cookie =
            libpbc_update_lastts (r, scfg->sectext, rr->cookie_data, ME(r),
                                  0, scfg->crypt_alg);
    } else {
        /* create a brand new cookie, initialized with the present time */
        cookie = libpbc_get_cookie (r,
                                    scfg->sectext,
                                    rr->user_full.data,
                                    (u_char *) PBC_VERSION,
                                    PBC_COOKIE_TYPE_S,
                                    rr->creds,
                                    (cfg->session_reauth < 0) ? 23 : 24,
                                    (u_char *) appsrvid(r),
                                    appid(r),
                                    ME(r), 0, scfg->crypt_alg);
    }

    new_cookie = ap_psprintf(p, "%s=%s; path=%s;%s",
                              make_session_cookie_name (p,
                                                        PBC_S_COOKIENAME,
                                                        (u_char *) appid(r)),
                              cookie, "/", secure_cookie);
    ap_table_add (HDRS_OUT, "Set-Cookie", new_cookie);

    if (firsttime && rr->cred_transfer.data) {
        char *blob = NULL;
        int bloblen;
        char *base64 = NULL;
        int res = 0;

        /* save the transfer creds in a cookie; we only need to do this
           the first time since our cred cookie doesn't expire (which is poor
           and why we need cookie extensions) */
        /* encrypt */
        if (libpbc_mk_priv (r, scfg->sectext, ME(r), 0, (char *) rr->cred_transfer.data,
                            rr->cred_transfer.len, &blob, &bloblen,
                            scfg->crypt_alg)) {
            pc_req_log(r,
                           "ERROR: credtrans: libpbc_mk_priv() failed");
            res = -1;
        }

        /* base 64 */
        if (!res) {
            base64 = ngx_palloc(p, (bloblen + 3) / 3 * 4 + 1);
            if (!libpbc_base64_encode (r, (u_char *) blob,
                                       (u_char *) base64,
                                       bloblen)) {
                pc_req_log(r,
                               "ERROR: credtrans: libpbc_base64_encode() failed");
                res = -1;
            }
        }

        /* set */
        new_cookie = ap_psprintf(p, "%s=%s; path=%s;%s",
                                  make_session_cookie_name (p,
                                                            PBC_CRED_COOKIENAME,
                                                            appid(r)),
                                  base64, "/", secure_cookie);
        ap_table_add (HDRS_OUT, "Set-Cookie", new_cookie);

        /* xxx eventually when these are just cookie extensions, they'll
           automatically be copied from the granting cookie to the 
           session cookies and from session cookie to session cookie */
    }

    ap_pfree(p, new_cookie);
}

/*
 * clear granting cookie
 */
static void
clear_granting_cookie (ngx_http_request_t * r)
{
    ngx_pubcookie_srv_t *scfg = ngx_http_get_module_srv_conf(r, ngx_pubcookie_module);
    char *new_cookie;

    if (scfg->use_post)
        new_cookie = ap_psprintf(r->pool, "%s=; path=/; expires=%s;%s",
                                  PBC_G_COOKIENAME,
                                  EARLIEST_EVER, secure_cookie);
    else
        new_cookie = ap_psprintf(r->pool, "%s=; domain=%s; path=/; expires=%s;%s",
                         PBC_G_COOKIENAME, PBC_ENTRPRS_DOMAIN,
                         EARLIEST_EVER, secure_cookie);

    pc_req_log(r,
               "clear_granting_cookie: setting cookie: %s",
               new_cookie);

    ap_table_add (HDRS_OUT, "Set-Cookie", new_cookie);
}

/*
 * clear cred transfer cookie
 */
static void
clear_transfer_cookie (ngx_http_request_t * r)
{
    char *new_cookie;

    new_cookie = ap_psprintf(r->pool,
                              "%s=; domain=%s; path=/; expires=%s;%s",
                              PBC_CRED_TRANSFER_COOKIENAME,
                              PBC_ENTRPRS_DOMAIN,
                              EARLIEST_EVER, secure_cookie);

    ap_table_add (HDRS_OUT, "Set-Cookie", new_cookie);
}

/*
 * clear pre session cookie
 */
static void
clear_pre_session_cookie (ngx_http_request_t * r)
{
    char *new_cookie;

    new_cookie = ap_psprintf(r->pool,
                              "%s=; path=/; expires=%s;%s",
                              PBC_PRE_S_COOKIENAME,
                              EARLIEST_EVER, secure_cookie);

    ap_table_add (HDRS_OUT, "Set-Cookie", new_cookie);
}

static int
clear_session_cookie (ngx_http_request_t * r)
{
    ngx_pubcookie_req_t *rr = ngx_http_get_module_ctx(r, ngx_pubcookie_module);
    char *new_cookie;

    if (NULL == rr)
        return NGX_OK;

    new_cookie = ap_psprintf(r->pool,
                              "%s=%s; path=/; expires=%s;%s",
                              make_session_cookie_name (r->pool,
                                                        PBC_S_COOKIENAME,
                                                        appid(r)),
                              PBC_CLEAR_COOKIE, EARLIEST_EVER,
                              secure_cookie);
    ap_table_add (HDRS_OUT, "Set-Cookie", new_cookie);

    if (NULL != rr->cred_transfer.data) {
        /* extra cookies (need cookie extensions) */
        new_cookie = ap_psprintf(r->pool,
                                  "%s=%s; path=/; expires=%s;%s",
                                  make_session_cookie_name (r->pool,
                                                            PBC_CRED_COOKIENAME,
                                                            appid(r)),
                                  PBC_CLEAR_COOKIE,
                                  EARLIEST_EVER, secure_cookie);

        ap_table_add (HDRS_OUT, "Set-Cookie", new_cookie);
    }

    return NGX_OK;
}

/**
 * process end session redirects
 * @param r the apache request rec
 * @return OK to let Apache know to finish the request
 *
 * Called from the check user hook 
 */
static int
do_end_session_redirect (ngx_http_request_t * r,
                         ngx_pubcookie_loc_t *cfg,
                         ngx_pubcookie_srv_t *scfg,
                         ngx_pubcookie_req_t *rr)
{
    char *refresh;
    pc_req_log(r, "do_end_session_redirect: hello");

    clear_granting_cookie(r);
    clear_pre_session_cookie(r);
    clear_session_cookie(r);
    set_no_cache_headers(r);

    refresh = ap_psprintf(r->pool, "%d;URL=%s?%s=%d&%s=%s&%s=%s",
                           PBC_REFRESH_TIME,
                           str2charp(r->pool, &scfg->login),
                           PBC_GETVAR_LOGOUT_ACTION,
                           (check_end_session(r) & PBC_END_SESSION_CLEAR_L
                            ? LOGOUT_ACTION_CLEAR_L : LOGOUT_ACTION_NOTHING),
                           PBC_GETVAR_APPID,
                           appid(r),
                           PBC_GETVAR_APPSRVID,
                           appsrvid(r));
    ap_rprintf(r, redirect_html, refresh);
    ap_pfree(r->pool, refresh);

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

static int
stop_the_show (ngx_http_request_t *r, ngx_pubcookie_srv_t *scfg,
               ngx_pubcookie_loc_t *cfg, ngx_pubcookie_req_t *rr)
{
    const char *admin = "postmaster@this.server";
    const char *msg = rr->stop_message ? rr->stop_message : "";

    pc_req_log(r, "stop_the_show: hello");

    clear_granting_cookie(r);
    clear_pre_session_cookie(r);
    clear_session_cookie(r);
    set_no_cache_headers(r);

    ap_rprintf(r, stop_html, admin, msg);
    rr->status = NGX_HTTP_BAD_REQUEST;

    return NGX_OK;
}

/*
 * Since we blank out cookies, they're stashed in the notes table.
 * blank_cookie only stashes in the topmost request's notes table, so
 * that's where we'll look.
 *
 * We don't bother with using the topmost request when playing with the
 * headers because only the pointer is copied, anyway.
 */
static char *
get_cookie (ngx_http_request_t * r, char *name, int n)
{
    ngx_pubcookie_srv_t *scfg = ngx_http_get_module_srv_conf(r, ngx_pubcookie_module);
    ngx_pubcookie_req_t *mrr = ngx_http_get_module_ctx(top_rrec(r), ngx_pubcookie_module);
    ngx_pool_t *p = r->pool;
    ngx_table_elt_t **cph;

    const char *cookie_header;
    char *chp;
    char *cookie, *ptr;
    char *name_w_eq;
    int i;

    ap_log_rerror (PC_LOG_DEBUG, r, "get_cookie: %s (%d)", name, n);

    /* get cookies */
    if ((n==0) && (cookie_header = ap_table_get (mrr->notes, name))&&(*cookie_header)) {
        ap_log_rerror (PC_LOG_DEBUG, r, " .. by cache: %s", cookie_header);
        return ap_pstrdup (p, cookie_header);
    }

    cph = r->headers_in.cookies.elts;
    cookie_header = NULL;
    for (i = 0; i < (int) r->headers_in.cookies.nelts; i++, cph++) {    
        if (ngx_strcmp_c((**cph).key, "Cookie")) {
            cookie_header = str2charp(p, &(**cph).value);
            pc_req_log(r, " .. summary Cookie[%s]", cookie_header);
            break;
        }
    }
    if (NULL == cookie_header) {
        pc_req_log(r, " .. cookies not found");
        return (NULL);
    }

    /* add an equal on the end */
    name_w_eq = ap_pstrcat3 (p, name, "=", NULL);

    /* find the one that's pubcookie */
    for (chp=(char*)cookie_header,i=0;i<=n;i++) {
       if (!(chp = strstr(chp, name_w_eq))) break;
       chp += strlen (name_w_eq);
    }

    cookie = ap_pstrdup (p, chp);
    ap_pfree(p, (char *)cookie_header);
    ap_pfree(p, name_w_eq);
    if (NULL == chp)  return NULL;    

    /* remove ';' */
    for (ptr = cookie; *ptr; ptr++) {
        if (*ptr == ';') {
            *ptr = 0;
            break;
        }
    }
    ptr = ap_pstrdup (r->pool, cookie);
    ngx_pfree(r->pool, cookie);
    cookie = ptr;

    /* cache and blank cookie */
    ap_table_set (mrr->notes, name, cookie);
    if (!scfg->noblank) {
       off_t off = (off_t)((char *)((**cph).value.data) - (char *)cookie_header);
       for (ptr=chp; *ptr&&*ptr!=';'; ptr++) *(ptr + off) = PBC_X_CHAR;
       pc_req_log(r, " .. blanked \"%V\"", &(**cph).value);
    }

    if (*cookie) {
        ap_log_rerror (PC_LOG_DEBUG, r, " .. return: %s", cookie);
        return cookie;
    }
    return (NULL);
}

/*
 * ?
 */
static int
get_pre_s_from_cookie (ngx_http_request_t * r)
{
    ngx_pubcookie_srv_t *scfg = ngx_http_get_module_srv_conf(r, ngx_pubcookie_module);

    pbc_cookie_data *cookie_data = NULL;
    char *cookie = NULL;
    int ccnt = 0;

    pc_req_log(r, "retrieving a pre-session cookie");
    while (NULL != (cookie = get_cookie (r, PBC_PRE_S_COOKIENAME, ccnt))) {
        cookie_data = libpbc_unbundle_cookie (r, scfg->sectext,
                                              cookie, ME(r), 0,
                                              scfg->crypt_alg);
        if (cookie_data) break;
        pc_req_log(r,
                       "INFO: get_pre_s_from_cookie: can't unbundle pre_s cookie uri: %V\n",
                       &r->uri);
        ccnt++;
    }
    if (!cookie_data) {
        pc_req_log(r,
                       "INFO: get_pre_s_from_cookie: no pre_s cookie, uri: %V\n",
                       &r->uri);
        return (-1);
    }

    dump_cookie_data(r, "get_pre_s_from_cookie", cookie_data);
    return ((*cookie_data).broken.pre_sess_token);

}

/***************************************************************************
 * Handle the post-method reply from the login server.
 *  Activated by:
 *      <Location /PubCookie.reply>
 *        SetHandler pubcookie-post-reply
 *      </Location>
 */

/*
 * Herein we deal with the redirect of the request to the login server
 * if it was only that simple ...
 */
static int
auth_failed_handler (ngx_http_request_t * r,
                     ngx_pubcookie_loc_t *cfg,
                     ngx_pubcookie_srv_t *scfg,
                     ngx_pubcookie_req_t *rr)
{
    ngx_pool_t *p = r->pool;
    char *refresh = NULL;
    char *pre_s;
    char *pre_s_cookie;
    char *g_req_cookie;
    char *g_req_contents = NULL;
    int g_req_contents_len;
    char *e_g_req_contents = NULL;
    const char *tenc = get_hdr_in(r,transfer_encoding);
    const char *ctype = get_hdr_in(r,content_type);
    const char *lenp = get_hdr_in(r,content_length);
    char *host = NULL;
    char *args;
    char *refresh_e;
    ngx_http_request_t *mr = top_rrec(r);
    char misc_flag = '0';
    char *file_to_upld = NULL;
    const char *referer;
    int pre_sess_tok;
    int port;
    char *post_data;
    char vstr[4];
    char *b64uri;

    pc_req_log(r, "auth_failed_handler: hello");

    if (r->main != r) {
        pc_req_log(r, " .. in subrequest: retuning noauth");
        return (NGX_HTTP_UNAUTHORIZED);
    }

    if (cfg->noprompt > 0)
        misc_flag = 'Q';

    /* reset these dippy flags */
    rr->failed = 0;

    /* acquire any GET args */
    if (r->args.data) {
        char *argst;
        /* error out if length of GET args would cause a problem */
        if (r->args.len > PBC_MAX_GET_ARGS) {
            rr->stop_message = ap_psprintf(p,
                             "GET arguments longer than supported.  (args length: %d)",
                             r->args.len);
            stop_the_show (r, scfg, cfg, rr);
            return (NGX_OK);
        }

        argst = ngx_pcalloc (p, (r->args.len + 3) / 3 * 4 + 1);
        libpbc_base64_encode (r, r->args.data, (u_char *) argst, r->args.len);
        pc_req_log(r,
                       "GET args before encoding length %d, string: %s",
                       r->args.len, r->args.data);
        args = fix_base64_for_url(p, argst);
        pc_req_log(r,
                       "GET args after encoding length %d, string: %s",
                       strlen (args), args);
    } else {
        args = "";
    }

    r->headers_out.content_type = pbc_content_type;
    r->headers_out.content_type_len = pbc_content_type.len;

    /* if there is a non-standard port number just tack it onto the hostname  */
    /* the login server just passes it through and the redirect works         */
    port = ap_get_server_port (r);
    if (port != 80 && port != 443 && !scfg->behind_proxy) {
        /* because of multiple passes through don't use r->hostname() */
        host = ap_psprintf(p, "%s:%d", ap_get_server_name(r), port);
    }

    /* To knit the referer history together */
    referer = get_hdr_in(r, referer);
    if (NULL == referer)
        referer = "";

    if ((pre_sess_tok = get_pre_s_token (r)) == -1) {
        /* this is weird since we're already in a handler */
        rr->stop_message = "Couldn't get pre session token. (Already in handler)";
        stop_the_show (r, scfg, cfg, rr);
        return (NGX_OK);
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
        b64uri = ngx_pcalloc (p, (mr->uri.len + 3) / 3 * 4 + 1);
        libpbc_base64_encode (r, mr->uri.data,
                              (u_char *) b64uri, mr->uri.len);
        pc_req_log (r,
                       "Post URI before encoding length %d, string: %V",
                       mr->uri.len, &mr->uri);
        pc_req_log (r,
                       "Post URI after encoding length %d, string: %s",
                       strlen (b64uri), b64uri);
    } else {
        b64uri = str2charp(p, &mr->uri);
        pc_req_log(r, "b64uri(GET):(%s)", b64uri);
    }

    g_req_contents = ap_psprintf (p,
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
                 str2charp(p, &r->main->method_name),
                 PBC_GETVAR_HOST,
                 host ? host : ap_get_server_name(r),
                 PBC_GETVAR_URI,
                 b64uri,
                 PBC_GETVAR_ARGS,
                 args,
                 PBC_GETVAR_REAL_HOST,
                 ap_get_server_name(r), /*FIXME: r->server->server_hostname*/
                 PBC_GETVAR_APPSRV_ERR,
                 rr->redir_reason_no,
                 PBC_GETVAR_FILE_UPLD,
                 (file_to_upld ? file_to_upld : ""),
                 PBC_GETVAR_REFERER,
                 referer,
                 PBC_GETVAR_SESSION_REAUTH,
                 (cfg->session_reauth == PBC_UNSET_SESSION_REAUTH ? PBC_SESSION_REAUTH_NO : cfg->session_reauth),
                 PBC_GETVAR_PRE_SESS_TOK,
                 pre_sess_tok,
                 PBC_GETVAR_FLAG, misc_flag);

    g_req_contents_len = strlen(g_req_contents);

    if (NULL != cfg->addl_requests.data && cfg->addl_requests.len > 0) {
        pc_req_log (r,
                       "auth_failed_handler: adding %V",
                       &cfg->addl_requests);
        
        ngx_memcpy((u_char *) g_req_contents + g_req_contents_len,
                    cfg->addl_requests.data, cfg->addl_requests.len);
        g_req_contents[g_req_contents_len += cfg->addl_requests.len] = '\0';
    }

    pc_req_log (r,
                   "g_req before encoding length %d, string: %s",
                   g_req_contents_len, g_req_contents);

    /* setup the client pull */
    refresh = ap_psprintf (p, "%d;URL=%V",
                    PBC_REFRESH_TIME, &scfg->login);

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
        ngx_pcalloc (p, (g_req_contents_len + 3) / 3 * 4 + 1);
    libpbc_base64_encode (r, (u_char *) g_req_contents,
                          (u_char *) e_g_req_contents,
                          g_req_contents_len);

    ap_pfree(p, g_req_contents);
    g_req_contents = NULL;

    /* The GET method requires a pre-session cookie */

    if (!scfg->use_post) {
        pc_req_log (r, "making a pre-session cookie");
        pre_s = (char *) libpbc_get_cookie (r,
                                            scfg->sectext,
                                            (unsigned char *) "presesuser",
                                            (unsigned char *) PBC_VERSION,
                                            PBC_COOKIE_TYPE_PRE_S,
                                            PBC_CREDS_NONE,
                                            pre_sess_tok,
                                            (unsigned char *) appsrvid (r),
                                            appid(r), ME(r), 0,
                                            scfg->crypt_alg);
        if (NULL == pre_s) {
            rr->stop_message = "Failure making pre-session cookie";
            stop_the_show(r, scfg, cfg, rr);
            goto END;
        }

        pre_s_cookie = ap_psprintf(p,
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
                     sizeof("multipart/form-data")-1)) {
        rr->stop_message = "multipart/form-data not allowed";
        stop_the_show (r, scfg, cfg, rr);
        goto END;
    }

    /* we handle post data unless it is too large, in which */
    /* case we treat it much like multi-part form data. */

    post_data = "";
    if (r->headers_in.content_length_n > 0) {
        int post_data_len = r->headers_in.content_length_n;
        if (post_data_len > MAX_POST_DATA ||
            NULL == (post_data = get_post_data (r, post_data_len))) {
            rr->stop_message = ap_psprintf(p,
                             "Invalid POST data. (POST data length: %d)",
                             post_data_len);
            stop_the_show (r, scfg, cfg, rr);
            goto END;
        }
    }

    if (!scfg->use_post) {
        /* GET method puts granting request in a cookie */
        g_req_cookie = ap_psprintf (p,
                     "%s=%s; domain=%s; path=/;%s",
                     PBC_G_REQ_COOKIENAME,
                     e_g_req_contents, PBC_ENTRPRS_DOMAIN, secure_cookie);

        pc_req_log (r,
                       "g_req length %d cookie: %s", strlen (g_req_cookie),
                       g_req_cookie);
        ap_table_add (HDRS_OUT, "Set-Cookie", g_req_cookie);


#ifdef REDIRECT_IN_HEADER
        if (!(tenc || lenp)) {
            refresh_e = ap_os_escape_path (p, refresh, 0);
            /* warning, this will break some browsers */
            ap_table_add (HDRS_OUT, "Refresh", refresh_e);
        }
#endif
    }

    /* If we're using the post method, just bundle everything
       in a post to the login server. */

    if (scfg->use_post) {
        u_char cp[12];
        if ((port == 80 || port == 443) && !scfg->behind_proxy)
            *cp = '\0';
        else
            ngx_sprintf (cp, ":%d%Z", port);

        ap_rprintf(r, post_request_html,
                    str2charp(p, &scfg->login),
                    e_g_req_contents,
                    encode_get_args(r, post_data, 1),
                    ap_get_server_name(r),
                    cp,
                    str2charp(p, &scfg->post_url) + 1 /* skip first slash */
                    );

    } else if (ctype && (tenc || lenp || r->method == NGX_HTTP_POST)) {
        ap_rprintf(r, get_post_request_html,
                    str2charp(p, &scfg->login),
                    encode_get_args(r, post_data, 1),
                    str2charp(p, &scfg->login),
                    PBC_WEBISO_LOGO,
                    PBC_POST_NO_JS_BUTTON);

    } else {
#ifdef REDIRECT_IN_HEADER
/* warning, this will break some browsers */
        ap_rprintf(r, nullpage_html);
#else
        ap_rprintf(r, redirect_html, refresh);
#endif
    }

    pc_req_log (r,
                   "auth_failed_handler: redirect sent. uri: %V reason: %d",
                   &mr->uri, rr->redir_reason_no);

    /* workaround for nginx problems with KeepAlive during redirections. */
    r->keepalive = 0;

END:
    if (NULL != refresh)
        ap_pfree(p, refresh);
    if (NULL != g_req_contents)
        ap_pfree(p, g_req_contents);
    if (NULL != e_g_req_contents)
        ap_pfree(p, e_g_req_contents);

    return (OK);
}

/**************************************
 *  User authentication
 */

static int
pubcookie_user_hook (ngx_http_request_t * r)
{
    ngx_pubcookie_loc_t *cfg = ngx_http_get_module_loc_conf(r, ngx_pubcookie_module);
    ngx_pubcookie_srv_t *scfg = ngx_http_get_module_srv_conf(r, ngx_pubcookie_module);
    ngx_pubcookie_req_t *rr = ngx_http_get_module_ctx(r, ngx_pubcookie_module);

    int s;
    int first_time_in_session = 0;
    char creds;

    /* pass if the request is for our post-reply */
    if (ngx_strcmp_eq(r->uri, scfg->post_url))
        return NGX_OK;

    /* get pubcookie creds or bail if not a pubcookie auth_type */
    if ((creds = pubcookie_auth_type(r)) == PBC_CREDS_NONE)
        return NGX_DECLINED;

    /* pass if the request is for favicon.ico */
    if (ngx_strcasecmp_c(r->uri, "/favicon.ico"))
        return NGX_OK;

    rr->creds = creds;
    s = pubcookie_user(r, cfg, scfg, rr);
    if (rr->failed) {
        pc_req_log(r, " .. user_hook: user failed");
        if (rr->failed == PBC_BAD_G_STATE) {
            pc_req_log(r, " .. user_hook: Can't use Granting cookie");
            stop_the_show(r, scfg, cfg, rr);
            return DONE;
        } else if (rr->failed == PBC_BAD_USER) {
            pc_req_log(r, " .. user_hook: bad user");
            ap_rprintf(r, "Unauthorized user.");
            return DONE;
        }
        auth_failed_handler(r, cfg, scfg, rr);
        return DONE;
    }
    pc_req_log(r, " .. user_hook: user '%V' OK", &rr->user_name);

    if (rr->has_granting) {
        pc_req_log(r, " .. user_hook: new session");
        first_time_in_session = 1;
        rr->has_granting = 0;
    }

    if (check_end_session(r) & PBC_END_SESSION_REDIR) {
        do_end_session_redirect(r, cfg, scfg, rr);
        return DONE;
    } else if (check_end_session(r) & PBC_END_SESSION_ANY) {
        clear_session_cookie(r);
        rr->user_name = blank_str;        /* rest of apache needs a user if there's an authtype */
    } else if (cfg->inact_exp > 0 || first_time_in_session) {
        if ((!first_time_in_session) && (!rr->cookie_data)) {
            pc_req_log(r, " .. user_hook: not first and no data! (sub?)");
        } else {
            set_session_cookie(r, cfg, scfg, rr, first_time_in_session);
        }
    }

    /* Since we've done something any "if-modified"s must be cancelled
       to prevent "not modified" responses.  There may be other "if"s
       (see: http_protocol.c:ap_meets_conditions) that we are not
       considering as they have not yet come up. */

    if (NULL != r->headers_in.if_modified_since) {
        pc_req_log(r, " .. user_hook: removing if-modified = %V",
                    &r->headers_in.if_modified_since->value);
        r->headers_in.if_modified_since = NULL;
    }

    pc_req_log(r, " .. user_hook exit");
    
    return (s);
}

/*
 * Check user id
 */
static int
pubcookie_user (ngx_http_request_t * r,
                ngx_pubcookie_loc_t *cfg,
                ngx_pubcookie_srv_t *scfg,
                ngx_pubcookie_req_t *rr)
{
    char *cookie;
    pbc_cookie_data *cookie_data;
    ngx_pool_t *p = r->pool;
    char *sess_cookie_name;
    int cred_from_trans;
    int pre_sess_from_cookie;
    int gcnt = 0;
    int scnt = 0;

    pc_req_log(r, "pubcookie_user: going to check uri: %V creds: %c", &r->uri, rr->creds);

    /* maybe dump the directory and server recs */
    dump_recs(r, cfg, scfg);

    sess_cookie_name = make_session_cookie_name(p, PBC_S_COOKIENAME, appid(r));

    /* force SSL */

    if (! r->connection->ssl)
    {
        pc_req_log(r, "Not SSL; uri: %V appid: %s", &r->uri, appid (r));
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_NOGORS_CODE;
        return NGX_OK;
    }

    /* before we check if they hav a valid S or G cookie see if it's a logout */
    if (check_end_session (r) & PBC_END_SESSION_ANY) {
        return NGX_OK;
    }

    pc_req_log(r,
               "pubcookie_user: about to look for some cookies; current uri: %V",
               &r->uri);

    /* check if we hav a granting cookie's and a pre-session cookie.
       when using GET method we need the pair (pre sess and granting), but 
       when using POST method there is no pre-session cookie used.  
       if the granting cookie fails to decrypt (unbundle) we move on to look 
       at the session cookie(s).  The assumption is that graning cookies that 
       fail to decrypt aren't for our app server.  In cases where the crypt
       key is incorrect on the app server this will cause looping */
    cookie_data = NULL;
    while ((cookie = get_cookie(r, PBC_G_COOKIENAME, gcnt))
        && (scfg->use_post || get_cookie(r, PBC_PRE_S_COOKIENAME, 0))) {
        cookie_data = libpbc_unbundle_cookie(r, scfg->sectext, cookie,
                                             (char *) ap_get_server_name(r), 1, scfg->crypt_alg);
        if (cookie_data)
            break;
        pc_req_log(r,
                   "can't unbundle G cookie, it's probably not for us; uri: %V\n",
                   &r->uri);
        gcnt++;
        clear_granting_cookie(r);
    }

    /* If no valid granting cookie, check session cookie  */
    if (NULL == cookie_data
        || ngx_strncasecmp ((u_char *) appid(r),
                            (u_char *) cookie_data->broken.appid,
                            sizeof(cookie_data->broken.appid) - 1) != 0)
    {
        char *ckfix;
        while (NULL != (cookie = get_cookie(r, sess_cookie_name, scnt))) {
            int cookie_len = strlen(cookie);
            cookie_data =
                libpbc_unbundle_cookie (r, scfg->sectext, cookie, ME(r), 0,
                                        scfg->crypt_alg);

            if (cookie_data)
                break;

            /* try 'fixing' the cookie */
            pc_req_log(r,
                       "retring failed unbundle of S cookie; uri: %V\n",
                       &r->uri);
            ckfix = ngx_pnalloc(p, cookie_len + 3);
            strcpy(ckfix, cookie);
            strcat(ckfix, "==");
            cookie_data = libpbc_unbundle_cookie (r, scfg->sectext, ckfix,
                                                    ME(r), 0, scfg->crypt_alg);
            if (cookie_data)
                break;

            pc_req_log(r,
                       "still can't unbundle S cookie; uri: %V\n",
                       &r->uri);
            scnt++;
        }

        if (cookie_data) {

            dump_cookie_data(r, "pubcookie_user.1", cookie_data);
            rr->cookie_data = cookie_data;

            /* we tell everyone what authentication check we did */
            ngx_str_assign_copy(p, &rr->user_name, cookie_data->broken.user);

            /* save the full user/realm for later */
            ngx_str_assign_copy(p, &rr->user_full, cookie_data->broken.user);

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
                           (thisrealm = ap_getword_white(p, &okrealms))) {
                        if (strcmp (thisrealm, tmprealm) == 0) {
                            realmmatched++;
                        }
                    }
                    if (realmmatched == 0) {
                        return NGX_HTTP_UNAUTHORIZED;
                    }
                }
            }

            if (libpbc_check_exp(r, cookie_data->broken.create_ts, cfg->hard_exp) == PBC_FAIL) {
                pc_req_log(r,
                           "S cookie hard expired; user: %s cookie timestamp: %d timeout: %d now: %d uri: %V\n",
                           cookie_data->broken.user,
                           cookie_data->broken.create_ts,
                           cfg->hard_exp, pbc_time (NULL), &r->uri);
                rr->failed = PBC_BAD_AUTH;
                rr->redir_reason_no = PBC_RR_SHARDEX_CODE;
                return NGX_OK;
            }

            if (cfg->inact_exp != -1 &&
                libpbc_check_exp(r, cookie_data->broken.last_ts,
                                  cfg->inact_exp) == PBC_FAIL) {
                pc_req_log(r,
                           "S cookie inact expired; user: %s cookie timestamp %d timeout: %d now: %d uri: %V\n",
                           cookie_data->broken.user,
                           cookie_data->broken.last_ts,
                           cfg->inact_exp, pbc_time (NULL), &r->uri);
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
                       "S cookie chk nop: user=%V, nop=%d", &rr->user_name,
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
                       "No G or S cookie; uri: %V appid: %s sess_cookie_name: %s",
                       &r->uri, appid (r), sess_cookie_name);
            rr->failed = PBC_BAD_AUTH;
            rr->redir_reason_no = PBC_RR_NOGORS_CODE;
            return NGX_OK;

        }                       /* end if session cookie */

    } else {

        dump_cookie_data(r, "pubcookie_user.2", cookie_data);
        rr->has_granting = 1;

        clear_granting_cookie (r);
        if (!scfg->use_post)
            clear_pre_session_cookie (r);

        pc_req_log(r,
                   "pubcookie_user: has granting; current uri is: %V",
                   &r->uri);

        /* If GET, check pre_session cookie */
        if (!scfg->use_post) {
            pre_sess_from_cookie = get_pre_s_from_cookie (r);
            pc_req_log(r, "pubcookie_user: ret from get_pre_s_from_cookie");
            if (cookie_data->broken.pre_sess_token !=
                pre_sess_from_cookie) {
                pc_req_log(r, "pubcookie_user, pre session tokens mismatched, uri: %V",
                           &r->uri);
                pc_req_log(r, "pubcookie_user, pre session from G: %d PRE_S: %d, uri: %V",
                           cookie_data->broken.pre_sess_token,
                           pre_sess_from_cookie, &r->uri);
                rr->failed = PBC_BAD_AUTH;
                rr->stop_message = ap_psprintf(r->pool,
                            "Couldn't decode pre-session cookie. (from G: %d from PRE_S: %d)",
                            cookie_data->broken.pre_sess_token, pre_sess_from_cookie);
                rr->redir_reason_no = PBC_RR_BADPRES_CODE;
                return NGX_OK;
            }
        }

        /* the granting cookie gets blanked too early and another login */
        /* server loop is required, this just speeds up that loop */
        if (strncmp (cookie, PBC_X_STRING, PBC_XS_IN_X_STRING) == 0) {
            pc_req_log(r,
                       "pubcookie_user: 'speed up that loop' logic; uri is: %V\n",
                       &r->uri);

            rr->failed = PBC_BAD_AUTH;
            rr->redir_reason_no = PBC_RR_DUMMYLP_CODE;
            return NGX_OK;
        }

        ngx_str_assign_copy(p, &rr->user_name, cookie_data->broken.user);

        /* Make sure we really got a user (unless noprompt) */
        if (!*rr->user_name.data && cfg->noprompt <= 0) {
            pc_req_log(r, "No user and not a noprompt");
            rr->stop_message = "Required user login didn't happen";
            rr->failed = PBC_BAD_G_STATE;
            return (DONE);
        }

        pc_req_log(r, "pubcookie_user: set user (%V)", &rr->user_name);

        /* save the full user/realm for later */
        ngx_str_assign_copy(p, &rr->user_full, cookie_data->broken.user);

        /* check for acceptable realms and strip realm */
        if (*rr->user_full.data) {
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
                       (thisrealm = ap_getword_white(p, &okrealms))) {
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
            rr->stop_message = "Required Session Reauthentication didn't happen";
            rr->failed = PBC_BAD_G_STATE;
            return (DONE);
        }

        if (libpbc_check_exp(r, cookie_data->broken.create_ts, PBC_GRANTING_EXPIRE) == PBC_FAIL) {
            pc_req_log(r,
                       "pubcookie_user: G cookie expired by %ld; user: %s create: %ld uri: %V",
                       pbc_time(NULL) - cookie_data->broken.create_ts -
                       PBC_GRANTING_EXPIRE, cookie_data->broken.user,
                       cookie_data->broken.create_ts, &r->uri);
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
                   "pubcookie_user: wrong appid; current: %s cookie: %s uri: %V",
                   appid (r), cookie_data->broken.appid, &r->uri);
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_WRONGAPPID_CODE;
        return NGX_OK;
    }

    /* check appsrv id */
    if (ngx_strncasecmp (appsrvid(r),
                     cookie_data->broken.appsrvid,
                     sizeof(cookie_data->broken.appsrvid) - 1) != 0) {
        pc_req_log(r,
                   "pubcookie_user: wrong app server id; current: %s cookie: %s uri: %V",
                   appsrvid (r), cookie_data->broken.appsrvid,
                   &r->uri);
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_WRONGAPPSRVID_CODE;
        return NGX_OK;
    }

    /* check version id */
    if (libpbc_check_version(r, cookie_data) == PBC_FAIL) {
        pc_req_log(r,
                   "pubcookie_user: wrong version id; module: %d cookie: %d uri: %V",
                   PBC_VERSION, cookie_data->broken.version, &r->uri);
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_WRONGVER_CODE;
        return NGX_OK;
    }

    /* check creds */
    if (rr->creds != cookie_data->broken.creds) {
        pc_req_log(r,
                   "pubcookie_user: wrong creds; required: %c cookie: %c uri: %V",
                   rr->creds, cookie_data->broken.creds, &r->uri);
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
        if (!libpbc_base64_decode(r, (u_char *) cookie, (u_char *) blob, &bloblen)) {
            pc_req_log(r, "credtrans: libpbc_base64_decode() failed");
            res = -1;
        }

        /* decrypt cookie. if credtrans is set, then it's from login server
           to me. otherwise it's from me to me. */
        if (!res && libpbc_rd_priv(r, scfg->sectext, cred_from_trans ?
                                    ap_get_server_name(r) : NULL,
                                    cred_from_trans ? 1 : 0,
                                    blob, bloblen, &plain, &plainlen,
                                    scfg->crypt_alg)) {
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
        ngx_sprintf((u_char *) krb5ccname, "/tmp/k5cc_%d_%V%Z", getpid(), &rr->user_full);
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
               "pubcookie_user: everything is o'tay; current uri is: %V",
               &r->uri);

    return NGX_OK;
}


/****************************************
 * Authentication handler
 */

static ngx_int_t
ngx_pubcookie_authz_handler(ngx_http_request_t *r)
{
    ngx_int_t rc, rc2;
    ngx_pubcookie_srv_t *scfg = ngx_http_get_module_srv_conf(r, ngx_pubcookie_module);

    /* get pubcookie creds or bail if not a pubcookie auth_type */
    if (pubcookie_auth_type(r) == PBC_CREDS_NONE)
        return NGX_DECLINED;

    if (0 == scfg->locations) /* server not enabled */
        return NGX_OK;

    if (r != r->main) /* subrequest */
        return NGX_OK;

    if (ngx_strcasecmp_c(r->uri, "/favicon.ico"))
        return NGX_OK;

    /* pass if it is our post-reply */
    if (ngx_strcmp_eq(r->uri, scfg->post_url))
        return NGX_OK;

    pubcookie_setup_request(r);
    rc = pubcookie_user_hook(r);
    rc2 = pubcookie_finish_request(r);
    return (rc2 == NGX_DECLINED ? rc : rc2);
}

/*
 * converts an authtype name to a pubcookie credential number
 */
static char
pubcookie_auth_type (ngx_http_request_t * r)
{
    ngx_pubcookie_loc_t  *conf = ngx_http_get_module_loc_conf(r, ngx_pubcookie_module);
    static const char * auth_type = "WebISO";

    if (NULL == conf || NULL == conf->appid.data)
        return PBC_CREDS_NONE;

    return libpbc_get_credential_id (r, auth_type);
}

/*
 *  ngx_pubcookie_init - inject into access phase chain
 */
static ngx_int_t
ngx_pubcookie_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *core_cf;

    core_cf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    if (NULL == (h = ngx_array_push(&core_cf->phases[NGX_HTTP_ACCESS_PHASE].handlers)))
        return NGX_ERROR;
    *h = ngx_pubcookie_authz_handler;

    return NGX_OK;
}

/*************************
 *  POST handler
 */

/*
 * Encode the args
 */
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

/*
 * entity encode some post data
 */
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
        if ((q = strchr (p, '&'))) *q++ = '\0';
        if ((s = strchr (p, '='))) *s++ = '\0';
        else s = "";

        decode_data (s);
        ap_table_set (argtbl, p, s);
        pc_req_log(r, "scan[%s]:\"%s\"", p, s);
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
    if (!libpbc_base64_decode (r, (unsigned char *) s,
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

static ngx_int_t
pubcookie_handle_post_reply (ngx_http_request_t * r)
{
    ngx_pubcookie_req_t *rr = ngx_http_get_module_ctx(r, ngx_pubcookie_module);
    ngx_pubcookie_loc_t *cfg = ngx_http_get_module_loc_conf(r, ngx_pubcookie_module);
    ngx_pubcookie_srv_t *scfg = ngx_http_get_module_srv_conf(r, ngx_pubcookie_module);
    ngx_pool_t *p = r->pool;
    table *args = ap_make_table (r->pool, 5);
    const char *greply, *creply, *pdata;
    char *arg;
    char *a;
    char *post_data;
    char *gr_cookie, *cr_cookie = "";
    const char *r_url;

    pc_req_log(r, "login_reply_handler: hello");

    set_no_cache_headers (r);

    /* Get the request data */

    if (r->args.len) {
        arg = str2charp (p, &r->args);
        scan_args (r, args, arg);
    }
    if (r->headers_in.content_length_n > 0) {
        post_data = get_post_data (r, r->headers_in.content_length_n);
        if (NULL == post_data)
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        scan_args (r, args, post_data);
    }

    greply = ap_table_get (args, PBC_G_COOKIENAME);
    if (!greply) {
        /* Send out bad call error */
        rr->stop_message = "No granting reply";
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
        rr->stop_message = "Invalid relay URL";
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
        arg = ap_pstrdup(p, r_url);
    }
    /* make sure there are no newlines in the redirect location */
    if ((a=strchr(arg,'\n'))) *a = '\0';
    if ((a=strchr(arg,'\r'))) *a = '\0';

    if (*pdata) {
        char *v, *t;
        int needclick = 0;

        post_data = ap_pstrdup (p, pdata);
        if (strstr (post_data, "submit=")) needclick = 1;
        ap_log_rerror (PC_LOG_DEBUG, r,
                       "relay is post, click=%d", needclick);

        /* send post form with original elements */
        ap_rprintf (r, post_reply_1_html,
                    needclick ? POST_REPLY_CLICK : POST_REPLY_SUBMIT,
                    arg);

        while (post_data) {
            if ((a = strchr (post_data, '&'))) *a++ = '\0';
            if (*post_data) {

                if ((v = strchr (post_data, '='))) *v++ = '\0';
                for (t = v; t&&*t; t++) if (*t == '+') *t = ' ';
                decode_data (post_data);
                decode_data (v);

                ap_rprintf (r, post_reply_arg_html, encode_data(r, post_data), encode_data(r, v)); 
            }
            post_data = a;
        }

        ap_rprintf (r, post_reply_2_html);

    } else {                    /* do a get */
        ap_table_add(HDRS_OUT, "Location", arg);
        return NGX_HTTP_MOVED_TEMPORARILY;
    }

    ap_pfree(p, arg);
    return (OK);
}

static ngx_int_t
pubcookie_post_handler (ngx_http_request_t * r)
{
    ngx_int_t rc, rc2;
    pubcookie_setup_request(r);
    rc = pubcookie_handle_post_reply(r);
    rc2 = pubcookie_finish_request(r);
    return (rc2 == NGX_DECLINED ? rc : rc2);
}


/**************************************
 *
 *          Configuration
 *
 **************************************/


static char *pubcookie_post_inact_exp (ngx_conf_t *cf, void *data, void *conf);
static ngx_conf_post_t pubcookie_conf_inact_exp = { pubcookie_post_inact_exp };

static char *pubcookie_post_hard_exp (ngx_conf_t *cf, void *data, void *conf);
static ngx_conf_post_t pubcookie_conf_hard_exp = { pubcookie_post_hard_exp };

static char *pubcookie_post_login (ngx_conf_t *cf, void *data, void *conf);
static ngx_conf_post_t pubcookie_conf_login = { pubcookie_post_login };

static char *pubcookie_post_domain (ngx_conf_t *cf, void *data, void *conf);
static ngx_conf_post_t pubcookie_conf_domain = { pubcookie_post_domain };

static ngx_conf_enum_t pubcookie_enum_method[] = {
    { ngx_string("get"), 0 },
    { ngx_string("post"), 1 },
    { ngx_null_string, 0 }
};

static ngx_conf_enum_t pubcookie_enum_crypt[] = {
    { ngx_string("des"), PBC_CRYPT_DES },
    { ngx_string("aes"), PBC_CRYPT_AES },
    { ngx_string("aes+domain"), PBC_CRYPT_AES_D },
    { ngx_null_string, 0 }
};

static char *pubcookie_set_appid (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *pubcookie_set_appsrvid (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *pubcookie_post_noprompt (ngx_conf_t *cf, void *data, void *conf);
static ngx_conf_post_t pubcookie_conf_noprompt = { pubcookie_post_noprompt };

static char *pubcookie_post_super_debug (ngx_conf_t *cf, void *data, void *conf);
static ngx_conf_post_t pubcookie_conf_super_debug = { pubcookie_post_super_debug };

static char *pubcookie_set_post_url (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *pubcookie_set_no_blank (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static char *pubcookie_post_dirdepth (ngx_conf_t *cf, void *data, void *conf);
static ngx_conf_post_t pubcookie_conf_dirdepth = { pubcookie_post_dirdepth };

static char *pubcookie_set_session_reauth (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *pubcookie_set_add_request (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *pubcookie_set_accept_realms (ngx_conf_t *cf, ngx_command_t *cmd, void *conf);


static ngx_command_t  ngx_pubcookie_commands[] = {
    /* "Set the inactivity expire time for PubCookies." */
    { ngx_string("pubcookie_inactive_expire"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, inact_exp),
      &pubcookie_conf_inact_exp },

    /* "Set the hard expire time for PubCookies." */
    { ngx_string("pubcookie_hard_expire"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, hard_exp),
      &pubcookie_conf_hard_exp },

    /* "Set super debugging." */
    { ngx_string("pubcookie_super_debug"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, dummy_super_debug),
      &pubcookie_conf_super_debug },

    /* "Set the login page for PubCookies." */
    { ngx_string("pubcookie_login"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, login),
      &pubcookie_conf_login },

    /* "Set the domain for PubCookies." */
    { ngx_string("pubcookie_domain"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, enterprise_domain),
      &pubcookie_conf_domain },

    /* "Set the location of PubCookie encryption keys." */
    { ngx_string("pubcookie_key_dir"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, keydir),
      NULL },

    /* "Set the name of the certfile for Granting PubCookies." */
    { ngx_string("pubcookie_granting_cert_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, granting_cert_file),
      NULL },

    /* "Set the name of the keyfile for Granting PubCookies." */
    { ngx_string("pubcookie_granting_key_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, granting_key_file),
      NULL },

    /* "Set the name of the keyfile for Session PubCookies." */
    { ngx_string("pubcookie_session_key_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, ssl_key_file),
      NULL },

    /* "Set the name of the certfile for Session PubCookies." */
    { ngx_string("pubcookie_session_cert_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, ssl_cert_file),
      NULL },

    /* "Set the name of the encryption keyfile for PubCookies." */
    { ngx_string("pubcookie_crypt_key_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, crypt_key),
      NULL },

    /* "Set the name of the EGD Socket if needed for randomness." */
    { ngx_string("pubcookie_egd_device"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, egd_socket),
      NULL },

    /* "Set post response URL. Def = /PubCookie.reply" */
    { ngx_string("pubcookie_post"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      pubcookie_set_post_url,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, post_url),
      NULL },

    /* "Set login method (GET/POST). Def = GET" */
    { ngx_string("pubcookie_login_method"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, use_post),
      pubcookie_enum_method },

    /* "Set encryption method (AES/DES)." */
    { ngx_string("pubcookie_encryption"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_enum_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, crypt_alg),
      pubcookie_enum_crypt },

    /* "Set the name of the application." */
    { ngx_string("pubcookie_app_id"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      pubcookie_set_appid,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, appid),
      NULL },

    /* "Set the name of the server(cluster)." */
    { ngx_string("pubcookie_app_srv_id"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      pubcookie_set_appsrvid,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, appsrvid),
      NULL },

    /* "Do not prompt for id and password if not already logged in." */
    { ngx_string("pubcookie_no_prompt"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, noprompt),
      &pubcookie_conf_noprompt },

    /* "End application session and possibly login session" */
    { ngx_string("pubcookie_end_session"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, end_session),
      NULL },

    /* "Do not blank cookies.". DEPRECATED in favour of pubcookie_no_obscure_cookies */
    { ngx_string("pubcookie_no_blank"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_NOARGS,
      pubcookie_set_no_blank,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, noblank),
      NULL },

    /* "Do not obscure Pubcookie cookies." */
    { ngx_string("pubcookie_no_obscure_cookies"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, noblank),
      NULL },

    /* Added by ddj@cmu.edu on 2006/05/01 to address security issue at CMU. */
    /* "Determines whether a new AppID replaces or is catenated to the old App ID." */
    { ngx_string("pubcookie_catenate_app_ids"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, catenate),
      NULL },
    /* End of ddj@cmu.edu's change. */

    /* "Specify the Directory Depth for generating default AppIDs." */
    { ngx_string("pubcookie_dir_depth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, dirdepth),
      &pubcookie_conf_dirdepth },

    /* "Force reauthentication for new sessions with specified timeout" */
    { ngx_string("pubcookie_session_reauth"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      pubcookie_set_session_reauth,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, session_reauth),
      NULL },

    /* "Send the following options to the login server along with authentication requests" */
    { ngx_string("pubcookie_add_request"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      pubcookie_set_add_request,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, addl_requests),
      NULL },

    /* "Only accept realms in this list" */
    { ngx_string("pubcookie_accept_realm"),
      NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      pubcookie_set_accept_realms,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, accept_realms),
      NULL },

    /* "Strip the realm (and set the REMOTE_REALM envirorment variable)" */
    { ngx_string("pubcookie_strip_realm"),
      NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, strip_realm),
      NULL },

    /* "Specify on-demand pubcookie directives." */
    { ngx_string("pubcookie_on_demand"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, keydirs),
      NULL },

    /* "Set to leave credentials in place after cleanup" */
    { ngx_string("pubcookie_no_clean_creds"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, no_clean_creds),
      NULL },

    /* "Set to ignore non-standard server port" */
    { ngx_string("pubcookie_behind_proxy"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, behind_proxy),
      NULL },

    ngx_null_command
};


static struct {
    const char *name;
    size_t offset;
} pbc_cfg_str_fields[] = {
    { "enterprise_domain",  offsetof(ngx_pubcookie_srv_t, enterprise_domain) },
    { "ssl_key_file",       offsetof(ngx_pubcookie_srv_t, ssl_key_file) },
    { "ssl_cert_file",      offsetof(ngx_pubcookie_srv_t, ssl_cert_file) },
    { "granting_key_file",  offsetof(ngx_pubcookie_srv_t, granting_key_file) },
    { "granting_cert_file", offsetof(ngx_pubcookie_srv_t, granting_cert_file) },
    { "crypt_key",          offsetof(ngx_pubcookie_srv_t, crypt_key) },
    { "login_uri",          offsetof(ngx_pubcookie_srv_t, login) },
    { "keydir",             offsetof(ngx_pubcookie_srv_t, keydir) },
    { "appsrvid",           offsetof(ngx_pubcookie_srv_t, appsrvid) },
    { "egd_socket",         offsetof(ngx_pubcookie_srv_t, egd_socket) },
    { "post_url",           offsetof(ngx_pubcookie_srv_t, post_url) },
    { NULL, 0 }
};


static ngx_http_module_t  ngx_pubcookie_module_ctx = {
    NULL,                             /* preconfiguration */
    ngx_pubcookie_init,               /* postconfiguration */

    NULL,                             /* create main configuration */
    NULL,                             /* init main configuration */

    ngx_pubcookie_create_srv_conf,    /* create server configuration */
    ngx_pubcookie_merge_srv_conf,     /* merge server configuration */

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


static char *
pubcookie_post_super_debug (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_flag_t *fp = conf;
    pubcookie_super_debug = *fp;
    return NGX_CONF_OK;
}

static char *
pubcookie_post_inact_exp (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_flag_t *np = conf;

    /* how to turn off inactivity checking */
    if (*np == -1) {
        return NGX_CONF_OK;
    }

    /* check for valid range */
    if (*np < PBC_MIN_INACT_EXPIRE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "pubcookie: inactivity expire parameter less then allowed minimum of %d, requested %d.",
            PBC_MIN_INACT_EXPIRE, *np);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
pubcookie_post_hard_exp (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_flag_t *np = conf;

    if (*np > PBC_MAX_HARD_EXPIRE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "pubcookie: Hard expire parameter greater then allowed maximium of %d, requested %d.",
            PBC_MAX_HARD_EXPIRE, *np);
        return NGX_CONF_ERROR;
    } else if (*np < PBC_MIN_HARD_EXPIRE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
            "pubcookie: Hard expire parameter less then allowed minimum of %d, requested %d.",
            PBC_MIN_HARD_EXPIRE, *np);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char *
pubcookie_post_login (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_str_t *sp = conf;
    if (0 != ngx_strncmp(sp->data, "https://", 8))
        return "pubcookie: pubcookie_login must start with https://";
    return NGX_CONF_OK;
}

static char *
pubcookie_post_domain (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_str_t *sp = conf;

    if (sp->len > 0 && sp->data[0] != '.') {
        static ngx_str_t dot = ngx_string(".");
        ngx_strcat3(cf->pool, sp, &dot, sp, NULL);
    }

    return NGX_CONF_OK;
}

#define SET_C_LETTER(c,a,b) (*(c)++ = '%', *(c)++ = (a), *(c)++ = (b))

static void
normalize_id_string (ngx_pool_t *pool, ngx_str_t *dst, ngx_str_t *src)
{
    register u_char *c;
    register ngx_uint_t i;
    c = dst->data = ngx_pnalloc (pool, src->len * 3 + 1);
    for (i = 0; i < src->len; ++i) {
        switch (src->data[i]) {
        case ' ': *c++ = '+'; break;
        case '%': SET_C_LETTER(c,'2','5'); break;
        case '&': SET_C_LETTER(c,'2','6'); break;
        case '+': SET_C_LETTER(c,'2','B'); break;
        case ':': SET_C_LETTER(c,'3','A'); break;
        case ';': SET_C_LETTER(c,'3','B'); break;
        case '=': SET_C_LETTER(c,'3','D'); break;
        case '?': SET_C_LETTER(c,'3','F'); break;
        default:  *c++ = src->data[i]; break;
        }
    }
    *c = '\0';
    dst->len = (int)(c - dst->data);
}

static char *
pubcookie_set_appid (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_t *cfg = conf;
    ngx_pubcookie_srv_t *scfg = ngx_http_conf_get_module_srv_conf(cf, ngx_pubcookie_module);
    ngx_str_t *value = cf->args->elts;

    normalize_id_string(cf->pool, &cfg->appid, &value[1]);
    scfg->locations++; /* mark server as pubcookie-enabled */
    return NGX_CONF_OK;
}

static char *
pubcookie_set_appsrvid (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_srv_t *scfg = conf;
    ngx_str_t *value = cf->args->elts;

    normalize_id_string(cf->pool, &scfg->appsrvid, &value[1]);
    return NGX_CONF_OK;
}

static char *
pubcookie_post_noprompt (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_flag_t *fp = conf;
    if (*fp == 0)
        *fp = -1;
    return NGX_CONF_OK;
}

static char *
pubcookie_set_post_url (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_srv_t *scfg = conf;
    ngx_http_core_loc_conf_t  *core_lcf;

    core_lcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    scfg->post_url = core_lcf->name;
    core_lcf->handler = pubcookie_post_handler;

    return NGX_CONF_OK;
}

/* allow admin to set a "dont blank the cookie" mode for proxy with pubcookie */
/* DEPRECATED in favour of PubcookieNoObscureCookie                          */
static char *
pubcookie_set_no_blank (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_srv_t *scfg = conf;
    scfg->noblank = 1;
    pc_cf_log (cf, "WARNING: pubcookie_no_nlank is deprecated in favor of pubcookie_no_obscure_cookie");
    return NGX_CONF_OK;
}

static char *
pubcookie_post_dirdepth (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_flag_t *np = conf;

    if (*np < 0)
        return "pubcookie: could not convert Directory Depth for AppID parameter to nonnegative number.";

    /* externally we count directories but internally we cound slashes
       external    internal
       /            == 0          1
       /blah/       == 1          2
       /blah/blong/ == 2          3
       and internally zero is 'unset'
     */
    (*np)++;

    return NGX_CONF_OK;
}

static char *
pubcookie_set_session_reauth (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;

    if (value[1].len == 0)
        cfg->session_reauth = 0;
    else if (ngx_strcasecmp_c (value[1], "on"))
        cfg->session_reauth = 1;
    else if (ngx_strcasecmp_c (value[1], "off"))
        cfg->session_reauth = 0;
    else {
        cfg->session_reauth = ngx_atoi (value[1].data, value[1].len);
        if (cfg->session_reauth == NGX_ERROR)
            return "pubcookie: cannot convert session_reauth to integer";
    }
    if (cfg->session_reauth < 0)
        cfg->session_reauth = 1;
    return NGX_CONF_OK;
}

static char *
pubcookie_set_add_request (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    static ngx_str_t ampersand = ngx_string("&");
    ngx_pubcookie_loc_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;
    ngx_uint_t i;

    for (i = 1; i < cf->args->nelts; i++)
        ngx_strcat3(cf->pool, &cfg->addl_requests,
                    &cfg->addl_requests, &ampersand, &value[i]);

    return NGX_CONF_OK;
}

static char *
pubcookie_set_accept_realms (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    static ngx_str_t blank = ngx_string(" ");
    ngx_pubcookie_loc_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;
    ngx_uint_t i;

    for (i = 1; i < cf->args->nelts; i++) {
        ngx_strcat3(cf->pool, &cfg->addl_requests,
                    &cfg->addl_requests, &blank, &value[i]);
    }

    return NGX_CONF_OK;
}


static void *
ngx_pubcookie_create_loc_conf(ngx_conf_t *cf)
{
    ngx_pubcookie_loc_t *cfg;

    if (NULL == (cfg = ngx_pcalloc(cf->pool, sizeof(ngx_pubcookie_loc_t))))
        return NULL;
    cfg->signature = PBC_LOC_SIGNATURE;

    cfg->inact_exp = NGX_CONF_UNSET;
    cfg->hard_exp = NGX_CONF_UNSET;
    cfg->non_ssl_ok = NGX_CONF_UNSET;
    cfg->session_reauth = NGX_CONF_UNSET;
    cfg->strip_realm = NGX_CONF_UNSET;
    cfg->noprompt = NGX_CONF_UNSET;

    return cfg;
}

static char *
ngx_pubcookie_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_pubcookie_loc_t  *prv = parent;
    ngx_pubcookie_loc_t  *cfg = child;

    ngx_conf_merge_value(cfg->inact_exp, prv->inact_exp, PBC_DEFAULT_INACT_EXPIRE);
    ngx_conf_merge_value(cfg->hard_exp, prv->hard_exp, PBC_DEFAULT_HARD_EXPIRE);
    ngx_conf_merge_value(cfg->non_ssl_ok, prv->non_ssl_ok, 0);
    ngx_conf_merge_value(cfg->session_reauth, prv->session_reauth, 0);
    ngx_conf_merge_value(cfg->strip_realm, prv->strip_realm, 0);
    ngx_conf_merge_value(cfg->noprompt, prv->noprompt, 0);

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
    if (prv->appid.data) {
        /* Yes.  Did the parent also have an *old* app ID? */
        if (prv->oldappid.data) {
	        /* Yes.  Glue them together and store as "old app ID". */
	        ngx_strcat3(cf->pool, &cfg->oldappid, &prv->oldappid, &prv->appid, NULL);
        } else {
            /* No.  The parent's app ID is now the "old app ID". */
            cfg->oldappid = prv->appid;
        }
    }

    /* life is much easier if the default value is zero or NULL */
    if (! cfg->appid.data)
        cfg->appid = prv->appid;

    if (! cfg->end_session.data)
        cfg->end_session = prv->end_session;

    if (prv->addl_requests.data) {
        static ngx_str_t ampersand = ngx_string("&");
        if (cfg->addl_requests.data)
	        ngx_strcat3(cf->pool, &cfg->addl_requests,
	                    &prv->addl_requests, &ampersand, &cfg->addl_requests);
        else
            cfg->addl_requests = prv->addl_requests;
    }

    if (! cfg->accept_realms.data)
        cfg->accept_realms = prv->accept_realms;

    if (cfg->keydirs && ! prv->keydirs) {
        cfg->keydirs = prv->keydirs;
    } else if (cfg->keydirs && prv->keydirs) {
        ngx_keyval_t *kv_old = prv->keydirs->elts;
        ngx_uint_t i;
        for (i = 0; i < prv->keydirs->nelts; i++) {
            ngx_keyval_t *kv_new = ngx_array_push(cfg->keydirs);
            if (! kv_new)
                return "pubcookie: not enough memory to merge keyed directives";
            *kv_new = kv_old[i];
        }
    }

    return NGX_CONF_OK;
}


static void *
ngx_pubcookie_create_srv_conf(ngx_conf_t *cf)
{
    ngx_pubcookie_srv_t  *scfg;

    if (NULL == (scfg = ngx_pcalloc(cf->pool, sizeof(ngx_pubcookie_srv_t))))
        return NULL;

    scfg->signature = PBC_SRV_SIGNATURE;
    scfg->log = cf->log;
    scfg->pool = cf->pool;

    scfg->dirdepth = NGX_CONF_UNSET;
    scfg->noblank = NGX_CONF_UNSET;
    scfg->catenate = NGX_CONF_UNSET;
    scfg->no_clean_creds = NGX_CONF_UNSET;
    scfg->use_post = NGX_CONF_UNSET;
    scfg->behind_proxy = NGX_CONF_UNSET;

    scfg->crypt_alg = NGX_CONF_UNSET_UINT;
    scfg->dummy_super_debug = NGX_CONF_UNSET;

    return scfg;
}


static char *
ngx_pubcookie_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_pubcookie_srv_t *sprv = parent;
    ngx_pubcookie_srv_t *scfg = child;
    int i;

    ngx_conf_merge_value(scfg->dirdepth, sprv->dirdepth, PBC_DEFAULT_DIRDEPTH);
    ngx_conf_merge_value(scfg->noblank, sprv->noblank, 0);
    ngx_conf_merge_value(scfg->catenate, sprv->catenate, 0);
    ngx_conf_merge_value(scfg->no_clean_creds, sprv->no_clean_creds, 0);
    ngx_conf_merge_value(scfg->use_post, sprv->use_post, 0);
    ngx_conf_merge_uint_value(scfg->crypt_alg, sprv->crypt_alg, PBC_DEF_CRYPT);
    ngx_conf_merge_value(scfg->behind_proxy, sprv->behind_proxy, 0);

    for (i = 0; pbc_cfg_str_fields[i].name != NULL; i++) {
        int off = pbc_cfg_str_fields[i].offset;
        ngx_str_t *ps = (ngx_str_t *)((char *) sprv + off);
        ngx_str_t *cs = (ngx_str_t *)((char *) scfg + off);
        if (NULL == cs->data)
            *cs = *ps;
    }

    if (0 == scfg->locations)
        return NGX_CONF_OK;

    if (scfg->use_post && NULL == scfg->post_url.data)
        return "pubcookie_post: post reply location e.g. /PubCookie.reply must be set!";

    if (NULL == scfg->ssl_key_file.data)
        return "pubcookie_session_key_file: configuration directive must be set!";
    if (NULL == scfg->ssl_cert_file.data)
        return "pubcookie_session_cert_file: configuration directive must be set!";
    if (NULL == scfg->granting_cert_file.data)
        return "pubcookie_granting_cert_file: configuration directive must be set!";
    if (NULL == scfg->keydir.data)
        return "pubcookie_key_dir: configuration directive must be set!";
    if (NULL == scfg->login.data)
        return "pubcookie_login: configuration directive must be set!";

    if (libpbc_pubcookie_init((pool *) scfg, &scfg->sectext) != PBC_OK)
        return "pubcookie_init: libpbc_pubcookie_init failed.";
    pc_cf_log(cf, "pubcookie_init: libpbc init done");

    return NGX_CONF_OK;
}

#if 0
static char *
create_location (ngx_conf_t *cf, const char *loc_name)
{
    void *core_srv_conf;
    ngx_command_t *cmd;
    ngx_str_t arg_cmd = ngx_string("location");
    ngx_str_t str_loc;
    ngx_str_t str_prefix = ngx_string("=/");
    ngx_str_t arg_loc;
    ngx_conf_t my_cf;
    ngx_array_t my_args;
    ngx_str_t *value;
    ngx_conf_file_t my_conf_file;
    ngx_buf_t my_buf;
    char *result;

    core_srv_conf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);
    for (cmd = ngx_http_core_module.commands; cmd->name.data; cmd++) {
        if (ngx_strcmp_c(cmd->name, "location"))
            break;
    }
    if (NULL == cmd->name.data || NULL == core_srv_conf) {
        return "Cannot find command";
    }

    /* simulate a null file */
    my_cf = *cf;
    my_buf = *cf->conf_file->buffer;
    my_conf_file = *cf->conf_file;
    my_buf.pos = my_buf.last = 0;
    my_conf_file.buffer = &my_buf;
    my_conf_file.file.offset = 0;
    my_conf_file.file.info.st_size = 0;
    my_conf_file.file.fd = NGX_INVALID_FILE;
    my_cf.conf_file = &my_conf_file;

    /* create arguments: "location" "=/LOCNAME" */
    str_loc.data = (u_char *) loc_name;
    str_loc.len = strlen(loc_name);
    ngx_strcat3(cf->pool, &arg_loc, &str_prefix, &str_loc, NULL);
    ngx_array_init(&my_args, cf->pool, 2, sizeof(ngx_str_t));
    my_cf.args = &my_args;
    value = my_args.elts;
    my_args.nelts = 2;
    value[0] = arg_cmd;
    value[1] = arg_loc;

    result = (*cmd->set)(&my_cf, cmd, core_srv_conf);
    return result;
}
#endif


/*
 * Debugging
 */
static void
dump_recs(ngx_http_request_t *r, ngx_pubcookie_loc_t *c, ngx_pubcookie_srv_t *s)
{
#if defined(DEBUG_DUMP_RECS)
    pc_req_log(r, "+--- dump_loc_req ---");
    pc_req_log(r, "| login=%V domain=%V",
            &s->login, &s->enterprise_domain);
    pc_req_log(r, "| keydir=%V grant_cf=%V ssl_keyf=%V ssl_cf=%V",
            &s->keydir, &s->granting_cert_file, &s->ssl_key_file, &s->ssl_cert_file);
    pc_req_log(r, "| crypt_key=%V egd_socket=%V",
            &s->crypt_key, &s->egd_socket);
    pc_req_log(r, "| dirdepth=%d noblank=%d catenate=%d no_clean_creds=%d use_post=%d behind_proxy=%d",
            s->dirdepth, s->noblank, s->catenate, s->no_clean_creds, s->use_post, s->behind_proxy);
    pc_req_log(r, "| oldappid=%V appid=%V appsrvid=%V",
            &c->oldappid, &c->appid, &s->appsrvid);
    pc_req_log(r, "| post_url=%V end_session=%V addl_requests=%V accept_realms=%V",
            &s->post_url, &c->end_session, &c->addl_requests, &c->accept_realms);
    pc_req_log(r, "| crypt_alg=%d inact_exp=%d hard_exp=%d non_ssl_ok=%d session_reauth=%d",
            s->crypt_alg, c->inact_exp, c->hard_exp, c->non_ssl_ok, c->session_reauth);
    pc_req_log(r, "| strip_realm=%d noprompt=%d",
            c->strip_realm, c->noprompt);
    pc_req_log(r, "+----------------------------------");
#endif /* DEBUG_DUMP_RECS */
}

static void
dump_cookie_data(ngx_http_request_t *r, const char *prefix, pbc_cookie_data *cookie_data)
{
#if defined(DEBUG_DUMP_RECS)
    cookie_data_struct *d = &cookie_data->broken;
    pc_req_log(r, "cookie_data(%s): user=\"%s\" version=\"%s\" appsrvid=\"%s\" appid=\"%s\"",
            prefix, d->user, d->version, d->appsrvid, d->appid);
#endif /* DEBUG_DUMP_RECS */
}


/*
 * Configuration helper for libpbc library
 */

const char *
libpbc_config_getstring(pool *ptr, const char *name, const char *defval)
{
    ngx_pubcookie_srv_t *scfg = NULL;
    int i;

    if (NULL != ptr) {
        if (*(uint32_t *)ptr == PBC_SRV_SIGNATURE)
            scfg = (ngx_pubcookie_srv_t *) ptr;
        else
            scfg = ngx_http_get_module_srv_conf(((ngx_http_request_t *)ptr), ngx_pubcookie_module);
    }

    if (NULL == scfg) {
        pc_log_log(log_of(ptr), "config_getstring: server configuration not found for \"%s\"", name);
        return defval;
    }

    for (i = 0; pbc_cfg_str_fields[i].name != NULL; i++) {
        if (0 == strcmp(pbc_cfg_str_fields[i].name, name)) {
            ngx_str_t *nsp = (ngx_str_t *) ((char *)scfg + pbc_cfg_str_fields[i].offset);
            char * val = nsp->data ? str2charp(pool_of(ptr), nsp) : (char *) defval;
            pc_log_log(log_of(ptr), "config_getstring: value of \"%s\" is \"%s\"",
                        name, val?:"(NULL)");
            return val;
        }
    }

    /* not found */
    pc_log_log(log_of(ptr), "config_getstring: field \"%s\" not found !!", name);
    return defval;
}


/* SVN Id: $Id$ */

