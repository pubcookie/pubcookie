/* ========================================================================
 * Copyright 2010 Vitki <vitki@vitki.net>
 *
 * Based on original code from mod_pubcookie.c,
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

/** @file ngx_http_pubcookie_module.c
 * Nginx pubcookie module
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

#define AP_PSPRINTF_SIZE PBC_4K

#define OK       NGX_OK
#define DONE     NGX_DONE
#define DECLINED NGX_DECLINED

#define HTTP_UNAUTHORIZED NGX_HTTP_UNAUTHORIZED
#define HTTP_MOVED_TEMPORARILY NGX_HTTP_MOVED_TEMPORARILY

#define ME(r) ap_get_server_name(r)

#define MAX_POST_DATA PBC_4K

#define pubcookie_module ngx_http_pubcookie_module

#define ngx_strcmp_c(ns,cs) ((ns).len == sizeof(cs)-1 && \
                            ! ngx_strncmp((ns).data, (u_char*)(cs), sizeof(cs)-1))
#define ngx_strcasecmp_c(ns,cs) ((ns).len == sizeof(cs)-1 && \
                            ! ngx_strncasecmp((ns).data, (u_char*)(cs), sizeof(cs)-1))

#define ngx_strcmp_eq(ns1,ns2) ((ns1).len == (ns2).len && \
                            ! ngx_strncmp((ns1).data, (ns2).data, (ns1).len))

#define get_hdr_in(R,H) (R->headers_in.H ? str2charp(R->pool, &R->headers_in.H->value) : NULL)

#define set_ngx_variable(r,name,val)      (0    /*FIXME*/)
#define get_ngx_variable(r,name)          (NULL /*FIXME*/)
#define get_server_admin(r)     "postmaster@this.server"

#define main_rrec(r)    ((r)->main)
#define top_rrec(r)     ((r)->main)

#define dd(args...)  pbc_ngx_log(r->connection->log,PC_LOG_DEBUG,args)

typedef ngx_pubcookie_loc_t pubcookie_dir_rec;
typedef ngx_pubcookie_srv_t pubcookie_server_rec;
typedef ngx_pubcookie_req_t pubcookie_req_rec;
typedef ngx_http_request_t request_rec;
typedef ngx_command_t command_rec;

typedef struct {
    const char *name;
    size_t offset;
} pbc_param_off_t;


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

extern ngx_module_t pubcookie_module;

static pbc_param_off_t pbc_cfg_str_fields[];


/***********************************
 * Prototypes
 */

#define pubcookie_set_realm(r,realm)   add_out_header(r,"WWW-Authenticate",realm,0)
#define flush_headers(r) (0)

static u_char *ngx_pstrcat3 (ngx_pool_t *pool, ngx_str_t *res, ngx_str_t *s1, ngx_str_t *s2, ngx_str_t *s3);

static char *encode_get_args (ngx_http_request_t *r, char *in, int ec);
static char *get_post_data (ngx_http_request_t * r, int post_len);

static ngx_int_t pubcookie_post_handler (ngx_http_request_t *r);
static ngx_int_t pubcookie_end_session_handler (ngx_http_request_t *r);
static int pubcookie_authz_hook (request_rec * r);

static ngx_int_t pubcookie_init (ngx_conf_t *cf);

static char pubcookie_auth_type (ngx_http_request_t * r);

static int pubcookie_user (request_rec * r, pubcookie_server_rec *scfg, pubcookie_dir_rec *cfg, pubcookie_req_rec *rr);
static int pubcookie_user_hook (ngx_http_request_t * r);

static void dump_recs (request_rec *r, pubcookie_server_rec *s, pubcookie_dir_rec *c);
static void dump_cookie_data (request_rec *r, const char *prefix, pbc_cookie_data *cookie_data);

const char *libpbc_config_getstring(pool *ptr, const char *name, const char *defval);

static char *make_session_cookie_name (ngx_pool_t * p, char *cookiename, unsigned char *_appid);

static int load_keyed_directives (request_rec * r, char *key);

static int pubcookie_cleanup (request_rec * r);

/**************************************
 * Apache/APR compatibility
 */

#define ap_log_error(v,r,args...)   pbc_ngx_log((r)->connection->log,v,args)
#define ap_log_rerror(v,r,args...)  pbc_ngx_log((r)->connection->log,v,args)

#define ap_pstrdup(p,s) __ap_pstrdup(p,s)
#define ap_palloc(p,n)  ngx_palloc(p,n)
#define ap_pcalloc(p,n) ngx_pcalloc(p,n)
#define ap_pnalloc(p,n) ngx_pnalloc(p,n)
#define ap_pfree(p,v)   ngx_pfree(p,v)

#define ap_getword_white_nc(p,s) ap_getword_white((p),(const char **)(s))

#define ap_table_add(tbl,hdr,val) add_out_header(r,hdr,val,1)

#define ap_auth_type(r) "WebISO"
#define USER user
#define AUTH_TYPE auth_type

typedef ngx_array_t table;
typedef int apr_port_t;

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
ap_snprintf(char *buf, int size, const char *fmt, ...)
{
    char *e;
    va_list args;
    va_start(args, fmt);
    e = (char *) ngx_vsnprintf((u_char *) buf, size, fmt, args);
    va_end(args);
    *e = '\0';
    return e;
}

static char *
ap_psprintf(ngx_pool_t *p, const char *fmt, ...)
{
    u_char *s, *e;
    va_list args;

    if (NULL == (s = ngx_pnalloc(p, AP_PSPRINTF_SIZE)))
        return NULL;

    va_start(args, fmt);
    e = ngx_vslprintf(s, s + AP_PSPRINTF_SIZE - 1, fmt, args);
    va_end(args);
    *e = '\0';

#if AP_PSPRINTF_COMPACT_STRINGS
    if ((int)(e - s) < AP_PSPRINTF_SIZE / 2) {
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
    ngx_pubcookie_req_t *rr = ngx_http_get_module_ctx(r, pubcookie_module);
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
ap_getword_white (ngx_pool_t *pool, const char **line)
{
    char *p = (char *) *line;
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
    ngx_pubcookie_req_t *rr = ngx_http_get_module_ctx(r, pubcookie_module);
    if (! rr->server_name_tmp)
        rr->server_name_tmp = str2charp(r->pool, &r->headers_in.host->value);
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

static u_char *
ngx_pstrcat3 (ngx_pool_t *pool, ngx_str_t *res, ngx_str_t *s1, ngx_str_t *s2, ngx_str_t *s3)
{
    u_char *p;
    int n, n1, n2, n3;
    n1 = !s1 || !s1->data ? 0 : s1->len == (size_t)-1 ? ngx_strlen(s1->data) : s1->len;
    n2 = !s2 || !s2->data ? 0 : s2->len == (size_t)-1 ? ngx_strlen(s2->data) : s2->len;
    n3 = !s3 || !s3->data ? 0 : s3->len == (size_t)-1 ? ngx_strlen(s3->data) : s3->len;
    n = n1 + n2 + n3 + 1;
    p = ngx_pnalloc(pool, n);
    if (!p)
        return NULL;
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
    return res->data;
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
    if (!p)
        return NULL;
    if (n1)  ngx_memcpy(p, s1, n1);
    if (n2)  ngx_memcpy(p + n1, s2, n2);
    if (n3)  ngx_memcpy(p + n1 + n2, s3, n3);
    p[n1+n2+n3] = '\0';
    return (char *) p;
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
join_ngx_strings (ngx_pool_t * p, char * str,
                ngx_str_t * value, ngx_uint_t nelts, const char * joiner)
{
    ngx_uint_t i;

    for (i = 1; i < nelts; i++) {
        char * prev = str;
        char * param = str2charp (p, &value[i]);
        str = ap_pstrcat3 (p, prev, prev ? joiner : NULL, param);
        if (!param || !str)
            return NULL;
        if (prev)  ap_pfree (p, prev);
        if (param)  ap_pfree (p, param);
    }

    return str;
}

/* Debugging */

static void
dump_recs (request_rec *r, pubcookie_server_rec *s, pubcookie_dir_rec *c)
{
#if defined(DEBUG_DUMP_RECS)
    dd("+--- dump_loc_req ---");
    dd("| login=%V domain=%V",
            &s->login, &s->enterprise_domain);
    dd("| keydir=%V grant_cf=%V ssl_keyf=%V ssl_cf=%V",
            &s->keydir, &s->granting_cert_file, &s->ssl_key_file, &s->ssl_cert_file);
    dd("| crypt_key=%V egd_socket=%V",
            &s->crypt_key, &s->egd_socket);
    dd("| dirdepth=%d noblank=%d catenate=%d no_clean_creds=%d use_post=%d behind_proxy=%d",
            s->dirdepth, s->noblank, s->catenate, s->no_clean_creds, s->use_post, s->vitki_behind_proxy);
    dd("| oldappid=%V appid=%V appsrvid=%V",
            &c->oldappid, &c->appid, &s->appsrvid);
    dd("| post_reply_url=%V end_session=%V addl_requests=%s accept_realms=%s",
            &s->post_reply_url, &c->end_session,
            c->addl_requests ? c->addl_requests : "",
            c->accept_realms ? c->accept_realms : "");
    dd("| crypt_alg=%d inact_exp=%d hard_exp=%d non_ssl_ok=%d session_reauth=%d",
            s->crypt_alg, c->inact_exp, c->hard_exp, c->non_ssl_ok, c->session_reauth);
    dd("| strip_realm=%d noprompt=%d",
            c->strip_realm, c->noprompt);
    dd("+----------------------------------");
#endif /* DEBUG_DUMP_RECS */
}

static void
dump_cookie_data(ngx_http_request_t *r, const char *prefix, pbc_cookie_data *cookie_data)
{
#if defined(DEBUG_DUMP_RECS)
    cookie_data_struct *d = &cookie_data->broken;
    dd("cookie_data(%s): user=\"%s\" version=\"%s\" appsrvid=\"%s\" appid=\"%s\"",
            prefix, d->user, d->version, d->appsrvid, d->appid);
#endif /* DEBUG_DUMP_RECS */
}

/**************************************
 * Requests
 */

static int
add_out_header (ngx_http_request_t *r, const char *name, const char *value, int free_value)
{
    ngx_table_elt_t *hdr;

    if (NULL == (hdr = ngx_list_push(&r->headers_out.headers))) {
        ap_log_rerror (PC_LOG_EMERG, r, "cannot allocate memory for header structure");
        return NGX_ERROR;
    }
    hdr->hash = 1;
    hdr->key.data = (u_char *) name;
    hdr->key.len = ngx_strlen((u_char *) name);

    if (NULL == (hdr->value.data = (u_char *) ap_pstrdup(r->pool, (char *) value))) {
        ap_log_rerror (PC_LOG_EMERG, r, "cannot allocate memory for header value");
        return NGX_ERROR;
    }
    hdr->value.len = strlen(value);

    dd("out_header[%s]:\"%s\"", name, value);
    if (free_value)
        ap_pfree(r->pool, (void *) value);

    return NGX_OK;
}

static char *
get_all_cookies (request_rec * r, ngx_str_t * orig_ptr)
{
    ngx_table_elt_t **cph = r->headers_in.cookies.elts;
    int n = (int) r->headers_in.cookies.nelts;
    int i;
    for (i = 0; i < n; i++, cph++) {    
        if (ngx_strcmp_c((**cph).key, "Cookie")) {
            if (orig_ptr)
                *orig_ptr = (**cph).value;
            ap_log_rerror (PC_LOG_DEBUG, r, "all cookies: \"%V\"", &(**cph).value);
            return str2charp(r->pool, &(**cph).value);
        }
    }
    if (orig_ptr) {
        orig_ptr->data = NULL;
        orig_ptr->len = 0;
    }
    return NULL;
}

static ngx_pubcookie_req_t *
pubcookie_setup_request (ngx_http_request_t *r)
{
    ngx_pubcookie_srv_t *scfg = ngx_http_get_module_srv_conf(r, pubcookie_module);
    ngx_pubcookie_req_t *rr = ngx_http_get_module_ctx(r, pubcookie_module);

    ap_log_rerror (PC_LOG_DEBUG, r,
                    "pubcookie_setup_request: r:%p rr:%p scfg:%p",
                    r, rr, scfg);
    scfg->log = r->connection->log;
    scfg->pool = r->pool;

    if (NULL == rr) {
        if (NULL == (rr = ngx_pcalloc(r->pool, sizeof(ngx_pubcookie_req_t))))
            return NULL;
        if (NULL == (rr->notes = ap_make_table(r->pool, 4)))
            return NULL;
        ngx_http_set_ctx(r, rr, pubcookie_module);
    }

    return rr;
}

static ngx_int_t
pubcookie_finish_request (ngx_http_request_t *r)
{
    ngx_pubcookie_req_t *rr = ngx_http_get_module_ctx(r, pubcookie_module);
    ngx_buf_t *b;
    ngx_chain_t out;
    u_char *msg;
    int len;

    if (!rr || !rr->msg.data)
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

static ngx_int_t
mark_location (ngx_conf_t *cf, ngx_pubcookie_loc_t *cfg, const char *msg)
{
    ngx_pubcookie_srv_t *scfg;
    ngx_http_core_srv_conf_t  *core_scf;
    ngx_http_core_loc_conf_t  *core_lcf;

    if (! cfg->appid.data)
        return NGX_DECLINED;

    scfg = ngx_http_conf_get_module_srv_conf(cf, pubcookie_module);
    core_scf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);
    core_lcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);

    cfg->marked = 1;
    cfg->location = core_lcf->name;
    scfg->locations++; /* mark server as pubcookie-enabled */

    pbc_ngx_log(cf->log, PC_LOG_DEBUG,
                "pubcookie_set_appid(%s): server \"%V\" location \"%V\" secured as \"%V\"",
                msg, &core_scf->server_name, &core_lcf->name, &cfg->appid);
    return NGX_OK;
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
    ngx_pstrcat3(cf->pool, &arg_loc, &str_prefix, &str_loc, NULL);
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
    int rem = post_len;
    ngx_int_t rc;
    ngx_chain_t *chain;
    int len;

    if (rem <= 0)
        return (ap_pstrdup (r->pool, ""));

    r->request_body_in_file_only = 0;
    /* r->request_body_in_single_buf = 1; */
    rc = ngx_http_read_client_request_body(r, dummy_body_handler);
    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        ngx_http_finalize_request(r, rc);
        return NULL;
    }

    if (NULL == (bp = buffer = ap_pnalloc (r->pool, post_len + 1))) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NULL;
    }

    for (chain = r->request_body->bufs; NULL != chain; chain = chain->next) {
        if (chain->buf->in_file) {
            ap_log_rerror (PC_LOG_ERR, r, "please increase client_buffer_size");
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return NULL;
        }
        len = chain->buf->last - chain->buf->pos;
        if (len > 0) {
            ngx_memcpy(bp, chain->buf->pos, len);
            bp += len;
            rem -= len;
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

    if ((i = libpbc_random_int (r)) == -1) {
        ap_log_rerror (PC_LOG_EMERG, r, "get_pre_s_token: OpenSSL error");
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
    pubcookie_server_rec *scfg;
    char *a;

    scfg =
        ngx_http_get_module_srv_conf(r, pubcookie_module);

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

static
int check_end_session (request_rec * r)
{
    int ret = 0;
    const char *end_session;
    char *word;
    ngx_pool_t *p = r->pool;
    pubcookie_dir_rec *cfg;

    cfg = ngx_http_get_module_loc_conf(r, pubcookie_module);

    end_session = str2charp(p, &cfg->end_session);

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
static
char pubcookie_auth_type (request_rec * r)
{
    pubcookie_dir_rec *cfg;
    const char *auth_type;
    cfg = ngx_http_get_module_loc_conf(r, pubcookie_module);
    if (! cfg->marked)
        return PBC_CREDS_NONE;
    auth_type = ap_auth_type (r);
    /* ok, check the list in libpubcookie */
    return libpbc_get_credential_id (r, auth_type);
}

/* figure out the appid                                                      */
static
unsigned char *appid (request_rec * r)
{
    pubcookie_server_rec *scfg;
    pubcookie_dir_rec *cfg;
    request_rec *rmain = main_rrec (r);
    ngx_pool_t *p = r->pool;
    ngx_str_t res;
    ngx_pubcookie_req_t *rr = ngx_http_get_module_ctx(r, pubcookie_module);

    cfg = ngx_http_get_module_loc_conf(r, pubcookie_module);
    scfg = ngx_http_get_module_srv_conf(r, pubcookie_module);

    if (! rr->app_path.data) {
        rr->app_path.data = get_app_path (r, str2charp(p, &rmain->uri));
        rr->app_path.len = ngx_strlen (rr->app_path.data);
    }

    /* Added by ddj@cmu.edu on 2006/05/10. */
    if (scfg->catenate) {	/* Catenate app IDs? */
        /* Yeah. Anything to catenate? 4 possibilities. */
        if (cfg->appid.data && cfg->oldappid.data) {
	    /* Old and new are both set. */
            /* Glue the default, old, and new together. */
            return ngx_pstrcat3 (p, &res, &rr->app_path, &cfg->oldappid, &cfg->appid);
        } else if (cfg->appid.data) {
            /* Just the new one is set. */
            /* Glue the default and the new one together. */
            return ngx_pstrcat3 (p, &res, &rr->app_path, &cfg->appid, NULL);
        } else if (cfg->oldappid.data) {
            /* Just the old one is set. */
            /* Glue the default and the old one together. */
            return ngx_pstrcat3 (p, &res, &rr->app_path, &cfg->oldappid, NULL);
        } else {
            /* None were ever set.  Just use the default. */
            return rr->app_path.data;
        }
    } else {
        /* No, don't catenate.  Use the 3.3.0a logic verbatim. */
        if (cfg->appid.data)
            return (cfg->appid.data);
        else
            return (rr->app_path.data);
    }
}

/* figure out the appsrvid                                                   */
static
unsigned char *appsrvid (request_rec * r)
{
    pubcookie_server_rec *scfg;
    scfg = ngx_http_get_module_srv_conf(r, pubcookie_module);

    if (scfg->appsrvid.data)
        return (scfg->appsrvid.data);
    else
        /* because of multiple passes through don't use r->hostname() */
        return (unsigned char *) ap_get_server_name(r);
}

/* make sure agents don't cache the redirect */
static
void set_no_cache_headers (request_rec * r)
{
    pubcookie_req_rec *rr;
    char datestr[32];
    rr = ngx_http_get_module_ctx(r, pubcookie_module);
    if (rr->nocache_sent)
        return;
    rr->nocache_sent = 1;
    *( ngx_http_time((u_char *) datestr, r->start_sec) ) = '\0';

    add_out_header (r, "Expires", datestr, 0);
    add_out_header (r, "Cache-Control", "no-store, no-cache, must-revalidate", 0);
    add_out_header (r, "Pragma", "no-cache", 0);
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
    ngx_pool_t *p = r->pool;

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
        if (libpbc_mk_priv (r, scfg->sectext, ME (r), 0, rr->cred_transfer,
                            rr->cred_transfer_len, &blob, &bloblen,
                            scfg->crypt_alg)) {
            ap_log_rerror (PC_LOG_ERR, r,
                           "credtrans: libpbc_mk_priv() failed");
            res = -1;
        }

        /* base 64 */
        if (!res) {
            base64 = ap_palloc (p, (bloblen + 3) / 3 * 4 + 1);
            if (!libpbc_base64_encode (r, (unsigned char *) blob,
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
static
void clear_granting_cookie (request_rec * r)
{
    char *new_cookie;
    ngx_pool_t *p = r->pool;
    pubcookie_server_rec *scfg;

    scfg =
        ngx_http_get_module_srv_conf(r, pubcookie_module);

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
static
void clear_transfer_cookie (request_rec * r)
{
    char *new_cookie;
    ngx_pool_t *p = r->pool;

    new_cookie = ap_psprintf (p,
                              "%s=; domain=%s; path=/; expires=%s;%s",
                              PBC_CRED_TRANSFER_COOKIENAME,
                              PBC_ENTRPRS_DOMAIN,
                              EARLIEST_EVER, secure_cookie);

    ap_table_add (HDRS_OUT, "Set-Cookie", new_cookie);
}

/** clear pre session cookie */
static
void clear_pre_session_cookie (request_rec * r)
{
    char *new_cookie;
    ngx_pool_t *p = r->pool;

    new_cookie = ap_psprintf (p,
                              "%s=; path=/; expires=%s;%s",
                              PBC_PRE_S_COOKIENAME,
                              EARLIEST_EVER, secure_cookie);

    ap_table_add (HDRS_OUT, "Set-Cookie", new_cookie);

}

static
void clear_session_cookie (request_rec * r)
{
    char *new_cookie;
    pubcookie_req_rec *rr;
    ngx_pool_t *p = r->pool;

    rr = ngx_http_get_module_ctx(r, pubcookie_module);
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
    ngx_pool_t *p = r->pool;

    ap_log_rerror (PC_LOG_DEBUG, r, "do_end_session_redirect: hello");

    clear_granting_cookie (r);
    clear_pre_session_cookie (r);
    clear_session_cookie (r);
    set_no_cache_headers (r);

    flush_headers (r);

    refresh = ap_psprintf (p, "%d;URL=%V?%s=%d&%s=%s&%s=%s",
                           PBC_REFRESH_TIME,
                           &scfg->login,
                           PBC_GETVAR_LOGOUT_ACTION,
                           (check_end_session (r) & PBC_END_SESSION_CLEAR_L
                            ? LOGOUT_ACTION_CLEAR_L :
                            LOGOUT_ACTION_NOTHING), PBC_GETVAR_APPID,
                           appid (r), PBC_GETVAR_APPSRVID, appsrvid (r));

    ap_rprintf (r, redirect_html, refresh);
    ap_pfree (p, refresh);
    r->keepalive = 0; /* workaround for keepalive problems after redirects */

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

    clear_granting_cookie (r);
    clear_pre_session_cookie (r);
    clear_session_cookie (r);
    set_no_cache_headers (r);

    flush_headers (r);

    ap_rprintf (r, stop_html, get_server_admin(r),
                rr->stop_message ? rr->stop_message : "");
    rr->status = NGX_HTTP_BAD_REQUEST;

    return (OK);

}

/* URL encode a base64 (deal with '+') */
static char *fix_base64_for_url(ngx_pool_t *p, char *b64)
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
    ngx_pool_t *p = r->pool;
    char *refresh = NULL;
    char *pre_s = NULL;
    char *pre_s_cookie = NULL;
    char *g_req_cookie = NULL;
    char *g_req_contents = NULL;
    char *e_g_req_contents = NULL;
    const char *tenc = get_hdr_in (r, transfer_encoding);
    const char *ctype = get_hdr_in (r, content_type);
    const char *lenp = get_hdr_in (r, content_length);
    char *host = NULL;
    char *args;
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

    if (r->main != r) {
        ap_log_rerror (PC_LOG_DEBUG, r,
                       " .. in subrequest: retuning noauth");
        return (HTTP_UNAUTHORIZED);
    }

    if (cfg->noprompt > 0)
        misc_flag = 'Q';

    /* reset these dippy flags */
    rr->failed = 0;

    /* acquire any GET args */
    if (r->args.len > 0 && r->args.data) {
        char *argst;
        /* error out if length of GET args would cause a problem */
        if (r->args.len > PBC_MAX_GET_ARGS) {
            rr->stop_message =
                ap_psprintf (p,
                             "GET arguments longer than supported.  (args length: %d)",
                             r->args.len);
            stop_the_show (r, scfg, cfg, rr);
            return (OK);
        }

        argst = ap_pcalloc (p, (r->args.len + 3) / 3 * 4 + 1);
        libpbc_base64_encode (r, r->args.data,
                              (unsigned char *) argst, r->args.len);
        ap_log_rerror (PC_LOG_DEBUG, r,
                       "GET args before encoding length %d, string: %V",
                       r->args.len, &r->args);
        args = fix_base64_for_url(p, argst);
        ap_log_rerror (PC_LOG_DEBUG, r,
                       "GET args after encoding length %d, string: %s",
                       strlen (args), args);
    } else
        args = ap_pstrdup (p, "");

    r->headers_out.content_type = pbc_content_type;
    r->headers_out.content_type_len = pbc_content_type.len;

    /* if there is a non-standard port number just tack it onto the hostname  */
    /* the login server just passes it through and the redirect works         */
    port = ap_get_server_port (r);
    if ((port != 80) && (port != 443) && !scfg->vitki_behind_proxy) {
        /* because of multiple passes through don't use r->hostname() */
        host = ap_psprintf (p, "%s:%d", ap_get_server_name (r), port);
    }
    if (!host)
        /* because of multiple passes through on www don't use r->hostname() */
        host = ap_pstrdup (p, ap_get_server_name (r));

    /* To knit the referer history together */
    referer = get_hdr_in(r, referer);
    if (!referer)  referer = "";

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
        b64uri = ap_pcalloc (p, (mr->uri.len + 3) / 3 * 4 + 1);
        libpbc_base64_encode (r, mr->uri.data,
                              (unsigned char *) b64uri, mr->uri.len);
        ap_log_rerror (PC_LOG_DEBUG, r,
                       "Post URI before encoding length %d, string: %V",
                       mr->uri.len, &mr->uri);
        ap_log_rerror (PC_LOG_DEBUG, r,
                       "Post URI after encoding length %d, string: %s",
                       strlen (b64uri), b64uri);
    } else b64uri = str2charp(p, &mr->uri);

    g_req_contents = ap_psprintf (p,
                 "%s=%s&%s=%s&%s=%c&%s=%s&%s=%V&%s=%s&%s=%s&%s=%s&%s=%s&%s=%d&%s=%s&%s=%s&%s=%d&%s=%d&%s=%c",
                 PBC_GETVAR_APPSRVID,
                 appsrvid (r),
                 PBC_GETVAR_APPID,
                 appid (r),
                 PBC_GETVAR_CREDS,
                 rr->creds,
                 PBC_GETVAR_VERSION,
                 vstr,
                 PBC_GETVAR_METHOD,
                 &r->main->method_name,
                 PBC_GETVAR_HOST,
                 host,
                 PBC_GETVAR_URI,
                 b64uri,
                 PBC_GETVAR_ARGS,
                 args,
                 PBC_GETVAR_REAL_HOST,
                 ap_get_server_name(r),
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

        g_req_contents = ap_pstrcat3 (p, g_req_contents,        /* FIXME: memory overhead */
                                     cfg->addl_requests, NULL);
    }

    ap_log_rerror (PC_LOG_DEBUG, r,
                   "g_req before encoding length %d, string: %s",
                   strlen (g_req_contents), g_req_contents);

    /* setup the client pull */
    refresh = ap_psprintf (p, "%d;URL=%V", PBC_REFRESH_TIME,
                            &scfg->login);


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
    libpbc_base64_encode (r, (unsigned char *) g_req_contents,
                          (unsigned char *) e_g_req_contents,
                          strlen (g_req_contents));
    ap_pfree(p, g_req_contents); g_req_contents = NULL;

    /* The GET method requires a pre-session cookie */

    if (!scfg->use_post) {
        ap_log_rerror (PC_LOG_DEBUG, r, "making a pre-session ckookie");
        pre_s = (char *) libpbc_get_cookie (r,
                                            scfg->sectext,
                                            (unsigned char *) "presesuser",
                                            (unsigned char *) PBC_VERSION,
                                            PBC_COOKIE_TYPE_PRE_S,
                                            PBC_CREDS_NONE,
                                            pre_sess_tok,
                                            (unsigned char *) appsrvid (r),
                                            appid (r), ME (r), 0,
                                            scfg->crypt_alg);
        if (!pre_s) {
            rr->stop_message = ap_pstrdup (p, "Failure making pre-session cookie");
            stop_the_show (r, scfg, cfg, rr);
            goto END;
        }

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
        goto END;
    }

    /* we handle post data unless it is too large, in which */
    /* case we treat it much like multi-part form data. */

    post_data = "";
    if (r->headers_in.content_length_n > 0) {
        int post_data_len;
        if ((post_data_len = r->headers_in.content_length_n) <= 0 ||
            post_data_len > MAX_POST_DATA ||
            (!(post_data = get_post_data (r, post_data_len)))) {
            rr->stop_message =
                ap_psprintf (p,
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

        ap_log_rerror (PC_LOG_DEBUG, r,
                       "g_req length %d cookie: %s", strlen (g_req_cookie),
                       g_req_cookie);
        ap_table_add (HDRS_OUT, "Set-Cookie", g_req_cookie);

#ifdef REDIRECT_IN_HEADER
        if (!(tenc || lenp)) {
            char *refresh_e = ap_os_escape_path (p, refresh, 0);
            /* warning, this will break some browsers */
            ap_table_add (HDRS_OUT, "Refresh", refresh_e);
        }
#endif

    }

    flush_headers (r);

    /* If we're using the post method, just bundle everything
       in a post to the login server. */

    if (scfg->use_post) {
        char cp[24];
        if ((port == 80 || port == 443) && !scfg->vitki_behind_proxy)
            cp[0] = '\0';
        else
            ap_snprintf (cp, sizeof(cp)-1, ":%d", port);
        ap_rprintf(r, post_request_html, str2charp(p, &scfg->login),
                    e_g_req_contents, encode_get_args(r, post_data, 1),
                    ap_get_server_name (r), cp, str2charp(p, &scfg->post_reply_url) + 1 /* skip first slash */);

    } else if (ctype && (tenc || lenp || r->method == NGX_HTTP_POST)) {

        ap_rprintf (r, get_post_request_html, str2charp(p, &scfg->login),
                    encode_get_args(r, post_data, 1), str2charp(p, &scfg->login), PBC_WEBISO_LOGO,
                    PBC_POST_NO_JS_BUTTON);

    } else {
#ifdef REDIRECT_IN_HEADER
/* warning, this will break some browsers */
        ap_rprintf (r, nullpage_html);
        rr->status = HTTP_MOVED_TEMPORARILY;
#else
        ap_rprintf (r, redirect_html, refresh);
#endif
    }

    ap_log_rerror (PC_LOG_DEBUG, r,
                   "auth_failed_handler: redirect sent. uri: %V reason: %d",
                   &mr->uri, rr->redir_reason_no);

    /* workaround for nginx problems with KeepAlive during redirections. */
    r->keepalive = 0;
END:
    if (refresh)  ap_pfree(p, refresh);
    if (g_req_contents)  ap_pfree(p, g_req_contents);
    if (e_g_req_contents)  ap_pfree(p, e_g_req_contents);

    return (OK);

}


/* figure out the session cookie name                                         */
static char *make_session_cookie_name (ngx_pool_t * p, char *cookiename,
                                unsigned char *_appid)
{
    /* 
       we now use JimB style session cookie names
       session cookie names are PBC_S_COOKIENAME_appid 
     */

    char *ptr;
    char *name;

    name = ap_pstrcat3 (p, cookiename, "_", (const char *) _appid);

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
static
char *get_cookie (request_rec * r, char *name, int n)
{
    const char *cookie_header;
    char *chp;
    char *cookie, *ptr;
    ngx_pubcookie_req_t *mr = ngx_http_get_module_ctx(top_rrec(r), pubcookie_module);
    char *name_w_eq;
    ngx_pool_t *p = r->pool;
    pubcookie_server_rec *scfg;
    int i;
    ngx_str_t orig_cookies;

    scfg = ngx_http_get_module_srv_conf(r, pubcookie_module);

    ap_log_rerror (PC_LOG_DEBUG, r, "get_cookie: %s (%d)", name, n);

    /* get cookies */
    if ((n==0) && (cookie_header = ap_table_get (mr->notes, name))&&(*cookie_header)) {
        ap_log_rerror (PC_LOG_DEBUG, r, " .. by cache: %s", cookie_header);
        return ap_pstrdup (p, cookie_header);
    }

    if (!(cookie_header = get_all_cookies (r, &orig_cookies)))
        return NULL;

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
    if (! chp)  return NULL;    

    ptr = cookie;
    while (*ptr) {
        if (*ptr == ';')
            { *ptr = 0; break; }
        ptr++;
    }
    ptr = ap_pstrdup (r->pool, cookie);
    ap_pfree(r->pool, cookie);
    cookie = ptr;

    /* cache and blank cookie */
    ap_table_set (mr->notes, name, cookie);
    if (!scfg->noblank) {
       off_t off = (off_t)((char *)orig_cookies.data - (char *)cookie_header);
       for (ptr=chp; *ptr&&*ptr!=';'; ptr++) *(ptr + off) = PBC_X_CHAR;
       dd(" .. blanked \"%V\"", &orig_cookies);
    }

                                                                                        if (*cookie) {
        ap_log_rerror (PC_LOG_DEBUG, r, " .. return: %s", cookie);
        return cookie;
    }
    return (NULL);

}

/* Initialize after config file commands have been processed */

static ngx_int_t pubcookie_init (ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *core_cf;

    core_cf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    if (NULL == (h = ngx_array_push(&core_cf->phases[NGX_HTTP_ACCESS_PHASE].handlers)))
        return NGX_ERROR;
    *h = pubcookie_authz_hook;

    return NGX_OK;
}

/*                                                                            */
static void *pubcookie_server_create (ngx_conf_t *cf)
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
    scfg->vitki_behind_proxy = NGX_CONF_UNSET;

    scfg->crypt_alg = NGX_CONF_UNSET_UINT;
    scfg->dummy_super_debug = NGX_CONF_UNSET;

    return (void *) scfg;
}

/*                                                                            */
static void *pubcookie_dir_create (ngx_conf_t *cf)
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

    return (void *) cfg;
}

/*                                                                            */
static char *pubcookie_server_merge (ngx_conf_t *cf, void *parent, void *child)
{
    ngx_pubcookie_srv_t *sprv = parent;
    ngx_pubcookie_srv_t *scfg = child;
    ngx_http_core_srv_conf_t *core_scf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_core_module);
    int i;

    ngx_conf_merge_value(scfg->dirdepth, sprv->dirdepth, PBC_DEFAULT_DIRDEPTH);
    /*
    ** Unlike pubcookie for apache, pubcookie for nginx does NOT blank cookies
    ** by default, because nginx shares cookie array between requests, while
    ** request structures are cleared, including notes table, resulting in
    ** in lost cookie values.
    */
    ngx_conf_merge_value(scfg->noblank, sprv->noblank, 1);
    ngx_conf_merge_value(scfg->catenate, sprv->catenate, 0);
    ngx_conf_merge_value(scfg->no_clean_creds, sprv->no_clean_creds, 0);
    ngx_conf_merge_value(scfg->use_post, sprv->use_post, 0);
    ngx_conf_merge_uint_value(scfg->crypt_alg, sprv->crypt_alg, PBC_DEF_CRYPT);
    ngx_conf_merge_value(scfg->vitki_behind_proxy, sprv->vitki_behind_proxy, 0);

    for (i = 0; pbc_cfg_str_fields[i].name != NULL; i++) {
        int off = pbc_cfg_str_fields[i].offset;
        ngx_str_t *ps = (ngx_str_t *)((char *) sprv + off);
        ngx_str_t *cs = (ngx_str_t *)((char *) scfg + off);
        if (! cs->data)
            *cs = *ps;
    }

    pbc_ngx_log(cf->log, PC_LOG_DEBUG,
                "pubcookie_server_merge: server %V has %d locations",
                &core_scf->server_name, scfg->locations);

    if (! scfg->locations)
        return NGX_CONF_OK;

    if (scfg->use_post && !scfg->post_reply_url.data)
        return "pubcookie_post: post reply location e.g. /PubCookie.reply must be set!";

    if (! scfg->ssl_key_file.data)
        return "pubcookie_session_key_file: configuration directive must be set!";
    if (! scfg->ssl_cert_file.data)
        return "pubcookie_session_cert_file: configuration directive must be set!";
    if (! scfg->granting_cert_file.data)
        return "pubcookie_granting_cert_file: configuration directive must be set!";
    if (! scfg->keydir.data)
        return "pubcookie_key_dir: configuration directive must be set!";
    if (! scfg->login.data)
        return "pubcookie_login: configuration directive must be set!";

    /*
    pbc_configure_init (p, "ngx_pubcookie_module",
                        NULL,
                        NULL,
                        &libpbc_apacheconfig_getint,
                        &libpbc_apacheconfig_getlist,
                        &libpbc_apacheconfig_getstring,
                        &libpbc_apacheconfig_getswitch);

    pbc_log_init (p, "ngx_mod_pubcookie_module", NULL, &mylog, NULL, NULL);
    */

    if (libpbc_pubcookie_init((pool *) scfg, &scfg->sectext) != PBC_OK)
        return "pubcookie_init: libpbc_pubcookie_init failed.";
    pbc_ngx_log(cf->log, PC_LOG_DEBUG, "pubcookie_init: libpbc init done");

    return NGX_CONF_OK;
}

/*                                                                            */
static char *pubcookie_dir_merge (ngx_conf_t *cf, void *parent, void *child)
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
	        ngx_pstrcat3(cf->pool, &cfg->oldappid, &prv->oldappid, &prv->appid, NULL);
        } else {
            /* No.  The parent's app ID is now the "old app ID". */
            cfg->oldappid = prv->appid;
        }
    }

    /* life is much easier if the default value is zero or NULL */
    if (! cfg->appid.data) {
        cfg->appid = prv->appid;
        if (cfg->appid.data)
            mark_location(cf, cfg, "merge");
    }

    if (! cfg->end_session.data)
        cfg->end_session = prv->end_session;
    if (cfg->end_session.data && !cfg->appid.data)
        return "pubcookie_end_session requires pubcookie_app_id";

    if (prv->addl_requests) {
        if (cfg->addl_requests)
	        cfg->addl_requests = ap_pstrcat3 (cf->pool, prv->addl_requests,
	                                            "&", cfg->addl_requests);
        else
            cfg->addl_requests = prv->addl_requests;
    }

    if (! cfg->accept_realms)
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


static
int get_pre_s_from_cookie (request_rec * r)
{
    pubcookie_server_rec *scfg;
    pbc_cookie_data *cookie_data = NULL;
    char *cookie = NULL;
    int ccnt = 0;

    scfg =
        ngx_http_get_module_srv_conf(r, pubcookie_module);

    ap_log_rerror (PC_LOG_DEBUG, r, "retrieving a pre-session ckookie");
    while ((cookie = get_cookie (r, PBC_PRE_S_COOKIENAME, ccnt))) {
        cookie_data = libpbc_unbundle_cookie (r, scfg->sectext,
                                              cookie, ME (r), 0,
                                              scfg->crypt_alg);
        if (cookie_data) break;
        ap_log_rerror (PC_LOG_INFO, r,
                       "get_pre_s_from_cookie: can't unbundle pre_s cookie uri: %V\n",
                       &r->uri);
        ccnt++;
    }
    if (!cookie_data) {
        ap_log_rerror (PC_LOG_INFO, r,
                       "get_pre_s_from_cookie: no pre_s cookie, uri: %V\n",
                       &r->uri);
        return (-1);
    }

    dump_cookie_data(r, "get_pre_s_from_cookie", cookie_data);
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
    ngx_table_elt_t *ifms;

    scfg =
        ngx_http_get_module_srv_conf(r, pubcookie_module);


    cfg =
        ngx_http_get_module_loc_conf(r, pubcookie_module);

    rr = ngx_http_get_module_ctx(r, pubcookie_module);

    ap_log_rerror (PC_LOG_DEBUG, r,
                   "pubcookie_user_hook: uri: %V location: \"%V\" auth_type: %s", &r->uri, &cfg->location,
                   ap_auth_type (r));

    if (!ap_auth_type (r))
        return DECLINED;

    /* pass if the request is for our post-reply */
    if (ngx_strcmp_eq(r->uri, scfg->post_reply_url))
        return OK;

    /* if it's basic auth then it's not pubcookie */
/*
    if( strcasecmp(ap_auth_type(r), "basic") == 0 ) return DECLINED;
 */

    /* get pubcookie creds or bail if not a pubcookie auth_type */
    if ((creds = pubcookie_auth_type (r)) == PBC_CREDS_NONE)
        return DECLINED;

    /* pass if the request is for favicon.ico */
    if (ngx_strcasecmp_c (r->uri, "/favicon.ico"))
        return OK;

    /* If this is a subrequest we either already have a user or we don't. */
    if (r != r->main) {
        pubcookie_req_rec *mr = ngx_http_get_module_ctx(r->main, pubcookie_module);
        ap_log_rerror (PC_LOG_DEBUG, r, "  .. user_hook: sub: %p, user=%s",
                       mr, mr ? mr->USER : "");
        if (mr && mr->USER && *mr->USER) {
            return OK;
        }
        if (cfg->noprompt>0) {
            rr->USER = ap_pstrdup (r->pool, "");
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
            flush_headers (r);
            ap_rprintf (r, "Unauthorized user.");
            rr->status = HTTP_UNAUTHORIZED;
            return DONE;
        }
        auth_failed_handler (r, scfg, cfg, rr);
        return DONE;
    }
    ap_log_rerror (PC_LOG_DEBUG, r, " .. user_hook: user '%s' OK", rr->USER ? rr->USER : "NULL");

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
        rr->USER = "";         /* rest of apache needs a user if there's an authtype */
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

    ifms = r->headers_in.if_modified_since;
    if (ifms) {
        ap_log_rerror (PC_LOG_DEBUG, r, " .. user_hook: removing if-modified = %V", &ifms->value);
        r->headers_in.if_modified_since = NULL;
    }

    ap_log_rerror (PC_LOG_DEBUG, r,
                   " .. user_hook exit: user '%s', type '%s'", rr->USER,
                   rr->AUTH_TYPE);

    return (s);
}

/* Check user id                                                              */
static
int pubcookie_user (request_rec * r, pubcookie_server_rec * scfg,
                    pubcookie_dir_rec * cfg, pubcookie_req_rec * rr)
{
    char *cookie;

    pbc_cookie_data *cookie_data;
    ngx_pool_t *p = r->pool;
    char *sess_cookie_name;

    int cred_from_trans;
    int pre_sess_from_cookie;
    int gcnt = 0;
    int scnt = 0;

    ap_log_rerror (PC_LOG_DEBUG, r,
                   "pubcookie_user: going to check uri: %V creds: %c",
                   &r->uri, rr->creds);

    /* maybe dump the directory and server recs */
    dump_recs(r, scfg, cfg);

    sess_cookie_name =
        make_session_cookie_name (p, PBC_S_COOKIENAME, appid (r));

    /* force SSL */

    if (! r->connection->ssl)
    {

        ap_log_rerror (PC_LOG_DEBUG, r,
                       "Not SSL; uri: %V appid: %s", &r->uri, appid (r));
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_NOGORS_CODE;
        return OK;
    }

    /* before we check if they hav a valid S or G cookie see if it's a logout */
    if (check_end_session (r) & PBC_END_SESSION_ANY) {
        return OK;
    }

    ap_log_rerror (PC_LOG_DEBUG, r,
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
    while ((cookie = get_cookie (r, PBC_G_COOKIENAME, gcnt))
        && (scfg->use_post || get_cookie (r, PBC_PRE_S_COOKIENAME, 0))) {
        cookie_data =
            libpbc_unbundle_cookie (r, scfg->sectext, cookie,
                                    ap_get_server_name (r), 1,
                                    scfg->crypt_alg);
        if (cookie_data) break;
        ap_log_rerror (PC_LOG_INFO, r,
                       "can't unbundle G cookie, it's probably not for us; uri: %V\n",
                       &r->uri);
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
        while ((cookie = get_cookie (r, sess_cookie_name, scnt))) {
            cookie_data =
                libpbc_unbundle_cookie (r, scfg->sectext, cookie, ME(r), 0,
                                        scfg->crypt_alg);

            if (cookie_data) break;

            /* try 'fixing' the cookie */
            ap_log_rerror (PC_LOG_INFO, r,
                           "retrying failed unbundle of S cookie; uri: %V\n",
                           &r->uri);
            ckfix = ap_pstrcat3 (p, cookie, "==", NULL);
            cookie_data = libpbc_unbundle_cookie (r, scfg->sectext, ckfix, ME(r), 0,
                                        scfg->crypt_alg);
            if (cookie_data) break;

            ap_log_rerror (PC_LOG_INFO, r,
                           "still can't unbundle S cookie; uri: %V\n",
                           &r->uri);
            scnt++;
        }

        if (cookie_data) {

            dump_cookie_data(r, "pubcookie_user.1", cookie_data);
            rr->cookie_data = cookie_data;

            /* we tell everyone what authentication check we did */
            rr->AUTH_TYPE = ap_pstrdup (p, ap_auth_type (r));
            rr->USER = ap_pstrdup (p, (char *) (*cookie_data).broken.user);

            /* save the full user/realm for later */

            /* check for acceptable realms and strip realm */
            if ((cfg->strip_realm == 1) || (cfg->accept_realms != NULL)) {
                char *tmprealm, *tmpuser;
                tmpuser =
                    ap_pstrdup (p, (char *) (*cookie_data).broken.user);
                tmprealm = index (tmpuser, '@');
                if (tmprealm) {
                    tmprealm[0] = 0;
                    tmprealm++;
                    set_ngx_variable (r, "REMOTE_REALM", tmprealm);
                }

                if (cfg->strip_realm == 1) {
                    rr->USER = tmpuser;
                } else {
                    rr->USER =
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
                (r, (*cookie_data).broken.create_ts,
                 cfg->hard_exp) == PBC_FAIL) {
                ap_log_rerror (PC_LOG_INFO, r,
                               "S cookie hard expired; user: %s cookie timestamp: %d timeout: %d now: %d uri: %V\n",
                               (*cookie_data).broken.user,
                               (*cookie_data).broken.create_ts,
                               cfg->hard_exp, pbc_time (NULL), &r->uri);
                rr->failed = PBC_BAD_AUTH;
                rr->redir_reason_no = PBC_RR_SHARDEX_CODE;
                return OK;
            }

            if (cfg->inact_exp != -1 &&
                libpbc_check_exp (r, (*cookie_data).broken.last_ts,
                                  cfg->inact_exp) == PBC_FAIL) {
                ap_log_rerror (PC_LOG_INFO, r,
                               "S cookie inact expired; user: %s cookie timestamp %d timeout: %d now: %d uri: %V\n",
                               (*cookie_data).broken.user,
                               (*cookie_data).broken.last_ts,
                               cfg->inact_exp, pbc_time (NULL), &r->uri);
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
                           "S cookie chk nop: user=%s, nop=%d", rr->USER,
                           cfg->noprompt);
            if ((cfg->noprompt <= 0) && !*rr->USER) {
                ap_log_rerror (PC_LOG_INFO, r,
                               "S cookie noprompt to prompt");
                rr->failed = PBC_BAD_AUTH;
                rr->redir_reason_no = PBC_RR_NOGORS_CODE;
                return OK;
            }

        } else {                /* hav S cookie */

            ap_log_rerror (PC_LOG_DEBUG, r,
                           "No G or S cookie; uri: %V appid: %s sess_cookie_name: %s",
                           &r->uri, appid (r), sess_cookie_name);
            rr->failed = PBC_BAD_AUTH;
            rr->redir_reason_no = PBC_RR_NOGORS_CODE;
            return OK;

        }                       /* end if session cookie */

    } else {
        dump_cookie_data(r, "pubcookie_user.2", cookie_data);
        rr->has_granting = 1;

        clear_granting_cookie (r);
        if (!scfg->use_post)
            clear_pre_session_cookie (r);

        ap_log_rerror (PC_LOG_DEBUG, r,
                       "pubcookie_user: has granting; current uri is: %V",
                       &r->uri);

        /* If GET, check pre_session cookie */
        if (!scfg->use_post) {
            pre_sess_from_cookie = get_pre_s_from_cookie (r);
            ap_log_rerror (PC_LOG_DEBUG, r,
                           "pubcookie_user: ret from get_pre_s_from_cookie");
            if ((*cookie_data).broken.pre_sess_token !=
                pre_sess_from_cookie) {
                ap_log_rerror (PC_LOG_INFO, r,
                               "pubcookie_user, pre session tokens mismatched, uri: %V",
                               &r->uri);
                ap_log_rerror (PC_LOG_DEBUG, r,
                               "pubcookie_user, pre session from G: %d PRE_S: %d, uri: %V",
                               (*cookie_data).broken.pre_sess_token,
                               pre_sess_from_cookie, &r->uri);
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
                           "pubcookie_user: 'speed up that loop' logic; uri is: %V\n",
                           &r->uri);

            rr->failed = PBC_BAD_AUTH;
            rr->redir_reason_no = PBC_RR_DUMMYLP_CODE;
            return OK;
        }

        rr->AUTH_TYPE = ap_pstrdup (p, ap_auth_type (r));
        rr->USER = ap_pstrdup (p, (char *) (*cookie_data).broken.user);

        /* Make sure we really got a user (unless noprompt) */
        if ((!*rr->USER) && (cfg->noprompt<=0)) {
            ap_log_rerror (PC_LOG_INFO, r,
                               "No user and not a noprompt");
            rr->stop_message = ap_pstrdup (p, "Required user login didn't happen");
            rr->failed = PBC_BAD_G_STATE;
            return (DONE);
        }

        ap_log_rerror (PC_LOG_DEBUG, r,
                       "pubcookie_user: set type (%s) and user (%s)",
                       rr->AUTH_TYPE, rr->USER);

        /* save the full user/realm for later */


        /* check for acceptable realms and strip realm */
        if (*rr->user) {
            char *tmprealm, *tmpuser;
            tmpuser = ap_pstrdup (p, (char *) (*cookie_data).broken.user);
            tmprealm = index (tmpuser, '@');
            if (tmprealm) {
                tmprealm[0] = 0;
                tmprealm++;
                set_ngx_variable (r, "REMOTE_REALM", tmprealm);
            }

            if (cfg->strip_realm == 1) {
                rr->USER = tmpuser;
            } else {
                rr->USER =
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
            (r, (*cookie_data).broken.create_ts,
             PBC_GRANTING_EXPIRE) == PBC_FAIL) {
            ap_log_rerror (PC_LOG_INFO, r,
                           "pubcookie_user: G cookie expired by %ld; user: %s create: %ld uri: %V",
                           pbc_time (NULL) - (*cookie_data).broken.create_ts -
                           PBC_GRANTING_EXPIRE, (*cookie_data).broken.user,
                           (*cookie_data).broken.create_ts, &r->uri);
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
                       "pubcookie_user: wrong appid; current: %s cookie: %s uri: %V",
                       appid (r), (*cookie_data).broken.appid, &r->uri);
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_WRONGAPPID_CODE;
        return OK;
    }

    /* check appsrv id */
    if (strncasecmp ((const char *) appsrvid (r),
                     (const char *) (*cookie_data).broken.appsrvid,
                     sizeof ((*cookie_data).broken.appsrvid) - 1) != 0) {
        ap_log_rerror (PC_LOG_INFO, r,
                       "pubcookie_user: wrong app server id; current: %s cookie: %s uri: %V",
                       appsrvid (r), (*cookie_data).broken.appsrvid,
                       &r->uri);
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_WRONGAPPSRVID_CODE;
        return OK;
    }

    /* check version id */
    if (libpbc_check_version (r, cookie_data) == PBC_FAIL) {
        ap_log_rerror (PC_LOG_INFO, r,
                       "pubcookie_user: wrong version id; module: %d cookie: %d uri: %V",
                       PBC_VERSION, (*cookie_data).broken.version, &r->uri);
        rr->failed = PBC_BAD_AUTH;
        rr->redir_reason_no = PBC_RR_WRONGVER_CODE;
        return OK;
    }

    /* check creds */
    if (rr->creds != cookie_data->broken.creds) {
        ap_log_rerror (PC_LOG_INFO, r,
                       "pubcookie_user: wrong creds; required: %c cookie: %c uri: %V",
                       rr->creds, (*cookie_data).broken.creds, &r->uri);
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
        ngx_file_t f;

        int res = 0;

        /* base64 decode cookie */
        if (!libpbc_base64_decode (r, (unsigned char *) cookie,
                                   (unsigned char *) blob, &bloblen)) {
            ap_log_rerror (PC_LOG_ERR, r,
                           "credtrans: libpbc_base64_decode() failed");
            res = -1;
        }

        /* decrypt cookie. if credtrans is set, then it's from login server
           to me. otherwise it's from me to me. */
        if (!res && libpbc_rd_priv (r, scfg->sectext, cred_from_trans ?
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
            rr->cred_transfer = ap_pnalloc(p, plainlen);
            memcpy (rr->cred_transfer, plain, plainlen);
            rr->cred_transfer_len = plainlen;
        }

        /* set a random KRB5CCNAME */
        krb5ccname = 
            ap_psprintf (p, "/tmp/k5cc_%d_%s", getpid (), rr->user);
        f.fd = NGX_INVALID_FILE;
        f.sys_offset = 0;
        if (!res) {
            /* save these creds in that file */
            f.fd = ngx_open_file (krb5ccname, NGX_FILE_RDWR,
                                  NGX_FILE_CREATE_OR_OPEN | NGX_FILE_TRUNCATE,
                                  0640);

            if (f.fd == NGX_INVALID_FILE) {
                ap_log_rerror (PC_LOG_ERR, r,
                               "credtrans: setenv() failed");
                res = -1;
            }
        }
        if (!res &&
            ngx_write_file (&f, (u_char *) rr->cred_transfer,
                            rr->cred_transfer_len, 0) == NGX_ERROR
            ) {
            ap_log_rerror (PC_LOG_ERR, r, "credtrans: setenv() failed");
            res = -1;
        }

        if (f.fd != NGX_INVALID_FILE) {
            ngx_close_file (f.fd);
        }

        if (cred_from_trans) {
            clear_transfer_cookie (r);
        }
    }

    ap_log_rerror (PC_LOG_DEBUG, r,
                   "pubcookie_user: everything is o'tay; current uri is: %V",
                   &r->uri);

    return OK;

}


/* Check authz */

static int pubcookie_authz_hook (request_rec * r)
{
    ngx_int_t rc, rc2;
    pubcookie_server_rec *scfg = ngx_http_get_module_srv_conf(r, pubcookie_module);

    if (!ap_auth_type (r))
        return DECLINED;

    /* get pubcookie creds or bail if not a pubcookie auth_type */
    if (pubcookie_auth_type (r) == PBC_CREDS_NONE)
        return DECLINED;

    if (ngx_strcasecmp_c (r->uri, "/favicon.ico"))
        return OK;

    /* pass if the request is our post-reply */
    if (ngx_strcmp_eq (r->uri, scfg->post_reply_url))
        return OK;

    if (r != r->main) /* subrequest */
        return OK;

    if (! scfg->locations) /* server not enabled */
        return OK;

    pubcookie_setup_request(r);
    rc = pubcookie_user_hook(r);
    rc2 = pubcookie_finish_request(r);
    return (rc2 == DECLINED ? rc : rc2);
}

/* Set any additional environment variables for the client */
static int pubcookie_fixups (request_rec * r)
{
    pubcookie_dir_rec *cfg;
    pubcookie_req_rec *rr;
    ngx_pool_t *p = r->pool;

    cfg = ngx_http_get_module_loc_conf(r, pubcookie_module);
    rr = ngx_http_get_module_ctx(r, pubcookie_module);

    if (!rr)
        return OK;              /* subrequest */

    if (rr->cred_transfer) {
        char *krb5ccname =
            ap_psprintf (p, "/tmp/k5cc_%d_%s", (int) getpid (),
                         rr->user);

        set_ngx_variable (r, "KRB5CCNAME", krb5ccname);
    }

    /* Clear the null user from noprompt */
    if ((rr->creds != PBC_CREDS_NONE) && rr->USER && !*rr->USER) {
        ap_log_rerror (PC_LOG_DEBUG, r, "pubcookie_fixup: clear authtype");
        rr->AUTH_TYPE = NULL;
        rr->USER = NULL;
    }

    return OK;
}

/* See if we should augment the directives */

static int pubcookie_hparse (request_rec * r)
{
    char *cookies;
    char *nextcookie;
    ngx_pool_t *p = r->pool;

    ap_log_rerror (PC_LOG_DEBUG, r, "pubcookie_hparse: main=%p", r->main);

    if (!(cookies = (char *) get_all_cookies(r, NULL)))
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

/*                                                                            */
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
                         "PUBCOOKIE: inactivity expire parameter less then allowed minimum of %d, requested %d.",
                         PBC_MIN_INACT_EXPIRE, *np);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

/**
 *  handle the PubCookieHardExpire directive
 *  does some range checking
 */
static char *
pubcookie_post_hard_exp (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_flag_t *np = conf;

    if (*np > PBC_MAX_HARD_EXPIRE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "PUBCOOKIE: Hard expire parameter greater then allowed maximium of %d, requested %d.",
                         PBC_MAX_HARD_EXPIRE, *np);
        return NGX_CONF_ERROR;
    } else if (*np < PBC_MIN_HARD_EXPIRE) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                         "PUBCOOKIE: Hard expire parameter less then allowed minimum of %d, requested %d.",
                         PBC_MIN_HARD_EXPIRE, *np);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


/**
 *  handle the PubCookieLogin directive
 *  we do a little checking to make sure the url is correctly formatted.
 */
static char *
pubcookie_post_login (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_str_t *sp = conf;
    if (0 != ngx_strncmp(sp->data, "https://", 8))
        return "PUBCOOKIE: PubCookieLogin must start with https://";
    return NGX_CONF_OK;
}

/**
 *  handle the PubCookieDomain directive
 */
static char *
pubcookie_post_domain (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_str_t *sp = conf;

    if (sp->len > 0 && sp->data[0] != '.') {
        static ngx_str_t dot = ngx_string(".");
        ngx_pstrcat3(cf->pool, sp, &dot, sp, NULL);
    }

    return NGX_CONF_OK;
}

static char *
pubcookie_set_appid (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;

    normalize_id_string(cf->pool, &cfg->appid, &value[1]);

    mark_location(cf, cfg, "set_appid");

    return NGX_CONF_OK;
}

static char *
pubcookie_addl_request (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_t *cfg = conf;
    cfg->addl_requests = join_ngx_strings (cf->pool, cfg->addl_requests,
                                        cf->args->elts, cf->args->nelts, "&");
    return cfg->addl_requests ? NGX_CONF_OK : "Not enough memory for add_request";
}

static char *
pubcookie_accept_realms (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_t *cfg = conf;
    cfg->accept_realms = join_ngx_strings (cf->pool, cfg->accept_realms,
                                        cf->args->elts, cf->args->nelts, " ");
    return cfg->accept_realms ? NGX_CONF_OK : "Not enough memory for accept_realms";
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

/*                                                                            */
static char *
pubcookie_set_session_reauth (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_loc_t *cfg = conf;
    ngx_str_t *value = cf->args->elts;

    if (!value[1].len)
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

/* allow admin to set a "dont blank the cookie" mode for proxy with pubcookie */
/* DEPRECATED in favour of PubcookieNoObscureCookie                          */
static char *
pubcookie_set_no_blank (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    pubcookie_server_rec *scfg;
    scfg = conf;
    pbc_ngx_log (cf->log, PC_LOG_DEBUG,
        "WARNING: pubcookie_no_nlank is deprecated in favor of pubcookie_no_obscure_cookie");
    scfg->noblank = 1;
    return NGX_CONF_OK;
}

/**
 * gives more debugging
 * @param cmd - command record
 * @param mconfig - module configuration
 * @param f - int
 * @returns NULL 
 */
static char *
pubcookie_post_super_debug (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_flag_t *fp = conf;
    pubcookie_super_debug = *fp;
    return NGX_CONF_OK;
}

/* Set the noprompt option */
static char *
pubcookie_post_noprompt (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_flag_t *fp = conf;
    if (*fp == 0)
        *fp = -1;
    return NGX_CONF_OK;
}

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

static char *
pubcookie_set_post_url (ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_pubcookie_srv_t *scfg = conf;
    ngx_http_core_loc_conf_t  *core_lcf;

    core_lcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    scfg->post_reply_url = core_lcf->name;
    core_lcf->handler = pubcookie_post_handler;

    return NGX_CONF_OK;
}

static char *
pubcookie_post_end_session (ngx_conf_t *cf, void *data, void *conf)
{
    ngx_http_core_loc_conf_t  *core_lcf;
    core_lcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    core_lcf->handler = pubcookie_end_session_handler;
    return NGX_CONF_OK;
}

/*
 *  Configuration
 */

static ngx_conf_post_t pubcookie_conf_inact_exp = { pubcookie_post_inact_exp };
static ngx_conf_post_t pubcookie_conf_hard_exp = { pubcookie_post_hard_exp };
static ngx_conf_post_t pubcookie_conf_login = { pubcookie_post_login };
static ngx_conf_post_t pubcookie_conf_dirdepth = { pubcookie_post_dirdepth };
static ngx_conf_post_t pubcookie_conf_domain = { pubcookie_post_domain };
static ngx_conf_post_t pubcookie_conf_super_debug = { pubcookie_post_super_debug };
static ngx_conf_post_t pubcookie_conf_noprompt = { pubcookie_post_noprompt };
static ngx_conf_post_t pubcookie_conf_end_session = { pubcookie_post_end_session };


static const command_rec pubcookie_commands[] = {
    /* "Set the inactivity expire time for PubCookies." */
    { ngx_string("pubcookie_inactive_expire"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, inact_exp),
      &pubcookie_conf_inact_exp },

    /* "Set the hard expire time for PubCookies." */
    { ngx_string("pubcookie_hard_expire"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, hard_exp),
      &pubcookie_conf_hard_exp },

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

    /* "Set the name of the certfile for Session PubCookies." */
    { ngx_string("pubcookie_session_cert_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, ssl_cert_file),
      NULL },

    /* "Set the name of the keyfile for Session PubCookies." */
    { ngx_string("pubcookie_session_key_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, ssl_key_file),
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

    /* "Set the name of the application." */
    { ngx_string("pubcookie_app_id"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
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

    /* "Specify the Directory Depth for generating default AppIDs." */
    { ngx_string("pubcookie_dir_depth"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, dirdepth),
      &pubcookie_conf_dirdepth },

    /* "Force reauthentication for new sessions with specified timeout" */
    { ngx_string("pubcookie_session_reauth"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      pubcookie_set_session_reauth,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, session_reauth),
      NULL },

    /* "End application session and possibly login session" */
    { ngx_string("pubcookie_end_session"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, end_session),
      &pubcookie_conf_end_session },

    /* "Send the following options to the login server along with authentication requests" */
    { ngx_string("pubcookie_addl_request"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      pubcookie_addl_request,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, addl_requests),
      NULL },

    /* "Only accept realms in this list" */
    { ngx_string("pubcookie_accept_realm"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_1MORE,
      pubcookie_accept_realms,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, accept_realms),
      NULL },

    /* "Strip the realm (and set the REMOTE_REALM envirorment variable)" */
    { ngx_string("pubcookie_strip_realm"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, strip_realm),
      NULL },

    /* "Specify on-demand pubcookie directives." */
    { ngx_string("pubcookie_on_demand"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_keyval_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, keydirs), /* FIXME */
      NULL },

    /* "Do not prompt for id and password if not already logged in." */
    { ngx_string("pubcookie_no_prompt"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, noprompt),
      &pubcookie_conf_noprompt },

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

    /* "Set post response URL. Def = /PubCookie.reply" */
    { ngx_string("pubcookie_post"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      pubcookie_set_post_url,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, post_reply_url),
      NULL },

    /* "Set super debugging." */
    { ngx_string("pubcookie_super_debug"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(ngx_pubcookie_srv_t, dummy_super_debug),
      &pubcookie_conf_super_debug },

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
      offsetof(ngx_pubcookie_srv_t, vitki_behind_proxy),
      NULL },

/* maybe for future exploration
*/
    /* "Set the non_ssl_ok." */
    { ngx_string("pubcookie_no_ssl_ok"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_pubcookie_loc_t, non_ssl_ok),
      NULL },

    ngx_null_command
};


static pbc_param_off_t
pbc_cfg_str_fields[] = {
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
    { "post_reply_url",     offsetof(ngx_pubcookie_srv_t, post_reply_url) },
    { NULL, 0 }
};

/* Configuration helper for libpbc library */

const char *
libpbc_config_getstring(pool *ptr, const char *name, const char *defval)
{
    ngx_pubcookie_srv_t *scfg = NULL;
    ngx_http_request_t *r;
    ngx_log_t *log = NULL;
    ngx_pool_t *pool = NULL;
    int i;

    if (ptr) {
        if (*(uint32_t *)ptr == PBC_SRV_SIGNATURE) {
            scfg = (ngx_pubcookie_srv_t *) ptr;
            log = scfg->log;
            pool = scfg->pool;
        } else {
            r = (ngx_http_request_t *) ptr;
            scfg = ngx_http_get_module_srv_conf(r, pubcookie_module);
            log = r->connection->log;
            pool = r->pool;
        }
    }

    if (! scfg) {
        pbc_ngx_log(log, PC_LOG_DEBUG, "config_getstring: server configuration not found for \"%s\"", name);
        return defval;
    }

    for (i = 0; pbc_cfg_str_fields[i].name != NULL; i++) {
        if (0 == strcmp(pbc_cfg_str_fields[i].name, name)) {
            ngx_str_t *nsp = (ngx_str_t *) ((char *)scfg + pbc_cfg_str_fields[i].offset);
            char * val = nsp->data ? str2charp(pool, nsp) : (char *) defval;
            pbc_ngx_log(log, PC_LOG_DEBUG, "config_getstring: value of \"%s\" is \"%s\"",
                        name, val?:"(NULL)");
            return val;
        }
    }

    /* not found */
    pbc_ngx_log(log, PC_LOG_DEBUG, "config_getstring: field \"%s\" not found !!", name);
    return defval;
}

/* Check for and load any keyed directives.  Return true if any found.
   Only a few directives can be invoked this way:
      "authtype", "require", and the following from pubcookie */

static char *odpc_dirs[] = {
    "pubcookie_inactive_expire",
    "pubcookie_hard_expire",
    "pubcookie_app_id",
    "pubcookie_session_cause_reauth",
    "pubcookie_end_session",
    "pubcookie_no_prompt",
    NULL
};

static int load_keyed_directives (request_rec * r, char *key)
{
    /* FIXME */
    return (0);
}

static int pubcookie_cleanup (request_rec * r)
{
    pubcookie_req_rec *rr;
    pubcookie_server_rec *scfg;

    ap_log_rerror (PC_LOG_DEBUG, r, "cleanup");

    rr = ngx_http_get_module_ctx(r, pubcookie_module);
    scfg = ngx_http_get_module_srv_conf(r, pubcookie_module);

    if (!rr)
        return OK;

    if (rr->cred_transfer && !scfg->no_clean_creds) {
        struct stat sb;
        const char *krb5ccname = get_ngx_variable (r, "KRB5CCNAME");

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
        if ((q = strchr (p, '&'))) *q++ = '\0';
        if ((s = strchr (p, '='))) *s++ = '\0';
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
static int login_reply_handler (request_rec * r)
{
    pubcookie_server_rec *scfg;
    pubcookie_dir_rec *cfg;
    pubcookie_req_rec *rr;
    table *args = ap_make_table (r->pool, 5);
    const char *greply, *creply, *pdata;
    char *arg;
    char *a;

    char *post_data;
    char *gr_cookie, *cr_cookie = "";
    const char *r_url;
    ngx_pool_t *p = r->pool;

    scfg =
        ngx_http_get_module_srv_conf(r, pubcookie_module);

    cfg = ngx_http_get_module_loc_conf(r, pubcookie_module);

    rr = ngx_http_get_module_ctx(r, pubcookie_module);

    ap_log_rerror (PC_LOG_DEBUG, r, "login_reply_handler: hello");

    set_no_cache_headers (r);

    /* Get the request data */

    if (r->args.len) {
        arg = str2charp (p, &r->args);
        scan_args (r, args, arg);
    }
    if (r->headers_in.content_length_n > 0) {
        post_data = get_post_data (r, r->headers_in.content_length_n);
        if (! post_data)
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        scan_args (r, args, post_data);
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
        arg = ap_pstrdup (p, r_url);
    }
    /* make sure there are no newlines in the redirect location */
    if ((a=strchr(arg,'\n'))) *a = '\0';
    if ((a=strchr(arg,'\r'))) *a = '\0';


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

        /* workaround for nginx problems with KeepAlive during redirections. */
        r->keepalive = 0;

        return (HTTP_MOVED_TEMPORARILY);

    }

    ap_pfree(p, arg);
    return (OK);
}

static ngx_int_t
pubcookie_post_handler (ngx_http_request_t * r)
{
    ngx_int_t rc, rc2;
    pubcookie_setup_request(r);
    rc = login_reply_handler(r);
    rc2 = pubcookie_finish_request(r);
    return (rc2 == NGX_DECLINED ? rc : rc2);
}


static ngx_int_t
pubcookie_end_session_handler (ngx_http_request_t * r)
{
    ngx_int_t rc, rc2;
    pubcookie_setup_request(r);
    rc = pubcookie_user_hook(r);
    rc2 = pubcookie_finish_request(r);
    return (rc2 == NGX_DECLINED ? rc : rc2);
}


static ngx_http_module_t  pubcookie_module_ctx = {
    NULL,                       /* preconfiguration */
    pubcookie_init,             /* postconfiguration */

    NULL,                       /* create main configuration */
    NULL,                       /* init main configuration */

    pubcookie_server_create,    /* create server configuration */
    pubcookie_server_merge,     /* merge server configuration */

    pubcookie_dir_create,       /* create location configuration */
    pubcookie_dir_merge         /* merge location configuration */
};

ngx_module_t pubcookie_module = {
    NGX_MODULE_V1,
    &pubcookie_module_ctx,                 /* module context */
    (command_rec *) pubcookie_commands,    /* module directives */
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

/* END, SVN Id: $Id$ */

