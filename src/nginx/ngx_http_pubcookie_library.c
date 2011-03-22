/*
 * Copyright (C) 2010 Vitki <vitki@vitki.net>
 *
 * SVN Id: $Id$
 */

#include "ngx_http_pubcookie.h"

#define pbc_log_activity(p,v,args...) pbc_ngx_log(log_of(p),(v),args);
#define pbc_vlog_activity(p,v,f,va)   pbc_ngx_log(log_of(p),(v),"libpubcookie: %s",f);

#undef pbc_malloc
#undef pbc_free
#undef pbc_strdup
#undef pbc_strndup
#undef ap_pstrdup
#define pbc_malloc(p,x) ngx_palloc(pool_of(p),x)
#define pbc_free(p,x) ngx_pfree(pool_of(p),x)
#define pbc_strdup(p,x) __ap_pstrdup(pool_of(p),x)
#define ap_strdup(p,x) __ap_pstrdup(pool_of(p),x)

static inline ngx_log_t * log_of (void *p)
{
    return (NULL == p ? NULL : (*(uint32_t *)p == PBC_SRV_SIGNATURE)
            ? ((ngx_pubcookie_srv_t *)p)->log : ((ngx_http_request_t *)p)->connection->log);
}

static inline ngx_pool_t * pool_of (void *p)
{
    return (NULL == p ? NULL : (*(uint32_t *)p == PBC_SRV_SIGNATURE)
            ? ((ngx_pubcookie_srv_t *)p)->pool : ((ngx_http_request_t *)p)->pool);
}

#define HAVE_STDARG_H
#define HAVE_SNPRINTF
#define HAVE_VSNPRINTF
#define HAVE_SYS_UTSNAME_H
#define strlcpy pbc_strlcpy
#define strlcat pbc_strlcat
#define assert(x) (0)

#include "base64.c"
#include "pbc_time.c"
#include "strlcpy.c"
#include "libpubcookie.c"

#define make_crypt_keyfile make_crypt_keyfile__security_legacy
static void make_crypt_keyfile (pool * p, const char *peername, char *buf);
#include "security_legacy.c"
#undef make_crypt_keyfile

#undef PBC_LOGIN_URI
#undef PBC_RELAY_LOGIN_URI
#undef PBC_KEYMGT_URI
#undef PBC_ENTRPRS_DOMAIN
#undef PBC_TEMPLATES_PATH
#undef PBC_RELAY_URI

/* SVN Id: $Id$ */

