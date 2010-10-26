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

/** @file libpubcookie.c
 * Core pubcookie library
 *
 * $Id: libpubcookie.c,v 2.93 2008/05/16 22:09:10 willey Exp $
 */


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

#if defined (APACHE2)
#define pbc_malloc(p, x) apr_palloc(p, x)
#define pbc_strdup(p, x) apr_pstrdup(p, x)
#endif

# ifdef HAVE_STDIO_H
#  include <stdio.h>
# endif /* HAVE_STDIO_H */

# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif /* HAVE_STDLIB_H */

# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# endif /* HAVE_STDARG_H */

# ifdef HAVE_STRING_H
#  include <string.h>
# endif /* HAVE_STRING_H */

# ifdef HAVE_STRINGS_H
#  include <strings.h>
# endif /* HAVE_STRINGS_S */

# ifdef HAVE_SYS_UTSNAME_H
#  include <sys/utsname.h>
# endif /* HAVE_SYS_UTSNAME_H */

# ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
# endif /* HAVE_NETINET_IN_H */

# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif /* HAVE_UNISTD_H */

# ifdef HAVE_NETDB_H
#  include <netdb.h>
# endif /* HAVE_NETDB_H */

#if defined (APACHE2)
#define pbc_malloc(p, x) apr_palloc(p, x)
#endif
#if defined (APACHE)
#  include "httpd.h"
#  include "http_config.h"
#  include "http_core.h"
#  include "http_log.h"
#  include "http_main.h"
#  include "http_protocol.h"
#  include "util_script.h"
# else
typedef void pool;
#endif

#ifdef APACHE2
#include "apr_strings.h"
typedef apr_pool_t pool;
typedef apr_table_t table;
#endif

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

#ifdef WIN32
# include <windows.h>
# include <process.h>           /* getpid */
# include <stdio.h>
# include <io.h>
# include <assert.h>
# include <httpfilt.h>
# include "pbc_config.h"
# include "pubcookie.h"
# include "Win32/PubCookieFilter.h"
typedef int pid_t;              /* win32 process ID */
#else
# include "pubcookie.h"
# include "pbc_config.h"
#endif

#ifdef APACHE2
#endif

#include "pbc_version.h"
#include "pbc_logging.h"
#include "libpubcookie.h"
#include "strlcpy.h"
#include "pbc_configure.h"
#include "security.h"

#ifdef HAVE_DMALLOC_H
# if !defined(APACHE)
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

/* CONSTANTS */

/* why is this user being sent back, well the redirect reason will tell ya */
const char *redirect_reason[] = {
    "NONE",                     /* 0 */
    "No G or S cookie",         /* 1 */
    "Can't unbundle S cookie",  /* 2 */
    "S cookie hard expired",    /* 3 */
    "S cookie inact expired",   /* 4 */
    "speed up that loop",       /* 5 */
    "Can't unbundle G cookie",  /* 6 */
    "G cookie expired",         /* 7 */
    "Wrong appid",              /* 8 */
    "Wrong app server id",      /* 9 */
    "Wrong version id",         /* 10 */
    "Wrong creds",              /* 11 */
    "Bad Pre-session Cookie",   /* 12 */
    "New Forced ReAuth",        /* 13 */
    "PInit"                     /* 14 */
};

const char *get_my_hostname (pool * p, const security_context * context)
{
    return libpbc_get_cryptname (p, context);
}

/** 
 * find the credential id value for an authtype name
 * @param name the name of the authtype
 * @returns either PBC_CREDS_NONE or the credential id to pass in the cookie
 */
char libpbc_get_credential_id (pool * p, const char *name)
{
    if (!strcasecmp (name, "uwnetid")) {
        pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                          "WARNING: AuthType %s will not be supported in future versions - use AuthType WebISO\n",
                          name);
        return PBC_BASIC_CRED_ID;
    }
    if (!strcasecmp (name, "webiso") ||
        !strcasecmp (name, "webiso-vanilla")) {
        return PBC_BASIC_CRED_ID;       /* flavor_basic */
    } else if (!strcasecmp (name, "uwsecurid")) {
        return PBC_UWSECURID_CRED_ID;   /* flavor_uwsecurid */
    } else if (!strcasecmp (name, "webiso-getcred")) {
        return PBC_GETCRED_CRED_ID;     /* flavor_getcred */
    } else {
        return PBC_CREDS_NONE;
    }
}

/*
 * print the passed bytes
 */
static void print_hex_nybble (pool * p, FILE * f, int n)
{
    char *hex = "0123456789abcdef";
    n &= 0x0f;
    fputc (hex[n], f);
}

static void print_hex_bytes (pool * p, FILE * f, void *s_in, int len)
{
    unsigned char *s = (unsigned char *) s_in;
    fprintf (f, "[%lx]", (long) s);
    if (s == 0) {
        fprintf (f, "(null)");
        return;
    }
    while (len-- > 0) {
        print_hex_nybble (p, f, (*s) >> 4);
        print_hex_nybble (p, f, (*s));
        s++;
    }
}

/* get a nice pretty log time                                                 */
char *libpbc_time_string (pool * p, pbc_time_t t)
{
    struct tm *tm;
    static char buf[PBC_1K];

    tm = localtime ( (const time_t *) &t);
    strftime (buf, sizeof (buf) - 1, "%Y/%m/%d %H:%M:%S", tm);

    return buf;
}

/* when things fail too badly to go on ...                                    */
void *libpbc_abend (pool * p, const char *format, ...)
{
    va_list args;

    va_start (args, format);
    pbc_vlog_activity (p, PBC_LOG_ERROR, format, args);
    va_end (args);

#if defined (WIN32)
    return NULL;
#else
    exit (EXIT_FAILURE);
#endif
}

void libpbc_void (pool * p, void *thing)
{
}

void *libpbc_malloc_debug (pool * p, size_t x)
{
    void *ptr;
    ptr = pbc_malloc (p, x);
    pbc_log_activity (p, PBC_LOG_ERROR, "  pbc_malloc(p, %d)= x%X\n", x,
                      ptr);
    return ptr;
}

void free_debug (pool * p, void *ptr)
{
    pbc_log_activity (p, PBC_LOG_ERROR, "  pbc_free= x%X\n", ptr);
    pbc_free (p, ptr);
}

/* keep pumping stuff into the random state                                   */
void libpbc_augment_rand_state (pool * p, unsigned char *array, int len)
{

/*  Window only has milliseconds */
#if defined (WIN32)
    SYSTEMTIME ts;
    unsigned char buf[sizeof (ts.wMilliseconds)];

    GetLocalTime (&ts);
    memcpy (buf, &ts.wMilliseconds, sizeof (ts.wMilliseconds));
    RAND_seed (buf, sizeof (ts.wMilliseconds));
#else
    const char *egd_sock = NULL;
    int alloc;

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_augment_rand_state: hello");

    if (RAND_status ()) {
        pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                          "Sufficient Randomness: nothing to do.");
        return;
    }

    egd_sock = libpbc_config_getstring (p, "egd_socket", NULL);

    if (egd_sock != NULL) {

        pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "Querying EGD Socket: %s",
                          egd_sock);

        if ((alloc = RAND_egd (egd_sock)) > 0) {
            pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                              "Got %d Random Bytes from egd.", alloc);
        } else {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "Got %d Random Bytes from egd on %s.",
                              egd_sock);
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "Continuing, but it probably won't work.");
        }
    } else {
        pbc_log_activity (p, PBC_LOG_ERROR, "egd_socket not specified.");
    }
    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_augment_rand_state: bye");

#endif

}

/*                                                                            */
/* any general startup stuff goes here                                        */
/*                                                                            */
int libpbc_pubcookie_init (pool * p, security_context ** contextp)
{
    unsigned char buf[sizeof (pid_t)];
    pid_t pid;

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "libpbc_pubcookie_init\n");
    pid = getpid ();
    memcpy (buf, &pid, sizeof (pid_t));
    libpbc_augment_rand_state (p, buf, sizeof (pid));

    if (security_init (p, contextp)) {
        pbc_log_activity (p, PBC_LOG_ERROR, "security_init failed");
        return PBC_FAIL;
    }

    return PBC_OK;
}

static void limit_strcpy (pool * p, char *dst, char *src, int siz)
{
    while (siz-- > 1) {
        char ch = *src++;
        if (ch == 0)
            break;
        *dst++ = ch;
    }
    if (siz > 0)
        *dst = 0;
}

/* mallocs a pbc_cookie_data struct                                           */
pbc_cookie_data *libpbc_init_cookie_data (pool * p)
{
    pbc_cookie_data *cookie_data;

    cookie_data =
        (pbc_cookie_data *) pbc_malloc (p, sizeof (pbc_cookie_data));
    memset (cookie_data, 0, sizeof (pbc_cookie_data));
    return cookie_data;
}

/*                                                                            */
unsigned char *libpbc_gethostip (pool * p)
{
    struct hostent *h;
    unsigned char *addr;

#if defined (WIN32)
    char hostname[PBC_1K];
    int err;

    hostname[0] = '\0';
    err = gethostname (hostname, sizeof (hostname));
    if ((h = gethostbyname (hostname)) == NULL) {
        libpbc_abend (p, "gethostname error= %d, %s: host unknown.\n", err,
                      hostname);
        return NULL;
    }
#else
    struct utsname myname;

    if (uname (&myname) < 0) {
        libpbc_abend (p, "problem doing uname lookup\n");
        return NULL;
    }

    if ((h = gethostbyname (myname.nodename)) == NULL) {
        libpbc_abend (p, "%s: host unknown.\n", myname.nodename);
        return NULL;
    }
#endif

    addr = pbc_malloc (p, h->h_length);
    memcpy (addr, h->h_addr_list[0], h->h_length);

    return addr;
}

/**
 * generates the filename that stores the DES key
 * @param peername the certificate name of the peer
 * @param buf a buffer of at least 1024 characters which gets the filename
 * @return always succeeds
 */
static void make_crypt_keyfile (pool * p, const char *peername, char *buf)
{
    char *ptr;

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "make_crypt_keyfile: hello\n");

    strlcpy (buf, PBC_KEY_DIR, 1024);

    if (buf[strlen (buf) - 1] != '/') {
        strlcat (buf, "/", 1024);
    }

    /* need this because some webservers will pass uppercase hostnames */
    for (ptr = (char *) peername; *ptr; ptr++)
        *ptr = tolower (*ptr);
    strlcat (buf, peername, 1024);

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "make_crypt_keyfile: goodbye\n");
}

/**
 * generates a random key for peer and writes it to the disk
 * @param peer the certificate name of the peer
 * @return PBC_OK for success, PBC_FAIL for failure
 */
int libpbc_generate_crypt_key (pool * p, const char *peer)
{
    unsigned char buf[PBC_DES_KEY_BUF];
    char keyfile[1024];
    FILE *f;

    RAND_bytes (buf, PBC_DES_KEY_BUF);

    make_crypt_keyfile (p, peer, keyfile);
    if (!(f = pbc_fopen (p, keyfile, "w"))) {
        return PBC_FAIL;
    }
    fwrite (buf, sizeof (char), PBC_DES_KEY_BUF, f);
    pbc_fclose (p, f);

    return PBC_OK;
}

/**
 * writes the key 'key' to disk for peer 'peer'
 * @param a pointer to the PB_C_DES_KEY_BUF-sized key
 * @param peer the certificate name of the peer
 * @return PBC_OK for success, PBC_FAIL for failure
 */
int libpbc_set_crypt_key (pool * p, const char *key, const char *peer)
{
    char keyfile[1024];
    FILE *f;

    make_crypt_keyfile (p, peer, keyfile);
#ifdef WIN32
    if (!(f = pbc_fopen (p, keyfile, "wb"))) {
#else
    if (!(f = pbc_fopen (p, keyfile, "w"))) {
#endif
        return PBC_FAIL;
    }
    fwrite (key, sizeof (char), PBC_DES_KEY_BUF, f);
    pbc_fclose (p, f);

    return PBC_OK;
}

/*                                                                           */
int libpbc_get_crypt_key (pool * p, crypt_stuff * c_stuff,
                          const char *peer)
{
    FILE *fp;
    char *key_in;
    char keyfile[1024];

/*  pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "libpbc_get_crypt_key\n"); */

    make_crypt_keyfile (p, peer, keyfile);

    key_in = (char *) pbc_malloc (p, PBC_DES_KEY_BUF);

    if (!(fp = pbc_fopen (p, keyfile, "rb"))) { /* win32 - must be binary read */
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "libpbc_get_crypt_key: Failed open: %s\n",
                          keyfile);
        return PBC_FAIL;
    }

    if (fread (key_in, sizeof (char), PBC_DES_KEY_BUF, fp) !=
        PBC_DES_KEY_BUF) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "libpbc_get_crypt_key: Failed read: %s\n",
                          keyfile);
        pbc_fclose (p, fp);
        return PBC_FAIL;
    }
#ifdef DEBUG_ENCRYPT_COOKIE
    pbc_log_activity (p, PBC_LOG_ERROR,
                      "libpbc_get_crypt_key: reading crypt key '%s'\n",
                      keyfile);
#endif

    pbc_fclose (p, fp);

    memcpy (c_stuff->key_a, key_in, sizeof (c_stuff->key_a));
    pbc_free (p, key_in);

    return PBC_OK;
}

/*                                                                           */
int libpbc_test_crypt_key (pool * p, const char *peer)
{
    FILE *fp;
    char keyfile[1024];

    pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "libpbc_test_crypt_key: peer=%s\n", peer);

    make_crypt_keyfile (p, peer, keyfile);

    if (!(fp = pbc_fopen (p, keyfile, "rb"))) {
       char *s = strchr(peer,'.');
       if (s) {
          s++;
          make_crypt_keyfile (p, s, keyfile);
          if (!(fp = pbc_fopen (p, keyfile, "rb"))) {
              pbc_log_activity(p, PBC_LOG_ERROR, "can't open %s or %s\n", peer, s); 
              return PBC_FAIL;
          }
        } else {
           pbc_log_activity(p, PBC_LOG_ERROR, "can't open %s\n", peer); 
           return PBC_FAIL;
        }
    }

    pbc_fclose (p, fp);

    return PBC_OK;
}

unsigned char *libpbc_stringify_seg (pool * p, unsigned char *start,
                                     unsigned char *seg, unsigned len)
{
    int seg_len;

    seg_len =
        (len <
         strlen ((const char *) seg)) ? len : strlen ((const char *) seg);
    memcpy (start, seg, seg_len);
    return start + len;
}

/*                                                                            */
pbc_cookie_data *libpbc_destringify_cookie_data (pool * p,
                                                 pbc_cookie_data *
                                                 cookie_data)
{

    (*cookie_data).broken.user[PBC_USER_LEN - 1] = '\0';
    (*cookie_data).broken.appid[PBC_APP_ID_LEN - 1] = '\0';
    (*cookie_data).broken.appsrvid[PBC_APPSRV_ID_LEN - 1] = '\0';
    return cookie_data;

}

void print_cookie_string (pool * p, const char *prelude,
                          char *cookie_string)
{
    unsigned char printable[PBC_4K];
    int i;

    memcpy (printable, cookie_string, sizeof (pbc_cookie_data));

    for (i = 0; i < sizeof (pbc_cookie_data); i++) {
        if (printable[i] == '\0')
            printable[i] = '-';

    }

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "%s %s", prelude, printable);

}

/* package the cookie info for transit                                        */
/*   - make the cookie_data struct a string                                   */
/*   - do network byte order conversion                                       */
unsigned char *libpbc_stringify_cookie_data (pool * p,
                                             pbc_cookie_data * cookie_data)
{
    unsigned char *cookie_string;
    unsigned char *ptr;
    int temp;

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_stringify_cookie_data: hello, user: %s\n",
                      (*cookie_data).broken.user);

    ptr = cookie_string =
        (unsigned char *) pbc_malloc (p, sizeof (pbc_cookie_data));
    memset (cookie_string, 0, sizeof (pbc_cookie_data));

    ptr =
        libpbc_stringify_seg (p, ptr, (*cookie_data).broken.user,
                              PBC_USER_LEN);
    ptr =
        libpbc_stringify_seg (p, ptr, (*cookie_data).broken.version,
                              PBC_VER_LEN);
    ptr =
        libpbc_stringify_seg (p, ptr, (*cookie_data).broken.appsrvid,
                              PBC_APPSRV_ID_LEN);
    ptr =
        libpbc_stringify_seg (p, ptr, (*cookie_data).broken.appid,
                              PBC_APP_ID_LEN);
    *ptr = (*cookie_data).broken.type;
    ptr++;

    *ptr = (*cookie_data).broken.creds;
    ptr++;

    temp = htonl ((*cookie_data).broken.pre_sess_token);
    memcpy (ptr, &temp, sizeof (int));
    ptr += sizeof (int);

    temp = htonl ((*cookie_data).broken.create_ts);
    memcpy (ptr, &temp, sizeof (pbc_time_t));
    ptr += sizeof (pbc_time_t);

    temp = htonl ((*cookie_data).broken.last_ts);
    memcpy (ptr, &temp, sizeof (pbc_time_t));
    ptr += sizeof (pbc_time_t);

    return cookie_string;

}

/* get some indices for choosing a key and modifying ivec                     */
int libpbc_get_crypt_index (pool * p)
{
    unsigned char r_byte[1];
    int index;

    r_byte[0] = '\0';
    while (r_byte[0] == '\0')
        RAND_bytes (r_byte, 1);
    index = (int) r_byte[0] - (int) r_byte[0] / PBC_DES_INDEX_FOLDER;
    return index;
}

/* put stuff in the cookie structure                                          */
/*  note: we don't do network byte order conversion here,                     */
/*  instead we leave that for stringify                                       */
/*                                                                            */
void libpbc_populate_cookie_data (pool * p, pbc_cookie_data * cookie_data,
                                  unsigned char *user,
                                  unsigned char *version,
                                  unsigned char type,
                                  unsigned char creds,
                                  int pre_sess_token,
                                  pbc_time_t create,
                                  pbc_time_t expire,
                                  unsigned char *appsrvid,
                                  unsigned char *appid)
{

    /* pbc_log_activity(p, PBC_LOG_DEBUG_LOW, "libpbc_populate_cookie_data\n"); */

    strncpy ((char *) (*cookie_data).broken.user, (const char *) user,
             PBC_USER_LEN - 1);
    strncpy ((char *) (*cookie_data).broken.version, (const char *) version,
             PBC_VER_LEN);
    (*cookie_data).broken.type = type;
    (*cookie_data).broken.creds = creds;
    (*cookie_data).broken.pre_sess_token = pre_sess_token;
    (*cookie_data).broken.create_ts = create;
    (*cookie_data).broken.last_ts = expire;
    strncpy ((char *) (*cookie_data).broken.appsrvid,
             (const char *) appsrvid, PBC_APPSRV_ID_LEN - 1);
    strncpy ((char *) (*cookie_data).broken.appid, (const char *) appid,
             PBC_APP_ID_LEN - 1);

}

/**
 * unfortunately libpbc_sign_bundle_cookie and libpbc_unbundle are not    
 * symmetrical in the data they deal with.  the bundle takes the stringified
 * info and the unbundle returns a struct.  maybe someday i'll clean that up
 *                                                                            
 * @param cookie_string pointer to the cookie buffer of length
 * sizeof(pbc_cookie_data)
 * @param peer the peer this cookie is destined for (NULL for myself)
 * @returns a pointer to a newly malloc()ed base64 string
 */
unsigned char *libpbc_sign_bundle_cookie (pool * p,
                                          const security_context * context,
                                          unsigned char *cookie_string,
                                          const char *peer,
                                          const char use_granting,
                                          char alg)
{
    unsigned char *cookie;
    char *out;
    int outlen;

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_sign_bundle_cookie: hello\n");

    if (libpbc_mk_priv (p, context, peer, use_granting,
                        (const char *) cookie_string,
                        sizeof (pbc_cookie_data), &out, &outlen, alg)) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "libpbc_sign_bundle_cookie: libpbc_mk_priv failed\n");
        return NULL;
    }

    cookie = (unsigned char *) pbc_malloc (p, 4 * outlen / 3 + 20);
    if (!cookie) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "libpbc_sign_bundle_cookie: pbc_malloc failed\n");
        pbc_free (p, out);
        return NULL;
    }

    libpbc_base64_encode (p, (unsigned char *) out, cookie, outlen);
    pbc_free (p, out);

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_sign_bundle_cookie: goodbye\n");
    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_sign_bundle_cookie: cookie: %s\n", cookie);

    return cookie;
}

/*                                                                            */
/* builds, signs and returns cookie                                           */
/*                                                                            */
/* for now we use the last_ts field in login cookie as expire_ts */
/* this is the call used for creating G and S cookies            */
unsigned char *libpbc_get_cookie (pool * p,
                                  const security_context * context,
                                  unsigned char *user, 
                                  unsigned char *version,
 				  unsigned char type,
                                  unsigned char creds, int pre_sess_token,
                                  unsigned char *appsrvid,
                                  unsigned char *appid, const char *peer,
                                  const char use_granting, char alg)
{

    return (libpbc_get_cookie_with_expire (p, context, user, version,
                                           type,
                                           creds,
                                           pre_sess_token,
                                           pbc_time (NULL),
                                           pbc_time (NULL),
                                           appsrvid,
                                           appid, peer, use_granting,
                                           alg));

}

/*                                                                            */
/* builds, signs and returns cookie                                           */
/*                                                                            */
/* for now we use the last_ts field in login cookie as expire_ts */
/* the overleading of last_ts with expire_ts is ugly but we're   */
/* going to reframe the library interfaces anyway and this will  */
/* be treated better then.                                       */
unsigned char *libpbc_get_cookie_with_expire (pool * p,
                                              const security_context *
                                              context, unsigned char *user,
                                              unsigned char *version,
                                              unsigned char type,
                                              unsigned char creds,
                                              int pre_sess_token,
                                              pbc_time_t create, pbc_time_t expire,
                                              unsigned char *appsrvid,
                                              unsigned char *appid,
                                              const char *peer,
                                              const char use_granting,
                                              char alg)
{

    pbc_cookie_data *cookie_data;
    unsigned char *cookie_string;
    unsigned char *cookie;

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_get_cookie_with_expire: hello\n");

    libpbc_augment_rand_state (p, user, PBC_USER_LEN);

    cookie_data = libpbc_init_cookie_data (p);
    libpbc_populate_cookie_data (p, cookie_data, user, version, type, creds,
                                 pre_sess_token, create, expire, appsrvid,
                                 appid);
    cookie_string = libpbc_stringify_cookie_data (p, cookie_data);
    pbc_free (p, cookie_data);

    cookie =
        libpbc_sign_bundle_cookie (p, context, cookie_string, peer,
                                   use_granting, alg);
    pbc_free (p, cookie_string);

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_get_cookie_with_expire: goodbye\n");

    return cookie;
}

/*                                                                            */
/*  deal with unbundling a cookie                                             */
/*                                                                            */
pbc_cookie_data *libpbc_unbundle_cookie (pool * p,
                                         const security_context * context,
                                         char *in, const char *peer,
                                         const char use_granting, char alg)
{
    pbc_cookie_data *cookie_data;
    char *plain;
    int plainlen;
    int outlen;
    unsigned char *buf = pbc_malloc (p, PBC_4K);

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_unbundle_cookie: hello\n");

    memset (buf, 0, PBC_4K);

    if (strlen (in) < sizeof (pbc_cookie_data) || strlen (in) > PBC_4K) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "libpbc_unbundle_cookie: malformed cookie %s\n",
                          in);
        pbc_free (p, buf);
        return 0;
    }

    if (!libpbc_base64_decode (p, (unsigned char *) in, buf, &outlen)) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "libpbc_unbundle_cookie: could not base64 decode cookie.");
        pbc_free (p, buf);
        return 0;
    }

    if (libpbc_rd_priv
        (p, context, peer, use_granting, (const char *) buf, outlen,
         &plain, &plainlen, alg)) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "libpbc_unbundle_cookie: libpbc_rd_priv() failed\n");
        pbc_free (p, buf);
        return 0;
    }

    if (plainlen != sizeof (pbc_cookie_data)) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "libpbc_unbundle_cookie: cookie wrong size: %d != %d",
                          plainlen, sizeof (pbc_cookie_data));
        pbc_free (p, plain);
        pbc_free (p, buf);
        return 0;
    }

    /* copy it into a pbc_cookie_data struct */
    cookie_data =
        (pbc_cookie_data *) pbc_malloc (p, sizeof (pbc_cookie_data));
    if (!cookie_data) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "libpbc_unbundle_cookie: pbc_malloc(p, ) failed");
        pbc_free (p, plain);
        pbc_free (p, buf);
        return 0;
    }
    memcpy ((*cookie_data).string, plain, sizeof (pbc_cookie_data));
    pbc_free (p, plain);

    cookie_data = libpbc_destringify_cookie_data (p, cookie_data);

    (*cookie_data).broken.last_ts = ntohl ((*cookie_data).broken.last_ts);
    (*cookie_data).broken.create_ts =
        ntohl ((*cookie_data).broken.create_ts);
    (*cookie_data).broken.pre_sess_token =
        ntohl ((*cookie_data).broken.pre_sess_token);

    pbc_free (p, buf);

    return cookie_data;
}

/*                                                                            */
/*  update last_ts in cookie                                                  */
/*                                                                            */
/* takes a cookie_data structure, updates the time, signs and packages up     */
/* the cookie to be sent back into the world                                  */
/*                                                                            */
unsigned char *libpbc_update_lastts (pool * p,
                                     const security_context * context,
                                     pbc_cookie_data * cookie_data,
                                     const char *peer,
                                     const char use_granting,
                                     unsigned char alg)
{
    unsigned char *cookie_string;
    unsigned char *cookie;

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_update_lastts: hello\n");

    (*cookie_data).broken.last_ts = pbc_time (NULL);
    cookie_string = libpbc_stringify_cookie_data (p, cookie_data);
    cookie =
        libpbc_sign_bundle_cookie (p, context, cookie_string, peer,
                                   use_granting, alg);
    pbc_free (p, cookie_string);

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "upd lastts: alg=%c\n", alg);

    return cookie;

}

/*                                                                            */
/* check version string in cookie                                             */
/*                                                                            */
int libpbc_check_version (pool * p, pbc_cookie_data * cookie_data)
{
    unsigned char *a = (*cookie_data).broken.version;
    unsigned char *b = (unsigned char *) PBC_VERSION;

    if (a[0] == b[0] && a[1] == b[1])
        return (PBC_OK);
    if (a[0] == b[0] && a[1] != b[1]) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "Minor version mismatch cookie: %s version: %s\n",
                          a, b);
        return (PBC_OK);
    }

    return (PBC_FAIL);

}

/** 
 * check to see if whatever has timed out
 * @param fromc time to be checked, format unix time
 * @param exp number of seconds for timeout
 * @returns PBC_OK if not expired, PBC_FAIL if expired
 */
int libpbc_check_exp (pool * p, pbc_time_t fromc, int exp)
{

#ifdef IMMORTAL_COOKIES
    return PBC_OK;
#endif

    if ((fromc + exp) > pbc_time (NULL))
        return PBC_OK;
    else
        return PBC_FAIL;

}

/** 
 * use openssl calls to get a random int
 * @returns random int or -1 for error
 */
int libpbc_random_int (pool * p)
{
    unsigned char buf[16];
    int i;
    unsigned long err;


    if (RAND_bytes (buf, sizeof (int)) == 0) {
        while ((err = ERR_get_error ()))
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "OpenSSL error getting random bytes: %lu",
                              err);
        return (-1);
    }

    bcopy (&buf, &i, sizeof (int));
    return (i);

}

/** 
 * something that should never be executed, but shuts-up the compiler warning
 */
void libpbc_dummy (pool * p)
{
    char c;

    c = *(redirect_reason[0]);

}

/* words for numbers */
char *numbers[61] = { "zero",
    "one", "two", "three", "four", "five",
    "six", "seven", "eight", "nine", "ten",
    NULL, NULL, NULL, NULL, "fifteen",
    NULL, NULL, NULL, NULL, "twenty",
    NULL, NULL, NULL, NULL, "twenty five",
    NULL, NULL, NULL, NULL, "thirty",
    NULL, NULL, NULL, NULL, "thirty five",
    NULL, NULL, NULL, NULL, "fourty",
    NULL, NULL, NULL, NULL, "fourty five",
    NULL, NULL, NULL, NULL, "fifty",
    NULL, NULL, NULL, NULL, "fifty five",
    NULL, NULL, NULL, NULL, "sixty"
};

/* converts number of seconds to number of ... */
#define SECS2HOURS(x) (int)( (x) / 3600 )
#define SECS2MINS(x)  (int)( (x) % 3600 / 60 )
#define SECS2SECS(x)  (int)( (x) % 3600 % 60 )
/* masks for building text string */
#define HMASK 4
#define MMASK 2
#define SMASK 1
#define AND1MASK 2
#define AND2MASK 1
#define NOANDS 0

/**
 * converts seconds to a text string with hours, mintues and seconds
 * @param *p apache memory pool
 * @param secs number of seconds
 * @param use_numbers always use numbers instead of words
 * @param cap capitolize the first char
 * @returns string with time text that must be free'd
       makes string of the format:
	h hour(s) m minute(s) and s second(s)  or
	h hour(s) and m minute(s)              or
	h hour(s) and s second(s)              or
	h hour(s)             		       or
        m minute(s) and s second(s)            or
        m minute(s)                            or
        s second(s)   
 */
const char *libpbc_time_text (pool * p, int secs, int use_numbers, int cap)
{
    char *string = NULL;
    char *h, *m, *s;
    int len = 256;
    char hours[20], minutes[20], seconds[20];
    int hms = 0;

    int and_array[] = { NOANDS, /* 0                             */
        NOANDS,                 /* 1 seconds                     */
        NOANDS,                 /* 2 minutes                     */
        AND2MASK,               /* 3 minutes and seconds         */
        NOANDS,                 /* 4 hours                       */
        AND2MASK,               /* 5 hours and seconds           */
        AND1MASK,               /* 6 hours and minutes           */
        AND2MASK                /* 7 hours minutes and seconds   */
    };

    bzero (hours, 20);
    bzero (minutes, 20);
    bzero (seconds, 20);
    if (!(string = malloc (len)))
        libpbc_abend (p, "out of memory");
    if (!(h = malloc (len)))
        libpbc_abend (p, "out of memory");
    if (!(m = malloc (len)))
        libpbc_abend (p, "out of memory");
    if (!(s = malloc (len)))
        libpbc_abend (p, "out of memory");

    /* get words for numbers, maybe */
    if (use_numbers == PBC_FALSE) {
        if (numbers[SECS2HOURS (secs)] != NULL)
            strcpy (hours, numbers[SECS2HOURS (secs)]);
        if (numbers[SECS2MINS (secs)] != NULL)
            strcpy (minutes, numbers[SECS2MINS (secs)]);
        if (numbers[SECS2SECS (secs)] != NULL)
            strcpy (seconds, numbers[SECS2SECS (secs)]);
    }
    if (*hours == '\0')
        snprintf (hours, 20, "%d", SECS2HOURS (secs));
    if (*minutes == '\0')
        snprintf (minutes, 20, "%d", SECS2MINS (secs));
    if (*seconds == '\0')
        snprintf (seconds, 20, "%d", SECS2SECS (secs));

    snprintf (m, len, "%s minute%c", minutes,
              (SECS2MINS (secs) >= 2 ? 's' : ' '));
    snprintf (h, len, "%s hour%c", hours,
              (SECS2HOURS (secs) >= 2 ? 's' : ' '));
    snprintf (s, len, "%s second%c", seconds,
              (SECS2SECS (secs) >= 2
               || SECS2SECS (secs) == 0 ? 's' : ' '));

    if (SECS2HOURS (secs) != 0)
        hms = hms | HMASK;
    if (SECS2MINS (secs) != 0)
        hms = hms | MMASK;
    if (SECS2SECS (secs) != 0)
        hms = hms | SMASK;

    if (secs == 0)
        snprintf (string, len, "%s", s);
    else
        snprintf (string, len, "%s %s %s %s %s",
                  (SECS2HOURS (secs) >= 1 ? h : ""),
                  (and_array[hms] & AND1MASK ? "and" : ""),
                  (SECS2MINS (secs) >= 1 ? m : ""),
                  (and_array[hms] & AND2MASK ? "and" : ""),
                  (SECS2SECS (secs) >= 1 ? s : ""));

    if (cap == PBC_TRUE)
        *string = toupper (*string);
    free (m);
    free (h);
    free (s);
    return string;

}

/** 
 * find any '%' and escape them as "%%"
 * @param string to be escaped
 * @returns escaped content, memory must be freed
 */
char *escape_percs (pool * p, char *in)
{
    char *out;
    char *ptr;
    int i = 0;

    /* count the number of '%' */
    for (ptr = in; ptr = strchr (ptr + 1, '%'); i++);

    if (!(out = malloc (strlen (in) + i))) {
        libpbc_abend (p, "out of memory");
    }

    ptr = out;
    while (*in) {
        *ptr = *in;
        if (*in == '%')
            *(++ptr) = '%';
        ptr++;
        in++;
    }
    *ptr = '\0';
    return (out);

}
