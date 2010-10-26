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

/** @file security_legacy.c
 * Heritage message protection
 *
 * $Id: security_legacy.c,v 1.61 2008/05/16 22:09:10 willey Exp $
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
typedef apr_pool_t pool;
typedef apr_table_t table;
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

/* openssl */
#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
# include <openssl/des.h>
# include <openssl/rand.h>
# include <openssl/err.h>
# include <openssl/evp.h>
#else
# include <pem.h>
# include <des.h>
# include <rand.h>
# include <err.h>
# include <evp.h>
#endif /* OPENSSL_IN_DIR */

#ifdef HAVE_ASSERT_H
# include <assert.h>
#endif /* HAVE_ASSERT_H */

#ifdef WIN32
# define DIR_SEP "\\"
#else
# define DIR_SEP "/"
#endif

#ifdef WIN32
# include <io.h>
# include <assert.h>
# include <httpfilt.h>
# include "pbc_config.h"
# include "pubcookie.h"
# include "Win32/PubCookieFilter.h"
# include "pbc_logging.h"
# include "libpubcookie.h"
# include "strlcpy.h"
# include "snprintf.h"
# include "pbc_configure.h"
# include "security.h"
#else
# include "pbc_config.h"
# include "pbc_logging.h"
# include "libpubcookie.h"
# include "strlcpy.h"
# include "snprintf.h"
# include "pbc_configure.h"
# include "security.h"
# include "pubcookie.h"
#endif

#ifdef APACHE2
#include "apr_strings.h"
#endif

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

#define PBC_SIG_LEN 128

/* privacy format is:

   outbuf = <sig> <crypted>
   crypted = <data> [index1 byte] [index2 byte]

   [index2 byte] is an offset into the shared secret which is XOR'd with
   PBC_INIT_IVEC to form the ivec

   [index1 byte] is an index into the shared secret which is taken as the
   DES key
   
 */

/* a place to hold all of the certificates and keys */
struct security_context_s
{
    /* our private session keypair */
    EVP_PKEY *sess_key;
    X509 *sess_cert;
    EVP_PKEY *sess_pub;

    /* the granting key & certificate */
    EVP_PKEY *g_key;
    X509 *g_cert;
    EVP_PKEY *g_pub;

    /* my name */
    char *myname;

    /* the crypt_key */
    unsigned char cryptkey[PBC_DES_KEY_BUF];
};

static char *mystrdup (pool * p, const char *s)
{
    if (s)
        return pbc_strdup (p, s);
    else
        return NULL;
}

/* destructively returns the value of the CN */
static char *extract_cn (pool * p, char *s)
{
    char *ptr;
    char *q;

    if (!s)
        return NULL;

    ptr = strstr (s, "CN=");
    if (ptr) {
        ptr += 3;
        q = strstr (ptr, "/Email=");
        if (q) {
            *q = '\0';
        }
        q = strchr (ptr, '/');
        if (q) {
            *q = '\0';
        }
    }

    return ptr;
}


/* find the keys that we'll be using, look for stuff in this order:
   . the SSL key/certificate
   . the pubcookie_session.{key,cert}
   . the pubcookie_login.{key,cert}.[hostname]
   . (generate them ourselves?)
   

   for the granting key/certificate:
   . check "granting_key_file", "granting_cert_file"
   . check pubcookie_granting

*/
int security_init (pool * p, security_context ** contextp)
{

    /* our private session keypair */
    char *keyfile = NULL;
    char *certfile = NULL;
    /* the granting key & certificate */
    char *g_keyfile;
    char *g_certfile;
    /* our crypt key */
    char *cryptkey = NULL;
#ifndef WIN32
    size_t cb_read;
#endif
    FILE *fp;
    security_context *context;

    context = *contextp = pbc_malloc (p, sizeof (**contextp));

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "security_init: hello\n");

    /* initialize the random number generator */
#if defined (WIN32)
    /* Windows only has milliseconds */
    {
        SYSTEMTIME ts;
        unsigned char buf[sizeof (ts.wMilliseconds)];

        GetLocalTime (&ts);
        memcpy (buf, &ts.wMilliseconds, sizeof (ts.wMilliseconds));
        RAND_seed (buf, sizeof (ts.wMilliseconds));
    }
#else
    {
        struct timeval tv;
        struct timezone tz;
        unsigned char buf[sizeof (tv.tv_usec)];

        gettimeofday (&tv, &tz);
        memcpy (buf, &tv.tv_usec, sizeof (tv.tv_usec));
        RAND_seed (buf, sizeof (tv.tv_usec));
    }
#endif

    /* first we try to use the ssl files */
    keyfile =
        mystrdup (p, libpbc_config_getstring (p, "ssl_key_file", NULL));
    if (keyfile && access (keyfile, R_OK | F_OK)) {
        if (access (keyfile, F_OK)) {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "security_init: Session keyfile (%s) doesn't exist.",
                              keyfile);
        } else if (access (keyfile, R_OK)) {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "security_init: Permissions prohibit reading session keyfile (%s).",
                              keyfile);
        }
        pbc_free (p, keyfile);
        /* not there ? */
        keyfile = NULL;
    }

    certfile =
        mystrdup (p, libpbc_config_getstring (p, "ssl_cert_file", NULL));
    if (certfile && access (certfile, R_OK | F_OK)) {
        if (access (certfile, F_OK)) {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "security_init: Session certfile (%s) doesn't exist.",
                              certfile);
        } else if (access (certfile, R_OK)) {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "security_init: Permissions prohibit reading session certfile (%s).",
                              certfile);
        }
        pbc_free (p, certfile);
        /* not there ? */
        certfile = NULL;
    }

    if (!keyfile && !certfile) {
        /* fall back to the pubcookie_session files */
        keyfile = pbc_malloc (p, 1025);
        snprintf (keyfile, 1024, "%s" DIR_SEP "%s", PBC_KEY_DIR,
                  "pubcookie_session.key");

        certfile = pbc_malloc (p, 1025);
        snprintf (certfile, 1024, "%s" DIR_SEP "%s", PBC_KEY_DIR,
                  "pubcookie_session.cert");

        if (access (keyfile, R_OK | F_OK)
            || access (certfile, R_OK | F_OK)) {
            /* session keys not valid */
            pbc_free (p, keyfile);
            pbc_free (p, certfile);
            keyfile = NULL;
            certfile = NULL;
        }
    }

    if (!keyfile && !certfile) {
        /* try the pubcookie_login files */
        keyfile = pbc_malloc (p, 1025);
        snprintf (keyfile, 1024, "%s" DIR_SEP "%s", PBC_KEY_DIR,
                  "pubcookie_login.key");

        certfile = pbc_malloc (p, 1025);
        snprintf (certfile, 1024, "%s" DIR_SEP "%s", PBC_KEY_DIR,
                  "pubcookie_login.cert");

        if (access (keyfile, R_OK | F_OK)
            || access (certfile, R_OK | F_OK)) {
            /* login keys not valid */
            pbc_free (p, keyfile);
            pbc_free (p, certfile);
            keyfile = NULL;
            certfile = NULL;
        }
    }
#ifndef WIN32
    if (!keyfile) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "security_init: couldn't find session keyfile (try setting ssl_key_file for login server or PubCookieSessionKeyFile for Apache module?)");
        return -1;
    }
    if (!certfile) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "security_init: couldn't find session certfile (try setting ssl_cert_file for login server or PubCookieSessionCertFile for Apache module?)");
        return -1;
    }
#endif
    /* it's generally easier to find the granting key/cert */
    g_keyfile =
        mystrdup (p,
                  libpbc_config_getstring (p, "granting_key_file", NULL));
    g_certfile =
        mystrdup (p,
                  libpbc_config_getstring (p, "granting_cert_file", NULL));


    if (!g_keyfile) {
        g_keyfile = pbc_malloc (p, 1025);
        snprintf (g_keyfile, 1024, "%s" DIR_SEP "%s", PBC_KEY_DIR,
                  "pubcookie_granting.key");
    }

    if (!g_certfile) {
        g_certfile = pbc_malloc (p, 1025);
        snprintf (g_certfile, 1024, "%s" DIR_SEP "%s", PBC_KEY_DIR,
                  "pubcookie_granting.cert");
    }
    /* test g_keyfile */
    if (access (g_keyfile, R_OK | F_OK)) {
        /* this is only a problem for login servers */
#ifdef LOGIN_SERVER
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "security_init: couldn't find granting keyfile (try setting granting_key_file?): tried %s",
                          g_keyfile);
        return -1;
#endif
        g_keyfile = NULL;
    }

    /* test g_certfile; it's a fatal error if this isn't found */
    if (access (g_certfile, R_OK | F_OK)) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "security_init: couldn't find granting certfile (try setting granting_cert_file?): tried %s",
                          g_certfile);
        return -1;
    }

    /* now read them into memory */

    /* session key */
#ifdef WIN32
    if (keyfile && certfile) {
#endif
        fp = pbc_fopen (p, keyfile, "r");

        if (!fp) {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "security_init: couldn't read keyfile: pbc_fopen %s",
                              keyfile);
            return -1;
        }

        context->sess_key =
            (EVP_PKEY *) PEM_read_PrivateKey (fp, NULL, NULL, NULL);

        if (!context->sess_key) {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "security_init: couldn't parse session key: %s",
                              keyfile);
            return -1;
        }
        pbc_fclose (p, fp);

        /* session cert */
        fp = pbc_fopen (p, certfile, "r");
        if (!fp) {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "security_init: couldn't read certfile: pbc_fopen %s",
                              certfile);
            return -1;
        }

        context->sess_cert = (X509 *) PEM_read_X509 (fp, NULL, NULL, NULL);

        if (!context->sess_cert) {
            /* xxx openssl errors */
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "security_init: couldn't parse session certificate: %s",
                              certfile);
            return -1;
        }
        context->sess_pub = X509_extract_key (context->sess_cert);
        context->myname =
            X509_NAME_oneline (X509_get_subject_name (context->sess_cert),
                               0, 0);
        context->myname = extract_cn (p, context->myname);
        if (!context->myname) {
            char tmp[1024];
            /* hmm, no name encoded in the certificate; we'll just use our
               hostname */
            gethostname (tmp, sizeof (tmp) - 1);
            context->myname = mystrdup (p, tmp);
        }
        pbc_fclose (p, fp);

#ifdef WIN32
    } else {

        context->sess_key = EVP_PKEY_new ();

        if (!EVP_PKEY_assign_RSA
            (context->sess_key,
             RSA_generate_key (1024, RSA_F4, NULL, NULL))) {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "[Pubcookie_Init] Unable to find or generate session keypair.");
            return -1;
        }

        /* sess_key was assigned both public and private keys */
        context->sess_pub = context->sess_key;
        pbc_log_activity (p, PBC_LOG_AUDIT,
                          "security_init: generated new session keypair.");
    }


    {
        char tmp[1024];
        struct hostent *hp;

        gethostname (tmp, sizeof (tmp) - 1);
        if (!(hp = gethostbyname (tmp))) {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "[Pubcookie_Init] gethostbyname failed.");
            return -1;
        }
        context->myname = mystrdup (p, hp->h_name);
    }

#endif

    /* granting key */
    if (g_keyfile) {
        fp = pbc_fopen (p, g_keyfile, "r");

        if (fp) {
            context->g_key =
                (EVP_PKEY *) PEM_read_PrivateKey (fp, NULL, NULL, NULL);

            if (!context->g_key) {
                pbc_log_activity (p, PBC_LOG_ERROR,
                                  "security_init: couldn't parse granting key: %s",
                                  g_keyfile);
                return -1;
            }
            pbc_fclose (p, fp);
        } else {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "security_init: couldn't read granting keyfile: pbc_fopen %s",
                              g_keyfile);
            /* fatal, since we were configured for it */
            exit (1);
        }
    }
    /* granting cert */
    fp = pbc_fopen (p, g_certfile, "r");
    if (!fp) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "security_init: couldn't read granting certfile: pbc_fopen %s",
                          g_certfile);
        return -1;
    }
    context->g_cert = (X509 *) PEM_read_X509 (fp, NULL, NULL, NULL);
    if (!context->g_cert) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "security_init: couldn't parse granting certificate: %s",
                          g_certfile);
        return -1;
    }
    context->g_pub = X509_extract_key (context->g_cert);

    pbc_fclose (p, fp);

    /* xxx CA file / CA dir ? */
#ifndef WIN32                   /*Windows only uses security_init for it's default context, which does not have or need a crypt key */
    /* our crypt key */
    cryptkey = (char *) libpbc_config_getstring (p, "crypt_key", NULL);
    if (cryptkey) {
        if (access (cryptkey, R_OK | F_OK) == -1) {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "security_init: can't access crypt key file %s, will try standard location",
                              cryptkey);
            pbc_free (p, cryptkey);
            cryptkey = NULL;
        }
    }
    if (!cryptkey) {
        cryptkey = pbc_malloc (p, 1024);
        make_crypt_keyfile (p, context->myname, cryptkey);
        if (access (cryptkey, R_OK | F_OK) == -1) {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "security_init: can't access crypt key file %s (try setting crypt_key)",
                              cryptkey);
            pbc_free (p, cryptkey);
            return -2;
        }
    }

    fp = pbc_fopen (p, cryptkey, "rb");
    if (!fp) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "security_init: couldn't read crypt key: pbc_fopen %s: %m",
                          cryptkey);
        return -2;
    }

    if ((cb_read =
         fread (context->cryptkey, sizeof (char), PBC_DES_KEY_BUF,
                fp)) != PBC_DES_KEY_BUF) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "can't read crypt key %s: short read: %d",
                          cryptkey, cb_read);
        pbc_fclose (p, fp);
        return -2;
    }
    pbc_fclose (p, fp);
    pbc_free (p, cryptkey);
#endif /* WIN32 */



    if (keyfile != NULL)
        pbc_free (p, keyfile);
    if (certfile != NULL)
        pbc_free (p, certfile);
    if (g_keyfile != NULL)
        pbc_free (p, g_keyfile);
    if (g_certfile != NULL)
        pbc_free (p, g_certfile);

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "security_init: goodbye\n");

    return 0;
}

const char *libpbc_get_cryptname (pool * p,
                                  const security_context * context)
{
    return context->myname;

}

/**
 * generates the filename that stores the DES key
 * @param peername the certificate name of the peer
 * @param buf a buffer of at least 1024 characters which gets the filename
 * @return always succeeds
 */
static void make_crypt_keyfile (pool * p, const char *peername, char *buf)
{
    pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "make_crypt_keyfile: hello\n");

    strlcpy (buf, PBC_KEY_DIR, 1024);

    if (buf[strlen (buf) - 1] != '/') {
        strlcat (buf, DIR_SEP, 1024);
    }
    strlcat (buf, peername, 1024);

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "make_crypt_keyfile: goodbye\n");
}

static int get_crypt_key (pool * p, const security_context * context,
                          const char *peername, char *buf)
{

    FILE *fp;
    char keyfile[1024];

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "get_crypt_key: myname=%s, peer=%s\n",
                      context->myname, peername);

    /* check to see if this is our key, which we already read in once */
    if (strcmp (peername, context->myname) == 0) {
        memcpy (buf, context->cryptkey, PBC_DES_KEY_BUF);
        return 0;
    }

    make_crypt_keyfile (p, peername, keyfile);

    if (!(fp = pbc_fopen (p, keyfile, "rb"))) {
        char *s = strchr (peername, '.');
        pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                          "can't open crypt key %s: %m", keyfile);
        if (s) {
            s++;
            pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "will try %s", s);
            make_crypt_keyfile (p, s, keyfile);
            if (!(fp = pbc_fopen (p, keyfile, "rb"))) {
                pbc_log_activity (p, PBC_LOG_ERROR,
                                  "can't open backup key %s either: %m",
                                  keyfile);
                return -1;
            }
        } else {
            pbc_log_activity (p, PBC_LOG_ERROR, "no backup available");
            return -1;
        }
    }

    if (fread (buf, sizeof (char), PBC_DES_KEY_BUF, fp) != PBC_DES_KEY_BUF) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "can't read crypt key %s: short read", keyfile);
        pbc_fclose (p, fp);
        return -1;
    }

    pbc_fclose (p, fp);
    pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "get_crypt_key: goodbye\n");

    return 0;
}

/**
 * libpbc_mk_priv takes 'buf', 'len', and returns 'outbuf', 'outlen',
 * an encrypted string that can only be read by 'peer'.
 * @param peer the name of the peer this is destined for.  if NULL,
 * the message will be signed with private material that is only known
 * to this host. 
 * @param buf a pointer to the cleartext string
 * @param len the length of the data pointed to by buf
 * @param outbuf will be filled in with a malloc()ed buffer.  it must
 * later be free()ed.
 * @param outlen the length of outbuf.
 * @param algorithm
 * @returns 0 on success, non-zero on failure.
 */

/* old des crypt */
int libpbc_mk_priv_des (pool * p, const security_context * context,
                        const char *peer, const char use_granting,
                        const char *buf, const int len,
                        char **outbuf, int *outlen)
{
    int r;
    int index1, index2;
    unsigned char r_byte;
    int i = 0;
    des_cblock key, ivec;
    des_key_schedule ks;
    unsigned char keybuf[PBC_DES_KEY_BUF];
    static unsigned char ivec_tmp[PBC_INIT_IVEC_LEN] = PBC_INIT_IVEC;
    const char *peer2;
    char *mysig = NULL;
    int siglen;
    int tries = 5;
    int c;

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "libpbc_mk_priv_des: hello\n");

    assert (outbuf != NULL && outlen != NULL);
    assert (buf != NULL && len > 0);

    peer2 = peer ? peer : libpbc_get_cryptname (p, context);


    if (get_crypt_key (p, context, peer2, (char *) keybuf) < 0) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "get_crypt_key(%s) failed", peer2);
        return -1;
    }

    memset (key, 0, sizeof (key));
    des_set_odd_parity (&key);
    index1 = 0;
    while (des_set_key_checked (&key, ks) < 0 && --tries) {
        r_byte = 0;             /* why isn't 0 allowed? */
        while (r_byte == 0)
            RAND_bytes (&r_byte, 1);
        index1 = r_byte;

        memcpy (key, &(keybuf[index1]), sizeof (key));
        des_set_odd_parity (&key);
    }
    if (!tries) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "couldn't find a good DES key");
        return -1;
    }

    r_byte = 0;                 /* why isn't 0 allowed? */
    while (r_byte == 0)
        RAND_bytes (&r_byte, 1);
    index2 = r_byte;

    /* setup ivec */
    memcpy (ivec, &keybuf[index2], sizeof (ivec));
    for (c = 0; c < sizeof (ivec); ++c) {
        ivec[c] ^= ivec_tmp[i % sizeof (ivec_tmp)];
    }

    r = libpbc_mk_safe (p, context, peer, use_granting, buf, len, &mysig,
                        &siglen);
    if (!r) {
        *outlen = len + siglen + 2;
        *outbuf = pbc_malloc (p, *outlen);
        if (!*outbuf) {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "libpbc_mk_priv: pbc_malloc failed");
            pbc_free (p, mysig);
            return -1;
        }

        des_cfb64_encrypt ((unsigned char *) mysig,
                           (unsigned char *) *outbuf, siglen, ks, &ivec,
                           &i, DES_ENCRYPT);

        pbc_free (p, mysig);

        des_cfb64_encrypt ((unsigned char *) buf,
                           (unsigned char *) (*outbuf) + siglen, len,
                           ks, &ivec, &i, DES_ENCRYPT);
        (*outbuf)[siglen + len] = (unsigned char) index1;
        (*outbuf)[siglen + len + 1] = (unsigned char) index2;
    }

    if (r) {
        pbc_log_activity (p, PBC_LOG_ERROR, "libpbc_mk_safe() failed");
        pbc_free (p, *outbuf);
        *outbuf = NULL;
    }
    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_mk_priv_des: goodbye\n");

    return r;
}

/* AES crypt */
int libpbc_mk_priv_aes (pool * p, const security_context * context,
                        const char *peer, const char use_granting,
                        const char *buf, const int len,
                        char **outbuf, int *outlen, char alg)
{
    int r;
    int index1, index2;
    int i = 0;
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char rb[EVP_MAX_IV_LENGTH];
    const char *peer2;
    char *mysig = NULL;
    int siglen;
    int c;
    unsigned char keybuf[PBC_DES_KEY_BUF];
    int olen, len1;
    unsigned char *keyptr;
    unsigned char shakey[SHA_DIGEST_LENGTH];

    const EVP_CIPHER *cip = EVP_aes_128_cbc ();
    EVP_CIPHER_CTX ctx;

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "libpbc_mk_priv_aes: hello\n");

    assert (outbuf != NULL && outlen != NULL);
    assert (buf != NULL && len > 0);

    peer2 = peer ? peer : libpbc_get_cryptname (p, context);

    if (get_crypt_key (p, context, peer2, (char *) keybuf) < 0) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "get_crypt_key(%s) failed", peer2);
        return -1;
    }


    /* choose a key from the file data  */
    index1 = libpbc_random_int ((pool *) NULL) % 128;
    if (index1 < 0)
        index1 = (0 - index1);
    index2 = 0;                 /* not used */
    RAND_bytes (iv, sizeof (iv));
    RAND_bytes (rb, sizeof (rb));

    EVP_CIPHER_CTX_init (&ctx);
    if (alg == 'A') {
        int lpeer = strlen (peer);
        unsigned char *sk = (unsigned char *) malloc (128 + lpeer);
        pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                          "..._priv_aes: doing domain key, peer=%s\n",
                          peer);
        memcpy (sk, keybuf + index1, 128);
        memcpy (sk + 128, peer, lpeer);
        SHA1 (sk, 128 + lpeer, shakey);
        keyptr = shakey;
    } else
        keyptr = keybuf + index1;

    EVP_EncryptInit_ex (&ctx, cip, NULL, keyptr, iv);

    r = libpbc_mk_safe (p, context, peer, use_granting, buf, len, &mysig,
                        &siglen);
    if (r) {
        pbc_log_activity (p, PBC_LOG_ERROR, "libpbc_mk_safe() failed");
        pbc_free (p, *outbuf);
        *outbuf = NULL;
        return (r);
    }

    *outbuf = pbc_malloc (p, len + siglen + sizeof (rb) + 16);
    assert (*outbuf != NULL);

    EVP_EncryptUpdate (&ctx, (unsigned char *) ((*outbuf)), &olen,
                       (unsigned char *) rb, sizeof (rb));

    EVP_EncryptUpdate (&ctx, (unsigned char *) ((*outbuf) + olen), &len1,
                       (unsigned char *) mysig, siglen);
    olen += len1;
    pbc_free (p, mysig);

    EVP_EncryptUpdate (&ctx, (unsigned char *) ((*outbuf) + olen), &len1,
                       (unsigned char *) buf, len);
    olen += len1;

    EVP_EncryptFinal_ex (&ctx, (unsigned char *) ((*outbuf) + olen),
                         &len1);
    olen += len1;

    EVP_CIPHER_CTX_cleanup (&ctx);

    (*outbuf)[olen] = (unsigned char) index1;
    (*outbuf)[olen + 1] = (unsigned char) index2;
    *outlen = olen + 2;

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_mk_priv_aes: goodbye\n");

    return r;
}

/* Choose an encoder */

int libpbc_mk_priv (pool * p, const security_context * context,
                    const char *peer, const char use_granting,
                    const char *buf, const int len,
                    char **outbuf, int *outlen, char alg)
{
    if ((alg == 'a') || (alg == 'A'))
        return (libpbc_mk_priv_aes (p, context, peer,
                                    use_granting, buf, len, outbuf, outlen,
                                    alg));
    else
        return (libpbc_mk_priv_des (p, context, peer,
                                    use_granting, buf, len, outbuf,
                                    outlen));
}


/**
 * libpbc_rd_priv decodes an encrypted string sent by 'peer'.  if
 * 'peer' is NULL, we assume that this host previously called libpbc_mk_priv
 * @param peer the peer this message is destined to (the first parameter to
 * libpbc_mk_priv()).
 * @param buf a pointer to the encrypted message
 * @param len the length of the encrypted message
 * @param outbuf a malloc()ed pointer to the plaintext message
 * @param outlen the length of the plaintext message
 * @returns 0 on success, non-0 on failure (including if the message could 
 * not be decrypted or did not pass integrity checks
 */

/* old des decoder */
libpbc_rd_priv_des (pool * p, const security_context * context,
                    const char *peer, const char use_granting,
                    const char *buf, const int len, char **outbuf,
                    int *outlen)
{
    int index1, index2;
    int i = 0;
    des_cblock key, ivec;
    des_key_schedule ks;
    unsigned char keybuf[PBC_DES_KEY_BUF];
    char *mysig;
    int sig_len;
    static unsigned char ivec_tmp[PBC_INIT_IVEC_LEN] = PBC_INIT_IVEC;
    int c;
    int r;

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "libpbc_rd_priv_des: hello\n");

    sig_len =
        EVP_PKEY_size (use_granting ? context->g_pub : context->sess_pub);

    if (len < sig_len + 2) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "libpbc_rd_priv() called with small length: %d",
                          len);
        return (1);
    }

    /* if peer is null, use cryptname */
    if (get_crypt_key
        (p, context, (peer ? peer : libpbc_get_cryptname (p, context)),
         (char *) keybuf) < 0) {
        return (1);
    }

    mysig = (char *) pbc_malloc (p, sig_len);

    index1 = (unsigned char) buf[len - 2];
    index2 = (unsigned char) buf[len - 1];

    /* setup ivec */
    memcpy (ivec, &(keybuf[index2]), sizeof (ivec));
    for (c = 0; c < sizeof (ivec); ++c) {
        ivec[c] ^= ivec_tmp[i % sizeof (ivec_tmp)];
    }

    /* setup key */
    memcpy (key, &keybuf[index1], sizeof (key));
    des_set_odd_parity (&key);
    if (des_set_key_checked (&key, ks)) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "des_set_key_checked failed: didn't derive a good key");
        pbc_free (p, mysig);
        return 1;
    }

    /* allocate outbuf */
    *outlen = len - sig_len - 2;
    *outbuf = (char *) pbc_malloc (p, *outlen);

    /* decrypt */
    des_cfb64_encrypt ((unsigned char *) buf, (unsigned char *) mysig,
                       sig_len, ks, &ivec, &i, DES_DECRYPT);

    des_cfb64_encrypt ((unsigned char *) buf + sig_len,
                       (unsigned char *) *outbuf, *outlen, ks, &ivec, &i,
                       DES_DECRYPT);

    /* verify signature */
    r = libpbc_rd_safe (p, context, peer, use_granting, *outbuf, *outlen,
                        mysig, sig_len);

    if (mysig != NULL)
        pbc_free (p, mysig);

    if (r) {
        pbc_free (p, *outbuf);
        *outbuf = 0;
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_rd_priv_des: goodbye\n");
    return r;

}


/* AES decoder */
libpbc_rd_priv_aes (pool * p, const security_context * context,
                    const char *peer, const char use_granting,
                    const char *buf, const int len, char **outbuf,
                    int *outlen, char alg)
{
    int index1, index2;
    int i = 0;
    unsigned char keybuf[PBC_DES_KEY_BUF];
    int siglen;
    int c;
    int r;
    unsigned char key[EVP_MAX_KEY_LENGTH];
    unsigned char iv[EVP_MAX_IV_LENGTH];
    unsigned char rb[EVP_MAX_IV_LENGTH];

    const EVP_CIPHER *cip = EVP_aes_128_cbc ();
    EVP_CIPHER_CTX ctx;

    int tlen, len1;

    char *tbuf;
    char *obuf;
    unsigned char *keyptr;
    unsigned char shakey[SHA_DIGEST_LENGTH];

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "libpbc_rd_priv_aes: hello\n");

    siglen =
        EVP_PKEY_size (use_granting ? context->g_pub : context->sess_pub);

    if (len < siglen + 2) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "libpbc_rd_priv() called with small length: %d",
                          len);
        return (1);
    }

    /* if peer is null, use cryptname */
    if (get_crypt_key
        (p, context, (peer ? peer : libpbc_get_cryptname (p, context)),
         (char *) keybuf) < 0) {
        return (1);
    }

    obuf = (char *) pbc_malloc (p, len + sizeof (rb) + 16);
    index1 = (unsigned char) buf[len - 2];
    /* index2 = (unsigned char) buf[len - 1]; */
    RAND_bytes (iv, sizeof (iv));

    EVP_CIPHER_CTX_init (&ctx);

    if (alg == 'A') {
        const char *zpeer = peer;
        int lpeer;
        unsigned char *sk;

        pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                          "..._priv_aes: doing domain key, peer=%s\n",
                          peer ? peer : "(null)");
        if (zpeer == NULL)
            zpeer = libpbc_get_cryptname (p, context);
        lpeer = strlen (zpeer);
        sk = (unsigned char *) malloc (128 + lpeer);
        memcpy (sk, keybuf + index1, 128);
        memcpy (sk + 128, zpeer, lpeer);
        SHA1 (sk, 128 + lpeer, shakey);
        keyptr = shakey;
    } else
        keyptr = keybuf + index1;

    EVP_DecryptInit_ex (&ctx, cip, NULL, keyptr, iv);

    /* decrypt */
    EVP_DecryptUpdate (&ctx, (unsigned char *) (obuf), &tlen,
                       (unsigned char *) buf, len - 2);

    EVP_DecryptFinal_ex (&ctx, (unsigned char *) ((obuf) + tlen), &len1);
    tbuf = obuf + sizeof (rb);
    tlen += len1 - sizeof (rb);

    EVP_CIPHER_CTX_cleanup (&ctx);

    /* verify signature */
    r = libpbc_rd_safe (p, context, peer, use_granting, tbuf + siglen,
                        tlen - siglen, tbuf, siglen);

    if (!r) {
        /* allocate and fill outbuf */
        *outlen = tlen - siglen;
        *outbuf = (char *) malloc (*outlen);
        memcpy (*outbuf, tbuf + siglen, *outlen);
    }

    pbc_free (p, obuf);

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_rd_priv_aes: goodbye\n");
    return r;

}

/* choose a decoder */
int libpbc_rd_priv (pool * p, const security_context * context,
                    const char *peer, const char use_granting,
                    const char *buf, const int len, char **outbuf,
                    int *outlen, char alg)
{
    if ((alg == 'a') || (alg == 'A'))
        return (libpbc_rd_priv_aes (p, context, peer, use_granting,
                                    buf, len, outbuf, outlen, alg));
    else
        return (libpbc_rd_priv_des (p, context, peer, use_granting,
                                    buf, len, outbuf, outlen));
}


/**
 * libpbc_mk_safe allocates a signature and returns it to the
 * application. 'outbuf' does not contain the plaintext message; both
 * 'buf' and 'outbuf' must be sent to the other side
 * Returns 0 on success, -1 on error
 */
int libpbc_mk_safe (pool * p, const security_context * context,
                    const char *peer, const char use_granting,
                    const char *buf, const int len, char **outbuf,
                    int *outlen)
{
    unsigned char *sig;
    unsigned int sig_len = 0;
    EVP_MD_CTX ctx;
    EVP_PKEY *thekey;
    int r;

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_mk_safe: hello, peer is %s",
                      peer ? peer : "self");

    assert (buf != NULL);
    assert (outbuf != NULL);
    assert (outlen != NULL);
    *outbuf = NULL;
    *outlen = 0;

    thekey = use_granting ? context->g_key : context->sess_key;

    sig = (unsigned char *) pbc_malloc (p, EVP_PKEY_size (thekey));
    sig_len = EVP_PKEY_size (thekey);

    EVP_SignInit (&ctx, EVP_md5 ());
    EVP_SignUpdate (&ctx, buf, len);
    if (EVP_SignFinal (&ctx, sig, &sig_len, thekey) == 1) {
        *outbuf = (char *) sig;
        *outlen = sig_len;
        r = 0;
    } else {
        /* xxx log openssl error */
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "libpbc_mk_safe: EVP_SignFinal failed");
        pbc_free (p, sig);
        r = -1;
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_mk_safe: goodbye, sig_len: %d", *outlen);

    return r;
}

/*
 * Returns 0 on success, -1 on error
 */
int libpbc_rd_safe (pool * p, const security_context * context,
                    const char *peer, const char use_granting,
                    const char *buf, const int len, const char *sigbuf,
                    const int siglen)
{
    EVP_MD_CTX ctx;
    int r;

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "libpbc_rd_safe: hello");

    assert (buf != NULL && sigbuf != NULL);

    /* initialize the MD5 context */
    EVP_VerifyInit (&ctx, EVP_md5 ());
    EVP_VerifyUpdate (&ctx, buf, len);
    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "Verifying signature with %s certificate",
                      use_granting ? "granting" : "session");
    if (EVP_VerifyFinal
        (&ctx, (unsigned char *) sigbuf, siglen,
         use_granting ? context->g_pub : context->sess_pub) == 1) {
        r = 0;
    } else {
        /* xxx log openssl error */
        ERR_load_crypto_strings ();
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "libpbc_rd_safe: couldn't verify signature for %s OpenSSL error: %s",
                          peer ? peer : "(self)",
                          ERR_error_string (ERR_get_error (), NULL));
        r = -1;
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "libpbc_rd_safe: goodbye, r: %d", r);

    return r;
}
