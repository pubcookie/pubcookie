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

/** @file keyserver.c
 * Server side of key management structure
 *
 * $Id: keyserver.c,v 2.70 2009/03/12 21:47:59 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

typedef void pool;

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_ASSERT_H
# include <assert.h>
#endif /* HAVE_ASSERT_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif /* HAVE_SYS_WAIT_H */

#include <sys/signal.h>

#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
# include <openssl/crypto.h>
# include <openssl/x509.h>
# include <openssl/pem.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/rand.h>
# include <openssl/objects.h>
# include <openssl/x509v3.h>
#else
# include <pem.h>
# include <crypto.h>
# include <x509.h>
# include <pem.h>
# include <ssl.h>
# include <err.h>
# include <objects.h>
# include <x509v3.h>
#endif /* OPENSSL_IN_DIR */

#ifndef KEYSERVER_CGIC
# ifdef HAVE_GETOPT_H
#  include <getopt.h>
# endif /* HAVE_GETOPT_H */
#else /* ifndef KEYSERVER_CGIC */
# ifdef HAVE_CGIC_H
#  include <cgic.h>
# endif /* HAVE_CGIC_H */
#endif /* ifndef KEYSERVER_CGIC */

#include "snprintf.h"
#include "pbc_config.h"
#include "pbc_logging.h"
#include "pbc_configure.h"
#include "libpubcookie.h"
#include "security.h"

#ifdef HAVE_DMALLOC_H
# if !defined(APACHE)
#  include <dmalloc.h>

#  ifdef __STDC__
extern char *optarg;
#  endif /* __STDC__ */
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

int debug = 0;

#ifndef KEYSERVER_CGIC
static SSL *ssl = NULL;

/**
 * log all outstanding errors from OpenSSL, attributing them to 'func'
 * @param func the function to attribute errors to
 */
static void logerrstr (const char *func)
{
    unsigned long r;
    pool *p = NULL;

    while ((r = ERR_get_error ())) {
        pbc_log_activity (p, PBC_LOG_ERROR, "%s: %s",
                          func, ERR_error_string (r, NULL));
    }
}

void myprintf (const char *format, ...)
{
    va_list args;
    char buf[4 * PBC_DES_KEY_BUF];
    pool *p = NULL;

    assert (ssl != NULL);

    va_start (args, format);
    vsnprintf (buf, sizeof (buf), format, args);
    va_end (args);

    if (debug) {
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "Sending: \"%s\"",
                          buf);
    }

    if (SSL_write (ssl, buf, strlen (buf)) < 0) {
        logerrstr ("SSL_write");
        exit (1);
    }
}
#else /* ifndef KEYSERVER_CGIC */
void myprintf (const char *format, ...)
{
    va_list args;

    va_start (args, format);
    vfprintf (stdout, format, args);
    va_end (args);
}
#endif /* ifndef KEYSERVER_CGIC */


const char *keyfile = NULL;
const char *certfile = NULL;
const char *cadir = NULL;
const char *cafile = NULL;
const char *gcfile = NULL;
const char *configfile = NULL;

enum optype
{
    NOOP,
    GENKEY,
    SETKEY,
    FETCHKEY,
    PERMIT,
    FETCHGC,
    SETPKEY
};

/**
 * iterate through the 'login_servers' configuration variable, contacting
 * each one and setting my copy of peer's key on it
 * @param name of the client key to push
 * @return the number of login servers we failed to set the key on
 * (thus 0 is success)
 */
int pushkey (const char *peer, const security_context * context,
             const char *crt)
{
    pool *p = NULL;
    char **lservers = libpbc_config_getlist (p, "login_servers");
    const char *hostname;
    char *lservername, *ptr, *lhostname;
    int x;
    int res;
    int fail = 0;

    if (!lservers) {
        /* only me here */
        return (0);
    }

    hostname = get_my_hostname (p, context);
    if (!hostname) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "get_my_hostname() failed? %m");
        perror ("get_my_hostname");
        exit (1);
    }

    x = 0;
    for (x = 0; lservers[x] != NULL; x++) {
        /* login_servers (should?  might?) contain a URI */

        /* break out the hostname and see if that is us */
        lhostname = lservername = strdup (lservers[x]);
        if (!strncmp (lhostname, "https://", 8))
            lhostname += 8;
        ptr = strchr (lhostname, '/');
        if (ptr) {
            *ptr = '\0';
        }
        ptr = strchr (lhostname, ':');
        if (ptr) {
            *ptr = '\0';
        }

        if (!strcasecmp (hostname, lhostname)) {
            /* don't push the key to myself */
            free (lservername);
            continue;
        }

        free (lservername);

        pbc_log_activity (p, PBC_LOG_AUDIT,
                          "setting %s's %s on %s", peer,
                          crt ? "pubkey" : "key", lservers[x]);

        res = fork ();
        if (res < 0) {
            pbc_log_activity (p, PBC_LOG_ERROR, "fork(): %m");
            perror ("fork");
            exit (1);
        }
        if (res == 0) {
            const char *keyclient = KEYCLIENT;
            const char *cmd[20];
            int n = 0;
            close(0);
            close(1);
            close(2);
            cmd[n++] = keyclient;
            cmd[n++] = "-q";
            if (crt) {
                cmd[n++] = "-U";        /* upload a cert */
                cmd[n++] = crt;
            } else
                cmd[n++] = "-u";        /* upload a key */
            cmd[n++] = "-H";
            cmd[n++] = peer;
            cmd[n++] = "-L";
            cmd[n++] = lservers[x];
            cmd[n++] = "-k";
            cmd[n++] = keyfile;
            cmd[n++] = "-c";
            cmd[n++] = certfile;
            if (cafile != NULL) {
                cmd[n++] = "-C";
                cmd[n++] = cafile;
            }
            if (cadir != NULL) {
                cmd[n++] = "-D";
                cmd[n++] = cadir;
            }
            if (NULL != configfile) {
                cmd[n++] = "-f";
                cmd[n++] = configfile;
            }
            cmd[n] = NULL;

            res = execv (keyclient, (char **const) cmd);
            pbc_log_activity (p, PBC_LOG_ERROR, "execv(): %m");
            for (n = 0; cmd[n] != NULL; n++) {
                pbc_log_activity (p, PBC_LOG_ERROR, "%d %s", n, cmd[n]);
            }
            exit (2);
        }

        /* parent */
        wait (&res);
        pbc_log_activity (p, PBC_LOG_AUDIT,
                          "setting %s's key on %s: %s", peer, lservers[x],
                          WEXITSTATUS (res) == 0 ? "done" : "error");
        if (WEXITSTATUS (res) != 0) {
            fail++;
        }
    }

    free (lservers);

    return fail;
}

/* ---- X509 tools ------------ */

/* Get a cn from a cert */
static char *get_cn_from_crt (X509 * crt)
{
    X509_NAME *subj;
    int l;
    char *ret = NULL;

    subj = X509_get_subject_name (crt);
    l = X509_NAME_get_text_by_NID (subj, NID_commonName, NULL, 0);
    ret = (char *) malloc (l + 8);
    X509_NAME_get_text_by_NID (subj, NID_commonName, ret, l + 4);
    return (ret);
}

/* Get a cert from a PEM string */

X509 *get_crt_from_pem (const char *crtstr)
{
    X509 *crt = NULL;
    BIO *cbio;

    cbio = BIO_new_mem_buf ((char *) crtstr, strlen (crtstr));
    if (cbio == NULL) {
        return (NULL);
    }

    crt = PEM_read_bio_X509 (cbio, NULL, NULL, NULL);

    BIO_free (cbio);
    return (crt);
}

/* Get the alt names from a cert */

char **get_altnames_from_crt (X509 * crt)
{
    X509_NAME *subj;
    char **ret;
    char **rn;
    int next, lext;
    int i, l;

    next = X509_get_ext_count (crt);

    ret = (char **) malloc ((next + 1) * sizeof (char *));
    rn = ret;
    lext = 0;
    for (i = 0; i < next; i++) {
        X509_EXTENSION *ext;
        ASN1_OBJECT *obj;
        STACK_OF (GENERAL_NAME) * alt;
        GENERAL_NAME *an;

        lext = X509_get_ext_by_NID (crt, NID_subject_alt_name, lext);
        if (lext < 0)
            break;
        ext = X509_get_ext (crt, lext);
        obj = X509_EXTENSION_get_object (ext);

        alt = X509V3_EXT_d2i (ext);
        if (alt) {
            int j, anl;
            char *ant;
            for (j = 0; j < sk_GENERAL_NAME_num (alt); j++) {
                an = sk_GENERAL_NAME_value (alt, j);
                if (an->type != GEN_DNS)
                    continue;
                ant = ASN1_STRING_data (an->d.ia5);
                anl = ASN1_STRING_length (an->d.ia5);
                *rn++ = strdup (ant);
            }
        }
    }
    *rn = NULL;
    return (ret);
}



/**
 @param peer machine talking to the keyserver
 @return PBC_FAIL if not in the access list, PBC_OK if ok.
 */
static int check_access_list (const char *peer)
{
    pool *p = NULL;
    char **access_list =
        libpbc_config_getlist (p, "keyserver_client_list");
    int i;

    /* if there is no access list then everyone is ok */
    if (access_list == NULL) {
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "No keyserver_client_list, hope that's ok");
        return (PBC_OK);
    }

    for (i = 0; access_list[i] != NULL; i++)
        if (strcasecmp (access_list[i], peer) == 0)
            return PBC_OK;

    return PBC_FAIL;

}

/* Test if the peer has authority for the host.  We allow
   a single '*' wildcard at the start of a cn. */
static int test_peer (char *host, X509 * ccert)
{
    char *cn;
    pool *p;
    char **altnames, **an;

    if (strchr (host, '*'))
        return (0);
    cn = get_cn_from_crt (ccert);
    if (!strcmp (host, cn))
        return (1);
    /* maybe cert has a wildcard */
    if (*cn == '*') {
        int nc;
        char *cp;
        for (nc = 0, cp = cn; cp; cp = strchr (cp + 1, '.'), nc++);
        if (nc < 3)
            return (0);
        if (!strcmp (cn + 1, host + (strlen (host) - strlen (cn + 1))))
            return (1);
    }
    /* maybe in altnames */
    altnames = get_altnames_from_crt (ccert);

    for (an = altnames; *an; an++) {
        if (!strcmp (host, *an)) {
            pbc_log_activity (p, PBC_LOG_AUDIT, "peer ok by altname");
            free (altnames);
            return (1);
        }
        if (**an == '*') {
            int nc;
            char *cp;
            for (nc = 0, cp = *an; cp; cp = strchr (cp + 1, '.'), nc++);
            if (!strcmp
                (*an + 1, host + (strlen (host) - strlen (*an + 1)))) {
                pbc_log_activity (p, PBC_LOG_AUDIT,
                                  "peer ok by wildcard altname");
                free (altnames);
                return (1);
            }
        }

    }
    free (altnames);
    return (0);
}

/**
 * do the keyserver operation
 * @param peer the cn from the client's certificate
 * @param op the operation to perform, one of: 
 *	PERMIT - authorize a keyserver client
 *	GENKEY - generate a new key for peer
 *      SETKEY - key from friend login server
 *      FETCHKEY - peer requests it's key
 *      FETCHGC - peer requests the granting cert
 *      SETPKEY - set the public key for a client's cert
 *      NOOP - for completeness
 * @param newkey if the operation is SETKEY, "peer;base64(key)"
 *               else is effective hostname for the op
 * @param ccert the client's certificate
 * @return 0 on success, non-zero on error
 */
int doit (const char *peer, security_context * context, enum optype op,
          const char *newkey, X509 * ccert)
{
    char buf[8 * PBC_DES_KEY_BUF];
    crypt_stuff c_stuff;
    pool *p = NULL;
    int dokeyret = 0;
    char *thepeer = NULL;       /* effective peer hostname */
    char *thekey64;
    FILE *gcf;
    int lgcf;
    char **keymgt_peers = libpbc_config_getlist (p, "keymgt_peers");
    int x, found;
    char *z;

    /* no HTML headers for me */
    myprintf ("\r\n");
    buf[0] = '\0';

    switch (op) {
    case PERMIT:
        {
            /* 'peer' has asked us to authorize a new CN (newkey) */
            if (check_access_list (peer) == PBC_FAIL) {
                myprintf
                    ("NO you (%s) are not authorized to authorize\r\n",
                     peer);
                pbc_log_activity (p, PBC_LOG_ERROR,
                                  "operation not allowed: %s", peer);
                return (1);
            }

            /* find <cn>;<test> */
            thepeer = strdup (newkey);
            thekey64 = strchr (thepeer, ';');
            if (!thekey64) {
                myprintf ("NO bad form for authorize\r\n");
                /* xxx log */
                return (1);
            }
            *thekey64++ = '\0';
            if (z = strchr (thekey64, ' '))
                *z = '\0';

            if (libpbc_test_crypt_key (p, thepeer) == PBC_OK) {
                myprintf ("OK already authorized\r\n");
                pbc_log_activity (p, PBC_LOG_ERROR, "already authorized");
                return (1);
            }

            /* if just a test, return now */
            if (!strncmp (thekey64, "test", 4)) {
                myprintf ("NO server is not authorized\r\n");
                pbc_log_activity (p, PBC_LOG_ERROR, "test - not yet");
                return (1);
            }


            pbc_log_activity (p, PBC_LOG_AUDIT, "authorizing %s", thepeer);

            if (libpbc_generate_crypt_key (p, thepeer) != PBC_OK) {
                myprintf ("NO generate_new_key() failed\r\n");
                pbc_log_activity (p, PBC_LOG_ERROR,
                                  "generate_new_key() failed");
                return (1);
            }

            /* push the new key to the other login servers */
            pushkey (thepeer, context, NULL);

            dokeyret = 0;       /* don't return the key to this client */
            break;
        }

    case GENKEY:
        {
            /* 'peer' has asked us to generate a new key */
            if (newkey)
                thepeer = strdup (newkey);
            else
                thepeer = (char *) peer;
            if (z = strchr (thepeer, ' '))
                *z = '\0';
            if (!test_peer (thepeer, ccert)) {
                myprintf ("NO you (%s) are not authorized for host %s\r\n",
                          peer, thepeer);
                pbc_log_activity (p, PBC_LOG_ERROR,
                                  "operation not allowed: p=%s, h=%s",
                                  peer, thepeer);
                return (1);
            }
            if (libpbc_test_crypt_key (p, thepeer) == PBC_FAIL) {
                myprintf ("NO you (%s) are not authorized for keys\r\n",
                          thepeer);
                pbc_log_activity (p, PBC_LOG_ERROR,
                                  "operation not allowed: %s", thepeer);
                return (1);
            }

            pbc_log_activity (p, PBC_LOG_AUDIT,
                              "generating a new key for %s", thepeer);

            if (libpbc_generate_crypt_key (p, thepeer) < 0) {
                myprintf ("NO generate_new_key() failed\r\n");
                pbc_log_activity (p, PBC_LOG_ERROR,
                                  "generate_new_key() failed");

                return (1);
            }

            /* push the new key to the other login servers */
            pushkey (thepeer, context, NULL);

            dokeyret = 1;
            break;
        }

    case SETKEY:
        {
            char *thekey64, *thepeer;
            char *thekey;
            int ksize;

            /* someone has asked us to set a key */

            /* verify that 'peer' is a fellow login server
               OR in the list of keymgt_peers.  this allows the pool of 
               key management hosts to push keys to servers outside their 
               cluster */
            if (strcasecmp (peer, PBC_LOGIN_HOST)) {
                found = 0;
                for (x = 0; keymgt_peers[x] != NULL && !found; x++)
                    if (!strcasecmp (peer, keymgt_peers[x]))
                        found = 1;
                if (!found) {
                    pbc_log_activity (p, PBC_LOG_ERROR,
                                      "%s attempted to set a key!", peer);
                    myprintf ("NO you are not authorized to set keys\r\n");
                    return (1);
                }
            }

            /* find <peer>;<key> */
            thepeer = strdup (newkey);
            thekey64 = strchr (thepeer, ';');
            if (!thekey64) {
                myprintf ("NO bad form for new key\r\n");
                /* xxx log */
                return (1);
            }
            *thekey64++ = '\0';
            if (z = strchr (thekey64, ' '))
                *z = '\0';

            /* base64 decode thekey64 */
            thekey = (char *) malloc (strlen (thekey64));
            if (strchr (thekey64, '\r')) {
                /* chomp new line */
                *strchr (thekey64, '\r') = '\0';
            }
            if (!thekey ||
                !libpbc_base64_decode (p, (unsigned char *) thekey64,
                                       (unsigned char *) thekey, &ksize) ||
                ksize != PBC_DES_KEY_BUF) {
                myprintf ("NO couldn't decode key\r\n");
                /* xxx log */
                return (1);
            }

            /* go ahead and write it to disk */
            if (libpbc_set_crypt_key (p, thekey, thepeer) != PBC_OK) {
                myprintf ("NO couldn't set key\r\n");
                /* xxx log */
                return (1);
            }

            free (thekey);

            pbc_log_activity (p, PBC_LOG_AUDIT,
                              "%s set key for %s!", peer, thepeer);
            myprintf ("OK key set\r\n");
            break;
        }

    case FETCHKEY:

        pbc_log_activity (p, PBC_LOG_AUDIT, "Fetching a key..");

        if (newkey)
            thepeer = strdup (newkey);
        else
            thepeer = (char *) peer;
        if (z = strchr (thepeer, ' '))
            *z = '\0';
        if (!test_peer (thepeer, ccert)) {
            myprintf ("NO you (%s) are not authorized for host %s\r\n",
                      peer, thepeer);
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "operation not allowed: p=%s, h=%s", peer,
                              thepeer);
            return (1);
        }
        dokeyret = 1;
        break;

    case FETCHGC:

        pbc_log_activity (p, PBC_LOG_AUDIT, "Fetching the cert..");

        if (!(gcfile && (gcf = fopen (gcfile, "r")))) {
            myprintf ("NO couldn't open cert file\r\n");
            return (1);
        }
        lgcf = fread (buf, 1, sizeof (buf) - 1, gcf);
        if (lgcf <= 0) {
            myprintf ("NO couldn't read cert file\r\n");
            return (1);
        }
        buf[lgcf] = '\0';
        dokeyret = 0;
        break;

    case SETPKEY:
        {
            /* 'peer' has asked us to store the public key for a host */
            /* newkey is the cert (pem) */
            X509 *crt;
            char *cn, *cn1;
            char *fn;
            FILE *fp;

            if (check_access_list (peer) == PBC_FAIL) {
                myprintf
                    ("NO you (%s) are not authorized to set cert keys\r\n",
                     peer);
                pbc_log_activity (p, PBC_LOG_ERROR,
                                  "operation not allowed: %s", peer);
                return (1);
            }

            pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "pkey cert = %s",
                              newkey);
            crt = get_crt_from_pem (newkey);
            if (!crt || !(cn = get_cn_from_crt (crt))) {
                myprintf ("NO bad cert\r\n");
                pbc_log_activity (p, PBC_LOG_ERROR, "bad pkey cert");
                return (1);
            }
            cn1 = cn;
            if (*cn1 == '*')
                cn1++;
            if (*cn1 == '.')
                cn1++;
            pbc_log_activity (p, PBC_LOG_AUDIT,
                              "setting pubkey for %s", cn1);

            fn = (char *) malloc (strlen (PBC_KEY_DIR) + strlen (cn1) +
                                  16);
            sprintf (fn, "%s/%s.crt", PBC_KEY_DIR, cn1);

            if (!((fp = fopen (fn, "w")) && (fputs (newkey, fp) > 0) &&
                  (fclose (fp) == 0))) {
                myprintf ("NO store pkey failed\r\n");
                pbc_log_activity (p, PBC_LOG_ERROR, "store pkey failed");
                return (1);
            }

            /* push the pkey to the other login servers */
            pushkey (thepeer, context, fn);

            dokeyret = 0;       /* don't return a key to this client */
            break;
        }

    case NOOP:

        pbc_log_activity (p, PBC_LOG_AUDIT, "Noop..");
        /* noop;  just for completeness */
        break;
    }

    if (dokeyret) {
        /* return the key */
        if (libpbc_get_crypt_key (p, &c_stuff, (char *) thepeer) != PBC_OK) {
            myprintf ("NO couldn't retrieve key\r\n");
            return 1;
        }

        /* now give the key back to the application */
        libpbc_base64_encode (p, c_stuff.key_a, (unsigned char *) buf,
                              PBC_DES_KEY_BUF);
    }

    myprintf ("OK %s\r\n", buf);
    fflush (stdout);

    return 0;
}

#ifndef KEYSERVER_CGIC

void usage (void)
{
    printf ("usage: keyserver [options]\n");
    printf
        ("  -c <cert file>     : certificate to use for TLS authentication\n");
    printf ("  -k <key>           : key to use for TLS authentication\n");
    printf ("  -a                 : expect keyfile in ASN.1\n");
    printf ("  -p (default)       : expect keyfile in PEM\n");
    printf
        ("  -C <cert file>     : CA cert to use for client verification\n");
    printf
        ("  -D <ca dir>        : directory of trusted CAs, hashed OpenSSL-style\n");
    printf ("\n");
    printf
        ("All options override the values in the configuration file.\n");
}

/* Check if a certificate's pubkey is on file.  */

static ASN1_BIT_STRING *cache_pkey = NULL;
static int verify_local_public_key (X509 * crt)
{
    int l;
    void *p = NULL;

    if (!cache_pkey) {
        char *cn, *cn1;
        char *fn;
        BIO *cb;
        X509 *cache_crt;

        cn = get_cn_from_crt (crt);
        if (!cn)
            return (0);

        cn1 = cn;
        if (*cn1 == '*')
            cn1++;
        if (*cn1 == '.')
            cn1++;

        fn = (char *) malloc (strlen (PBC_KEY_DIR) + strlen (cn1) + 16);
        sprintf (fn, "%s/%s.crt", PBC_KEY_DIR, cn1);

        cb = BIO_new (BIO_s_file ());

        if (BIO_read_filename (cb, fn) > 0) {
            cache_crt = PEM_read_bio_X509 (cb, NULL, NULL, NULL);
            if (cache_crt)
                cache_pkey = X509_get0_pubkey_bitstr (cache_crt);
        }
        BIO_free (cb);
        free (cn);
        free (fn);
    }

    if (cache_pkey) {
        ASN1_BIT_STRING *nkey;
        nkey = X509_get0_pubkey_bitstr (crt);
        if (nkey && (nkey->length == cache_pkey->length) &&
            (memcmp (nkey->data, cache_pkey->data, nkey->length) == 0))
            return (1);
    }
    return (0);
}

static int verify_callback (int ok, X509_STORE_CTX * ctx)
{
    X509 *err_cert;
    int err;
    pool *p = NULL;

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                      "verifying peer certificate... ok=%d", ok);

    err_cert = X509_STORE_CTX_get_current_cert (ctx);
    err = X509_STORE_CTX_get_error (ctx);

    if (!ok) {
        pbc_log_activity (p, PBC_LOG_ERROR, "verify error:num=%d:%s", err,
                          X509_verify_cert_error_string (err));

        switch (ctx->error) {

            /* ignore any key usage problems */
        case X509_V_ERR_INVALID_PURPOSE:
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "invalid purpose; ignoring error!");
            ok = 1;
            break;


            /* no approved ca - check local cache of public keys */
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_CERT_UNTRUSTED:
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
            ok = verify_local_public_key (err_cert);
            if (ok)
                pbc_log_activity (p, PBC_LOG_ERROR, "pubkey on file");
            break;

        default:
            break;
        }
    }

    return ok;
}

/* Catch an idle connection. Logging ought to be ok here, since we suspect
   this is always caused by a bogus connection that is passing no data,
   and we are leaving right afterwards. */

void sig_alarm ()
{
    pbc_log_activity (NULL, PBC_LOG_ERROR,
                      "Bogus connection terminated by alarm");
    exit (1);
}


/* run as if invoked by inetd */
int main (int argc, char *argv[])
{
    int c;
    int filetype = SSL_FILETYPE_PEM;
    char *peer = NULL;
    char *ptr;
    char buf[4096];
    enum optype op = NOOP;
    char *setkey = NULL;
    SSL_CTX *ctx;
    X509 *client_cert;
    int r;
    pool *p = NULL;
    security_context *context = NULL;
    int max_wait = 0;

    while ((c = getopt (argc, argv, "apc:k:C:D:f:")) != -1) {
        switch (c) {
        case 'a':
            filetype = SSL_FILETYPE_ASN1;
            break;

        case 'p':
            filetype = SSL_FILETYPE_PEM;
            break;

        case 'c':
            /* 'optarg' is the certificate file */
            certfile = strdup (optarg);
            break;

        case 'k':
            /* 'optarg' is the key file */
            keyfile = strdup (optarg);
            break;

        case 'C':
            /* 'optarg' is the CA we accept */
            cafile = strdup (optarg);
            break;

        case 'D':
            /* 'optarg' is a directory of CAs */
            cadir = strdup (optarg);
            break;

        case 'f':
            configfile = strdup (optarg);
            break;

        case '?':
        default:
            usage ();
            break;
        }
    }

    libpbc_config_init (p, configfile, "keyserver");
    pbc_log_init_syslog (p, "keyserver");
    libpbc_pubcookie_init (p, &context);

    debug = libpbc_config_getint (p, "logging_level", 0);
    if (!keyfile)
        keyfile =
            libpbc_config_getstring (p, "ssl_key_file", "server.pem");
    if (!certfile)
        certfile =
            libpbc_config_getstring (p, "ssl_cert_file", "server.pem");
    if (!cafile)
        cafile = libpbc_config_getstring (p, "ssl_ca_file", NULL);
    if (!cadir)
        cadir = libpbc_config_getstring (p, "ssl_ca_path", NULL);

    gcfile = libpbc_config_getstring (p, "granting_cert_file", NULL);
    max_wait = libpbc_config_getint (p, "keyserver_max_wait_time", 0);
    if (max_wait < 0)
        max_wait = 0;

    /* xxx log connection information */

    /* initalize the PRNG as best we can if we have to */
    if (RAND_status () == 0) {
        pbc_time_t t = pbc_time (NULL);
        pid_t pid = getpid ();
        char buf[1024];
        char *cmd[3] = { "/bin/ps", "-ef", NULL };

        RAND_seed ((unsigned char *) &t, sizeof (t));
        RAND_seed ((unsigned char *) &pid, sizeof (pid));

        capture_cmd_output (p, cmd, buf, sizeof (buf));
        RAND_seed ((unsigned char *) buf, sizeof (buf));
    }

    /* Load SSL Error Strings */
    SSL_load_error_strings ();

    /* initialize the OpenSSL connection */
    SSL_library_init ();

    ctx = SSL_CTX_new (TLSv1_server_method ());

    /* setup the correct certificate */
    if (!SSL_CTX_use_certificate_file (ctx, certfile, filetype)) {
        logerrstr ("SSL_CTX_use_certificate_file");
        exit (1);
    }
    if (!SSL_CTX_use_PrivateKey_file (ctx, keyfile, filetype)) {
        logerrstr ("SSL_CTX_use_PrivateKey_file");
        exit (1);
    }
    if (!SSL_CTX_load_verify_locations (ctx, cafile, cadir)) {
        logerrstr ("SSL_CTX_load_verify_locations");
        exit (1);
    }

    SSL_CTX_set_verify (ctx,
                        SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
                        | SSL_VERIFY_CLIENT_ONCE, verify_callback);

    ssl = SSL_new (ctx);

    /* negotiate SSL */
    SSL_set_rfd (ssl, 0);
    SSL_set_wfd (ssl, 1);
    SSL_set_accept_state (ssl);

    /* If no data in max_wait seconds, give up */
    if (max_wait) {
        signal (SIGALRM, sig_alarm);
        alarm (max_wait);
    }

    if (SSL_accept (ssl) <= 0) {
        logerrstr ("SSL_accept");
        ERR_print_errors_fp (stderr);
        exit (1);
    }
    if (max_wait)
        alarm (0);

    /* check certificate */
    client_cert = SSL_get_peer_certificate (ssl);
    if (client_cert == NULL) {
        pbc_log_activity (p, PBC_LOG_ERROR, "client_cert == NULL???");
        exit (1);
    }

    peer = get_cn_from_crt (client_cert);
    if (peer == NULL) {
        pbc_log_activity (p, PBC_LOG_ERROR, "peer == NULL???");
        exit (1);
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "peer cn: %s\n", peer);

    /* read HTTP query */
    if ((c=SSL_read (ssl, buf, sizeof(buf)-1)) <= 0) {
        pbc_log_activity (p, PBC_LOG_ERROR, "SSL_read() failed");
        ERR_print_errors_fp (stderr);
        exit (1);
    }
    buf[c] = '\0';

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "REQ=%s", buf);
    for (ptr = buf; *ptr != '\0'; ptr++) {
        if (*ptr == '?' || *ptr == '&') {       /* next arg */
            /* look for 'genkey' */
            if (!strncmp (ptr + 1, "genkey=yes", 10)) {
                op = GENKEY;
            }

            else if (!strncmp (ptr + 1, "genkey=no", 9)) {
                op = FETCHKEY;
            }

            else if (!strncmp (ptr + 1, "genkey=put", 10)) {
                op = SETKEY;
            }

            else if (!strncmp (ptr + 1, "genkey=permit", 13)) {
                op = PERMIT;
            }

            else if (!strncmp (ptr + 1, "genkey=getgc", 12)) {
                op = FETCHGC;
            }

            else if (!strncmp (ptr + 1, "genkey=setpkey", 12)) {
                op = SETPKEY;
            }

            /* look for 'setkey' */
            else if (!strncmp (ptr + 1, "setkey=", 7)) {
                char *q;

                ptr++;          /* ? or & */
                ptr += 7;       /* setkey= */

                setkey = strdup (ptr);
                /* terminated by ? - this is a bit dubious, but i think it's 
                   compensated for later - ssw */
                q = strchr (setkey, '?');
                if (q)
                    *q = '\0';
            }
        }
    }

    if (op == NOOP) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "peer didn't specify an operation");
        exit (1);
    }

    /* call doit */

    r = doit (peer, context, op, setkey, client_cert);
    SSL_shutdown (ssl);

    return r;
}

#else /* ifndef KEYSERVER_CGIC */
/*
  this CGI requires client-side SSL authentication.
  make sure Apache is configured thusly in the SSL section:
  
  SSLVerifyClient optional
  SSLOptions +StdEnvVars

*/

/* run as if invoked as a CGI from Apache or another web server */

/**
 * cgiMain() is called per-connection
 */
int cgiMain ()
{
    const char *peer;
    char buf[2048];

    if (debug) {
        fprintf (stderr,
                 "cgiMain: keyserver built on " __DATE__ " " __TIME__
                 "\n");
    }

    /* xxx log connection */

    libpbc_config_init (p, NULL, "keyserver");
    debug = libpbc_config_getint (p, "logging_level", 0);

    if (!getenv ("HTTPS") || strcmp (getenv ("HTTPS"), "on")) {
        printf ("\r\nNO HTTPS required\r\n");
        fprintf (stderr, "keyserver invoked without HTTPS\n");
        exit (1);
    }

    peer = getenv ("SSL_CLIENT_S_DN_CN");
    if (!peer) {
        printf ("\r\nNO REMOTE_USER not found\r\n");
        fprintf (stderr, "keyserver invoked without REMOTE_USER\n");
        exit (1);
    }
    if (debug) {
        fprintf (stderr, "peer identified as %s\n", peer);
    }

    buf[0] = '\0';

    /* find out what sort of request this is */
    if (cgiFormString ("genkey", buf, sizeof (buf) - 1) != cgiFormSuccess) {
        printf ("\r\nNO bad genkey parameter\r\n");
        fprintf (stderr, "keyserver invoked with bad params\n");
        exit (1);
    }

    if (!strcmp (buf, "yes")) {
        if (debug) {
            fprintf (stderr, "peer requested a new key\n");
        }
        doit (peer, GENKEY, NULL);
    } else if (!strcmp (buf, "put")) {
        if (debug) {
            fprintf (stderr, "peer requested me to set a key\n");
        }

        if (cgiFormString ("setkey", buf, sizeof (buf) - 1) !=
            cgiFormSuccess) {
            printf ("\r\nNO bad setkey parameter\r\n");
            /* xxx log */
            exit (1);
        }

        doit (peer, SETKEY, buf);
    } else {
        /* we're just downloading the existing key */
        doit (peer, FETCHKEY, NULL);
    }
    return 0;
}

#endif /* ifndef KEYSERVER_CGIC */
