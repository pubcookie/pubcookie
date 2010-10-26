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

/** @file keyclient.c
 * Key administration tool for clients
 *
 * $Id: keyclient.c,v 2.65 2008/05/16 22:09:10 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

typedef void pool;

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif /* HAVE_ARPA_INET_H */

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif /* HAVE_NETDB_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
# include <openssl/crypto.h>
# include <openssl/x509.h>
# include <openssl/ssl.h>
# include <openssl/err.h>
# include <openssl/rand.h>
#else
# include <pem.h>
# include <crypto.h>
# include <x509.h>
# include <ssl.h>
# include <err.h>
# include <rand.h>
#endif /* OPENSSL_IN_DIR */

#include "pbc_config.h"
#include "pbc_configure.h"
#include "pbc_logging.h"
#include "libpubcookie.h"
#include "strlcpy.h"
#include "snprintf.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>

#  ifdef __STDC__
extern char *optarg;
#  endif /* __STDC__ */
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

#ifdef WIN32
char *SystemRoot;
#  include "Win32/debug.h"
#  include "Win32/getopt.h"
#  include <process.h>
#  include <io.h>
#  define pid_t int
#  define snprintf _snprintf
#endif

/* We can't use the library because we may not haev a granting cookie.
   We son't actually do much with it anyway, so it's not missed.
   Define this to make keyclient not work */

/* globals */
int noop = 0;
int verb = 1;

/*
 * keyclient should print errors to standard error, not syslog
 * because no one ever will see them in syslog
 */
static void mylog (pool * p, int logging_level, const char *msg)
{
    if (logging_level <= libpbc_config_getint (p, "logging_level", 0)) {
        fprintf (stderr, "%s", msg);
    }
}

static void usage (void)
{
    printf
        ("usage: keyclient [options]                 Download (upload) host key\n");
    printf
        ("       keyclient -P <host> [options]       Permit 'host' to access keyserver\n");
    printf
        ("       keyclient -U <cert_file> [options]  Set the cert's public key\n");
    printf
        ("       keyclient -G <gcertfile> [options]  Get granting cert (to gcertfile)\n");
    printf ("\n  options:\n");
    printf
        ("  -C <ca file>    : authorized CA certs file. Def: ssl_ca_file\n");
    printf
        ("  -D <ca dir>     : authorized CA certs dir. Def: ssl_ca_path\n");
    printf ("  -H <hostname>   : pretend to be <hostname> (dangerous!)\n");
    printf ("  -K <URI>        : URI of key management server\n");
    printf ("  -a              : expect keyfile in ASN.1\n");
    printf
        ("  -c <cert file>  : cert to use for authn. Def: ssl_cert_file\n");
    printf
        ("  -d              : don't generate a new hostkey, download existing\n");
    printf
        ("  -f <config file>   : alternate file with configuration variables\n");
    printf
        ("  -k <key file>   : key to use for authen. Def: ssl_key_file\n");
    printf ("  -n              : just show what would be done\n");
    printf ("  -p              : expect keyfile in PEM (default) \n");
    printf ("  -q              : quiet mode\n");
    printf
        ("  -u              : upload the local hostkey to the server\n");

    exit (1);
}


static int verify_callback (int ok, X509_STORE_CTX * ctx)
{
    X509 *err_cert;
    int err;
    pool *p = NULL;

    err_cert = X509_STORE_CTX_get_current_cert (ctx);
    err = X509_STORE_CTX_get_error (ctx);

    if (!ok) {
        fprintf (stderr, "verify error:num=%d:%s\n", err,
                 X509_verify_cert_error_string (err));

        /* we want to ignore any key usage problems but no other faults */
        switch (ctx->error) {
        case X509_V_ERR_INVALID_PURPOSE:
            fprintf (stderr, ".. ignoring the invalid purpose error\n");
            ok = 1;
            break;

        default:
            break;
        }
    }

    return ok;
}

int main (int argc, char *argv[])
{
    SSL_CTX *ctx;
    SSL *ssl;
    int sd;
    struct sockaddr_in sa;
    struct hostent *h;
    char *str, *cp;
    char buf[8 * PBC_DES_KEY_BUF];      /* plenty of room for key or cert */
    unsigned char thekey[PBC_DES_KEY_BUF];
    crypt_stuff c_stuff;
    const char *hostname;
    int newkeyp;
    int permit;
    X509 *server_cert;
    X509_NAME *peer_name;
    char peer_cn[257];
    const char *keyfile = NULL;
    const char *certfile = NULL;
    const char *cafile = NULL;
    const char *cadir = NULL;
    int done = 0;
    int c;
    int filetype = SSL_FILETYPE_PEM;
    const char *keymgturi = NULL;
    char *keyhost = NULL;
    int keyport = 443;
    int r;
    pool *p = NULL;
    char *gcert = NULL;
    char *pcert = NULL;
    const char *cluster = NULL;
    const char *configfile = NULL;

#ifdef WIN32
    SystemRoot = malloc (MAX_PATH * sizeof (char));
    GetEnvironmentVariable ("windir", SystemRoot, MAX_PATH);
    strcat (SystemRoot, "\\System32");
    strcpy (Instance, "KeyClient");
    {

        WSADATA wsaData;

        if (WSAStartup ((WORD) 0x0101, &wsaData)) {
            fprintf (stderr, "Unable to initialize WINSOCK: %d",
                     WSAGetLastError ());
            return -1;
        }
    }
#endif

    hostname = NULL;

    newkeyp = 1;
    permit = 0;
    while ((c =
            getopt (argc, argv,
                    "0:1:P:aqpc:k:C:D:nudH:L:K:G:U:f:")) != -1) {
        switch (c) {
        case 'a':
            filetype = SSL_FILETYPE_ASN1;
            break;

        case 'p':
            filetype = SSL_FILETYPE_PEM;
            break;

        case 'q':
            verb = 0;
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

        case 'n':
            /* noop */
            noop = 1;
            break;

        case 'd':
            /* download, don't generate a new key */
            newkeyp = 0;
            break;

        case 'u':
            /* upload, don't generate a new key */
            newkeyp = -1;
            break;

        case 'H':
            hostname = strdup (optarg);
            break;

        case 'L':
        case 'K':
            /* connect to the specified key management server
               Overrides PBC_KEYMGT_URI */
            keymgturi = strdup (optarg);
            break;

        case '0':
            /* deny access to a cn */
            newkeyp = -1;
            permit = -1;
            hostname = strdup (optarg);
            break;

        case 'P':
        case '1':
            /* permit access to a cn */
            newkeyp = -1;
            permit = 1;
            hostname = strdup (optarg);
            break;

        case 'G':
            gcert = strdup (optarg);
            newkeyp = -1;
            break;

        case 'U':
            pcert = strdup (optarg);
            newkeyp = -1;
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

    libpbc_config_init (p, configfile, "keyclient");
    pbc_log_init (p, "keyclient", NULL, &mylog, NULL, NULL);

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

    cluster = libpbc_config_getstring (p, "login_host", "");

    /* initalize the PRNG as best we can if we have to */
    if (RAND_status () == 0) {
        pbc_time_t t = pbc_time (NULL);
        pid_t pid = getpid ();
#ifndef WIN32
        char buf[1024];
#endif
        char *cmd[3] = { "/bin/ps", "-ef", NULL };

        RAND_seed ((unsigned char *) &t, sizeof (t));
        RAND_seed ((unsigned char *) &pid, sizeof (pid));

#ifndef WIN32
        capture_cmd_output (p, cmd, buf, sizeof (buf));
        RAND_seed ((unsigned char *) buf, sizeof (buf));
#endif
    }

    /* Load SSL Error Strings */
    SSL_load_error_strings ();

    /* initialize the OpenSSL connection */
    SSL_library_init ();

    ctx = SSL_CTX_new (TLSv1_client_method ());

    /* setup the correct certificate */
    if (!SSL_CTX_use_certificate_file (ctx, certfile, filetype)) {
        fprintf (stderr, "SSL_CTX_use_certificate_file:\n");
        ERR_print_errors_fp (stderr);
        exit (1);
    }
    if (!SSL_CTX_use_PrivateKey_file (ctx, keyfile, filetype)) {
        fprintf (stderr, "SSL_CTX_use_PrivateKey_file:\n");
        ERR_print_errors_fp (stderr);
        exit (1);
    }
    SSL_CTX_set_verify (ctx, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_verify_depth (ctx, 5);

    if (!SSL_CTX_load_verify_locations (ctx, cafile, cadir)) {
        fprintf (stderr, "SSL_CTX_load_verify_locations failed:\n");
        ERR_print_errors_fp (stderr);
        fprintf (stderr, "(set 'ssl_ca_file' or 'ssl_ca_path'?)\n");
        exit (1);
    }


    ssl = SSL_new (ctx);
    if (!ssl) {
        fprintf (stderr, "SSL_connect() failed:\n");
        ERR_print_errors_fp (stderr);
    }

    /* figure out the key management server */
    if (!keymgturi) {
        keymgturi = PBC_KEYMGT_URI;
    }
    keyhost = strdup (keymgturi);

    if (!strncmp (keyhost, "https://", 8))
        keyhost += 8;
    cp = strchr (keyhost, '/');
    if (cp) {
        *cp = '\0';
    }

    cp = strchr (keyhost, ':');
    if (cp) {
        *cp++ = '\0';
        keyport = atoi (cp);
    }

    /* connect to the keyserver */
    sd = socket (AF_INET, SOCK_STREAM, 0);
    if (sd < 0) {
        perror ("socket");
        exit (1);
    }

    sa.sin_family = AF_INET;
    h = gethostbyname (keyhost);
    if (!h) {
        fprintf(stderr, "gethostbyname failed for: %s\n", keyhost);
        exit (1);
    }
    memcpy (&sa.sin_addr, h->h_addr, h->h_length);
#ifdef WIN32
    sa.sin_port = htons ((unsigned short) keyport);
#else
    sa.sin_port = htons (keyport);
#endif

    if (connect (sd, (struct sockaddr *) &sa, sizeof (sa)) < 0) {
        perror ("connect");
        exit (1);
    }

    /* negotiate SSL */
    SSL_set_fd (ssl, sd);
    if (SSL_connect (ssl) < 0) {
        ERR_print_errors_fp (stderr);
        exit (1);
    }

    /* check certificate */
    server_cert = SSL_get_peer_certificate (ssl);
    if (server_cert == NULL) {
        fprintf (stderr, "server_cert == NULL???\n");
        exit (1);
    }

    if (X509_NAME_get_text_by_NID (X509_get_subject_name (server_cert),
                                   NID_commonName, peer_cn,
                                   sizeof (peer_cn)) < 0) {
        fprintf (stderr, "Couldn't get CN from server cert!\n");
        exit (1);
    }
    if (strcasecmp (peer_cn, keyhost) && strcasecmp (peer_cn, cluster)) {
        fprintf (stderr,
                 "certificate presented isn't the key server: %s != %s\n",
                 peer_cn, keyhost);
        exit (1);
    }

    if (!hostname) {
        X509 *mycert;
        /* retrieve the hostname from the client cert we're using */
        mycert = SSL_get_certificate (ssl);
        if (mycert == NULL) {
            fprintf (stderr, "mycert == NULL???\n");
            exit (1);
        }

        if (X509_NAME_get_text_by_NID (X509_get_subject_name (mycert),
                                       NID_commonName, peer_cn,
                                       sizeof (peer_cn)) < 0) {
            fprintf (stderr, "Couldn't get CN from your %s cert!\n",
                     certfile);
            exit (1);
        }
        hostname = strdup (peer_cn);
    }

    /* make the HTTP query */

    /* newkeyp = 1 means generate and get a key 
       newkeyp = 0 means get a key 
       newkeyp = -1 means something else
     */

    if (newkeyp == -1) {
        char enckey[PBC_DES_KEY_BUF * 2];

        if (permit) {           /* permit or deny a host */
            snprintf (buf, sizeof (buf),
                      "GET %s?genkey=%s&setkey=%s;\r\n\r\n",
                      keymgturi, (permit < 0 ? "deny" : "permit"),
                      hostname);

        } else if (gcert) {     /* get the granting cert */
            snprintf (buf, sizeof (buf),
                      "GET %s?genkey=getgc;\r\n\r\n", keymgturi);

        } else if (pcert) {     /* set the pubkey */
            FILE *fp = fopen (pcert, "r");
            char crt[10240];
            if (fp && fread (crt, 1, 10240, fp)) {
                snprintf (buf, sizeof (buf),
                          "GET %s?genkey=setpkey&setkey=%s;\r\n\r\n",
                          keymgturi, crt);
                fclose (fp);
            } else {
                perror (pcert);
                exit (1);
            }

        } else {                /* set the key */
            if (libpbc_get_crypt_key (p, &c_stuff, hostname) != PBC_OK) {
                fprintf (stderr, "couldn't retrieve key\r\n");
                exit (1);
            }

            libpbc_base64_encode (p, c_stuff.key_a,
                                  (unsigned char *) enckey,
                                  PBC_DES_KEY_BUF);

            /* we're uploading! */
            snprintf (buf, sizeof (buf),
                      "GET %s?genkey=put&setkey=%s;%s\r\n\r\n",
                      keymgturi, hostname, enckey);
        }
    } else {                    /* get the key */
        snprintf (buf, sizeof (buf),
                  "GET %s?genkey=%s&setkey=%s HTTP/1.0\r\n\r\n", keymgturi,
                  newkeyp ? "yes" : "no", hostname);
    }

    if (noop && newkeyp) {
        printf ("-n specified; not performing any writes:\n");
        printf ("%s", buf);
        exit (1);
    }

    r = SSL_write (ssl, buf, strlen (buf));
    if (r < 0) {
        fprintf (stderr, "SSL_write failed. Return code: %d\n",
                 SSL_get_error (ssl, r));
        ERR_print_errors_fp (stderr);
        exit (1);
    }

    cp = buf;
    for (;;) {
        /* read the response */
        r = SSL_read (ssl, cp, sizeof (buf) - 1 - (cp - buf));
        if (r < 0) {
            fprintf (stderr, "SSL_read failed:\n");
            ERR_print_errors_fp (stderr);
            exit (1);
        }
        if (r == 0) {
            break;
        }
        cp += r;
        *cp = '\0';
    }

    cp = buf;
    /* look for the 'OK' */
    while (*cp) {
        if (cp[0] == '\r' && cp[1] == '\n' &&
            cp[2] == 'O' && cp[3] == 'K' && cp[4] == ' ') {
            char *s;
            cp += 5;

            if (newkeyp != -1) {
                /* If getting a key, cp points to a base64 key to decode */
                if (strlen (cp) >= (4 * PBC_DES_KEY_BUF + 100) / 3) {
                    fprintf (stderr, "key too long\n");
                    exit (1);
                }

                if ((s = strchr (cp, '\r')))
                    *s = '\0';
                if ((s = strchr (cp, '\n')))
                    *s = '\0';

                if (noop) {
                    printf ("would have set key to '%s'\n", cp);
                } else {
                    int osize = 0;
                    int ret;
                    if ((s = strchr (cp, '\r')))
                        *s = '\0';
                    ret =
                        libpbc_base64_decode (p, (unsigned char *) cp,
                                              thekey, &osize);
                    if (osize != PBC_DES_KEY_BUF) {
                        fprintf (stderr,
                                 "keyserver returned wrong key size: expected %d got %d\n",
                                 PBC_DES_KEY_BUF, osize);
                        exit (1);
                    }

                    if (!ret) {
                        fprintf (stderr, "Bad base64 decode.\n");
                        exit (1);
                    }

                    if (libpbc_set_crypt_key
                        (p, (const char *) thekey, hostname) != PBC_OK) {
                        fprintf (stderr,
                                 "libpbc_set_crypt_key() failed\n");
                        exit (1);
                    }
                    if (verb)
                        printf ("Set crypt key for %s\n", hostname);
                }
            } else if (gcert) {
                /* If getting a cert, cp points to start of PEM cert */
                FILE *cf = fopen (gcert, "w");
                if (!cf) {
                    perror ("gcert");
                    exit (1);
                }
                fputs (cp, cf);
                fclose (cf);
                if (verb)
                    printf ("Granting cert saved to %s\n", gcert);
            } else if (permit) {
                if (verb)
                    printf ("Host %s %s\n", hostname,
                            permit > 0 ? "is permitted" : "is denied");

            } else {
                if (verb)
                    printf ("Uploaded key ofr %s\n", hostname);
            }

            done = 1;
            goto jump;
        }
        cp++;
    }

  jump:
    SSL_shutdown (ssl);

    if (!done) {
        if (verb)
            printf ("Failed: %s\n", buf);
        r = 1;
    } else {
        r = 0;
    }

    close (sd);
    SSL_free (ssl);
    SSL_CTX_free (ctx);

    exit (r);
}
