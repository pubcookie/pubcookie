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

/** @file check_crypted_blob.c
 * takes an encrytped blob and checks it
 *
 * $Id: check_crypted_blob.c,v 1.18 2008/05/16 22:09:10 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#include "pbc_time.h"

#if !defined(WIN32)
# include <netdb.h>
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


#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
#else
# include <pem.h>
#endif /* OPENSSL_IN_DIR */

#if defined (WIN32)
# include <winsock2.h>          // jimb - WSASTARTUP for gethostname
# include <getopt.h>            // jimb - getopt from pdtools
extern char *optarg;
# define bzero(s,n) memset((s),0,(n))   // jimb - win32
#else /* WIN32 */

# ifdef HAVE_UNISTD_H
#  include <unistd.h>
# endif /* HAVE_UNISTD_H */

# ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
# endif /* HAVE_SYS_SOCKET_H */

# ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
# endif /* HAVE_NETINET_IN_H */

# ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
# endif /* HAVE_ARPA_INET_H */

# ifdef HAVE_GETOPT_H
#  include <getopt.h>
# endif /* HAVE_GETOPT_H */

#endif /* WIN32 */

#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"
#include "pbc_version.h"

#if defined (WIN32)
extern int Debug_Trace = 0;
extern FILE *debugFile = NULL;
#endif

void usage (const char *progname)
{
    printf ("%s -c crypted_file [-k c_key_file] [-h]\n\n", progname);
    printf ("\t crypted_file:\tcrypted stuff to be decrypted.\n");
    printf ("\t c_key_file:\tdefault is %s/%s\n\n", PBC_PATH,
            get_my_hostname ());
    exit (1);
}

int main (int argc, char **argv)
{
    crypt_stuff *c1_stuff;
    unsigned char in[PBC_1K];
    unsigned char intermediate[PBC_1K];
    unsigned char out[PBC_1K];
    FILE *cfp;
    int c, barfarg = 0;
    char *key_file = NULL;
    char *crypted_file = NULL;
#if defined (WIN32)
    char SystemRoot[256];

    Debug_Trace = 1;
    debugFile = stdout;
#endif

    printf ("check_crypted_blob\n\n");

    bzero (in, 1024);
    bzero (out, 1024);
    bzero (intermediate, 1024);
    strcpy ((char *) in,
            "Maybe this plaintext is another world's ciphertext.");

    optarg = NULL;
    while (!barfarg && ((c = getopt (argc, argv, "hc:k:")) != -1)) {
        switch (c) {
        case 'h':
            usage (argv[0]);
            break;
        case 'c':
            if (crypted_file != NULL) {
                usage (argv[0]);
                break;
            }
            crypted_file = strdup (optarg);
            break;
        case 'k':
            key_file = strdup (optarg);
            break;
        default:
            if (crypted_file != NULL) {
                usage (argv[0]);
                break;
            }
            crypted_file = strdup (optarg);
            break;
        }
    }

#if defined(WIN32)
    {
        WSADATA wsaData;

        if (WSAStartup ((WORD) 0x0101, &wsaData)) {
            printf ("Unable to initialize WINSOCK: %d",
                    WSAGetLastError ());
            return -1;
        }
    }
#endif

    if (key_file)
        c1_stuff = libpbc_init_crypt (key_file);
    else {
        key_file = malloc (256);
#if defined(WIN32)
        GetEnvironmentVariable ("windir", SystemRoot, 256);
        sprintf (key_file, "%s%s/%s", SystemRoot, PBC_PATH,
                 get_my_hostname ());
#else
        sprintf (key_file, "%s/%s", PBC_PATH, get_my_hostname ());
#endif
        printf ("Using c_key file: %s\n\n", key_file);
        c1_stuff = libpbc_init_crypt (key_file);
    }

    if (c1_stuff == NULL) {
        printf ("unable to initialize encryption context\n");
        usage (argv[0]);
    }

    if (crypted_file != NULL) {
        if (!(cfp = pbc_fopen (crypted_file, "r"))) {
            libpbc_abend ("\n*** Cannot open the crypted file %s\n",
                          crypted_file);
            exit (1);
        }
        fread (intermediate, sizeof (char), PBC_1K, cfp);
    } else {
        printf ("Must specify a file with ciphertext\n\n");
        usage (argv[0]);
    }

    if (!libpbc_decrypt_cookie
        (intermediate, out, c1_stuff, strlen ((char *) in))) {
        printf ("\n*** Libpbc_decrypt_cookie failed\n");
        exit (1);
    }

    printf ("\nencrypted message is: %s\n", out);

    if (memcmp (in, out, sizeof (in)) != 0)
        printf ("\n*** cfb64 encrypt/decrypt error ***!\n");
    else
        printf ("\nYeah!  It worked\n\n");

#if defined(WIN32)
    WSACleanup ();
#endif

    exit (0);

}
