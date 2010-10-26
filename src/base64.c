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

/** @file base64.c
 * Base64 functions
 *
 * $Id: base64.c,v 1.27 2008/05/16 22:09:10 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef APACHE2
#undef HAVE_CONFIG_H
#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION
#endif

#if defined (APACHE)
#  include "httpd.h"
#  include "http_config.h"
#  include "http_core.h"
#  include "http_log.h"
#  include "http_main.h"
#  include "http_protocol.h"
#  include "util_script.h"
#  ifdef APACHE2
typedef apr_pool_t pool;
typedef apr_table_t table;
#  endif

# else
typedef void pool;
#endif

#ifdef WIN32
# include <Windows.h>
# include <httpfilt.h>
# include "pbc_config.h"
# include "pubcookie.h"
# include "Win32/PubCookieFilter.h"
#endif

#ifdef HAVE_STRING_H
# include <string.h>            /* for win32 */
#endif /* HAVE_STRING_H */

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */


/* BASE64 encoding stuff. */

#define NL 99                   /* invalid character */
#define EQ 98                   /* equal sign has special meaning. */

static unsigned char encode[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
    'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
    'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
    'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', '+', '/'
};

static unsigned char decode[256] = {
    NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
    NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
    NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
    NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
    NL, NL, NL, 62, NL, NL, NL, 63, 52, 53,
    54, 55, 56, 57, 58, 59, 60, 61, NL, NL,
    NL, EQ, NL, NL, NL, 0, 1, 2, 3, 4,
    5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
    25, NL, NL, NL, NL, NL, NL, 26, 27, 28,
    29, 30, 31, 32, 33, 34, 35, 36, 37, 38,
    39, 40, 41, 42, 43, 44, 45, 46, 47, 48,
    49, 50, 51, NL, NL, NL, NL, NL, NL, NL,
    NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
    NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
    NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
    NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
    NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
    NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
    NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
    NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
    NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
    NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
    NL, NL, NL, NL, NL, NL, NL, NL, NL, NL,
    NL, NL, NL, NL, NL, NL
};

int libpbc_base64_encode (pool * p, unsigned char *in, unsigned char *out,
                          int size)
{
    unsigned int a, b, c;

    while (size > 0) {
        a = (unsigned int) *in++;
        size--;
        if (size > 0) {
            b = (unsigned int) *in++;
            size--;
            if (size > 0) {
                c = (unsigned int) *in++;
                size--;
                *out++ = encode[(a >> 2)];
                *out++ = encode[((a & 3) << 4) + (b >> 4)];
                *out++ = encode[((b & 15) << 2) + (c >> 6)];
                *out++ = encode[((c & 63))];
            } else {
                *out++ = encode[(a >> 2)];
                *out++ = encode[((a & 3) << 4) + (b >> 4)];
                *out++ = encode[((b & 15) << 2)];
                *out++ = '=';
            }
        } else {
            *out++ = encode[(a >> 2)];
            *out++ = encode[((a & 3) << 4)];
            *out++ = '=';
            *out++ = '=';
        }
    }
    *out = 0;
    return 1;
}

int libpbc_base64_decode (pool * p, unsigned char *in, unsigned char *out,
                          int *osizep)
{
    unsigned int a, b, c, d;
    int size = strlen ((const char *) in);
    int correct = 0;
    int osize = 0;

    while (size > 0) {
        if (*in != 0) {
            a = decode[(unsigned int) *in++];
            if (a == EQ)
                return 0;
            size--;
            if (*in != 0) {
                b = decode[(unsigned int) *in++];
                if (b == EQ)
                    return 0;
                size--;
                if (*in != 0) {
                    c = decode[(unsigned int) *in++];
                    if (c == EQ)
                        correct++;
                    size--;
                    if (*in != 0) {
                        d = decode[(unsigned int) *in++];
                        if (d == EQ)
                            correct++;
                        size--;
                        if ((a == NL) || (b == NL) || (c == NL)
                            || (d == NL))
                            return 0;
                        *out++ = (a << 2) + (b >> 4);
                        *out++ = ((b & 15) << 4) + (c >> 2);
                        *out++ = ((c & 3) << 6) + d;
                        osize += 3;
                    } else
                        return 0;
                } else
                    return 0;
            } else
                return 0;
        } else
            return 0;
    }
    *(out - correct) = 0;
    osize -= correct;
    if (osizep)
        *osizep = osize;
    return 1;
}

#ifdef TEST_BASE64

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */


int main (int argc, char *argv[])
{
    int decode = 0;
    int arg = 1;
    int outlen = 0;
    int ret;
    char *outbuf;
    char *outbuf2;
    char *inbuf;
    int inlen = BUFSIZ;
    int tot = 0;
    int compare = 0;
    int verbose = 0;
    void *p;
    char *ptr;

    if (argc > 1) {
        if (strcmp (argv[arg], "-d") == 0) {
            decode = 1;
            arg++;
        }

        if (arg < argc && (strcmp (argv[arg], "-h") == 0)) {
            printf ("Usage: %s [-d] [text]\n", argv[0]);
            printf ("       -d   - Decode base64 text.\n");
            printf ("       -v   - Enable verbose output.\n");
            printf ("       -vv  - More verbose output (show base64.)\n");
            printf
                ("       -vvv - Even more verbose output (show unencoded.)\n");
            printf ("       text - Text to be encoded or decoded.\n");
            printf
                ("            If no text is specified, reads from STDIN.\n");
            exit (0);
            arg++;
        }

        if (arg < argc && (strcmp (argv[arg], "-vvv") == 0)) {
            verbose = 3;
            arg++;
        }

        if (arg < argc && (strcmp (argv[arg], "-vv") == 0)) {
            verbose = 2;
            arg++;
        }

        if (arg < argc && (strcmp (argv[arg], "-v") == 0)) {
            verbose = 1;
            arg++;
        }
    }

    if (arg == (argc - 1)) {
        inbuf = argv[arg];
        tot = strlen (inbuf);
    } else {
        int num = 0;
        inbuf = (char *) calloc (inlen, sizeof (char));

        while ((num = read (0, inbuf + tot, BUFSIZ)) > 0) {
            tot += num;
            inlen += BUFSIZ;
            inbuf = (char *) realloc (inbuf, inlen);
        }

        ptr = inbuf + strlen (inbuf);
        while (ptr > inbuf) {
            if (*ptr == '\n' || *ptr == '\r')
                *ptr = '\0';
            ptr--;
        }

    }

    if (!decode) {
        if (verbose > 2) {
            printf ("Encoding \"%s\"\n", inbuf);
        }

        outbuf = (char *) malloc (2 * tot);
        ret = libpbc_base64_encode (p, (unsigned char *) inbuf,
                                    (unsigned char *) outbuf, tot);
        outlen = strlen (outbuf);

        if (ret) {
            if (verbose) {
                printf ("unencoded length: %d\n", tot);
                printf ("encoded length: %d\n", outlen);
                if (verbose > 1) {
                    printf ("encoded text: %s\n", outbuf);
                }
            }
        } else {
            printf ("Error encoding.\n");
            exit (1);
        }

        if (verbose) {
            printf ("\n");
        }
        compare = 1;
    } else {
        outbuf = inbuf;
    }

    if (verbose > 1) {
        printf ("Decoding \"%s\"\n", outbuf);
    }

    outbuf2 = (char *) malloc (tot);
    ret = libpbc_base64_decode (p, (unsigned char *) outbuf,
                                (unsigned char *) outbuf2, &outlen);

    if (ret) {
        if (verbose) {
            printf ("encoded length: %d\n", strlen (outbuf));
            printf ("unencoded length: %d\n", outlen);
            if (verbose > 2) {
                printf ("decoded: %s\n", outbuf2);
            }
        }
    } else {
        printf ("Error decoding.\n");
        exit (1);
    }

    if (compare) {
        if (verbose) {
            printf ("\n");
        }
        if (strcmp (inbuf, outbuf2) == 0) {
            printf ("Base64 encoding and decoding sucessfull.\n");
        } else {
            printf ("Error in base64 encode and decode.\n");
            exit (1);
        }
    }

    return 0;
}

#endif
