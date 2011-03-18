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

/** @file security.c
 * Support for security structure
 *
 * $Id: security.c,v 1.16 2008-05-16 22:09:10 willey Exp $
 */


typedef void pool;

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#include "security.h"


void printme (pool * p, char *desc, char *str, int sz)
{
    int s;

    printf ("got %s, size %d:\n", desc, sz);
    for (s = 0; s < sz; s++) {
        if (isprint (str[s]))
            putchar (str[s]);
        else
            putchar ('.');
    }
    putchar ('\n');
}

int main (int argc, char *argv[])
{
    int outlen, out2len;
    char *outbuf, *out2buf;
    char *in;
    int inlen;
    security_context *sectext;
    pool *p = NULL;

    if (argc != 2) {
        fprintf (stderr, "%s <string>\n", argv[0]);
        exit (1);
    }

    libpbc_config_init (p, NULL, "security");

    printf ("initializing...\n");
    if (security_init (p, &sectext)) {
        printf ("failed\n");
        exit (1);
    }
    printf ("ok\n");

    in = argv[1];
    inlen = strlen (in);
    printf ("signing '%s'...\n", in);
    if (libpbc_mk_safe (p, sectext, NULL, 0, in, inlen, &outbuf, &outlen)) {
        printf ("libpbc_mk_safe() failed\n");
        exit (1);
    }
    printme (p, "sig", outbuf, outlen);

    printf ("verifying sig...");
    if (libpbc_rd_safe (p, sectext, NULL, 0, in, inlen, outbuf, outlen)) {
        printf ("libpbc_rd_safe() failed\n");
        exit (1);
    }
    printf ("ok\n");


    printf ("DES encrypting '%s'...\n", in);
    if (libpbc_mk_priv_des (p, sectext, NULL, 0, in, inlen, &outbuf, &outlen)) {
        printf ("libpbc_mk_priv() failed\n");
        exit (1);
    }
    printme (p, "blob", outbuf, outlen);

    printf ("DES decrypting blob...\n");
    if (libpbc_rd_priv_des
        (p, sectext, NULL, 0, outbuf, outlen, &out2buf, &out2len)) {
        printf ("libpbc_rd_priv() failed\n");
        exit (1);
    }
    printme (p, "plaintext", out2buf, out2len);
    if (inlen != out2len || strncmp (in, out2buf, inlen)) {
        printf ("encryption/decryption FAILED (%s %s)\n", in, out2buf);
        exit (1);
    }


    printf ("AES encrypting '%s'...\n", in);
    if (libpbc_mk_priv_aes (p, sectext, NULL, 0, in, inlen, &outbuf, &outlen)) {
        printf ("libpbc_mk_priv() failed\n");
        exit (1);
    }
    printme (p, "blob", outbuf, outlen);

    printf ("AES decrypting blob...\n");
    if (libpbc_rd_priv_aes
        (p, sectext, NULL, 0, outbuf, outlen, &out2buf, &out2len)) {
        printf ("libpbc_rd_priv() failed\n");
        exit (1);
    }
    printme (p, "plaintext", out2buf, out2len);
    if (inlen != out2len || strncmp (in, out2buf, inlen)) {
        printf ("encryption/decryption FAILED (%s %s)\n", in, out2buf);
        exit (1);
    }
}
