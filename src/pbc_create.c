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

/** @file pbc_create.c
 * Manually create pubcookies
 *
 * arguments come in via standard in and the cookie is put out on stdout
 *
 * args are: user appsrvid appid type creds pre_sess_token
 *             crypt_file cert_key_file
 *    anything too big is just truncated, no support for defaults or anything
 *
 * $Id: pbc_create.c,v 1.26 2008/05/16 22:09:10 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#include "pbc_time.h"

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
#else
# include <pem.h>
#endif /* OPENSSL_IN_DIR */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_config.h"

int main (int argc, char **argv)
{
    md_context_plus *ctx_plus;
    crypt_stuff *c_stuff;

    unsigned char user[PBC_USER_LEN];
    unsigned char appsrvid[PBC_APPSRV_ID_LEN];
    unsigned char appid[PBC_APP_ID_LEN];
    unsigned char type;
    unsigned char creds;
    int pre_sess_token;

    unsigned char crypt_keyfile[PBC_1K];
    unsigned char cert_keyfile[PBC_1K];

    unsigned char user_buf[PBC_1K];
    unsigned char appsrvid_buf[PBC_1K];
    unsigned char appid_buf[PBC_1K];

    unsigned char *cookie;

    if (fscanf (stdin, "%1023s%1023s%1023s %c %c %d %1023s%1023s\n",
                user_buf,
                appsrvid_buf,
                appid_buf,
                &type,
                &creds,
                &pre_sess_token, crypt_keyfile, cert_keyfile) != 8) {
        exit (1);
    }

    /* move the arguments out of buffers and right size them */
    strncpy ((char *) user, (const char *) user_buf, sizeof (user));
    user[sizeof (user) - 1] = '\0';
    strncpy ((char *) appsrvid, (const char *) appsrvid_buf,
             sizeof (appsrvid));
    appsrvid[sizeof (appsrvid) - 1] = '\0';
    strncpy ((char *) appid, (const char *) appid_buf, sizeof (appid));
    appsrvid[sizeof (appid) - 1] = '\0';

    crypt_keyfile[sizeof (crypt_keyfile) - 1] = '\0';
    cert_keyfile[sizeof (cert_keyfile) - 1] = '\0';

    /* read in and initialize crypt and signing structures */
    c_stuff = libpbc_init_crypt ((char *) crypt_keyfile);
    ctx_plus = libpbc_sign_init ((char *) cert_keyfile);

    /* go get the cookie */
    cookie =
        libpbc_get_cookie (user, type, creds, pre_sess_token, appsrvid,
                           appid, ctx_plus, c_stuff);

    printf ("%s", cookie);

    exit (0);

}
