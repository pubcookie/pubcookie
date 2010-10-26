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

/** @file pbc_verify.c
 * Manually verify cookies
 *
 * args are:
 *   granting_or_no 
 *
 * granting or no is 1 for granting or 0 for no
 *
 * cookie comes in on stdin, contenets are printed to stdout
 *
 * key and cert locations all come from pubcookie config
 *
 * $Id: pbc_verify.c,v 1.28 2008/05/16 22:09:10 willey Exp $
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

/* An apache "pool" */
typedef void pool;

#include "pbc_config.h"
#include "pubcookie.h"
#include "libpubcookie.h"
#include "pbc_configure.h"
#include "pbc_version.h"
#include "pbc_logging.h"


int main (int argc, char **argv)
{
    pbc_cookie_data *cookie_data;
    char in[PBC_4K];
    char *s;
    void *p = NULL;
    security_context *context = NULL;
    int use_granting = 0;

    fgets (in, sizeof (in), stdin);

    /* clean some junk off the end of message */
    s = in;
    while (*s) {
        if (*s == '\r' || *s == '\n') {
            *s = '\0';
            break;
        }
        s++;
    }

    use_granting = argv[1][0];

    libpbc_config_init (p, NULL, "pbc_verify");
    pbc_log_init_syslog (p, "pbc_verifyr");
    libpbc_pubcookie_init (p, &context);

    if (!
        (cookie_data =
         libpbc_unbundle_cookie (p, context, in, NULL, use_granting, PBC_DEF_CRYPT)))
        exit (1);

    printf ("user: %s\n", (*cookie_data).broken.user);
    printf ("version: %s\n", (*cookie_data).broken.version);
    printf ("type: %c\n", (*cookie_data).broken.type);
    printf ("creds: %c\n", (*cookie_data).broken.creds);
    printf ("pre_sess_token: %d\n", (*cookie_data).broken.pre_sess_token);
    printf ("appsrvid: %s\n", (*cookie_data).broken.appsrvid);
    printf ("appid: %s\n", (*cookie_data).broken.appid);
    printf ("create_ts: %d\n", (int) (*cookie_data).broken.create_ts);
    printf ("last_ts: %d\n", (int) (*cookie_data).broken.last_ts);

    exit (0);

}
