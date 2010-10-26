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

/** @file verify_alwaystrue.c
 * Alwaystrue verifier
 *
 * $Id: verify_alwaystrue.c,v 1.19 2008/05/16 22:09:10 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

/* Pretending we're Apache */
typedef void pool;

#include "verify.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

extern int debug;

int alwaystrue_v (pool * p, const char *userid,
                  const char *passwd,
                  const char *service,
                  const char *user_realm,
                  struct credentials **creds, const char **errstr)
{

    if (debug) {
        fprintf (stderr, "alwaystrue_verifier: hello\n");
        fprintf (stderr, "userid: %s\n",
                 userid == NULL ? "(null)" : userid);
        fprintf (stderr, "passwd: %s\n",
                 passwd == NULL ? "(null)" : passwd);
        fprintf (stderr, "service: %s\n",
                 service == NULL ? "(null)" : service);
        fprintf (stderr, "user_realm: %s\n",
                 user_realm == NULL ? "(null)" : user_realm);
    }

    if (errstr)
        *errstr = NULL;
    if (creds)
        *creds = NULL;

    return 0;
}

verifier alwaystrue_verifier = { "alwaystrue",
    &alwaystrue_v, NULL, NULL
};
