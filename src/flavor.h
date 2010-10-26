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

/** @file flavor.h
 * flavor definitions
 *
 * a flavor specifies:
 * - the policy of when freerides are allowed
 * - what the layout of the login page is, how login messages are printed. 
 *
 * $Id: flavor.h,v 1.17 2008/05/16 22:09:10 willey Exp $
 */

#ifndef INCLUDED_FLAVOR_H
#define INCLUDED_FLAVOR_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "index.cgi.h"

typedef enum
{
    LOGIN_OK = 0,               /* proceed with request */
    LOGIN_ERR = 1,              /* request not allowed */
    LOGIN_INPROGRESS = 2        /* return to login page */
}
login_result;

/** flavor definition
	a flavor defines
	- the policy of when freerides are allowed
        - what the layout of the login page is, how login messages are printed.
  */
struct login_flavor
{
    /* a user readable flavor name */
    const char *name;

    /* the unique byte representing this flavor.
       all values < 0x80 are reserved for the pubcookie distribution;
       all values >= 0x80 are available for local use. */
    const char id;

    /* initialize this flavor; if non-zero return, this flavor is not
       available */
    int (*init_flavor) (void);

    /* given a login request 'l' and a (possibly NULL) login cookie 'c',
       process the request.  if there are insufficient credentials,
       print out a login form and return accordingly. */
      login_result (*process_request) (pool * p,
                                       const security_context * context,
                                       login_rec * l, login_rec * c,
                                       const char **errstr);
};

/**
 * given a flavor id, return the corresponding login_flavor
 * @param pool Apache memory pool or void
 * @param id the unique byte representing the flavor 
 * @returns the struct login_flavor if supported, NULL otherwise */
struct login_flavor *get_flavor (pool * p, const char id);

#endif /* INCLUDED_FLAVOR_H */
