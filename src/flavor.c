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

/** @file flavor.c
 * Flavor generic code
 *
 * $Id: flavor.c,v 1.20 2008/05/16 22:09:10 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

typedef void pool;

#include "flavor.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

extern struct login_flavor login_flavor_basic;
extern struct login_flavor login_flavor_getcred;
#ifdef ENABLE_UWSECURID
extern struct login_flavor login_flavor_uwsecurid;
#endif

/**
 */
static struct login_flavor *flavors[] = {
    &login_flavor_basic,
    &login_flavor_getcred,
#ifdef ENABLE_UWSECURID
    &login_flavor_uwsecurid,
#endif
    NULL
};                              /*! list of available flavors */

struct login_flavor *get_flavor (pool * p, const char id)
{
    struct login_flavor **f = flavors;

    while (*f) {
        if ((*f)->id == id)
            break;
        f++;
    }

    return (*f);
}
