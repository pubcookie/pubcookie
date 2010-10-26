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

/** @file pbc_time.c
 * Configure stuff
 *
 * $Id: pbc_time.c,v 2.4 2008/05/16 22:09:10 willey Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif /* HAVE_SYS_TIME_H */

#ifdef HAVE_TIME_H
# include <time.h>
#endif /* HAVE_TIME_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#include "pbc_time.h"

pbc_time_t pbc_time( pbc_time_t *tloc ) {
    pbc_time_t pbc_time;
    time_t not_pbc_time;

    not_pbc_time = time (NULL);

    /* Make sure that we don't overflow... */

    memcpy( &pbc_time, &not_pbc_time, sizeof pbc_time );

    if ( tloc != NULL )
        *tloc = pbc_time;

    return pbc_time;
}
