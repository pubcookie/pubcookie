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

/** @file strlcpy.c
 * strlcpy()
 *
 * $Id: strlcpy.c,v 2.15 2008/05/16 22:09:10 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
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

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

#ifndef HAVE_STRLCPY
/* strlcpy -- copy string smartly.
 *
 * i believe/hope this is compatible with the BSD strlcpy(). 
 */
size_t strlcpy (char *dst, const char *src, size_t len)
{
    size_t n;

    /* Avoid problems if size_t is unsigned */
    if (len <= 0)
        return strlen (src);

    for (n = 0; n < len - 1; n++) {
        if ((dst[n] = src[n]) == '\0')
            break;
    }
    if (n >= len-1) {
        /* ran out of space */
        dst[n] = '\0';
        while (src[n])
            n++;
    }
    return n;
}
#endif

#ifndef HAVE_STRLCAT
size_t strlcat (char *dst, const char *src, size_t len)
{
    size_t i, j, o;

    o = strlen (dst);
    if (len < o + 1)
        return o + strlen (src);
    len -= o + 1;
    for (i = 0, j = o; i < len; i++, j++) {
        if ((dst[j] = src[i]) == '\0')
            break;
    }
    dst[j] = '\0';
    if (src[i] == '\0') {
        return j;
    } else {
        return j + strlen (src + i);
    }
}
#endif
