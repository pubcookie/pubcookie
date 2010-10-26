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

/** @file pbc_apacheconfig.c
 * Apacheconfig
 *
 * $Id: pbc_apacheconfig.c,v 2.21 2008/05/16 22:09:10 willey Exp $
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


#if defined (APACHE1_3) || defined (APACHE2)
# include "httpd.h"
# include "http_config.h"
# include "http_core.h"
# include "http_log.h"
# include "http_main.h"
# include "http_protocol.h"
# include "util_script.h"
#else
typedef void pool;
#endif

#ifdef APACHE2

#include "apr_strings.h"
typedef apr_pool_t pool;
typedef apr_table_t table;
#define ap_table_get apr_table_get

#define PC_LOG_DEBUG  APLOG_MARK,APLOG_DEBUG,0
#define PC_LOG_NOTICE APLOG_MARK,APLOG_NOTICE,0
#define PC_LOG_INFO   APLOG_MARK,APLOG_INFO,0
#define PC_LOG_WARn   APLOG_MARK,APLOG_INFO,0
#define PC_LOG_ERR    APLOG_MARK,APLOG_ERR,0
#define PC_LOG_EMERG  APLOG_MARK,APLOG_EMERG,0
#define PC_LOG_CRIT   APLOG_MARK,APLOG_CRIT,0

#else

#define PC_LOG_DEBUG  APLOG_MARK,APLOG_DEBUG|APLOG_NOERRNO
#define PC_LOG_INFO   APLOG_MARK,APLOG_INFO|APLOG_NOERRNO
#define PC_LOG_NOTICE APLOG_MARK,APLOG_NOTICE|APLOG_NOERRNO
#define PC_LOG_WARN   APLOG_MARK,APLOG_NOTICE|APLOG_NOERRNO
#define PC_LOG_ERR    APLOG_MARK,APLOG_ERR
#define PC_LOG_EMERG  APLOG_MARK,APLOG_EMERG|APLOG_NOERRNO
#define PC_LOG_CRIT   APLOG_MARK,APLOG_CRIT|APLOG_NOERRNO

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

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif /* HAVE_CTYPE_H */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif /* HAVE_SYS_STAT_H */

#ifdef HAVE_SYSEXITS_H
# include <sysexits.h>
#endif /* HAVE_SYSEXITS_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif /* HAVE_ERRNO_H */

#include "pbc_config.h"
#include "pbc_myconfig.h"
#include "snprintf.h"
#include "pubcookie.h"
#include "libpubcookie.h"
#include "mod_pubcookie.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

const char *libpbc_apacheconfig_getstring (pool * p, const char *key,
                                           const char *def)
{
    server_rec *sr;
    request_rec *rr;
    pubcookie_server_rec *scfg;
    table *configlist;
    const char *ret;

    /* If the pool is from config then it has the server record.
       If the pool is from the request, then it has the request record. */

    if (!(sr = find_server_from_pool (p))) {
        rr = find_request_from_pool (p);
        if (!rr) {
            return (def);
        }
        sr = rr->server;
    }

    scfg =
        (pubcookie_server_rec *) ap_get_module_config (sr->module_config,
                                                       &pubcookie_module);
    configlist = scfg->configlist;

    if (key == NULL)
        return def;

    ret = ap_table_get (configlist, key);

    if (ret) {
        ap_log_error (PC_LOG_DEBUG, sr, "found %s with value %s", key,
                      ret);
        return ret;
    }
    ap_log_error (PC_LOG_DEBUG, sr,
                  "failed to find %s, returning default %s", key, def);
    return def;
}

int libpbc_apacheconfig_getint (pool * p, const char *key, int def)
{
    const char *val = libpbc_myconfig_getstring (p, key, (char *) 0);

    if (!val)
        return def;
    if (!isdigit ((int) *val) && (*val != '-' || !isdigit ((int) val[1])))
        return def;
    return atoi (val);
}


/*
 * the rest of the functions need to be re-implemented in the apache scheme
 * i didn't bother because they're not used (yet)
 *
 */

/* see the myconfig equivalents for reference */

char **libpbc_apacheconfig_getlist (pool * p, const char *key)
{
    ap_log_error (PC_LOG_CRIT, NULL,
                  "libpbc_apacheconfig_getlist not implmented, was looking for %s",
                  key);
    return NULL;
}

int libpbc_apacheconfig_getswitch (pool * p, const char *key, int def)
{
    ap_log_error (PC_LOG_CRIT, NULL,
                  "libpbc_apacheconfig_getswitch not implmented, was looking for %s",
                  key);
    return def;
}
