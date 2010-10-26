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

/** @file pbc_myconfig.c
 * Runtime configuration 
 *
 * $Id: pbc_myconfig.c,v 1.50 2008/05/16 22:09:10 willey Exp $
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

#if defined (APACHE2)
#define pbc_malloc(p, x) apr_palloc(p, x)
#define pbc_strdup(p, x) apr_pstrdup(p, x)
#endif

#if defined (APACHE)
#  include "httpd.h"
#  include "http_config.h"
#  include "http_core.h"
#  include "http_log.h"
#  include "http_main.h"
#  include "http_protocol.h"
#  include "util_script.h"
# else
typedef void pool;
#endif /* APACHE */

#ifdef APACHE2
typedef apr_pool_t pool;
typedef apr_table_t table;
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
#else
# define EX_OSERR 71
#endif /* HAVE_SYSEXITS_H */

#ifndef WIN32                   /* See below for WIN32 code */

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
#include "pbc_configure.h"
#include "pbc_logging.h"

#ifdef APACHE2
#include "apr_strings.h"
#endif

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

struct configlist
{
    char *key;
    char *value;
};

#define REQUIRED 1
#define NOT_REQUIRED 0

static struct configlist *configlist;
static int nconfiglist;

static void myconfig_read (pool * p, const char *alt_config, int required);

static void fatal (pool * p, const char *s, int ex);

int libpbc_myconfig_init (pool * p, const char *alt_config,
                          const char *ident)
{
    const char *val;
    int umaskval = 0;
    char *sub_config, *ptr, *ptr2;
    int len;

    myconfig_read (p, alt_config, REQUIRED);

    /* get the sub config file for the pubcookie sub-system */
    if (ident != NULL) {
        /* +1 for oes and +1 for extra '/' */
        len =
            strlen (PBC_PATH) + strlen (ident) + strlen (PBC_SUBCONFIG) +
            1 + 1;
        sub_config = pbc_malloc (p, sizeof (char *) * len);
        bzero (sub_config, len);
        snprintf (sub_config, len, "%s/%s%s", PBC_PATH, ident,
                  PBC_SUBCONFIG);

        /* remove that extra slash */
        ptr = ptr2 = sub_config;
        while (*ptr2) {
            if (ptr2 != sub_config && *ptr2 == '/' && *(ptr2 - 1) == '/')
                ptr2++;
            else
                *ptr++ = *ptr2++;
        }
        *ptr = '\0';

        myconfig_read (p, sub_config, NOT_REQUIRED);
        free (sub_config);
    }

    /* Look up umask */
    val = libpbc_myconfig_getstring (p, "umask", "022");
    while (*val) {
        if (*val >= '0' && *val <= '7')
            umaskval = umaskval * 8 + *val - '0';
        val++;
    }
    umask (umaskval);

    /* paranoia checks */

    /* check that our login host is in our enterprise domain */
    if (!strstr (PBC_LOGIN_HOST, PBC_ENTRPRS_DOMAIN)) {

    }

    /* xxx check that our login URI points to our login host */

    /* xxx check that keydir exists */

    /* xxx check that we can read our symmetric key */

    /* xxx check that the granting certificate (public key) is readable */

    return 0;
}

const char *libpbc_myconfig_getstring (pool * p, const char *key,
                                       const char *def)
{
    int opt;

    if (key == NULL)
        return def;

    for (opt = 0; opt < nconfiglist; opt++) {
        if (configlist[opt].key == NULL) {
            libpbc_abend (p,
                          "Option key suddenly became NULL!  Somebody fudged a pointer!");
        }
        if (*key == configlist[opt].key[0] &&
            !strcasecmp (key, configlist[opt].key))
            return configlist[opt].value;
    }
    return def;
}

/* output must be free'd.  (no subpointers should be free'd.) */
char **libpbc_myconfig_getlist (pool * p, const char *key)
{
    const char *tval = libpbc_myconfig_getstring (p, key, NULL);
    char *val;
    char **ret;
    char *ptr;
    int c;

    if (tval == NULL) {
        return NULL;
    }

    c = 1;                      /* initial string */
    for (ptr = strchr (tval, ' '); ptr != NULL;
         ptr = strchr (ptr + 1, ' ')) {
        c++;
    }

    /* we malloc a buffer long enough for the subpointers followed by
       the string that we modify by adding \0 */
    ret = pbc_malloc (p, sizeof (char *) * (c + 2) + strlen (tval) + 1);
    if (!ret) {
        fatal (p, "out of memory", EX_OSERR);
    }

    /* copy the string to the end of the buffer.
       assumes sizeof(char) = 1 */
    val = ((char *) ret) + (sizeof (char *) * (c + 2));

    strcpy (val, tval);
    c = 0;
    ret[c++] = val;
    for (ptr = strchr (val, ' '); ptr != NULL; ptr = strchr (ptr, ' ')) {
        *ptr++ = '\0';
        if (*ptr == ' ')
            continue;
        ret[c++] = ptr;
    }
    ret[c] = NULL;

    return ret;
}

/* int=dddS, dddM, dddH */
int libpbc_myconfig_str2int (const char *val, int def)
{
    int v = 0;
    int m = 1;
    int n = 1;

    if (!val)
        return (def);
    if (*val == '-')
        val++, n = (-1);

    for (; *val; val++) {
        if (isdigit (*val))
            v = v * 10 + *val - '0';
        else if (m > 1)
            return (def);       /* Not a valid time spec */
        else if (*val == 'S' || *val == 's')
            m = 1;
        else if (*val == 'M' || *val == 'm')
            m = 60;
        else if (*val == 'H' || *val == 'h')
            m = 3600;
        else
            return (def);
    }
    return (v * n * m);
}

int libpbc_myconfig_getint (pool * p, const char *key, int def)
{
    const char *val = libpbc_myconfig_getstring (p, key, (char *) 0);

    return (libpbc_myconfig_str2int (val, def));
}

int libpbc_myconfig_getswitch (pool * p, const char *key, int def)
{
    const char *val = libpbc_myconfig_getstring (p, key, (char *) 0);

    if (!val)
        return def;

    if (*val == '0' || *val == 'n' ||
        (*val == 'o' && val[1] == 'f') || *val == 'f') {
        return 0;
    } else if (*val == '1' || *val == 'y' ||
               (*val == 'o' && val[1] == 'n') || *val == 't') {
        return 1;
    }

    return def;
}

#define CONFIGLISTGROWSIZE 30   /* 100 */
static void myconfig_read (pool * p, const char *alt_config, int required)
{
    FILE *infile;
    const char *filename;
    int lineno = 0;
    int plineno = 0;
    int alloced = 0;
    char buf[8192];
    char *ptr, *key;
    char *bp = buf;

    filename = alt_config ? alt_config : PBC_CONFIG;
    infile = pbc_fopen (p, filename, "r");
    if (!infile) {
        if (required == NOT_REQUIRED) {
            return;
        }
        snprintf (buf, sizeof (buf),
                  "can't open configuration file %s: %s", filename,
                  strerror (errno));
        fatal (p, buf, EX_CONFIG);
    }

    while (fgets (bp, sizeof (buf) + buf - bp, infile)) {
        lineno++;
        if (bp != buf)
            plineno++;
        /* remove trailing and leading spaces */
        for (ptr = bp + strlen (bp) - 1;
             ptr >= bp && (*ptr == '\n' || isspace (*ptr)); *ptr-- = '\0');
        for (ptr = bp; *ptr && isspace (*ptr); ptr++);
        if (!*ptr || *ptr == '#')
            continue;
        if (ptr > bp)
            memmove (bp, ptr, strlen (ptr) + 1);
        if (bp[strlen (bp) - 1] == '\\') {
            bp += strlen (bp) - 1;
            *bp = '\0';
            continue;
        }

        /* OK, got a complete line */
        ptr = buf;
        key = ptr;
        while (*ptr
               && (isalnum ((int) *ptr) || *ptr == '-' || *ptr == '_'
                   || *ptr == '.')) {
            if (isupper ((unsigned char) *ptr))
                *ptr = tolower ((unsigned char) *ptr);
            ptr++;
        }
        if (*ptr != ':') {
            snprintf (buf, sizeof (buf),
                      "invalid option name on line %d of configuration file %s",
                      plineno, filename);
            fatal (p, buf, EX_CONFIG);
        }
        *ptr++ = '\0';

        while (*ptr && isspace ((int) *ptr))
            ptr++;

        if (!*ptr) {
            snprintf (buf, sizeof (buf),
                      "empty option value on line %d of configuration file %s",
                      lineno, filename);
            fatal (p, buf, EX_CONFIG);
        }

        if (nconfiglist == alloced) {
            alloced += CONFIGLISTGROWSIZE;

            if (configlist == NULL) {
                configlist = (struct configlist *)
                    pbc_malloc (p, alloced * sizeof (struct configlist));
            } else {
                configlist = (struct configlist *)
                    realloc ((char *) configlist,
                             alloced * sizeof (struct configlist));
            }
            if (!configlist) {
                fatal (p, "out of memory", EX_OSERR);
            }
        }

        configlist[nconfiglist].key = pbc_strdup (p, key);
        if (!configlist[nconfiglist].key) {
            fatal (p, "out of memory", EX_OSERR);
        }
        configlist[nconfiglist].value = pbc_strdup (p, ptr);
        if (!configlist[nconfiglist].value) {
            fatal (p, "out of memory", EX_OSERR);
        }
        nconfiglist++;

        bp = buf;
        plineno = lineno;
    }
    pbc_fclose (p, infile);
}

static void fatal (pool * p, const char *s, int ex)
{
    fprintf (stderr, "fatal error: %s\n", s);
    exit (ex);
}

#ifdef TEST_MYCONFIG
/* a short test program for pbc_myconfig */

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */


int errno;

int main (int argc, char *argv[])
{
    char **v;
    int c;
    pool *p = NULL;

    libpbc_myconfig_init (p, (argc > 1) ? argv[1] : "myconf", NULL);

    v = libpbc_myconfig_getlist (p, "foo");
    if (v) {
        c = 0;
        while (v[c]) {
            printf ("'%s'\n", v[c]);
            c++;
        }
        printf ("c = %d\n", c);
    } else {
        printf ("NULL\n");
        exit (1);
    }

    return 0;
}
#endif

#else /*WIN32 */

#include <windows.h>
#include <time.h>
#include <httpfilt.h>
#include <tchar.h>
#include <strsafe.h>

#include "pubcookie.h"
#include "pbc_config.h"
#include "Win32/PubCookieFilter.h"

#include "Win32/debug.h"
#include "pbc_configure.h"
#include "snprintf.h"
#include "libpubcookie.h"
#include "pbc_logging.h"


static void fatal (pubcookie_dir_rec * p, const LPTSTR s, int ex)
{
    syslog (LOG_ERR, "fatal error: %s\n", s);
    exit (ex);
}


LPTSTR libpbc_myconfig_copystring (LPTSTR outputstring,
                                   LPCTSTR inputstring, int size)
{
    if (inputstring != NULL) {
        StringCchCopy (outputstring, size, inputstring);
        return outputstring;
    } else {
        return NULL;
    }
}

/* This will return either p->strbuff or NULL.  p->strbuff will contain 
   the found value or def, unless def is NULL. */
LPTSTR get_reg_value (pubcookie_dir_rec * p, LPCTSTR key, LPDWORD size,
                      LPCTSTR def)
{

    char keyBuff[PBC_1K];
    LPTSTR value;
    HKEY hKey;

    /* first look in web instance key */
    if (strlen (p->instance_id)) {
        StringCchCopy (keyBuff, PBC_1K, PBC_FILTER_KEY);
        StringCchCat (keyBuff, PBC_1K, "\\");
        StringCchCat (keyBuff, PBC_1K, PBC_INSTANCE_KEY);
        StringCchCat (keyBuff, PBC_1K, "\\");
        StringCchCat (keyBuff, PBC_1K, p->instance_id);
        if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, keyBuff, 0, KEY_READ, &hKey)
            == ERROR_SUCCESS) {
            if (RegQueryValueEx
                (hKey, key, NULL, NULL, (LPBYTE) p->strbuff,
                 size) == ERROR_SUCCESS) {
                /* if we find the value here, we're done */
                RegCloseKey (hKey);
                return p->strbuff;
            }
            RegCloseKey (hKey);
        }
    }

    /* then look for config. settings in main pubcookie service key */
    StringCchCopy (keyBuff, PBC_1K, PBC_FILTER_KEY);

    if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, keyBuff, 0, KEY_READ, &hKey) ==
        ERROR_SUCCESS) {
        if (RegQueryValueEx
            (hKey, key, NULL, NULL, (LPBYTE) p->strbuff,
             size) == ERROR_SUCCESS) {
            /* if we find the value here, we're done */
            RegCloseKey (hKey);
            return p->strbuff;
        } else {
            RegCloseKey (hKey);
            value =
                libpbc_myconfig_copystring (p->strbuff, def, MAX_REG_BUFF);
        }
    } else {
        value = libpbc_myconfig_copystring (p->strbuff, def, MAX_REG_BUFF);
    }

    return value;
}

/* Note that p must have been allocated by the calling process */
/* Note that functions in pbc_myconfig should not call libpbc_getstring or libpbc_getint
   as there is only one static buffer defined for p. This includes syslog()*/
LPTSTR libpbc_myconfig_getstring (pubcookie_dir_rec * p, LPCTSTR key,
                                  LPCTSTR def)
{
    DWORD dsize;

    if (!p) {
        syslog (LOG_ERR,
                "libpbc_myconfig_getstring(p,%s,%s) called without an allocated pool",
                key, def);
        exit (3);
    }

    dsize = MAX_REG_BUFF;

    return (get_reg_value (p, key, &dsize, def));
}


int libpbc_myconfig_getint (pubcookie_dir_rec * p, LPCTSTR key, int def)
{
    DWORD dsize;
    LPSTR value;

    if (!p) {
        syslog (LOG_ERR,
                "libpbc_myconfig_getint(p,%s,%d) called without an allocated pool",
                key, def);
        exit (3);
    }

    dsize = sizeof (DWORD);

    bzero (p->strbuff, 8);

    value = get_reg_value (p, key, &dsize, "NONE");

    if (_tcsncmp ("NONE", value, 4)) {
        return *(int *) value;  /* sizeof(int) = sizeof(DWORD) only on 32-bit systems */
    } else {
        return def;
    }
}

int libpbc_myconfig_getswitch (pubcookie_dir_rec * p, LPCTSTR key, int def)
{
    /* Unimplemented */
    return def;
}

LPTSTR *libpbc_myconfig_getlist (pubcookie_dir_rec * p, LPCTSTR key)
{
    /* Unimplemented */
    return NULL;
}

int libpbc_myconfig_init (pubcookie_dir_rec * p, LPCTSTR alt_config,
                          LPCTSTR ident)
{
    return TRUE;
}

LPTSTR AddSystemRoot (pubcookie_dir_rec * p, LPCTSTR subdir)
{
    if (!p)
        fatal (p, "AddSystemRoot called without an allocated pool", 3);

    if (strncmp
        (libpbc_config_getstring (p, "System_Root", ""), "",
         MAX_PATH) == 0) {
        GetSystemDirectory (p->strbuff, MAX_PATH + 1);
    }
    strncat (p->strbuff, subdir, MAX_PATH + 1);
    return (p->strbuff);
}


#endif /*WIN32 */
