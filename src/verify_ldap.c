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

/** @file verify_ldap.c
 * LDAP Verifier
 *
 * Verifies users against an LDAP server (or servers.)
 * 
 * $Id: verify_ldap.c,v 1.35 2008/05/16 22:09:10 willey Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */


/* a pointer for an Apache memory pool is passed everywhwere */
typedef void pool;

#include "verify.h"

#ifdef ENABLE_LDAP

/* LibC */
#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

/* ldap - using OpenLDAP SDK or Netscape SDK */
#ifdef HAVE_LDAP_H
# include <ldap.h>
#endif /* HAVE_LDAP_H */

/* login cgi includes */
#include "index.cgi.h"
#include "pbc_myconfig.h"
#include "pbc_configure.h"
#include "snprintf.h"
#include "pbc_config.h"

/* Error logging! */
#include "pbc_logging.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

/**
 * Generates the name for the config file key
 * @param prefix char *
 * @param suffix char *
 * @retval malloc()d string (must be free()d!)
 */
static char *gen_key (const char *prefix, char *suffix)
{
    char *result;
    size_t len;
    int num;

    if (prefix == NULL)
        prefix = "";

    if (suffix == NULL)
        suffix = "";

    /* Add 2, one for the \0 and one for a _ */
    len = strlen (prefix) + strlen (suffix) + 7;

    result = calloc (len, sizeof (char));

    num = snprintf (result, len, "ldap%s%s_%s",
                    strlen (prefix) ? "_" : "", prefix, suffix);

    if (num >= len)
        return NULL;

    return result;

}

/**
 * Actually does an LDAP Bind
 * @param p pool *
 * @param ld LDAP *
 * @param user char *
 * @param password char *
 * @param errstr const char **
 * @retval 0 for sucess, nonzero on failure.
 */
static int do_bind (pool * p, LDAP * ld, char *user,
                    const char *password, const char **errstr)
{
    int rc;

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "do_bind: hello\n");

    rc = ldap_simple_bind_s (ld, user, password);

    if (rc != LDAP_SUCCESS) {
        pbc_log_activity (p, PBC_LOG_DEBUG_LOW, "do_bind: failed - %s\n",
                          ldap_err2string (rc));
        *errstr = "Bind failed -- auth failed";
        return -1;
    } else {
        pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                          "do_bind: bind successful\n");
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "do_bind: bye!\n");

    return 0;
}

#ifdef LDAP_SUN

void urlcpy (char *dest, char *src, int len)
{
    if (strchr (src, '%') == NULL) {
        strlcpy (dest, src, len);
    } else {
        int i = 0;
        int j = 0;

        /* I know, it's sloppy to just fail to char-by-char, but I'm lazy. */

        for (i = 0; i < len && src[i] != '\0'; i++) {
            if (src[i] != '%') {
                dest[j] = src[i];
            } else {
                int num = 0;
                int old;

                old = src[i + 3];
                src[i + 3] = '\0';

                num = (int) strtol (&src[i + 1], NULL, 16);

                dest[j] = num;

                src[i + 3] = old;

                i += 2;
            }

            j++;
        }
        dest[j] = '\0';
    }
}

char **parse_url_exts (char *ldap_url)
{
    char *p = ldap_url;
    char *q = NULL;
    int i;
    char **retval = NULL;
    int retnum = 0;
    int len;

    /* Skip the first four '?' to get to the extended data. */
    for (i = 0; i < 4; i++) {
        p = strchr (p, '?');
        if (p == NULL)
            return NULL;
        p++;
    }

    /* p should point to the '?' beginning the extended data */

    if (*p == '?' && *(p - 1) != '?') {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "Error parsing \"%s\": p=\"%s\"", ldap_url, p);
        return NULL;
    }

    if (*p == '\0') {
        pbc_log_activity (p, PBC_LOG_ERROR, "No Extended data on \"%s\"",
                          ldap_url);
        return NULL;
    }

    while (p != NULL) {

        retnum++;

        q = strchr (p, ',');

        if (q != NULL)
            *q = '\0';

        if (retval == NULL)
            retval = malloc (sizeof (char *) * retnum);
        else
            retval = realloc (retval, sizeof (char *) * retnum);

        len = strlen (p) + 1;

        retval[retnum - 1] = malloc (sizeof (char) * len);

        urlcpy (retval[retnum - 1], p, len);

        if (q != NULL) {
            *q = ',';
            p = q + 1;
        } else
            p = NULL;

        q = NULL;

    }

    if (retval != NULL) {
        retval = realloc (retval, sizeof (char *) * retnum + 1);
        retval[retnum] = NULL;
    }

    return retval;
}

#endif

/**
 * Connects to an LDAP Server
 * @param p poll *
 * @param ld LDAP **
 * @param ldap_port int
 * @param errstr const char **
 * @retval 0 for sucess, nonzero on failure.
 */
static int ldap_connect (pool * p, LDAP ** ld,
                         char *ldap_uri, const char **errstr)
{
    int rc = 0;
    char *tmp_uri;
    int tmplen = 0;

    char *dn = NULL;
    char *pwd = NULL;
    char *version = NULL;

    LDAPURLDesc *ludp;
    char **exts = NULL;

    const char func[] = "ldap_connect";

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: hello\n", func);

    if (ldap_url_parse (ldap_uri, &ludp)) {
        pbc_log_activity (p, PBC_LOG_ERROR, "%s: Cannot parse \"%s\"\n",
                          func, ldap_uri);
        *errstr = "System Error.  Contact your system administrator.";
        return -1;
    }

    if ((exts =
#ifdef LDAP_OPENLDAP
         ludp->lud_exts
#else
# ifdef LDAP_SUN
         parse_url_exts (ldap_uri)
# else
#  error "No LDAP API!"
# endif /* LDAP_SUN */
#endif /* LDAP_OPENLDAP */
        ) != NULL) {

        while (*exts != NULL) {
            char *val = strchr (*exts, '=');

            if (val != NULL) {

                *val = '\0';
                val++;

                if (strcasecmp (*exts, "x-BindDN") == 0) {
                    dn = strdup (val);
                } else if (strcasecmp (*exts, "x-Password") == 0) {
                    pwd = strdup (val);
                } else if (strcasecmp (*exts, "x-Version") == 0) {
                    version = strdup (val);
                } else {
                    pbc_log_activity (p, PBC_LOG_ERROR,
                                      "%s: unknown extension %s=%s\n",
                                      func, *exts, val);
                }
            } else {
                pbc_log_activity (p, PBC_LOG_ERROR,
                                  "%s: extension error parsing \"%s\"\n",
                                  func, *exts);
            }

            exts++;
        }
    }
#ifdef LDAP_OPENLDAP

    /*
     * Work around a bug in the OpenLDAP stuff that causes the init to fail when
     * there are things other than the server name in the URI.
     */

    /* The magic number 6 here is the most number of digits a port number can
     * have, i.e. 65535, plus one for the \0. */

    tmplen = strlen (ludp->lud_scheme) + strlen (ludp->lud_host) + 6 +
        strlen ("://:/");

    tmp_uri = malloc (tmplen);

    snprintf (tmp_uri, tmplen, "%s://%s:%d/",
              ludp->lud_scheme, ludp->lud_host, ludp->lud_port);

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: ldap_uri (%s)", 
                      func, tmp_uri);

    /* lookup DN for username using an anonymous bind */
    rc = ldap_initialize (ld, tmp_uri);

    free (tmp_uri);
#else
# ifdef LDAP_SUN

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                      "%s: Server: %s Port: %d SSL: %d", 
                      func, ludp->lud_host, ludp->lud_port,
                      ludp->lud_options & LDAP_URL_OPT_SECURE);

    if (ludp->lud_options & LDAP_URL_OPT_SECURE) {

        if (ldapssl_client_init (CERT_DB_PATH, NULL) != 0) {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "%s: Error loading cert db \"%s\"!",
                              func, CERT_DB_PATH);
            return -2;
        }

        *ld = (LDAP *) ldapssl_init (ludp->lud_host, ludp->lud_port, 1);
    } else {
        *ld = ldap_init (ludp->lud_host, ludp->lud_port);
    }

    if (*ld == (LDAP *) - 1)
        *ld = NULL;

# endif /* LDAP_SUN */
#endif /* LDAP_OPENLDAP */

    if (*ld != NULL) {
        // Default LDAP Version is 3
        int ldap_version = LDAP_VERSION3;

        if (version != NULL && strcmp (version, "2") == 0)
            ldap_version = LDAP_VERSION2;

        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "%s: Version Requested: %s Version Using: %d\n",
                          func, NULL == version ? "3" : version, ldap_version);

        rc = ldap_set_option (*ld, LDAP_OPT_PROTOCOL_VERSION,
                              &ldap_version);
        if (rc != LDAP_SUCCESS)
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "%s: ldap_set_option %s failed: %s", 
                              func, "LDAP_OPT_PROTOCOL_VERSION",
                              ldap_err2string(rc));

#ifdef LDAP_OPENLDAP

        if (libpbc_config_getswitch (p, "ldap_tls", 0)) { 
            int opt_x_tls = LDAP_OPT_X_TLS_DEMAND;
            int opt_x_require_cert = LDAP_OPT_X_TLS_DEMAND;
            char *ldapkeyfile = NULL;
            char *ldapcertfile = NULL;
            char *ldapcafile = NULL;

        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                   "ldap_connect: Using TLS client auth");

            rc = ldap_set_option(*ld, LDAP_OPT_X_TLS, &opt_x_tls);
            if (rc != LDAP_SUCCESS)
                pbc_log_activity (p, PBC_LOG_ERROR,
                                  "%s: ldap_set_option %s failed: %s", 
                                  func, "LDAP_OPT_X_TLS",
                                  ldap_err2string(rc));

            rc = ldap_set_option(NULL, LDAP_OPT_X_TLS_REQUIRE_CERT, &opt_x_require_cert);
            if (rc != LDAP_SUCCESS)
                pbc_log_activity (p, PBC_LOG_ERROR,
                                  "%s: ldap_set_option %s failed: %s", 
                                  func, "LDAP_OPT_X_TLS_REQUIRE_CERT",
                                  ldap_err2string(rc));

            ldapkeyfile =
                 (char *) libpbc_config_getstring (p, "ldap_key_file", NULL);
            if (ldapkeyfile && access (ldapkeyfile, R_OK | F_OK)) {
                if (access (ldapkeyfile, F_OK)) {
                    pbc_log_activity (p, PBC_LOG_ERROR, "%s: "
                                      "ldap_key_file (%s) doesn't exist.",
                                      func, ldapkeyfile);
                } else if (access (ldapkeyfile, R_OK)) {
                    pbc_log_activity (p, PBC_LOG_ERROR, "%s: "
                                      "Permissions prohibit reading "
                                      "ldap_key_file (%s).",
                                      func, ldapkeyfile);
                }
                pbc_free (p, ldapkeyfile);
                /* not there ? */
                ldapkeyfile = NULL;
            } else if (ldapkeyfile) {
                rc = ldap_set_option(NULL, 
                                     LDAP_OPT_X_TLS_KEYFILE, ldapkeyfile);
                if (rc != LDAP_SUCCESS)
                    pbc_log_activity (p, PBC_LOG_ERROR,
                                      "%s: ldap_set_option %s (%s) failed: %s", 
                                      func, "LDAP_OPT_X_TLS_KEYFILE",
                                      ldapkeyfile, ldap_err2string(rc));
            } else {
                pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: "
                                  "Try setting ldap_key_file",
                                  func, ldapcafile);
            }

            ldapcertfile =
                (char *) libpbc_config_getstring (p, "ldap_cert_file", NULL);
            if (ldapcertfile && access (ldapcertfile, R_OK | F_OK)) {
                if (access (ldapcertfile, F_OK)) {
                    pbc_log_activity (p, PBC_LOG_ERROR, "%s: "
                                      "ldap_cert_file (%s) doesn't exist.",
                                      func, ldapcertfile);
                } else if (access (ldapcertfile, R_OK)) {
                    pbc_log_activity (p, PBC_LOG_ERROR, "%s: "
                                      "Permissions prohibit reading "
                                      "ldap_cert_file (%s).",
                                      func, ldapcertfile);
                }
                pbc_free (p, ldapcertfile);
                /* not there ? */
                ldapcertfile = NULL;
            } else if (ldapcertfile) {
                rc = ldap_set_option(NULL, 
                                     LDAP_OPT_X_TLS_CERTFILE, ldapcertfile);
                if (rc != LDAP_SUCCESS)
                    pbc_log_activity (p, PBC_LOG_ERROR,
                                      "%s: ldap_set_option %s (%s) failed: %s", 
                                      func, "LDAP_OPT_X_TLS_CERTFILE",
                                      ldapcertfile, ldap_err2string(rc));
            } else {
                pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: "
                                  "Try setting ldap_cert_file",
                                  func, ldapcafile);
            }

            ldapcafile =
                (char *) libpbc_config_getstring (p, "ldap_ca_file", NULL);
            if (ldapcafile && access (ldapcafile, R_OK | F_OK)) {
                if (access (ldapcafile, F_OK)) {
                    pbc_log_activity (p, PBC_LOG_ERROR, "%s: "
                                      "ldap_ca_file (%s) doesn't exist.",
                                      func, ldapcafile);
                } else if (access (ldapcafile, R_OK)) {
                    pbc_log_activity (p, PBC_LOG_ERROR, "%s: "
                                      "Permissions prohibit reading "
                                      "ldap_ca_file (%s).",
                                      func, ldapcafile);
                }
                pbc_free (p, ldapcafile);
                /* not there ? */
                ldapcafile = NULL;
            } else if (ldapcafile) {
                rc = ldap_set_option(NULL, 
                                     LDAP_OPT_X_TLS_CACERTFILE, ldapcafile);
                if (rc != LDAP_SUCCESS)
                    pbc_log_activity (p, PBC_LOG_ERROR,
                                      "%s: ldap_set_option %s (%s) failed: %s", 
                                      func, "LDAP_OPT_X_TLS_CACERTFILE",
                                      ldapcafile, ldap_err2string(rc));
            } else {
                pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: "
                                  "Try setting ldap_ca_file",
                                  func, ldapcafile);
            }
        }
#endif /* LDAP_OPENLDAP */
    }

    rc = do_bind (p, *ld, dn, pwd, errstr);

    /* OK, We're bound, so we don't need the dn/pwd strings anymore.. */

    if (dn != NULL)
        free (dn);

    if (pwd != NULL)
        free (pwd);

    if (rc == -1) {
        /* Here a bind failing isn't catastrophic..  */
        pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                          "%s: Bind Failed.\n", func);
        /* ldap_unbind(*ld); */
        return -2;
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: bye!\n",func);

    return 0;
}

/* Do the search, get the matching Dn. */
/* Careful!  You have to free() the dn!  */

/**
 * Gets the DN of an object.
 * @param ld LDAP *
 * @param searchbase char *
 * @param attr char *
 * @param val const char *
 * @param dn char ** - malloc()d (must be free()d)
 * @param errstr const char **
 * @retval 0 for sucess, nonzero on failure.
 */
static int get_dn (pool * p, LDAP * ld,
                   char *ldapuri, char **dn, const char **errstr)
{
    int err = 0;
    int num_entries;


    LDAPMessage *results = NULL;
    LDAPMessage *entry = NULL;
    LDAPURLDesc *ludp = NULL;

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "get_dn: hello\n");

    *dn = NULL;

    if (ldap_url_parse (ldapuri, &ludp)) {
        pbc_log_activity (p, PBC_LOG_ERROR, "Cannot parse \"%s\"\n",
                          ldapuri);
        *errstr = "System Error.  Contact your system administrator.";
        return -1;
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "searching: %s for %s",
                      ludp->lud_dn, ludp->lud_filter);

    err = ldap_search_s (ld, ludp->lud_dn, LDAP_SCOPE_SUBTREE,
                         ludp->lud_filter, NULL, 0, &results);

    if (err != LDAP_SUCCESS) {
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "User not found - error %d (%s)!",
                          err, ldap_err2string (err));
        *errstr = "user not found -- auth failed";
        return -1;
    }

    num_entries = ldap_count_entries (ld, results);

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                      "get_dn: Found %d Entries\n", num_entries);

    if (num_entries != 1) {
        ldap_msgfree (results);
        *errstr = "too many or no entries found -- auth failed";
        return -1;
    }

    entry = ldap_first_entry (ld, results);

    if (entry == NULL) {
        ldap_msgfree (results);
        *errstr = "error getting ldap entry -- auth failed";
        /* The server had something go wrong -- OK to try again. */
        return -2;
    }

    *dn = ldap_get_dn (ld, entry);

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "get_dn: Got DN: \"%s\"\n",
                      *dn);

    if (*dn == NULL) {
        ldap_msgfree (results);
#ifdef LDAP_SUN
        ldap_msgfree (entry);
#endif
        *errstr = "error getting ldap dn -- auth failed";
        /* Again not fatal, probably a server error. */
        return -2;
    }

    ldap_msgfree (results);
#ifdef LDAP_SUN
    ldap_msgfree (entry);
#endif

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "get_dn: bye!\n");

    return 0;
}

/**
 * Actually verifies the user against the LDAP server
 * @param userid const char *
 * @param passwd const char *
 * @param service const char *
 * @param user_realm const char *
 * @param errstr const char **
 * @retval 0 on success, nonzero on failure
 */

static int ldap_v (pool * p, const char *userid,
                   const char *passwd,
                   const char *service,
                   const char *user_realm,
                   struct credentials **creds, const char **errstr)
{
    int got_error = -2;
    int i = 0;

    char **ldap_uri_list;
    char *key = NULL;

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "ldap_verifier: hello\n");

    if (creds)
        *creds = NULL;

    key = gen_key (user_realm, "uri");
    ldap_uri_list = libpbc_config_getlist (p, key);
    free (key);

    if (service != NULL) {
        *errstr = "LDAP Verifier can't handle Service cleanly...";
        return -2;
    }

    if (userid == NULL || strlen (userid) == 0) {
        *errstr = "Username MUST be specified.";
        return -2;
    }

    if (passwd == NULL || strlen (passwd) == 0) {
        *errstr = "Password MUST be specified.";
        return -2;
    }

    while ((got_error == -2)
           && (ldap_uri_list != NULL)
           && (ldap_uri_list[i] != NULL)) {
        char *ldap_uri_in = ldap_uri_list[i];
        char *ldap_uri;
        int len, num;

        LDAP *ld = NULL;
        char *user_dn = NULL;
        char *limit, *ptr_in, *ptr_out;

        if (strstr (ldap_uri_in, "%s") == NULL) {
            /* The LDAP URI must contain a %s to hold the user name! */
            *errstr = "System Error.  Contact your system administrator.";
            return -1;
        }

        /* Something big enough to hold the uri, userid and a \0 */
        len = strlen (ldap_uri_in) + strlen (userid) + 1;
        ldap_uri = malloc (len);

        if (ldap_uri == NULL) {
            /* Ooops, out of memory! */
            *errstr = "System Error.  Contact your system administrator.";
            return -1;
        }

        /* Copy the bytes which precede the (first) %s into the allocated URI
         * string. 
         */

        ptr_in = ldap_uri_in;
        ptr_out = ldap_uri;
        limit = strstr (ldap_uri_in, "%s");
        while (ptr_in < limit) {
            *ptr_out++ = *ptr_in++;
        }

        /* Add the userid to the allocated URI string */

        *ptr_out = '\0';
        strcat (ptr_out, userid);

        /* Copy the rest of the URI */
        ptr_in = limit + 2;
        ptr_out += strlen (userid);
        limit = ldap_uri_in + strlen (ldap_uri_in);
        while (ptr_in < limit) {
            *ptr_out++ = *ptr_in++;
        }
        *ptr_out = '\0';

        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "ldap_verifier: uri: \"%s\"\n", ldap_uri);

        if (userid == NULL || passwd == NULL) {
            *errstr = "username or password is null -- auth failed";
            got_error = -1;
        }

        /*
         * The definately needs to be changed.  There will need to be a
         * "searching" login that we use to find the Dn.
         */
        got_error = ldap_connect (p, &ld, ldap_uri, errstr);
        if (got_error == 0) {

            got_error = get_dn (p, ld, ldap_uri, &user_dn, errstr);

            if (got_error == 0 && strlen (user_dn)) {
                LDAPURLDesc *ludp;
                int err;

                if (ldap_url_parse (ldap_uri, &ludp)) {
                    /* For some reason we can't parse the URL. Eeek. */
                    got_error = -2;
                } else {

                    got_error = do_bind (p, ld, user_dn, passwd, errstr);

                    if (got_error != 0)
                        *errstr = "couldn't bind as user -- auth failed";

                    if (got_error == 0) {
                        pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                                          "%s succesfully bound to %s:%d\n",
                                          userid, ludp->lud_host,
                                          ludp->lud_port);
                    } else if (got_error == -1) {
                        pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                                          "%s fatal error binding to %s:%d\n",
                                          userid, ludp->lud_host,
                                          ludp->lud_port);
                    } else if (got_error == -2) {
                        pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                                          "%s error binding to %s:%d.  Continuing\n",
                                          userid, ludp->lud_host,
                                          ludp->lud_port);
                    }
                }

            }

            if (user_dn != NULL)
                free (user_dn);

            /* close ldap connection */
            ldap_unbind (ld);
        }

        if (ldap_uri != NULL)
            free (ldap_uri);

        i++;
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "ldap_verifier: bye!\n");

    return (got_error);
}


#else /* ENABLE_LDAP */

static int ldap_v (pool * p, const char *userid,
                   const char *passwd,
                   const char *service,
                   const char *user_realm,
                   struct credentials **creds, const char **errstr)
{
    if (creds)
        *creds = NULL;

    *errstr = "ldap not implemented";
    return -1;
}
#endif

verifier ldap_verifier = { "ldap", &ldap_v, NULL, NULL };
