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

/*
    the u of Wa flavor of logins.  expect a username and a password and
    checks against one of the defined verifiers (see 'struct verifier'
    and verify_*.c for possible verifiers).
    
 */

/*
    $Id: flavor_uwsecurid.c,v 2.20 2008/05/16 22:09:10 willey Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef ENABLE_UWSECURID

#if defined (APACHE1_3)
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

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_ASSERT_H
# include <assert.h>
#endif /* HAVE_ASSERT_H */

#include "snprintf.h"
#include "flavor.h"
#include "verify.h"
#include "security.h"

#include "pbc_config.h"
#include "pbc_logging.h"
#include "pbc_configure.h"
#include "pbc_version.h"
#include "libpubcookie.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

static verifier *v1 = NULL;
static verifier *v2 = NULL;

/* The types of reasons for printing the login page.. 
 * Should this be in a header?  I don't think I need it outside this file.. */

#define FLUS_BAD_AUTH          1
#define FLUS_REAUTH            2
#define FLUS_LCOOKIE_ERROR     3
#define FLUS_CACHE_CREDS_WRONG 4
#define FLUS_NEXT_PRN          6
#define FLUS_LCOOKIE_EXPIRED   7
#define FLUS_AUTH_PROB         8

/* The beginning size for the hidden fields */
#define INIT_HIDDEN_SIZE 2048
#define GETCRED_HIDDEN_MAX 512

/* no reason to leave this in except that we might want to change verifiers */
static int init_uwsecurid ()
{
    const char *vname1;
    const char *vname2;
    void *p;

    /* find the first verifier configured */
    vname1 =
        libpbc_config_getstring (p, "uwsecurid_verifier1", "kerberos_v5");

    v1 = get_verifier (vname1);

    if (!v1 || !v1->v) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "flavor_uwsecurid: verifier not found: %s",
                          vname1);
        v1 = NULL;
        return -1;
    }

    /* find the second verifier configured */
    vname2 =
        libpbc_config_getstring (p, "uwsecurid_verifier2", "uwsecurid");

    v2 = get_verifier (vname2);

    if (!v2 || !v2->v) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "flavor_uwsecurid: verifier not found: %s",
                          vname2);
        v2 = NULL;
        return -1;
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "init_uwsecurid: using %s and %s verifiers", vname1,
                      vname2);
    return 0;
}

/*
 * return the length of the passed file in bytes or 0 if we cant tell
 * resets the file postion to the start
 */
static long file_size (pool * p, FILE * afile)
{
    long len;
    if (fseek (afile, 0, SEEK_END) != 0)
        return 0;
    len = ftell (afile);
    if (fseek (afile, 0, SEEK_SET) != 0)
        return 0;
    return len;
}

/* get the reason for our existing.  Returns NULL for an empty file. */
char *flus_get_reason (pool * p, const char *reasonpage)
{
    char *reasonfile;
    const char *reasonpath = TMPL_FNAME;
    int reasonfilelen;
    int reason_len;
    FILE *reason_file;
    char *reasonhtml;
    int readlen;

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "flus_get_reason: hello");

    reasonfilelen =
        strlen (reasonpath) + strlen ("/") + strlen (reasonpage) + 1;

    reasonfile = malloc (reasonfilelen * sizeof (char));

    if (snprintf (reasonfile, reasonfilelen, "%s%s%s",
                  reasonpath,
                  reasonpath[strlen (reasonpath) - 1] == '/' ? "" : "/",
                  reasonpage) > reasonfilelen) {
        /* Need to do something, we would have overflowed. */
        abend (p, "Reason filename overflow!\n");
    }

    reason_file = pbc_fopen (p, reasonfile, "r");

    if (reason_file == NULL) {
        libpbc_abend (p, "Cannot open reasonfile %s", reasonfile);
    }

    reason_len = file_size (p, reason_file);

    if (reason_len == 0)
        return NULL;

    reasonhtml = malloc ((reason_len + 1) * sizeof (char));

    if (reasonhtml == NULL) {
        /* Out of memory! */
        libpbc_abend (p, "Out of memory allocating to read reason file");
    }

    readlen = fread (reasonhtml, 1, reason_len, reason_file);

    if (readlen != reason_len) {
        libpbc_abend (p, "read %d when expecting %d on reason file read.",
                      readlen, reason_len);
    }

    reasonhtml[reason_len] = '\0';
    pbc_fclose (p, reason_file);
    free (reasonfile);

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                      "flus_get_reason: goodbye");

    return reasonhtml;
}

/**
 * flus_get_custom_login_msg get custom login message if there is such
 * @param p apache memory pool
 * @param appid application id
 * @param appsrvid application server id
 * @param mout output string
 * @return PBC_OK if ok or PBC_FAIL if a problem
 */
int flus_get_custom_login_msg (pool * p, const char *appid,
                               const char *appsrvid, char **mout)
{
    char *new, *ptr, *filename;
    const char *s;
    int len;
    const char *template_dir = libpbc_config_getstring (p,
                                                        "custom_login_message_dir",
                                                        TMPL_FNAME);
    const char *cust_login_prefix = libpbc_config_getstring (p,
                                                             "custom_login_file_prefix",
                                                             CUSTOM_LOGIN_MSG);
    const char func[] = "flus_get_custom_login_msg";
    const char *l_appid = strdup( appid ? appid : "");
    const char *l_appsrvid = strdup( appsrvid ? appsrvid : "");

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                      "%s: hello appid: %s appsrvid: %s", func, l_appid,
                      l_appsrvid);

    len =
        strlen (l_appid) + strlen (l_appsrvid) + strlen (cust_login_prefix) +
        3;
    filename = calloc (len, sizeof (char));
    snprintf (filename, len, "%s%c%s%c%s", cust_login_prefix,
              APP_LOGOUT_STR_SEP, l_appsrvid,
              APP_LOGOUT_STR_SEP, l_appid);

    /* clean non compliant chars from string */
    ptr = new = filename;
    while (*ptr) {
        if (isalnum ((int) *ptr) || *ptr == '-' || *ptr == '_'
            || *ptr == '.') {
            *new++ = *ptr;
        }
        ptr++;
    }
    *new = '\0';

    if (ntmpl_tmpl_exist (p, template_dir, filename))
        *mout = ntmpl_sub_template (p, template_dir, filename, NULL);

    if (filename != NULL)
        free (filename);

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                      "%s: bye message mout: %s ", func,
                      *mout == NULL ? "(null)" : *mout);

    return (PBC_OK);

}

/* for some n seconds after authenticating we don't ask the user to */
/* retype their credentials                                         */
/*    returns credentials ok for ride free                          */
char ride_free_zone (login_rec * l, login_rec * c)
{
    char *cookie;
    pbc_time_t t;
    pool *p = NULL;
    char func[] = "ride_free_zone";


    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: hello", func);

    if (!(cookie = pbc_malloc (p, PBC_4K))) {
        abend (p, "out of memory");
    }

    if (c == NULL)
        return (PBC_CREDS_NONE);
    if (l != NULL && l->check_error != NULL)
        return (PBC_CREDS_NONE);

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                      "%s: in ride_free_zone ready to look at cookie contents user: %s",
                      func, c->user ? c->user : "Null");

    /* look at what we got back from the cookie */
    if (!c->user) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "%s: no user from L cookie? user from g_req: %s",
                          func, l->user ? l->user : "Null");
        return (PBC_CREDS_NONE);
    }

    if ((c->create_ts + RIDE_FREE_TIME) < (t = pbc_time (NULL))) {
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "%s %s: No Free Ride login cookie created: %d now: %d user: %s",
                          func, l->first_kiss, c->create_ts, t, c->user);
        return (PBC_CREDS_NONE);
    } else {
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "%s%s Yeah! Free Ride!!! login cookie created: %d now: %d user: %s",
                          func, l->first_kiss, c->create_ts, t, c->user);

        if (l->user == NULL)
            l->user = c->user;

        return (PBC_BASIC_CRED_ID);
    }

}

/* get the html for user or password or whatever field, static or dynamic */
char *flus_get_field_html (pool * p, const char *field_page,
                           const char *contents)
{
    char *field_html = NULL;    /* net result */
    char *fieldfile;
    const char *field_path = TMPL_FNAME;
    int filelen;
    int field_len;
    FILE *field_file;
    int readlen;
    char buf[PBC_1K];
    char *start = NULL;
    char *end = NULL;
    int len = (contents != NULL ? strlen (contents) : 0);
    char func[] = "flus_get_field_html";

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: hello", func);

    filelen = strlen (field_path) + strlen ("/") + strlen (field_page) + 1;

    fieldfile = malloc (filelen * sizeof (char));

    if (snprintf (fieldfile, filelen, "%s%s%s",
                  field_path,
                  field_path[strlen (field_path) - 1] == '/' ? "" : "/",
                  field_page) > filelen) {
        /* Need to do something, we would have overflowed. */
        abend (p, "field filename overflow!\n");
    }

    field_file = pbc_fopen (p, fieldfile, "r");

    if (field_file == NULL) {
        libpbc_abend (p, "Cannot open field file %s", fieldfile);
    }

    field_len = file_size (p, field_file);

    if (field_len == 0)
        return NULL;

    if (field_len >= sizeof (buf)) {
        libpbc_abend (p,
                      "Need bigger buffer for reading form field file, %D not big enough",
                      sizeof (buf));
    }

    field_html = malloc ((field_len + 1) * sizeof (char) + len);

    if (field_html == NULL) {
        /* Out of memory! */
        libpbc_abend (p, "Out of memory allocating to field file");
    }

    readlen = fread (buf, 1, field_len, field_file);

    if (readlen != field_len) {
        libpbc_abend (p, "read %d when expecting %d on field file read.",
                      readlen, field_len);
    }

    pbc_fclose (p, field_file);
    if (fieldfile != NULL)
        free (fieldfile);

    buf[field_len] = '\0';
    strcpy (field_html, buf);

    /* if there is a substiturion to be made, make it */
    while (strstr (buf, "%contents%") != NULL) {
        /* cheesy non-generic substitution for field */
        /* chop up the strings */
        end = strstr (strstr (buf, "%contents%") + 1, "%");
        start = strstr (field_html, "%contents%");

        /* piece them back together */
        strcpy (start, (contents != NULL ? contents : ""));
        strcpy (start + len, end + 1);

        strncpy (buf, field_html, PBC_1K);
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: goodbye: %s",
                      func, field_html);

    return field_html;

}

/* figure out what html to use for user field */
char *flus_get_user_field (pool * p, login_rec * l, login_rec * c,
                           int reason)
{
    char func[] = "flus_get_user_field";
    const char *loser = (l != NULL && l->user != NULL ? l->user
                         : (c != NULL ? c->user : NULL));
    const char *static_config =
        libpbc_config_getstring (p, "static_user_field",
                                 STATIC_USER_FIELD_KIND);
    char *user_field_html;

    if (strcmp (static_config, STATIC_USER_FIELD_KIND) == 0) {
        if ((c && c->user &&
               (reason == FLUS_REAUTH || reason == FLUS_NEXT_PRN ||
               reason == FLUS_CACHE_CREDS_WRONG)) ||
               (l->user != NULL && l->ride_free_creds == PBC_BASIC_CRED_ID)) {
           user_field_html =
                flus_get_field_html (p,
                                     libpbc_config_getstring (p,
                                                              "tmpl_login_user_static",
                                                              "login_user_static"),
                                     loser);
            l->hide_user = PBC_TRUE;
        } else {
            user_field_html =
                flus_get_field_html (p,
                                     libpbc_config_getstring (p,
                                                              "tmpl_login_user_form_field",
                                                              "login_user_form_field"),
                                     loser);
            l->hide_user = PBC_FALSE;
        }
    } else if (strcmp (static_config, STATIC_USER_FIELD_FASCIST) == 0) {
        if (c != NULL && c->user != NULL ||
            l->user != NULL && l->ride_free_creds == PBC_BASIC_CRED_ID) {
            user_field_html =
                flus_get_field_html (p,
                                     libpbc_config_getstring (p,
                                                              "tmpl_login_user_static",
                                                              "login_user_static"),
                                     loser);
            l->hide_user = PBC_TRUE;
        } else {
            user_field_html =
                flus_get_field_html (p,
                                     libpbc_config_getstring (p,
                                                              "tmpl_login_user_form_field",
                                                              "login_user_form_field"),
                                     loser);
            l->hide_user = PBC_FALSE;
        }
    } else {                    /* STATIC_USER_FIELD_NEVER */
        user_field_html =
            flus_get_field_html (p,
                                 libpbc_config_getstring (p,
                                                          "tmpl_login_user_form_field",
                                                          "login_user_form_field"),
                                 loser);
        l->hide_user = PBC_FALSE;
    }

    return (user_field_html);

}

/* figure out what html to use for pass field */
char *flus_get_pass_field (pool * p, login_rec * l, login_rec * c,
                           int reason)
{
    if (l->ride_free_creds == PBC_BASIC_CRED_ID) {
        return (flus_get_field_html (p,
                                     libpbc_config_getstring (p,
                                                              "tmpl_login_pass_static",
                                                              "login_pass_static"),
                                     ""));
    } else {
        return (flus_get_field_html (p,
                                     libpbc_config_getstring (p,
                                                              "tmpl_login_pass_form_field",
                                                              "login_pass_form_field"),
                                     ""));
    }

}

/* get the html for user field, static or dynamic */
char *flus_get_hidden_user_field (pool * p, login_rec * l, login_rec * c,
                                  int reason)
{
    const char *loser = (l != NULL && l->user != NULL ? l->user
                         : (c != NULL ? c->user : NULL));

    if (l != NULL && l->hide_user == PBC_TRUE)
        return (flus_get_field_html (p, libpbc_config_getstring (p,
                                                                 "tmpl_login_user_hidden",
                                                                 "login_user_hidden"),
                                     loser));
    else
        return (NULL);

}

int flus_get_reason_html (pool * p, int reason, login_rec * l,
                          login_rec * c, char **out)
{
    char *tag = NULL;
    char *subst = NULL;
    const char *reasonpage = NULL;
    int ret = PBC_FAIL;
    char func[] = "flus_get_reason_html";

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: hello reason: %d",
                      func, reason);

    switch (reason) {
    case FLUS_BAD_AUTH:
        /* username will be static and prefilled use a different bad
           auth message, one without comments about the username */
        if (c != NULL && c->user != NULL)
            reasonpage = libpbc_config_getstring (p,
                                                  "tmpl_login_bad_auth_uwsecurid_static_user",
                                                  "login_bad_auth_uwsecurid_static_user");
        else
            reasonpage = libpbc_config_getstring (p,
                                                  "tmpl_login_bad_auth_uwsecurid",
                                                  "login_bad_auth_uwsecurid");
        break;
    case FLUS_REAUTH:
        reasonpage = libpbc_config_getstring (p, "tmpl_login_reauth",
                                              "login_reauth");
        break;
    case FLUS_CACHE_CREDS_WRONG:
        reasonpage =
            libpbc_config_getstring (p, "tmpl_login_cache_creds_wrong",
                                     "login_cache_creds_wrong");
        break;
    case FLUS_NEXT_PRN:
        reasonpage = libpbc_config_getstring (p, "tmpl_login_next_prn",
                                              "login_next_prn");
        break;
    case FLUS_LCOOKIE_EXPIRED:
        reasonpage = libpbc_config_getstring (p, "tmpl_login_expired",
                                              "login_expired");
        break;
    case FLUS_AUTH_PROB:
        reasonpage =
            libpbc_config_getstring (p, "tmpl_login_auth_prob_uwsecurid",
                                     "login_auth_prob_uwsecurid");
        break;
    case FLUS_LCOOKIE_ERROR:
    default:
        reasonpage = libpbc_config_getstring (p, "tmpl_login_nolcookie",
                                              "login_nolcookie");
        break;
    }

    if (reasonpage == NULL) {
        /* We shouldn't be here, but handle it anyway, of course. */
        libpbc_abend (p, "Reasonpage is null, this is impossible.");
    }

    /* Get the HTML for the error reason */
    *out =
        ntmpl_sub_template (p, TMPL_FNAME, reasonpage, tag, subst, NULL);
    if (*out == NULL)
        ret = PBC_FAIL;
    else
        ret = PBC_OK;

    if (tag != NULL)
        pbc_free (p, tag);
    if (subst != NULL)
        pbc_free (p, subst);

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: bye return: %d",
                      func, reason);

    return (ret);

}

static void print_login_page (pool * p, login_rec * l, login_rec * c,
                              int reason)
{
    /* currently, we never clear the login cookie
       we always clear the greq cookie */
    int need_clear_login = 0;
    int need_clear_greq = 1;
    char message_out[1024];
    const char *reasonpage = NULL;

    char *hidden_fields = NULL;
    int hidden_len = 0;
    int hidden_needed_len = INIT_HIDDEN_SIZE;
    char *getcred_hidden = NULL;
    char now[64];
    char *user_field = NULL;
    char *pass_field = NULL;
    char *hidden_user = NULL;
    char func[] = "print_login_page";
    char *login_msg = NULL;
    char *reason_msg = NULL;
    int ret = PBC_FAIL;

    int ldur, ldurp;
    char ldurtxt[64], *ldurtyp;


    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: hello, reason: %d",
                      func, reason);

    /* set the cookies */
    if (need_clear_login) {
        print_header (p,
                      "Set-Cookie: %s=%s; domain=%s; path=%s; expires=%s; secure\n",
                      PBC_L_COOKIENAME, PBC_CLEAR_COOKIE, PBC_LOGIN_HOST,
                      LOGIN_DIR, EARLIEST_EVER);
    }

    if (need_clear_greq) {
        add_app_cookie (PBC_G_REQ_COOKIENAME, PBC_CLEAR_COOKIE, NULL);
    }

    /* if there is a custom login message AND the reason for logging-in is:
       reauth, wrong creds (flavours), expired login cookie, or
       login cookie error.  The later case is the catch-all and included
       inital visits when the user doesn't hav a login cookie
       else
       use the traditional reason text
     */
    if (reason == FLUS_REAUTH || reason == FLUS_CACHE_CREDS_WRONG ||
        reason == FLUS_LCOOKIE_EXPIRED || reason == FLUS_LCOOKIE_ERROR)
        if ((ret = flus_get_custom_login_msg (p, l->appid,
                                              l->appsrvid,
                                              &login_msg)) == PBC_FAIL)
            goto done;

    /* if there is no custom login message go get the reason text
       in the case of expired login messages we use both the
       the custom message (itis) and the lcookie expired message
     */
    if (login_msg == NULL || reason == FLUS_LCOOKIE_EXPIRED)
        if ((ret =
             flus_get_reason_html (p, reason, l, c,
                                   &reason_msg)) == PBC_FAIL)
            goto done;

    while (hidden_needed_len > hidden_len) {

        /* Just in case there's a bad implementation of realloc() .. */
        if (hidden_fields == NULL) {
            hidden_fields = malloc (hidden_needed_len * sizeof (char));
        } else {
            hidden_fields =
                realloc (hidden_fields, hidden_needed_len * sizeof (char));
        }

        if (hidden_fields == NULL) {
            /* Out of memory, ooops. */
            libpbc_abend (p,
                          "Out of memory allocating for hidden fields!");
        }

        hidden_len = hidden_needed_len;

        /* Yeah, this sucks, but I don't know a better way. 
         * That doesn't mean there isn't one. */

        hidden_needed_len = snprintf (hidden_fields, hidden_len,
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%c\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%c\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%d\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%d\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%d\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%d\">\n",
                                      PBC_GETVAR_APPSRVID,
                                      (l->appsrvid ? l->appsrvid : ""),
                                      PBC_GETVAR_APPID,
                                      (l->appid ? l->appid : ""),
                                      "creds_from_greq",
                                      l->creds_from_greq, PBC_GETVAR_CREDS,
                                      l->creds, PBC_GETVAR_VERSION,
                                      (l->version ? l->version : ""),
                                      PBC_GETVAR_METHOD,
                                      (l->method ? l->method : ""),
                                      PBC_GETVAR_HOST,
                                      (l->host ? l->host : ""),
                                      PBC_GETVAR_URI,
                                      (l->uri ? l->uri : ""),
                                      PBC_GETVAR_RELAY_URL,
                                      (l->relay_uri ? l->relay_uri : ""),
                                      PBC_GETVAR_ARGS,
                                      (l->args ? l->args : ""),
                                      PBC_GETVAR_FR, (l->fr ? l->fr : ""),
                                      PBC_GETVAR_REAL_HOST,
                                      (l->real_hostname ? l->
                                       real_hostname : ""),
                                      PBC_GETVAR_APPSRV_ERR,
                                      (l->appsrv_err ? l->appsrv_err : ""),
                                      PBC_GETVAR_FILE_UPLD,
                                      (l->file ? l->file : ""),
                                      PBC_GETVAR_FLAG,
                                      (l->flag ? l->flag : ""),
                                      PBC_GETVAR_REFERER,
                                      (l->referer ? l->referer : ""),
                                      PBC_GETVAR_POST_STUFF,
                                      (l->post_stuff ? l->post_stuff : ""),
                                      PBC_GETVAR_SESSION_REAUTH,
                                      l->session_reauth,
                                      PBC_GETVAR_PRE_SESS_TOK,
                                      l->pre_sess_tok, "first_kiss",
                                      (l->first_kiss ? l->first_kiss : ""),
                                      PBC_GETVAR_PINIT, l->pinit,
                                      PBC_GETVAR_REPLY, FORM_REPLY);
    }

    snprintf (now, sizeof (now), "%d", pbc_time (NULL));

    /* what should the uwnetid field look like? */
    user_field = flus_get_user_field (p, l, c, reason);

    /* what should the password field look like? */
    pass_field = flus_get_pass_field (p, l, c, reason);

    /* if the user field should be hidden */
    hidden_user = flus_get_hidden_user_field (p, l, c, reason);

    /* login session lifetime message */
    if (!(ldur = get_kiosk_duration (p, l)))
        ldur =
            libpbc_config_getint (p, "default_l_expire",
                                  DEFAULT_LOGIN_EXPIRE);
    if (((ldurp = ldur / 3600) * 3600) == ldur)
        ldurtyp = "hour";
    else if (((ldurp = ldur / 60) * 60) == ldur)
        ldurtyp = "minute";
    else
        ldurp = ldur, ldurtyp = "second";
    sprintf (ldurtxt, "%d %s%s", ldurp, ldurtyp, ldurp == 1 ? "" : "s");

    /* Display the login form. */
    ntmpl_print_html (p, TMPL_FNAME,
                      libpbc_config_getstring (p, "tmpl_login_uwsecurid",
                                               "login_uwsecurid"),
                      "loginuri", PBC_LOGIN_URI,
                      "message", login_msg != NULL ? login_msg : "",
                      "reason", reason_msg != NULL ? reason_msg : "",
                      "curtime", now,
                      "hiddenuser", hidden_user != NULL ? hidden_user : "",
                      "hiddenfields", hidden_fields,
                      "user_field", user_field != NULL ? user_field : "",
                      "pass_field", pass_field != NULL ? pass_field : "",
                      "durationtext", ldurtxt,
                      "version", PBC_VERSION_STRING, NULL);

    /* this tags the incoming request as a form reply */

    print_html (p, "\n");

  done:

    if (user_field != NULL)
        free (user_field);

    if (pass_field != NULL)
        free (pass_field);

    if (hidden_user != NULL)
        free (hidden_user);

    if (login_msg != NULL)
        free (login_msg);

    if (hidden_fields != NULL)
        free (hidden_fields);

    if (getcred_hidden != NULL)
        free (getcred_hidden);

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: goodbye", func);
}

/* process_uwsecurid():
   this routine is responsible for authenticating the user.
   if authentication is not possible (either the user hasn't logged in
   or the password was incorrect) it displays the login page and returns
   LOGIN_INPROGRESS.

   if authentication for this user will never succeed, it returns LOGIN_ERR.

   if authentication has succeeded, no output is generated and it returns
   LOGIN_OK.
 */
static login_result process_uwsecurid (pool * p,
                                       const security_context * context,
                                       login_rec * l, login_rec * c,
                                       const char **errstr)
{
    int result1, result2;

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                      "process_uwsecurid: hello\n");

    /* make sure we're initialized */
    assert (v1 != NULL);
    assert (v2 != NULL);
    assert (l != NULL);
    /* c seems to always be null here. */
    /* XXX need to re-examine exactly what l and c should contain here */
    /* assert(c != NULL); */
    assert (errstr);

    *errstr = NULL;

    if (!v1) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "flavor_uwsecurid: flavor not correctly configured");
        return LOGIN_ERR;
    }
    if (!v2) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "flavor_uwsecurid: flavor not correctly configured");
        return LOGIN_ERR;
    }

    /* choices, choices */

    /* index.cgi is responsible for extracting replies to the prompts
       that I printed into 'l'.  I'm responsible for modifying 'l' for
       later free rides.

       so, some possibilities:
       . reply from login page
       'l' is unauthed but has a username/pass that i should
       verify.  if yes, modify login cookie accordingly and return
       LOGIN_OK.  if no, print out the page and return
       LOGIN_INPROGRESS.

       . expired login cookie
       i should print out the page and return LOGIN_INPROGRESS.

       . valid login cookie
       i should return LOGIN_OK.
     */

    l->ride_free_creds = ride_free_zone (l, c);

    if (l->reply == FORM_REPLY) {

        result1 =
            v1->v (p, l->user, l->pass, NULL, l->realm, NULL, errstr);
        /* only do securid check if necessary */
        if (l->ride_free_creds == PBC_BASIC_CRED_ID || result1 == 0)
            result2 =
                v2->v (p, l->user, l->pass2, NULL, l->realm, NULL, errstr);

        if ((l->ride_free_creds == PBC_BASIC_CRED_ID || result1 == 0)
            && result2 == 0) {

            pbc_log_activity (p, PBC_LOG_AUDIT,
                              "%s Authentication success: %s IP: %s type: %c\n",
                              l->first_kiss,
                              l->user,
                              (cgiRemoteAddr ==
                               NULL ? "(null)" : cgiRemoteAddr), l->creds);

            /* authn succeeded! */


            /* set the create time */
            l->create_ts = pbc_time (NULL);
            if (c != NULL)
                c->create_ts = pbc_time (NULL);

            /* xxx modify 'l' accordingly ? */

            pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                              "process_uwsecurid: good login, goodbye\n");

            return LOGIN_OK;
        } else {

            /* see if the securid server had a problem */
            if (result2 == -2) {
                pbc_log_activity (p, PBC_LOG_AUDIT,
                                  "flavor_uwsecurid: SecurID had a problem %s",
                                  l->user == NULL ? "(null)" : l->user);

                print_login_page (p, l, c, FLUS_AUTH_PROB);
            }
            /* see if the securid server wants next prn */
            else if (result2 == -3) {
                pbc_log_activity (p, PBC_LOG_AUDIT,
                                  "flavor_uwsecurid: SecurID wants next prn %s",
                                  l->user == NULL ? "(null)" : l->user);

                print_login_page (p, l, c, FLUS_NEXT_PRN);
            } else {

                /* authn failed! */
                if (!*errstr)
                    *errstr = "authentication failed";

                pbc_log_activity (p, PBC_LOG_AUDIT,
                                  "flavor_uwsecurid: login failed for %s: %s",
                                  l->user == NULL ? "(null)" : l->user,
                                  *errstr);

                /* make sure 'l' reflects that */

                if (!libpbc_config_getswitch (p,
                                              "retain_username_on_failed_authn",
                                              0)) {
                    l->user = NULL;     /* in case wrong username */
                }

                print_login_page (p, l, c, FLUS_BAD_AUTH);

            }

            pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                              "process_uwsecurid: login in progress, goodbye\n");
            return LOGIN_INPROGRESS;
        }
    } else if (l->session_reauth) {
        *errstr = "reauthentication required";
        pbc_log_activity (p, PBC_LOG_AUDIT,
                          "flavor_uwsecurid: %s: %s", l->user, *errstr);

        print_login_page (p, l, c, FLUS_REAUTH);
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "process_uwsecurid: login in progress, goodbye\n");
        return LOGIN_INPROGRESS;

        /* l->check_error will be set whenever the l cookie isn't valid
           including (for example) when the login cookie has expired. 
         */
    } else if (l->check_error) {
        *errstr = l->check_error;
        pbc_log_activity (p, PBC_LOG_ERROR, "flavor_uwsecurid: %s",
                          *errstr);

        if (strcmp (l->check_error, "expired") == 0)
            print_login_page (p, l, c, FLUS_LCOOKIE_EXPIRED);
        else
            print_login_page (p, l, c, FLUS_LCOOKIE_ERROR);

        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "process_uwsecurid: login in progress, goodbye\n");
        return LOGIN_INPROGRESS;

        /* if l->check_error is NULL, then 'c' must be set and must
           contain the login cookie information */
    } else if (!c) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "flavor_uwsecurid: check_error/c invariant violated");
        abort ();

        /* make sure the login cookie represents credentials for this flavor */
    } else if (c->creds != PBC_UWSECURID_CRED_ID) {
        *errstr = "cached credentials wrong flavor";
        pbc_log_activity (p, PBC_LOG_ERROR, "flavor_uwsecurid: %s",
                          *errstr);

        print_login_page (p, l, c, FLUS_CACHE_CREDS_WRONG);
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "process_uwsecurid: login in progress, goodbye\n");
        return LOGIN_INPROGRESS;

    } else {                    /* securid requires reauth */
        *errstr = "uwsecurid requires reauth";
        pbc_log_activity (p, PBC_LOG_AUDIT,
                          "flavor_uwsecurid: %s: %s", l->user, *errstr);
        print_login_page (p, l, c, FLUS_REAUTH);
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "process_uwsecurid: login in progress, goodbye\n");
        return LOGIN_INPROGRESS;
    }

}

struct login_flavor login_flavor_uwsecurid = {
    "uwsecurid",                /* name */
    PBC_UWSECURID_CRED_ID,      /* id; see libpbc_get_credential_id() */
    &init_uwsecurid,            /* init_flavor() */
    &process_uwsecurid          /* process_request() */
};

#endif /* ENABLE_UWSECURID */
