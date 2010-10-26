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

/** @file flavor_basic.c
 * The basic flavor of logins
 *
 *   expect a username and a password and
 *   checks against one of the defined verifiers (see 'struct verifier'
 *   and verify_*.c for possible verifiers).
 *   
 *   will pass l->realm to the verifier and append it to the username when
 *   'append_realm' is set
 *
 * $Id: flavor_basic.c,v 1.85 2008/05/16 22:09:10 willey Exp $
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

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

static verifier *v = NULL;

extern int get_kiosk_duration (pool * p, login_rec * l);

/* The types of reasons for printing the login page.. 
 * Should this be in a header?  I don't think I need it outside this file.. */

#define FLB_BAD_AUTH          1
#define FLB_REAUTH            2
#define FLB_LCOOKIE_ERROR     3
#define FLB_CACHE_CREDS_WRONG 4
#define FLB_PINIT             5
#define FLB_PLACE_HOLDER      6 /* for consistancy btwn flavors, why? */
#define FLB_LCOOKIE_EXPIRED   7
#define FLB_FORM_EXPIRED      8

/* The beginning size for the hidden fields */
#define INIT_HIDDEN_SIZE 2048
#define GETCRED_HIDDEN_MAX 512

static int init_basic ()
{
    const char *vname;
    void *p = NULL;

    /* find the verifier configured */
    vname = libpbc_config_getstring (p, "basic_verifier", NULL);

    if (!vname) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "flavor_basic: no verifier configured");
        return -1;
    }

    v = get_verifier (vname);

    if (!v || !v->v) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "flavor_basic: verifier not found: %s", vname);
        v = NULL;
        return -1;
    }
    pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                      "init_basic: using %s verifier", vname);
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

/* figure out what html to use for user field */
/* if the sub template function returns NULL we just pass it on */
char *flb_get_user_field (pool * p, login_rec * l, login_rec * c,
                          int reason)
{
    char func[] = "flb_get_user_field";
    const char *loser = (l != NULL && l->user != NULL ? l->user
                         : (c != NULL ? c->user : NULL));
    const char *static_config =
        libpbc_config_getstring (p, "static_user_field",
                                 STATIC_USER_FIELD_KIND);
    char *user_field_html;

    if (loser == NULL)
        loser = strdup ("");

    if (strcmp (static_config, STATIC_USER_FIELD_KIND) == 0) {
        if ((c && c->user &&
             (reason == FLB_REAUTH || reason == FLB_CACHE_CREDS_WRONG)) ||
            (l->user && l->ride_free_creds == PBC_BASIC_CRED_ID)) {
            user_field_html = ntmpl_sub_template (p, TMPL_FNAME,
                                                  libpbc_config_getstring
                                                  (p,
                                                   "tmpl_login_user_static",
                                                   "login_user_static"),
                                                  "contents", loser, NULL);
            l->hide_user = PBC_TRUE;
        } else {
            user_field_html = ntmpl_sub_template (p, TMPL_FNAME,
                                                  libpbc_config_getstring
                                                  (p,
                                                   "tmpl_login_user_form_field",
                                                   "login_user_form_field"),
                                                  "contents", loser, NULL);
            l->hide_user = PBC_FALSE;
        }
    } else if (strcmp (static_config, STATIC_USER_FIELD_FASCIST) == 0) {
        if (c != NULL && c->user != NULL ||
            l->user != NULL && l->ride_free_creds == PBC_BASIC_CRED_ID) {
            user_field_html = ntmpl_sub_template (p, TMPL_FNAME,
                                                  libpbc_config_getstring
                                                  (p,
                                                   "tmpl_login_user_static",
                                                   "login_user_static"),
                                                  "contents", loser, NULL);
            l->hide_user = PBC_TRUE;
        } else {
            user_field_html = ntmpl_sub_template (p, TMPL_FNAME,
                                                  libpbc_config_getstring
                                                  (p,
                                                   "tmpl_login_user_form_field",
                                                   "login_user_form_field"),
                                                  "contents", loser, NULL);
            l->hide_user = PBC_FALSE;
        }
    } else {                    /* STATIC_USER_FIELD_NEVER */
        user_field_html = ntmpl_sub_template (p, TMPL_FNAME,
                                              libpbc_config_getstring (p,
                                                                       "tmpl_login_user_form_field",
                                                                       "login_user_form_field"),
                                              "contents", loser, NULL);
        l->hide_user = PBC_FALSE;
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: goodbye: %s",
                      func,
                      (user_field_html ==
                       NULL ? "(NULL)" : user_field_html));

    return (user_field_html);
}

/* get the html for user field, static or dynamic */
char *flb_get_hidden_user_field (pool * p, login_rec * l, login_rec * c,
                                 int reason)
{
    const char *loser = (l != NULL && l->user != NULL ? l->user
                         : (c != NULL ? c->user : NULL));

    if (l != NULL && l->hide_user == PBC_TRUE)
        return (ntmpl_sub_template
                (p, TMPL_FNAME,
                 libpbc_config_getstring (p, "tmpl_login_user_hidden",
                                          "login_user_hidden"), "contents",
                 loser, NULL));
    else
        return (NULL);

}


/**
 * flb_get_custom_login_msg get custom login message if there is such
 * @param p apache memory pool
 * @param appid application id
 * @param appsrvid application server id
 * @param mout output string
 * @return PBC_OK if ok or PBC_FAIL if a problem
 */
int flb_get_custom_login_msg (pool * p, const char *appid,
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
    const char func[] = "flb_get_custom_login_msg";
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

int flb_get_reason_html (pool * p, int reason, login_rec * l,
                         login_rec * c, char **out)
{
    char *tag = NULL;
    char *subst = NULL;
    const char *reasonpage = NULL;
    int ret = PBC_FAIL;
    char func[] = "flb_get_reason_html";

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: hello reason: %d",
                      func, reason);

    switch (reason) {
    case FLB_BAD_AUTH:
        /* username will be static and prefilled use a different bad
           auth message, one without comments about the username */
        /* left the default file the same only config key is different */
        if (c != NULL && c->user != NULL)
            reasonpage =
                libpbc_config_getstring (p,
                                         "tmpl_login_bad_auth_static_user",
                                         "login_bad_auth");
        else
            reasonpage = libpbc_config_getstring (p, "tmpl_login_bad_auth",
                                                  "login_bad_auth");
        break;
    case FLB_REAUTH:
        reasonpage = libpbc_config_getstring (p, "tmpl_login_reauth",
                                              "login_reauth");
        break;
    case FLB_CACHE_CREDS_WRONG:
        reasonpage =
            libpbc_config_getstring (p, "tmpl_login_cache_creds_wrong",
                                     "login_cache_creds_wrong");
        break;
    case FLB_PINIT:
        reasonpage = libpbc_config_getstring (p, "tmpl_login_pinit",
                                              "login_pinit");
        break;
    case FLB_LCOOKIE_EXPIRED:
        reasonpage = libpbc_config_getstring (p, "tmpl_login_expired",
                                              "login_expired");
        break;
    case FLB_FORM_EXPIRED:
        reasonpage = libpbc_config_getstring (p, "tmpl_form_expired",
                                              "form_expired");
        tag = strdup ("time");
        subst = (char *) libpbc_time_text (p, libpbc_config_getint (p,
                                                                    "form_expire_time",
                                                                    PBC_DEFAULT_FORM_EXPIRE_TIME),
                                           PBC_FALSE, PBC_FALSE);
        break;
    case FLB_LCOOKIE_ERROR:
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

static int print_login_page (pool * p, login_rec * l, login_rec * c,
                             int reason)
{
    /* currently, we never clear the login cookie
       we always clear the greq cookie */
    int need_clear_login = 0;
    int need_clear_greq = 1;

    char *hidden_fields = NULL;
    int hidden_len = 0;
    int hidden_needed_len = INIT_HIDDEN_SIZE;
    char *getcred_hidden = NULL;

    char *user_field = NULL;
    char *hidden_user = NULL;
    char now[64];
    int ldur, ldurp;
    char ldurtxt[64], *ldurtyp;
    char func[] = "print_login_page";
    int ret = PBC_FAIL;
    char *login_msg = NULL;
    char *reason_msg = NULL;
    const char *domain = login_host_cookie_domain(p);

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: hello reason: %d",
                      func, reason);

    /* set the cookies */
    if (need_clear_login) {
        print_header (p,
                      "Set-Cookie: %s=%s; domain=%s; path=%s; expires=%s; secure\n",
                      PBC_L_COOKIENAME, PBC_CLEAR_COOKIE, 
                      (domain == NULL ? "" : domain),
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
    if (reason == FLB_REAUTH || reason == FLB_CACHE_CREDS_WRONG ||
        reason == FLB_LCOOKIE_EXPIRED || reason == FLB_LCOOKIE_ERROR)
        if ((ret = flb_get_custom_login_msg (p, l->appid,
                                             l->appsrvid,
                                             &login_msg)) == PBC_FAIL)
            goto done;

    /* if there is no custom login message go get the reason text 
       in the case of expired login messages we use both the 
       the custom message (itis) and the lcookie expired message
     */
    if (login_msg == NULL || reason == FLB_LCOOKIE_EXPIRED)
        if ((ret =
             flb_get_reason_html (p, reason, l, c,
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
                                      "<input type=\"hidden\" name=\"%s\" value=\"%d\">\n"
                                      "<input type=\"hidden\" name=\"%s\" value=\"%ld\">\n",
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
                                      PBC_GETVAR_REPLY, FORM_REPLY,
                                      PBC_GETVAR_CREATE_TS, pbc_time (NULL)
            );
    }

    /* xxx save add'l requests */
    {
        /* xxx sigh, i have to explicitly save this */
        char *target = get_string_arg (p, PBC_GETVAR_CRED_TARGET,
                                       NO_NEWLINES_FUNC);

        if (target) {
            int needed_len;

            getcred_hidden = malloc (GETCRED_HIDDEN_MAX * sizeof (char));

            if (getcred_hidden == NULL) {
                /* Out of memory */
                libpbc_abend (p, "Out of memory allocating for GetCred");
            }

            needed_len = snprintf (getcred_hidden, GETCRED_HIDDEN_MAX,
                                   "<input type=\"hidden\" name=\"%s\" value=\"%s\">\n",
                                   PBC_GETVAR_CRED_TARGET, target);

            if (needed_len > GETCRED_HIDDEN_MAX) {
                /* We were going to overflow, oops. */
                libpbc_abend (p, "Almost overflowed writing GetCred");
            }
        }
    }

    snprintf (now, sizeof (now), "%ld", pbc_time (NULL));

    /* what should the user field look like? */
    user_field = flb_get_user_field (p, l, c, reason);
    if (user_field == NULL) {
        ret = PBC_FAIL;
        goto done;
    }

    /* if the user field should be hidden */
    hidden_user = flb_get_hidden_user_field (p, l, c, reason);

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
                      libpbc_config_getstring (p, "tmpl_login", "login"),
                      "loginuri", PBC_LOGIN_URI,
                      "message", login_msg != NULL ? login_msg : "",
                      "reason", reason_msg != NULL ? reason_msg : "",
                      "curtime", now,
                      "hiddenuser", hidden_user != NULL ? hidden_user : "",
                      "hiddenfields", hidden_fields,
                      "user_field", user_field != NULL ? user_field : "",
                      "getcredhidden",
                      getcred_hidden != NULL ? getcred_hidden : "",
                      "durationtext", ldurtxt, "version",
                      PBC_VERSION_STRING, NULL);

    /* this tags the incoming request as a form reply */

    print_html (p, "\n");

    ret = PBC_OK;

  done:

    if (user_field != NULL)
        free (user_field);

    if (login_msg != NULL)
        free (login_msg);

    if (hidden_user != NULL)
        free (hidden_user);

    if (hidden_fields != NULL)
        free (hidden_fields);

    if (getcred_hidden != NULL)
        free (getcred_hidden);

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: goodbye: %d", func,
                      ret);

    return ret;

}

/* process_basic():
   this routine is responsible for authenticating the user.
   if authentication is not possible (either the user hasn't logged in
   or the password was incorrect) it displays the login page and returns
   LOGIN_INPROGRESS.

   if authentication for this user will never succeed, it returns LOGIN_ERR.

   if authentication has succeeded, no output is generated and it returns
   LOGIN_OK.
 */
static login_result process_basic (pool * p,
                                   const security_context * context,
                                   login_rec * l, login_rec * c,
                                   const char **errstr)
{
    struct credentials *creds = NULL;
    struct credentials **credsp = NULL;
    int also_allow_cred = 0;
    int rcode;
    const char *domain = login_host_cookie_domain(p);

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "process_basic: hello\n");
    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                      "process_basic: create=%d,  reauth=%d\n",
                      c ? c->create_ts : (-1), l->session_reauth);

    /* make sure we're initialized */
    assert (v != NULL);
    assert (l != NULL);
    /* c seems to always be null here. */
    /* XXX need to re-examine exactly what l and c should contain here */
    /* assert(c != NULL); */
    assert (errstr);

    *errstr = NULL;

    if (!v) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "flavor_basic: flavor not correctly configured");
        return LOGIN_ERR;
    }

    /* allow flavor basic to honor login cookies from other flavors */
    also_allow_cred =
        libpbc_config_getint (p, "basic_also_accepts", 0) + 48;

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

    if (l->reply == FORM_REPLY) {
        if (libpbc_config_getswitch (p, "save_credentials", 0)) {
            credsp = &creds;
        }

        /* Make sure response is timely */
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "process_basic: create=%d\n", l->create_ts);
        if (l->create_ts
            && (pbc_time (NULL) >
                (l->create_ts +
                 libpbc_config_getint (p, "form_expire_time",
                                       PBC_DEFAULT_FORM_EXPIRE_TIME)))) {
            *errstr = "The login form has expired.";
            rcode = FLB_FORM_EXPIRED;
        } else if (v->v (p, l->user, l->pass, NULL,
                         l->realm, credsp, errstr) == 0) {
            /* xxx log realm */
            pbc_log_activity (p, PBC_LOG_AUDIT,
                              "%s Authentication success: %s%s%s IP: %s type: %c\n",
                              l->first_kiss,
                              l->user,
                              (l->realm == NULL ? "" : "@"),
                              (l->realm == NULL ? "" : l->realm),
                              (cgiRemoteAddr ==
                               NULL ? "(null)" : cgiRemoteAddr), l->creds);

            /* authn succeeded! */

            /* set the create time */
            l->create_ts = pbc_time (NULL);
            if (c != NULL)
                c->create_ts = pbc_time (NULL);

            /* xxx modify 'l' accordingly ? */

            /* optionally stick @REALM into the username */
            if (l->user && l->realm &&
                libpbc_config_getswitch (p, "append_realm", 0)) {
                /* append @REALM onto the username */
                char *tmp;
                tmp =
                    pbc_malloc (p,
                                strlen (l->user) + strlen (l->realm) + 2);
                if (tmp) {
                    memset (tmp, 0, strlen (l->user) + strlen (l->realm) + 2);
                    strncat (tmp, l->user, strlen (l->user));
                    strncat (tmp, "@", 1);
                    strncat (tmp, l->realm, strlen (l->realm));
                    free (l->user);
                    l->user = tmp;
                } else {
                    pbc_log_activity (p, PBC_LOG_ERROR,
                              "Unable to append realm for user %s realm %s",
                              l->user, l->realm); 
                }
            }

            /* if we got some long-term credentials, save 'em for later */
            if (creds != NULL) {
                char *outbuf;
                int outlen;
                char *out64;

                if (!libpbc_mk_priv
                    (p, context, NULL, 0, creds->str, creds->sz, &outbuf,
                     &outlen, PBC_DEF_CRYPT)) {
                    /* save for later */
                    out64 = malloc (outlen * 4 / 3 + 20);
                    libpbc_base64_encode (p, (unsigned char *) outbuf,
                                          (unsigned char *) out64, outlen);

                    print_header (p,
                                  "Set-Cookie: %s=%s; %ssecure\n",
                                  PBC_CRED_COOKIENAME, out64,
                                  (domain == NULL ? "" : domain));

                    /* free buffer */
                    free (outbuf);
                    free (out64);
                } else {
                    pbc_log_activity (p, PBC_LOG_ERROR,
                                      "libpbc_mk_priv failed: can't save credentials");
                }

                /* xxx save creds for later just in case we're
                   really flavor_getcred. this leaks. */
                l->flavor_extension = creds;

                creds = NULL;
            }

            pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                              "process_basic: good login, goodbye\n");

            return LOGIN_OK;
        } else {
            /* authn failed! */
            if (!*errstr) {
                *errstr = "authentication failed";
            }
            pbc_log_activity (p, PBC_LOG_AUDIT,
                              "%s flavor_basic: login failed for %s: %s",
                              l->first_kiss,
                              l->user == NULL ? "(null)" : l->user,
                              *errstr);

            /* possibly reset username */
            if (!libpbc_config_getswitch
                (p, "retain_username_on_failed_authn", 0)) {
                l->user = NULL; /* in case wrong username */
            }
            rcode = FLB_BAD_AUTH;
        }

        /* If the pinit flag is set, show a pinit login page */
    } else if (l->pinit == PBC_TRUE) {
        *errstr = "pinit";
        rcode = FLB_PINIT;

        /* l->check_error will be set whenever the l cookie isn't valid
           including (for example) when the login cookie has expired.
         */
    } else if (l->check_error) {
        *errstr = l->check_error;
        if (strcmp (l->check_error, "expired"))
            rcode = FLB_LCOOKIE_ERROR;
        else
            rcode = FLB_LCOOKIE_EXPIRED;

        /* if l->check_error is NULL, then 'c' must be set and must
           contain the login cookie information */
    } else if (!c) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "flavor_basic: check_error/c invariant violated");
        abort ();

        /* make sure the login cookie represents credentials for this flavor */
    } else if (c->creds != PBC_BASIC_CRED_ID
               && c->creds != also_allow_cred) {
        *errstr = "cached credentials wrong flavor";
        rcode = FLB_CACHE_CREDS_WRONG;

        /* Auth request entry. */
        /* If reauth, check time limit */
    } else if (l->session_reauth &&
               ((l->session_reauth == 1) ||
                (c
                 && (c->create_ts + (l->session_reauth) < pbc_time (NULL))))) {
        *errstr = "reauthentication required";
        rcode = FLB_REAUTH;

    } else {                    /* valid login cookie */
        pbc_log_activity (p, PBC_LOG_DEBUG_LOW,
                          "flavor_basic: L cookie valid user: %s",
                          l->user);
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "process_basic: L cookie valid, goodbye\n");
        return LOGIN_OK;
    }

    /* User not properly logged in.  Show login page unless quiet login */
    pbc_log_activity (p, PBC_LOG_ERROR,
                      "%s flavor_basic: %s: %s", 
                      l->first_kiss,
                      l->user ? l->user : "(null)",
                      *errstr);
    if (l->flag && strchr (l->flag, 'Q')) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "flavor_basic: quiet login, returning no user");
        l->user = strdup ("");
        return LOGIN_OK;
    }

    if (print_login_page (p, l, c, rcode) != PBC_OK) {
        *errstr = "Problem printing login page.";
        return LOGIN_ERR;
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                      "process_basic: login in progress, goodbye\n");
    return LOGIN_INPROGRESS;
}

struct login_flavor login_flavor_basic = {
    "basic",                    /* name */
    PBC_BASIC_CRED_ID,          /* id; see libpbc_get_credential_id() */
    &init_basic,                /* init_flavor() */
    &process_basic              /* process_request() */
};
