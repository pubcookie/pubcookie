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
     $Id: pbc_config.h,v 1.112 2008/05/16 22:09:10 willey Exp $
 */

#ifndef PUBCOOKIE_CONFIG
#define PUBCOOKIE_CONFIG

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef WIN32
#  define PBC_KEY_DIR (AddSystemRoot(p, "\\inetsrv\\pubcookie\\keys"))
#else
#  include "pbc_path.h"
#endif


#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

/* names of the login servers */
#ifndef WIN32
#define PBC_LOGIN_HOST (libpbc_config_getstring(p,"login_host", "weblogin.washington.edu"))
#endif
#define PBC_LOGIN_URI (libpbc_config_getstring(p,"login_uri", "https://weblogin.washington.edu/"))
#define PBC_RELAY_LOGIN_URI (libpbc_config_getstring(p,"relay_login_uri", ""))
#define PBC_KEYMGT_URI (libpbc_config_getstring(p,"keymgt_uri", "https://weblogin.washington.edu/cgi-bin/keyserver"))
#define PBC_ENTRPRS_DOMAIN (libpbc_config_getstring(p,"enterprise_domain", ".washington.edu"))
#define PBC_TEMPLATES_PATH libpbc_config_getstring(p, "relay_template_path", "")
#define PBC_RELAY_URI libpbc_config_getstring(p, "relay_uri", "https://relay.example.url/relay/index.cgi")
#define CUSTOM_LOGIN_MSG "custom_login_msg"

#if defined (WIN32)
#define PBC_PUBLIC_NAME (libpbc_config_getstring(p, "PUBLIC_dir_name", "PUBLIC"))
#define PBC_NETID_NAME (libpbc_config_getstring(p, "NETID_dir_name", "UWNETID"))
#define PBC_SECURID_NAME (libpbc_config_getstring(p, "SECURID_dir_name", "SECURID"))
#define PBC_DEFAULT_APP_NAME (libpbc_config_getstring(p, "DEFAULT_APP_name", "defaultapp"))
#define PBC_LEGACY_DIR_NAMES (libpbc_config_getint(p, "LegacyDirNames", 1))
#define PBC_DEBUG_TRACE (libpbc_config_getint(p, "Debug_Trace", 0))
#define PBC_IGNORE_POLL (libpbc_config_getint(p, "Ignore_Poll", 0))
#define PBC_AUTHTYPE0 (libpbc_config_getstring(p, "AuthTypeName0", "NONE"))
#define PBC_AUTHTYPE1 (libpbc_config_getstring(p, "AuthTypeName1", "UWNETID"))
#define PBC_AUTHTYPE2 (libpbc_config_getstring(p, "AuthTypeName2", ""))
#define PBC_AUTHTYPE3 (libpbc_config_getstring(p, "AuthTypeName3", "SECURID"))
#define PBC_FILTER_KEY "System\\CurrentControlSet\\Services\\PubcookieFilter"
#define PBC_CLIENT_LOG_FMT (libpbc_config_getstring(p, "ClientLogFormat", "%w(%p)"))
#define PBC_WEB_VAR_LOCATION (libpbc_config_getstring(p, "WebVarLocation", PBC_FILTER_KEY))
#define PBC_RELAY_WEB_KEY "_PBC_Relay_CGI"
#define PBC_INSTANCE_KEY "_PBC_Web_Instances"
#define PBC_DEFAULT_KEY "default"
#define PBC_ENCRYPT_METHOD (libpbc_config_getstring(p, "Encryption_Method", "AES"))
#endif

#define PBC_DEFAULT_FORM_EXPIRE_TIME	60
#define PBC_REFRESH_TIME 0
#define PBC_MIN_INACT_EXPIRE 	      ( 5 * 60 )
#define PBC_DEFAULT_INACT_EXPIRE     ( 30 * 60 )
#define PBC_UNSET_INACT_EXPIRE                 0
#define PBC_MIN_HARD_EXPIRE 	 ( 1 * 60 * 60 )
#define PBC_MAX_HARD_EXPIRE 	( 12 * 60 * 60 )
#define PBC_DEFAULT_HARD_EXPIRE  ( 8 * 60 * 60 )
#define PBC_UNSET_HARD_EXPIRE                  0
#define PBC_GRANTING_EXPIRE               ( 60 )
#define PBC_BAD_AUTH 1
#define PBC_BAD_USER 2
#define PBC_FORCE_REAUTH 3
#define PBC_BAD_G_STATE  4      /* G cookie is unusable, don't return to WLS */
#define PBC_NO_PS_MATCH  5      /* pression token mismatch, redirect */

#define PBC_TRANSCRED_MAX_COOKIES 10
#define PBC_TRANSCRED_MAX_COOKIE_LENGTH 3900
/* cookies can theoretically be up to 4KB, but some browsers
 * really limit it to 4000 bytes, and include the name of the
 * cookie in the limit, so we limit to 3900 bytes for now.
 */

#define PBC_DEFAULT_DIRDEPTH 0

#define PBC_OK   1
#define PBC_FAIL 0
#define PBC_TRUE   1
#define PBC_FALSE  0

#define PBC_PINIT_SUCCESS 2
#define PBC_PINIT_START 1
#define PBC_PINIT_FALSE 0

/* the cookies; l, g, and s have the same format g request and pre s
   are different internally
 */
/* the formmulti part will probably only hang around until will correctly
   handle form/multipart
 */
#define PBC_L_COOKIENAME "pubcookie_l"
#define PBC_G_COOKIENAME "pubcookie_g"
#define PBC_G_REQ_COOKIENAME "pubcookie_g_req"
#define PBC_S_COOKIENAME "pubcookie_s"
#define PBC_PRE_S_COOKIENAME "pubcookie_pre_s"
#define PBC_FORM_MP_COOKIENAME "pubcookie_formmultipart"
#define PBC_CRED_COOKIENAME "pubcookie_cred"
#define PBC_CRED_TRANSFER_COOKIENAME "pubcookie_transcred"
#define PBC_ODKEY_COOKIENAME "OnDemandKey"
#define PBC_ODKEY_ENVNAME "ON_DEMAND_KEY"

/* this apache module stuff should go into something like mod_pubcookie.h */
#define PBC_AUTH_FAILED_HANDLER "pubcookie-failed-handler"
#define PBC_BAD_USER_HANDLER "pubcookie-bad-user"
#define PBC_END_SESSION_REDIR_HANDLER "pubcookie-end-session-redir-handler"
#define PBC_STOP_THE_SHOW_HANDLER "pubcookie-stop-the-show-handler"

#define PBC_G_REQ_EXP (10 * 60) /* shrug?  ten minutes? */
#define PBC_PRE_S_EXP (10 * 60) /* shrug?  ten minutes? */

/* set in apache config to clear session cookie and redirect to weblogin */
#define PBC_END_SESSION_ARG_REDIR   "redirect"
#define PBC_END_SESSION_ARG_CLEAR_L "clearLogin"
#define PBC_END_SESSION_ARG_ON      "On"
#define PBC_END_SESSION_ARG_OFF     "Off"

#define PBC_END_SESSION_NOPE          0 /* no end session */
#define PBC_END_SESSION_ONLY          1 /* end session only */
#define PBC_END_SESSION_REDIR         2 /* end session, redirect to WLS */
#define PBC_END_SESSION_CLEAR_L       4 /* end session, redirect to WLS, 
                                           clear Login cookie */
#define PBC_END_SESSION_ANY           127       /* any of the above, except NONE */

#define LOGOUT_ACTION_UNSET          -1
#define LOGOUT_ACTION_NOTHING        0
#define LOGOUT_ACTION_CLEAR_L        1  /* expires the L cookie */
#define LOGOUT_ACTION_CLEAR_L_NO_APP 2  /* only way to clear a L cookie */

#define PBC_SESSION_REAUTH 1
#define PBC_SESSION_REAUTH_NO 0
#define PBC_UNSET_SESSION_REAUTH -1

#define PBC_SUPER_DEBUG 1
#define PBC_CLEAR_COOKIE "clear"
#define PBC_SET "set"

#define EARLIEST_EVER "Fri, 11-Jan-1990 00:00:01 GMT"

/* this is the content of the redirect page's body if there is a POST */

#define PBC_POST_NO_JS_HTML1 "<HTML><HEAD></HEAD>\n \
<BODY BGCOLOR=\"white\" onLoad=\"document.query.submit.click()\">\n \
<CENTER>\n \
<FORM METHOD=\"POST\" ACTION=\""
         /* url of login page */
#define PBC_POST_NO_JS_HTML2 "\" NAME=\"query\">\n \
<INPUT TYPE=\"hidden\" NAME=\"post_stuff\" VALUE=\""
         /* packages POST stuff */
#define PBC_POST_NO_JS_HTML3 "\">\n \
<TABLE CELLPADDING=0 CELLSPACING=0 BORDER=0 WIDTH=520><TR><TD WIDTH=300 VALIGN=\"MIDDLE\"> <IMG SRC=\""
         /* UWnetID logdo url */
#define PBC_POST_NO_JS_HTML4 "\" ALT=\"UW NetID Login\" HEIGHT=\"64\" WIDTH=\"208\"> \n \
<SCRIPT LANGUAGE=\"JavaScript\">\n\
document.write(\"<P>Your browser should move to the next page in a few seconds.  If it doesn't, please click the button to continue.<P>\")\n \
</SCRIPT> <NOSCRIPT> \
<P>You do not have Javascript turned on, please click the button to continue.<P>\n </NOSCRIPT>\n</TABLE>\n \
<INPUT TYPE=\"SUBMIT\" NAME=\"submit\" VALUE=\""
        /* button text (PBC_POST_NO_JS_BUTTON) */
#define PBC_POST_NO_JS_HTML5 "\">\n </FORM>\n"
#define PBC_POST_NO_JS_HTML6 "</CENTER>\n </BODY></HTML>\n"

#define PBC_POST_NO_JS_BUTTON "Click here to continue"
#define PBC_WEBISO_LOGO "images/login.gif"

/* 
 for the GET line to the login server
 this is used in the login script too
 */
#define PBC_GETVAR_APPSRVID "one"
#define PBC_GETVAR_APPID "two"
#define PBC_GETVAR_CREDS "three"
#define PBC_GETVAR_VERSION "four"
#define PBC_GETVAR_METHOD "five"
#define PBC_GETVAR_HOST "six"   /* host portion of url, could be host:port */
#define PBC_GETVAR_URI "seven"
#define PBC_GETVAR_ARGS "eight"
#define PBC_GETVAR_FR "fr"
/* new in dec 1999 */
#define PBC_GETVAR_REAL_HOST "hostname" /* machine's hostname         */
#define PBC_GETVAR_APPSRV_ERR "nine"    /* let the login server know why */
#define PBC_GETVAR_FILE_UPLD "file"     /* for form multipart testing    */
#define PBC_GETVAR_FLAG "flag"  /* not currently used            */
#define PBC_GETVAR_REFERER "referer"    /* to knit together the referer  */
#define PBC_GETVAR_POST_STUFF "post_stuff"      /* post args               */
/* new in Aug 2001 */
#define PBC_GETVAR_SESSION_REAUTH "sess_re"     /* session delta force reauth */
#define PBC_GETVAR_REPLY "reply"        /* tags a reply from the form */
/* new in oct 2001 */
#define PBC_GETVAR_DURATION "duration"
/* new in March 2002 to support short term logout */
#define PBC_GETVAR_LOGOUT_ACTION "logout_action"
/* added previously but only now as defines March 2002 */
#define PBC_GETVAR_FIRST_KISS "first_kiss"
#define PBC_GETVAR_USER "user"
#define PBC_GETVAR_REALM "realm"
#define PBC_GETVAR_PASS "pass"
#define PBC_GETVAR_PASS2 "pass2"
#define PBC_GETVAR_GREQ_CREDS "creds_from_greq"
/* added May 2002 willey*/
#define PBC_GETVAR_PINIT "pinit"
/* added June 2002 leg */
#define PBC_GETVAR_CRED_TARGET "cred_target"
/* added June 2002 willey */
#define PBC_GETVAR_PRE_SESS_TOK "pre_sess_tok"

#define PBC_GETVAR_RELAY_URL "relay_url"        /* relay url                 */
#define PBC_GETVAR_CREATE_TS "create_ts"        /* time form issued          */

/* 
 things that are used both places (module and the library)
 */
#define PBC_CREDS_NONE    '0'

/* never make the username field static */
#define STATIC_USER_FIELD_NEVER "never"
/* allow the use to change the username field if the login
   cookie is expired to 'logged out
 */
#define STATIC_USER_FIELD_KIND "kind"
/* username field is static whenever there is a login cookie 
   with a username available
 */
#define STATIC_USER_FIELD_FASCIST "always"

#define PBC_COOKIE_TYPE_NONE  '0'
#define PBC_COOKIE_TYPE_G     '1'
#define PBC_COOKIE_TYPE_S     '2'
#define PBC_COOKIE_TYPE_L     '3'
#define PBC_COOKIE_TYPE_PRE_S '4'

#define PBC_BASIC_CRED_ID '1'
#define PBC_GETCRED_CRED_ID '2'
#define PBC_UWSECURID_CRED_ID '3'

/* stealing chars from the version space to use for other things */
#define PBC_VERSION_REAUTH_YES 'R'
#define PBC_VERSION_REAUTH_NO  'N'

/* macros to support older version of apache */

#ifdef APACHE
#ifndef pbc_malloc
#define pbc_malloc(p, x) ap_palloc(p, x)
#endif
#define pbc_free(p, x) libpbc_void(p, x)
#ifndef pbc_strdup
#define pbc_strdup(p, x) ap_pstrdup(p, x)
#endif
#define pbc_strndup(p, s, n) ap_pstrdup(p, s, n)
#ifdef APACHE2
/* in the module use apr_file_open etc. */
#define pbc_fopen(p, x, y) fopen(x, y)
#define pbc_fclose(p, x) fclose(x)
#else
#define pbc_fopen(p, x, y) ap_pfopen(p, x, y)
#define pbc_fclose(p, x) ap_pfclose(p, x)
#endif
#endif

#ifndef pbc_malloc
#define pbc_malloc(p, x) malloc(x)
#endif
#ifndef pbc_free
#define pbc_free(p, x) free(x)
#endif
#ifndef pbc_strdup
#define pbc_strdup(p, x) strdup(x)
#endif
#ifndef pbc_strndup
#define pbc_strndup(p, s, n) (char *)strncpy(calloc(n+1, sizeof(char)), s, n)
#endif
#ifndef pbc_fopen
#define pbc_fopen(p, x, y) fopen(x, y)
#endif
#ifndef pbc_fclose
#define pbc_fclose(p, x) fclose(x)
#endif

#endif /* !PUBCOOKIE_CONFIG */
