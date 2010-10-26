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
  $Id: index.cgi.h,v 1.64 2008/05/16 22:09:10 willey Exp $
 */

#ifndef PUBCOOKIE_LOGIN_CGI
#define PUBCOOKIE_LOGIN_CGI

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#include "pbc_time.h"

/* cgic---needed for typenames */
#ifdef HAVE_CGIC_H
# include <cgic.h>
#endif /* HAVE_CGIC_H */

#include "pubcookie.h"
#include "security.h"

typedef struct
{
    char *args;
    char *uri;
    char *host;
    char *method;
    char *version;
    char creds;
    char creds_from_greq;
    char ride_free_creds;
    char *appid;
    char *appsrvid;
    char *fr;
    char *user;
    int hide_user;
    char *realm;
    char *pass;
    char *pass2;
    char *post_stuff;
    char *real_hostname;
    char *appsrv_err;
    char *appsrv_err_string;
    char *file;
    char *flag;
    char *referer;
    char type;
    pbc_time_t create_ts;
    pbc_time_t expire_ts;
    int pre_sess_token;
    int session_reauth;
    int duration;
    char *first_kiss;
    int reply;
    int alterable_username;
    int pinit;
    int pre_sess_tok;
    char *check_error;
    char *relay_uri;
    void *flavor_extension;     /* used for ad-hoc purposes until
                                   we add a general extension mechanism to the
                                   cookie structure */
}
login_rec;

struct browser
{
    char agent[1024];
    int timeout;
    int allow;
    int deny;
    struct browser *next;
    struct browser *prev;
};

typedef struct browser browser_rec;

typedef enum
{
    NOTOK_OK = 0,               /* really ok */
    NOTOK_GENERIC = 1,          /* who knows? */
    NOTOK_FORMMULTIPART = 2,    /* we don't support form multipart */
    NOTOK_BADAGENT = 3,         /* not a supported or supportable browser */
    NOTOK_NEEDSSL = 4           /* requires ssl, unused */
}
notok_event;

#define FREE_RIDE_MESSAGE "You entered it less than 10 minutes ago.<BR>\n"

/* prototypes */
int cgiMain ();
void abend (pool *, char *);
int cookie_test (pool *, const security_context *, login_rec *,
                 login_rec *);
void notok (pool *, notok_event, char *);
void print_http_header (pool *);
void notok_need_ssl (pool *);
void notok_formmultipart (pool *);
void notok_generic (pool *);
void notok_bad_agent (pool *);
void print_login_page_part1 (pool *, char *);
void print_login_page_part5 (pool *);
int check_user_agent (pool *);
void log_message (pool *, const char *, ...);
void log_error (pool *, int, const char *, int, const char *, ...);
void clear_error (pool *, const char *, const char *);
void print_uwnetid_logo (pool *);
login_rec *verify_unload_login_cookie (pool *, const security_context *,
                                       login_rec *);
int create_cookie (pool *, const security_context *, char *, char *, char *,
                   char *, char, char, int, pbc_time_t, pbc_time_t, char *,
                   const char *host, int, char);
int get_cookie (pool * p, char *name, char *result, int max, int n);
login_rec *get_query (pool *);
char *check_login (pool *, login_rec *, login_rec *);
char *check_l_cookie (pool *, const security_context *, login_rec *,
                      login_rec *);
void print_redirect_page (pool *, const security_context *, login_rec *,
                          login_rec *);
char *url_encode (pool *, char *);
char *get_cookie_created (pool *, char *);
char *decode_granting_request (pool *, char *, char **peerp);
const char *login_host (pool *);
const char *login_host_cookie_domain (pool *);
const char *enterprise_domain (pool *);
int set_pinit_cookie (pool *);
int clear_pinit_cookie (pool *);
char *get_string_arg (pool *, char *name, cgiFormResultType (*f) ());

/* print part of the HTML */
void print_html (pool *, const char *format, ...);
/* print it from the template "fname" */
void tmpl_print_html (pool *, const char *fpath, const char *fname, ...);

void ntmpl_print_html (pool * p, const char *fname, ...);

char *ntmpl_sub_template (pool *, const char *, const char *, ...);

/* print part of the HTTP headers */
void print_header (pool *, const char *format, ...);

#define RIDE_FREE_TIME (10 * 60)
#define LOGIN_DIR "/"
#define THIS_CGI "cindex.cgi"
#define REFRESH "0"
#define DEFAULT_LOGIN_EXPIRE (8 * 60 * 60)
#define APP_LOGOUT_STR "app_logout_string"
#define APP_LOGOUT_STR_SEP '-'

#define STATUS_HTML_REFRESH "<meta http-equiv=\"Refresh\" content=\"%d;URL=/?countdown=%d\">"
#define STATUS_INIT_SIZE 256

/* the pinit cookie is used to transition from a pinit login to 
   a pinit responce */
#define PBC_PINIT_COOKIENAME "pinit"

/* some messages about people who hit posts and don't have js on */
#define PBC_POST_NO_JS_TEXT "Thank you for logging in\n"

/* special strings about time remaining */
#define REMAINING_EXPIRED "expired"
#define REMAINING_UNKNOWN "unknown"

/* tags the request as a reply from the form */
#define FORM_REPLY 1

/* identify log messages */
#define ANY_LOGINSRV_MESSAGE "PUBCOOKIE_LOGINSRV_LOG"
#define SYSERR_LOGINSRV_MESSAGE "PUBCOOKIE SYSTEM ERROR"

/* flags to send to get_string_arg */
#define YES_NEWLINES_FUNC cgiFormString
#define NO_NEWLINES_FUNC cgiFormStringNoNewlines

/* flags to send to print_login_page */
#define YES_CLEAR_LOGIN 1
#define NO_CLEAR_LOGIN 0
#define YES_CLEAR_GREQ 1
#define NO_CLEAR_GREQ 0

/* flags to send to print_login_page_part1 */
#define YES_FOCUS 1
#define NO_FOCUS 0

/* how big can a filled-in template be? */
#define MAX_EXPANDED_TEMPLATE_SIZE (110*1024)

#endif /* PUBCOOKIE_LOGIN_CGI */
