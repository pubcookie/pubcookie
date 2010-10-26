/* 09/04/01, Russell Tokuyama (UH ITS); Localized for UH. */
/* 

    Copyright 1999, University of Washington.  All rights reserved.

     ____        _                     _    _
    |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
    | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
    |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
    |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|


    All comments and suggestions to pubcookie@cac.washington.edu
    More info: http://www.washington.edu/computing/pubcookie/
    Written by the Pubcookie Team

    this is the header file for index.cgi the pubcookie login cgi

 */

/*
    $Id: index.cgi.h,v 1.1 2001/12/14 00:38:59 willey Exp $
 */

typedef struct {
    char	*args;
    char	*uri;
    char	*host;
    char	*method;
    char	*version;
    char	creds;
    char	creds_from_greq;
    char	*appid;
    char	*appsrvid;
    char	*fr;
    char	*user;
    char	*pass;
    char	*pass2;
    char	*post_stuff;
    char	*real_hostname;
    char	*appsrv_err;
    char	*appsrv_err_string;
    char	*file;
    char	*flag;
    char	*referer;
    char	type;
    time_t	create_ts;
    time_t	last_ts;
    int		serial;
    int		next_securid;
    char	*first_kiss;
} login_rec;

/* prototypes */
int cgiMain();
char *auth_kdc(const char *, const char *);
char *auth_ndcpasswd(const char *, const char *);
char *auth_securid(char *, char *, int, login_rec *);
char *auth_ldap(const char *, const char *);
void abend(char *);
int cookie_test();
void notok( void (*)() );
void notok_no_g_or_l();
void print_http_header();
void print_j_test();
void notok_need_ssl();
void notok_no_g();
void notok_formmultipart();
void notok_generic();
void notok_bad_agent();
void print_login_page_part1(int);
void print_login_page_part5();
int check_user_agent();
void log_message(const char *, ...);
void log_error(int, const char *, int, const char *, ...);
void clear_error(const char *, const char *);
void print_login_page(login_rec *, char *, char *, int, int);
void print_login_page_lhs1(char *, char *, char *);
void print_login_page_lhs2(login_rec *);
void print_login_page_centre();
void print_login_page_rhs();
void print_login_page_bottom();
void print_uwnetid_logo();
void print_login_page_hidden_stuff(login_rec *);
void print_login_page_expire_info();
login_rec *verify_login_cookie (char *, login_rec *);
int create_cookie(char *, char *, char *, char, char, int, char *, int);
login_rec *get_query();
char *check_login(login_rec *);
char *check_l_cookie(login_rec *);
void print_redirect_page(login_rec *);
int get_next_serial();
char *url_encode();
char *get_cookie_created(char *);
char *decode_granting_request(char *);

#define OK 1
#define FAIL 0

#define LOGIN_DIR "/"
#define THIS_CGI "cindex.cgi"
#define REFRESH "0"
#define EXPIRE_LOGIN 60 * 60 * 8

/* some messages about people who hit posts and don't have js on */
#define PBC_POST_NO_JS_TEXT "Thank you for logging in\n"

#define PRINT_LOGIN_PLEASE "Please log in."
#define TROUBLE_CREATING_COOKIE "Trouble creating cookie.  Please re-enter."
#define PROBLEMS_PERSIST "If problems persist contact help@hawaii.edu."
#define AUTH_FAILED_MESSAGE1 "Login failed.  Please re-enter.\n"
#define AUTH_FAILED_MESSAGE2 "<p>Please make sure your <b>Caps Lock key is OFF</b> and your <b> Number Lock key is ON</b>.</p>"
#define AUTH_TROUBLE "There are currently problems with authentication services, please try again later"

#define CHECK_LOGIN_RET_BAD_CREDS "invalid creds"
#define CHECK_LOGIN_RET_SUCCESS "success"
#define CHECK_LOGIN_RET_FAIL "fail"

#define EARLIEST_EVER "Fri, 11-Jan-1990 00:00:01 GMT"
#define PROMPT_UWNETID "<B>UW NetID:</B><BR>"
#define PROMPT_PASSWD "<B>Password:</B><BR>"
#define PROMPT_SECURID "<B>Securid:</B><BR>"
#define PROMPT_INVALID "<B>BOGUS:</B><BR>"
#define PROMPT_UHNETID "<B>ITS Username:</B><BR>"

/* replacement string for g req cookies once they hav gone thru the cgi */
#define G_REQ_RECIEVED "g req received"

/* these are creds strings for meta-auth */
#define NDCUSERNAME "username"
#define NDCPASSWORD "ndcpasswd"

/* how we accentuate warning messages */
#define PBC_EM1_START "<P><B><FONT COLOR=\"#FF0000\" SIZE=\"+1\">" 
#define PBC_EM1_END "</FONT></B><BR></P>"
/* how we accentuate less important warning messages */
#define PBC_EM2_START "<P><B><FONT SIZE=\"+1\">" 
#define PBC_EM2_END "</FONT></B><BR></P>"

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

/* a date before pubcookie that is guaranteed to be expired */
#define EXPIRED_EXPIRES "Fri, 11-Jan-1990 00:00:01 GMT"

/* flags to send to print_login_page_part1 */
#define YES_FOCUS 1
#define NO_FOCUS 0

/* keys and certs */
#define KEY_DIR "/usr/local/pubcookie/"
#define CRYPT_KEY_FILE "c_key"
#define CERT_FILE "pubcookie.cert"      /* granting cert */
#define CERT_KEY_FILE "pubcookie.key"   /* granting key */

/* some misc settings */
#define SERIAL_FILE "/tmp/s"
#define FIRST_SERIAL 23

/* file to get the list of ok browsers from */
#define OK_BROWSERS_FILE "/usr/local/pubcookie/ok_browsers"

/* utility to send messages to pilot */
#define SEND_PILOT_CMD "/usr/local/adm/send_pilot_stat.pl"


/* text */

/* Right hand side text */
#define LOGIN_PAGE_RHS_TEXT "<td width=\"250\" valign=\"MIDDLE\">\n\
<p>\n\
<a href=\"http://www.hawaii.edu/help/accounts/idreqinfo.html\">Need a UH ITS Username?</a>\n\
</p>\n\
<p>\n\
<a href=\"http://www.hawaii.edu/infotech/userprefs/\">Forget your password?</a>\n\
</p>\n\
<dl>\n\
<dt>Have a question?</dt>\n\
<dd>\n\
  <a href=\"http://www.hawaii.edu/help/accounts/idreqinfo.html\">Read About UH ITS Usernames</a><BR>\n\
  <a href=\"http://www.hawaii.edu/help/\">Contact ITS Help Desk</a>\n\
</dd>\n\
</dl>\n\
</td>"

/* login page bottom text about expires and such */
#define LOGIN_PAGE_BOTTOM_TEXT "</tr>\n\
\n\
<tr>\n\
<td colspan=\"5\" align=\"center\">\n\
<p>Login gives you 8-hour access without repeat login to ITS Username-protected Web resources.</p>\n\
<p><strong>WARNING</strong>: Protect your privacy! Prevent unauthorized use!<br>\n\
<a href=\"http://www.hawaii.edu/web/logout.html\">Completely exit your Web browser when you are finished.</a></p>\n\
</td>\n\
</tr>"

#define NOTOK_NO_G_OR_L_TEXT1 "<P><B><font size=\"+1\" color=\"#FF0000\">\
A problem has been detected!</font></B></P> \
\
<p><b><font size=\"+1\">Either your browser is not configured to accept \
cookies,\
or the URL address you opened contains a shortened domain name.</font></b></p>\
\
<p>Review \
<A HREF=\"http://www.hawaii.edu/web/login-problems.html\">Common\
Problems With the UH Web Login Page</A> for further advice.</p>\
\
<p>&nbsp;</p>"

#define J_TEST_TEXT1 "<SCRIPT LANGUAGE=\"JavaScript\"><!-- \
 \
name = \"cookie_test\"; \n
    s = (new Date().getSeconds());
    document.cookie = name + \"=\" + s;
\n
    dc = document.cookie;
    prefix = name + \"=\";
    begin = dc.indexOf(\"; \" + prefix);
\n
    if (begin == -1) {
        begin = dc.indexOf(prefix);
        if (begin != 0) returned = \"\";
    } else
        begin += 2;
    end = document.cookie.indexOf(\";\", begin);
\n
    if (end == -1)
        end = dc.length;
    returned = unescape(dc.substring(begin + prefix.length, end));
\n
if ( returned == s ) {
"

#define J_TEST_TEXT2 "    document.write(\"<P><B><font size=\\\"+1\\\" color=\\\"#FF0000\\\">A problem has been detected!</font></B></P>\");
    document.write(\"<p><b><font size=\\\"+1\\\">Either you tried to use the BACK button to return to pages you\");
    document.write(\" visited before the UH Web Login page, or the URL address you opened contains a shortened\");
    document.write(\" domain name. </font></b></p>\");
    document.write(\"<p>Review <A HREF=\\\"http://www.hawaii.edu/web/login-problems.html\\\">Common\");
    document.write(\" Problems With the UH Web Login Page</A> for further advice.</p>\");
    document.write(\"<p>&nbsp;</p>\");
"

#define J_TEST_TEXT3 "    document.cookie = name + \"=; expires=Thu, 01-Jan-70 00:00:01 GMT\";
}
else {
"

#define J_TEST_TEXT4 "    document.write(\"<P><B><font size=\\\"+1\\\" color=\\\"#FF0000\\\">This browser doesn't accept cookies!</font></B></P>\");
    document.write(\"<p><b><font size=\\\"+1\\\">Your browser must <a href=\\\"http://www.hawaii.edu/web/cookies.html\\\">accept cookies</a> in\");
    document.write(\" order to use the UH Web Login page.</font></b></p>\");
    document.write(\"<p>&nbsp;</p>\");
"

#define J_TEST_TEXT5 "}

// -->
</SCRIPT>
"

#define NOTOK_NO_G_TEXT1 "<P><B><font size=\"+1\" color=\"#FF0000\">A problem has been detected!</font></B></P>\
\
<p><b><font size=\"+1\">Either you tried to use the BACK button to return to pages you visited before the UH Web Login page, or the URL address you opened contains a shortened domain name. </font></b></p>\
\
<p>Review <A HREF=\"http://www.hawaii.edu/web/login-problems.html\">Common Problems With the UH Web Login Page</A> for further advice.</p>\
\
<p>&nbsp;</p>\
"

#define NOTOK_FORMMULTIPART_TEXT1 "<P><B><font size=\"+1\" color=\"#FF0000\">A problem has been detected!</font></B></P> \
\
<p><b><font size=\"+1\">The resource you requested requires \"multipart/form-data\" capabilities not supported by the UH Web Login page. Please email <a href=\"mailto:help@hawaii.edu\">help@hawaii.edu</a> for further assistance.</font></b></p>\
\
<p>&nbsp;</p>\
"

#define NOTOK_BAD_AGENT_TEXT1 "<P><B><font size=\"+1\" color=\"#FF0000\">This browser is either incompatible or has serious security flaws.</font></B></P>\
\
<p><b><font size=\"+1\">Please upgrade to the most recent version of either <A HREF=\"http://home.netscape.com/computing/download/index.html\">Netscape Navigator</A>, <A HREF=\"http://www.microsoft.com/windows/ie/default.htm\">Internet Explorer</A>, or <A HREF=\"http://www.opera.com/\">Opera</A>.  "

#define NOTOK_BAD_AGENT_TEXT2 "<P>\
\
Please email <a href=\"mailto:help@hawaii.edu\">help@hawaii.edu</a> for further assistance.</font></b></p>\
\
<p>&nbsp;</p>\
"

#define NOTOK_GENERIC_TEXT1 "<P><B><font size=\"+1\" color=\"#FF0000\">A problem has been detected!</font></B></P> \
\
<p>Review <A HREF=\"http://www.hawaii.edu/web/login-problems.html\">Common Problems With the UH Web Login Page</A> for further advice.</p>\
\
<p>&nbsp;</p>\
"

#define NOTOK_NEEDSSL_TEXT1 "<P><B><font size=\"+1\" color=\"#FF0000\">A problem has been detected!</font></B></P> \n\
<P>I'm sorry this page is only accessible via a ssl protected connection.<BR>\n\
"

