*** ../index.cgi.h	Tue Oct 16 20:32:54 2001
--- ../../pubcookie-v1-cmu2/pubcookie_login-1.20/index.cgi.h	Mon Jul 16 05:47:39 2001
***************
*** 10,16 ****
  
  
      All comments and suggestions to pubcookie@cac.washington.edu
!     More info: http://www.washington.edu/computing/pubcookie/
      Written by the Pubcookie Team
  
      this is the header file for index.cgi the pubcookie login cgi
--- 10,16 ----
  
  
      All comments and suggestions to pubcookie@cac.washington.edu
!     More info: https:/www.washington.edu/pubcookie/
      Written by the Pubcookie Team
  
      this is the header file for index.cgi the pubcookie login cgi
***************
*** 18,24 ****
   */
  
  /*
!     $Id: diff.index.cgi.h,v 1.1 2001/12/14 00:38:59 willey Exp $
   */
  
  typedef struct {
--- 18,24 ----
   */
  
  /*
!     $Id: diff.index.cgi.h,v 1.1 2001/12/14 00:38:59 willey Exp $
   */
  
  typedef struct {
***************
*** 29,35 ****
      char	*version;
      char	creds;
      char	creds_from_greq;
-     char	ride_free_creds;
      char	*appid;
      char	*appsrvid;
      char	*fr;
--- 29,34 ----
***************
*** 48,56 ****
      time_t	last_ts;
      int		serial;
      int		next_securid;
-     int		session_reauth;
      char	*first_kiss;
-     char	reply;
  } login_rec;
  
  /* prototypes */
--- 47,53 ----
***************
*** 62,114 ****
  int cookie_test();
  void notok( void (*)() );
  void notok_no_g_or_l();
- void print_http_header();
  void print_j_test();
  void notok_need_ssl();
  void notok_no_g();
  void notok_formmultipart();
  void notok_generic();
  void notok_bad_agent();
- void print_login_page_part1(char *);
- void print_login_page_part5();
  int check_user_agent();
  void log_message(const char *, ...);
  void log_error(int, const char *, int, const char *, ...);
  void clear_error(const char *, const char *);
- void print_login_page(login_rec *, login_rec *, char *, char *, int, int);
- void print_login_page_lhs1(char *, char *, char *);
- void print_login_page_lhs2(login_rec *);
- void print_login_page_centre();
- void print_login_page_rhs();
- void print_login_page_bottom();
- void print_uwnetid_logo();
  void print_login_page_hidden_stuff(login_rec *);
! void print_login_page_expire_info();
! login_rec *verify_unload_login_cookie (login_rec *);
  int create_cookie(char *, char *, char *, char, char, int, char *, int);
  login_rec *get_query();
! char *check_login(login_rec *, login_rec *);
! char *check_l_cookie(login_rec *, login_rec *);
! void print_redirect_page(login_rec *, login_rec *);
  int get_next_serial();
  char *url_encode();
  char *get_cookie_created(char *);
  char *decode_granting_request(char *);
- char ride_free_zone(login_rec *, login_rec *);
  
! #define RIDE_FREE_TIME (10 * 60)
  #define LOGIN_DIR "/"
  #define THIS_CGI "cindex.cgi"
  #define REFRESH "0"
  #define EXPIRE_LOGIN 60 * 60 * 8
  
! #define TMPL_FNAME "/usr/local/pubcookie/login_templates/"
! 
! /* why print login page ? */
! #define LOGIN_REASON_AUTH_FAIL   "bad auth"
! #define LOGIN_REASON_SECURID     "securid requires reauth"
! #define LOGIN_REASON_NO_L        "no L cookie yet"
! #define LOGIN_REASON_SESS_REAUTH "session timeout requires reauth"
  
  /* some messages about people who hit posts and don't have js on */
  #define PBC_POST_NO_JS_TEXT "Thank you for logging in\n"
--- 59,95 ----
  int cookie_test();
  void notok( void (*)() );
  void notok_no_g_or_l();
  void print_j_test();
  void notok_need_ssl();
  void notok_no_g();
  void notok_formmultipart();
  void notok_generic();
  void notok_bad_agent();
  int check_user_agent();
  void log_message(const char *, ...);
  void log_error(int, const char *, int, const char *, ...);
  void clear_error(const char *, const char *);
  void print_login_page_hidden_stuff(login_rec *);
! login_rec *verify_login_cookie (char *, login_rec *);
  int create_cookie(char *, char *, char *, char, char, int, char *, int);
  login_rec *get_query();
! char *check_login(login_rec *);
! char *check_l_cookie(login_rec *);
! void print_redirect_page(login_rec *);
  int get_next_serial();
  char *url_encode();
  char *get_cookie_created(char *);
  char *decode_granting_request(char *);
  
! #define OK 1
! #define FAIL 0
! 
  #define LOGIN_DIR "/"
  #define THIS_CGI "cindex.cgi"
  #define REFRESH "0"
  #define EXPIRE_LOGIN 60 * 60 * 8
  
! #define TMPL_FNAME "/usr/www/pubcookie_login_templates/"
  
  /* some messages about people who hit posts and don't have js on */
  #define PBC_POST_NO_JS_TEXT "Thank you for logging in\n"
***************
*** 130,138 ****
  #define PROMPT_SECURID "<B>Securid:</B><BR>"
  #define PROMPT_INVALID "<B>BOGUS:</B><BR>"
  
- /* tags the request as a reply from the form */
- #define FORM_REPLY '1'
- 
  /* replacement string for g req cookies once they hav gone thru the cgi */
  #define G_REQ_RECIEVED "g req received"
  
--- 111,116 ----
***************
*** 169,175 ****
  #define NO_FOCUS 0
  
  /* keys and certs */
! #define KEY_DIR "/usr/local/pubcookie/"
  #define CRYPT_KEY_FILE "c_key"
  #define CERT_FILE "pubcookie.cert"
  #define CERT_KEY_FILE "pubcookie.key"
--- 147,153 ----
  #define NO_FOCUS 0
  
  /* keys and certs */
! #define KEY_DIR "/usr/www/pubcookie/"
  #define CRYPT_KEY_FILE "c_key"
  #define CERT_FILE "pubcookie.cert"
  #define CERT_KEY_FILE "pubcookie.key"
***************
*** 179,186 ****
  #define FIRST_SERIAL 23
  
  /* file to get the list of ok browsers from */
- #define OK_BROWSERS_FILE "/usr/local/pubcookie/ok_browsers"
  
  /* utility to send messages to pilot */
  #define SEND_PILOT_CMD "/usr/local/adm/send_pilot_stat.pl"
  
--- 157,164 ----
  #define FIRST_SERIAL 23
  
  /* file to get the list of ok browsers from */
  
+ #define OK_BROWSERS_FILE "/usr/www/pubcookie/ok_browsers"
  /* utility to send messages to pilot */
  #define SEND_PILOT_CMD "/usr/local/adm/send_pilot_stat.pl"
  
***************
*** 230,281 ****
  
  #define J_TEST_TEXT1 "<SCRIPT LANGUAGE=\"JavaScript\"><!-- \
   \
! name = \"cookie_test\"; \n
!     s = (new Date().getSeconds());
!     document.cookie = name + \"=\" + s;
! \n
!     dc = document.cookie;
!     prefix = name + \"=\";
!     begin = dc.indexOf(\"; \" + prefix);
! \n
!     if (begin == -1) {
!         begin = dc.indexOf(prefix);
!         if (begin != 0) returned = \"\";
!     } else
!         begin += 2;
!     end = document.cookie.indexOf(\";\", begin);
! \n
!     if (end == -1)
!         end = dc.length;
!     returned = unescape(dc.substring(begin + prefix.length, end));
! \n
! if ( returned == s ) {
  "
  
! #define J_TEST_TEXT2 "    document.write(\"<P><B><font size=\\\"+1\\\" color=\\\"#FF0000\\\">A problem has been detected!</font></B></P>\");
!     document.write(\"<p><b><font size=\\\"+1\\\">Either you tried to use the BACK button to return to pages you\");
!     document.write(\" visited before the UW NetID login page, or the URL address you opened contains a shortened\");
!     document.write(\" domain name. </font></b></p>\");
!     document.write(\"<p>Review <A HREF=\\\"http://www.washington.edu/computing/web/login-problems.html\\\">Common\");
!     document.write(\" Problems With the UW NetID Login Page</A> for further advice.</p>\");
!     document.write(\"<p>&nbsp;</p>\");
  "
  
! #define J_TEST_TEXT3 "    document.cookie = name + \"=; expires=Thu, 01-Jan-70 00:00:01 GMT\";
! }
! else {
  "
  
! #define J_TEST_TEXT4 "    document.write(\"<P><B><font size=\\\"+1\\\" color=\\\"#FF0000\\\">This browser doesn't accept cookies!</font></B></P>\");
!     document.write(\"<p><b><font size=\\\"+1\\\">Your browser must <a href=\\\"http://www.washington.edu/computing/web/cookies.html\\\">accept cookies</a> in\");
!     document.write(\" order to use the UW NetID login page.</font></b></p>\");
!     document.write(\"<p>&nbsp;</p>\");
  "
  
! #define J_TEST_TEXT5 "}
! 
! // -->
! </SCRIPT>
  "
  
  #define NOTOK_NO_G_TEXT1 "<P><B><font size=\"+1\" color=\"#FF0000\">A problem has been detected!</font></B></P>\
--- 208,259 ----
  
  #define J_TEST_TEXT1 "<SCRIPT LANGUAGE=\"JavaScript\"><!-- \
   \
! name = \"cookie_test\"; \n\
!     s = (new Date().getSeconds());\
!     document.cookie = name + \"=\" + s;\
! \n\
!     dc = document.cookie;\
!     prefix = name + \"=\";\
!     begin = dc.indexOf(\"; \" + prefix);\
! \n\
!     if (begin == -1) {\
!         begin = dc.indexOf(prefix);\
!         if (begin != 0) returned = \"\";\
!     } else\
!         begin += 2;\
!     end = document.cookie.indexOf(\";\", begin);\
! \n\
!     if (end == -1)\
!         end = dc.length;\
!     returned = unescape(dc.substring(begin + prefix.length, end));\
! \n\
! if ( returned == s ) {\
  "
  
! #define J_TEST_TEXT2 "    document.write(\"<P><B><font size=\\\"+1\\\" color=\\\"#FF0000\\\">A problem has been detected!</font></B></P>\");\
!     document.write(\"<p><b><font size=\\\"+1\\\">Either you tried to use the BACK button to return to pages you\");\
!     document.write(\" visited before the UW NetID login page, or the URL address you opened contains a shortened\");\
!     document.write(\" domain name. </font></b></p>\");\
!     document.write(\"<p>Review <A HREF=\\\"http://www.washington.edu/computing/web/login-problems.html\\\">Common\");\
!     document.write(\" Problems With the UW NetID Login Page</A> for further advice.</p>\");\
!     document.write(\"<p>&nbsp;</p>\");\
  "
  
! #define J_TEST_TEXT3 "    document.cookie = name + \"=; expires=Thu, 01-Jan-70 00:00:01 GMT\";\
! }\
! else {\
  "
  
! #define J_TEST_TEXT4 "    document.write(\"<P><B><font size=\\\"+1\\\" color=\\\"#FF0000\\\">This browser doesn't accept cookies!</font></B></P>\");\
!     document.write(\"<p><b><font size=\\\"+1\\\">Your browser must <a href=\\\"http://www.washington.edu/computing/web/cookies.html\\\">accept cookies</a> in\");\
!     document.write(\" order to use the UW NetID login page.</font></b></p>\");\
!     document.write(\"<p>&nbsp;</p>\");\
  "
  
! #define J_TEST_TEXT5 "}\
! \
! // -->\
! </SCRIPT>\
  "
  
  #define NOTOK_NO_G_TEXT1 "<P><B><font size=\"+1\" color=\"#FF0000\">A problem has been detected!</font></B></P>\
