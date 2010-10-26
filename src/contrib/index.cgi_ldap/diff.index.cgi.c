*** index.cgi.c	Wed Oct 17 15:17:39 2001
--- ../../pubcookie-v1-cmu2/pubcookie_login-1.20/index.cgi.c	Mon Jul 16 07:33:25 2001
***************
*** 1,4 ****
- /* 09/04/01, Russell Tokuyama (UH ITS); Localized for UH. */
  /*
  
      Copyright 1999-2001, University of Washington.  All rights reserved.
--- 1,3 ----
***************
*** 11,17 ****
  
  
      All comments and suggestions to pubcookie@cac.washington.edu
!     More info: http://www.washington.edu/computing/pubcookie/
      Written by the Pubcookie Team
  
      this is the pubcookie login cgi, YEAH!
--- 10,16 ----
  
  
      All comments and suggestions to pubcookie@cac.washington.edu
!     More info: https:/www.washington.edu/pubcookie/
      Written by the Pubcookie Team
  
      this is the pubcookie login cgi, YEAH!
***************
*** 21,27 ****
   */
  
  /*
!     $Id: diff.index.cgi.c,v 1.1 2001/12/14 00:38:59 willey Exp $
   */
  
  
--- 20,26 ----
   */
  
  /*
!     $Id: diff.index.cgi.c,v 1.1 2001/12/14 00:38:59 willey Exp $
   */
  
  
***************
*** 34,39 ****
--- 33,39 ----
  #include <stdio.h>
  #include <stdlib.h>
  #include <string.h>
+ #include <strings.h>
  #include <sys/utsname.h>
  #include <sys/socket.h>
  #include <sys/time.h>
***************
*** 43,48 ****
--- 43,49 ----
  #include <pem.h>
  /* krb5  */
  #include <com_err.h>
+ #include <krb5-types.h>
  #include <krb5.h>
  /* securid */
  #include "securid.h"
***************
*** 54,59 ****
--- 55,66 ----
  #include "index.cgi.h"
  /* cgic */
  #include <cgic.h>
+ #include "k5auth.h"
+ #ifdef KRB4
+ #include "k4auth.h" 
+ #endif
+ 
+ int login_debug=0;
  
  #ifdef MAKE_MIRROR
  /* the mirror file is a mirror of what gets written out of the cgi */
***************
*** 61,69 ****
  FILE	*mirror;
  #endif 
  
-   /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
-  /*	general utility thingies                                            */
  /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
  
  /* this returns first cookie for a given name */
  int get_cookie(char *name, char *result, int max)
--- 68,167 ----
  FILE	*mirror;
  #endif 
  
  /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
+ /*	general utility thingies                                            */
+ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
+ 
+ /*
+  * return the length of the passed file in bytes or 0 if we cant tell
+  * resets the file postion to the start
+  */
+ static long file_size(FILE *afile)
+ {
+   long len;
+   if(fseek(afile,0,SEEK_END)!=0)
+     return 0;
+   len=ftell(afile);
+   if(fseek(afile,0,SEEK_SET)!=0)
+     return 0;
+   return len;
+ }
+ 
+ /*
+  * return a template html file
+  */
+ static char *get_file_template(const char *fname)
+ {
+   char *template;
+   FILE *tmpl_file=fopen(fname,"r");
+   long len;
+   if(tmpl_file==0) {
+     log_error(5, "abend", 0,"cant open template file '%s'",fname);
+     return 0;
+   }
+   len=file_size(tmpl_file);
+   if(len==0)
+     return 0;
+   template=malloc(len+1);
+   *template=0;
+   if(fread(template,1,len,tmpl_file)!=len)
+     len=0;
+   if(len==0) {
+     free(template);
+     return 0;
+   }
+   template[len]=0;
+   return template;
+ }
+ 
+ /*
+  * print to the passed buffer given the name of the file containing the %s info
+  */
+ static void buf_template_vprintf(const char *fname,char *dst,size_t n,va_list ap)
+ {
+   char *template=get_file_template(fname);
+   vsnprintf(dst,n,template,ap);
+   free(template);
+ }
+ 
+ 
+ void print_out(char *format,...)
+ {
+     va_list	args;
+ 
+     va_start(args, format);
+     vprintf(format, args);
+   if(login_debug)
+     vfprintf(stderr, format, args);
+ #ifdef MAKE_MIRROR
+     vfprintf(mirror, format, args);
+ #endif 
+     va_end(args);
+ 
+ }
+ 
+ /*
+  * print out using a template
+  */
+ static void tmpl_print_out(const char *fname,...)
+ {
+   char *format;
+ #define MAX_EXPANDED_TEMPLATE_SIZE (110*1024)
+   char buf[MAX_EXPANDED_TEMPLATE_SIZE];
+   va_list args;
+   va_start(args,fname);
+   format=get_file_template(fname);
+   buf_template_vprintf(fname,buf,sizeof(buf),args);
+   va_end(args);
+ 
+   printf("%s",buf);
+   if(login_debug)
+     fprintf(stderr,"%s",buf);
+ #ifdef MAKE_MIRROR
+     fprintf(mirror,"%s",buf);
+ #endif 
+     
+ }
  
  /* this returns first cookie for a given name */
  int get_cookie(char *name, char *result, int max)
***************
*** 172,180 ****
  login_rec *load_login_rec(login_rec *l) 
  {
  
! #ifdef DEBUG
      fprintf(stderr, "load_login_rec: hello\n");
- #endif
  
      /* only created by the login cgi */
      l->next_securid     = get_int_arg("next_securid");
--- 270,277 ----
  login_rec *load_login_rec(login_rec *l) 
  {
  
!   if(login_debug)
      fprintf(stderr, "load_login_rec: hello\n");
  
      /* only created by the login cgi */
      l->next_securid     = get_int_arg("next_securid");
***************
*** 203,211 ****
      l->flag 		= get_string_arg(PBC_GETVAR_FLAG, NO_NEWLINES_FUNC);
      l->referer 		= get_string_arg(PBC_GETVAR_REFERER, NO_NEWLINES_FUNC);
  
! #ifdef DEBUG
      fprintf(stderr, "load_login_rec: bye\n");
- #endif
  
      return(l);
  
--- 300,307 ----
      l->flag 		= get_string_arg(PBC_GETVAR_FLAG, NO_NEWLINES_FUNC);
      l->referer 		= get_string_arg(PBC_GETVAR_REFERER, NO_NEWLINES_FUNC);
  
!   if(login_debug)
      fprintf(stderr, "load_login_rec: bye\n");
  
    return(l);
  
***************
*** 321,326 ****
--- 417,425 ----
  
      va_end(args);
  
+   if(login_debug)
+     fprintf(stderr,"log_message:%s\n",message);
+ 
      libpbc_debug(message);
  
  }
***************
*** 400,421 ****
  }
  #endif 
  
- void print_out(char *format,...)
- {
-     va_list	args;
- 
-     va_start(args, format);
-     vprintf(format, args);
- #ifdef DEBUG
-     vfprintf(stderr, format, args);
- #endif
- #ifdef MAKE_MIRROR
-     vfprintf(mirror, format, args);
- #endif 
-     va_end(args);
- 
- }
- 
  char *get_my_hostname() 
  {
      struct utsname	myname;
--- 499,504 ----
***************
*** 483,494 ****
      char	*out;
  
      out = strdup(in);    
!     base64_decode(in, out);
      return(out);
  
  }
  
  
    /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
   /*	main line                                                           */
  /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
--- 566,604 ----
      char	*out;
  
      out = strdup(in);    
!     base64_decode((void*)in,(void*) out);
      return(out);
  
  }
  
  
+ #include <fcntl.h>
+ 
+ 
+ static void print_login_page(login_rec *l, char *message, char *reason, int need_clear_login, int need_clear_greq)
+ {
+     char	*hostname = strdup(get_domain_hostname());
+ 
+     log_message("%s Printing login page, reason: %s", l->first_kiss, reason);
+ 
+     if( need_clear_login ) 
+         print_out("Set-Cookie: %s=%s; domain=%s; path=%s; expires=%s; secure\n",
+             PBC_L_COOKIENAME, 
+             PBC_CLEAR_COOKIE,
+             hostname, 
+             LOGIN_DIR, 
+             EARLIEST_EVER);
+     if( need_clear_greq ) 
+         print_out("Set-Cookie: %s=%s; domain=%s; path=/; secure\n",
+             PBC_G_REQ_COOKIENAME, 
+             G_REQ_RECIEVED,
+             PBC_ENTRPRS_DOMAIN);
+ 
+     tmpl_print_out(TMPL_FNAME "login_part1",message,reason);
+     print_login_page_hidden_stuff(l);
+     tmpl_print_out(TMPL_FNAME "login_part2",message,reason);
+ }
+ 
    /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
   /*	main line                                                           */
  /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ /* */ 
***************
*** 499,511 ****
      char	*res;
      char	message[PBC_4K];
  
      /* make the effective uid nobody */
      if( setreuid(0, 65534) != 0 )
          log_message("main: not able to setuid to nobody");
- 
- #ifdef DEBUG
-     fprintf(stderr, "cgiMain: hello\n");
  #endif
  #ifdef MAKE_MIRROR
      init_mirror_file();
  #endif
--- 609,627 ----
      char	*res;
      char	message[PBC_4K];
  
+     login_debug=(getenv("LOGINDEBUG")!=0);
+ 
+     if(login_debug)
+       fprintf(stderr, "cgiMain: hello built on " __DATE__ " " __TIME__ "\n");
+ 
+ 
      /* make the effective uid nobody */
+ #ifdef RUBBISH
+ we are already nobody
      if( setreuid(0, 65534) != 0 )
          log_message("main: not able to setuid to nobody");
  #endif
+ 
  #ifdef MAKE_MIRROR
      init_mirror_file();
  #endif
***************
*** 528,536 ****
      /* malloc and populate login_rec                                   */
      l = get_query(); 
  
! #ifdef DEBUG
      fprintf(stderr, "cgiMain: after get_query\n");
- #endif
  
      /* log the arrival */
      log_message("%s Visit from user: %s client addr: %s app host: %s appid: %s uri: %s because: %s", 
--- 644,651 ----
      /* malloc and populate login_rec                                   */
      l = get_query(); 
  
!   if(login_debug)
      fprintf(stderr, "cgiMain: after get_query\n");
  
      /* log the arrival */
      log_message("%s Visit from user: %s client addr: %s app host: %s appid: %s uri: %s because: %s", 
***************
*** 553,561 ****
          exit(0);
      }
  
! #ifdef DEBUG
      fprintf(stderr, "cgiMain: after user check_user_agent\n");
- #endif
  
      /* allow for older versions that don't have froce_reauth */
      if ( !l->fr ) {
--- 668,675 ----
          exit(0);
      }
  
!   if(login_debug)
      fprintf(stderr, "cgiMain: after user check_user_agent\n");
  
      /* allow for older versions that don't have froce_reauth */
      if ( !l->fr ) {
***************
*** 589,597 ****
  
      /* the main logic */
      if ( l->user ) {                           /* a reply from the login page */
! #ifdef DEBUG
          fprintf(stderr, "wohooo!, an answer from the login page!\n");
! #endif
          res = check_login(l);
          if( strcmp(res, CHECK_LOGIN_RET_SUCCESS) ) {
              log_message("%s Authentication failed: %s type: %c %s", l->first_kiss, l->user, l->creds, res);
--- 703,711 ----
  
      /* the main logic */
      if ( l->user ) {                           /* a reply from the login page */
!   if(login_debug)
          fprintf(stderr, "wohooo!, an answer from the login page!\n");
! 
          res = check_login(l);
          if( strcmp(res, CHECK_LOGIN_RET_SUCCESS) ) {
              log_message("%s Authentication failed: %s type: %c %s", l->first_kiss, l->user, l->creds, res);
***************
*** 645,842 ****
      return(0);  
  }
  
- 
- void print_form_field(char *field, char *var) {
-     char	*field_type;
- 
-     if( !strcmp(field, PROMPT_UWNETID) ||
-         !strcmp(field, PROMPT_SECURID) ||
-         !strcmp(field, PROMPT_UHNETID) )
-         field_type = strdup("text");
-     else
-         field_type = strdup("password");
- 
-     print_out("<P>\n");
-     print_out("%s\n", field);
-     print_out("<input type=\"%s\" ", field_type);
-     print_out("name=\"%s\" SIZE=\"20\">\n", var);
- 
- }
- 
- 
- void print_login_page(login_rec *l, char *message, char *reason, int need_clear_login, int need_clear_greq)
- {
-     char	*log_in_with = NULL;
-     char	*field1 = NULL;
-     char	*field2 = NULL;
-     char	*field3 = NULL;
-     char	*hostname = strdup(get_domain_hostname());
- 
-     log_message("%s Printing login page, reason: %s", l->first_kiss, reason);
- 
-     switch (l->creds) {
-     case PBC_CREDS_UWNETID:
-         field1 = strdup(PROMPT_UWNETID);
-         field2 = strdup(PROMPT_PASSWD);
-         log_in_with = strdup("UW NetID and password");
-         break;
-     case PBC_CREDS_SECURID:
-         field1 = NULL;
-         break;
-     case PBC_CREDS_UWNETID_SECURID:
-         field1 = strdup(PROMPT_UWNETID);
-         field2 = strdup(PROMPT_PASSWD);
-         field3 = strdup(PROMPT_SECURID);
-         log_in_with = strdup("UW NetID, password, and SecurID");
-         break;
-     case PBC_CREDS_UHNETID:
-         field1 = strdup(PROMPT_UHNETID);
-         field2 = strdup(PROMPT_PASSWD);
-         log_in_with = strdup("ITS Username and password");
-         break;
-     default:
-         field1 = NULL;
-         break;
-     }
- 
-     if( need_clear_login ) 
-         print_out("Set-Cookie: %s=%s; domain=%s; path=%s; expires=%s; secure\n",
-             PBC_L_COOKIENAME, 
-             PBC_CLEAR_COOKIE,
-             hostname, 
-             LOGIN_DIR, 
-             EARLIEST_EVER);
-     if( need_clear_greq ) 
-         print_out("Set-Cookie: %s=%s; domain=%s; path=/; secure\n",
-             PBC_G_REQ_COOKIENAME, 
-             G_REQ_RECIEVED,
-             PBC_ENTRPRS_DOMAIN);
- 
-     print_http_header();
- 
-     print_login_page_part1(YES_FOCUS);
- 
-     print_login_page_lhs1(message, reason, log_in_with);
- 
-     if( field1 ) print_form_field( field1, "user" );
-     if( field2 ) print_form_field( field2, "pass" );
-     if( field3 ) print_form_field( field3, "pass2" );
- 
-     print_login_page_lhs2(l);
- 
-     print_login_page_centre();
- 
-     print_login_page_rhs();
- 
-     print_login_page_expire_info();
- 
-     print_login_page_bottom();
- 
- }
- 
  char *check_login_uwnetid(const char *user, const char *pass)
  {
! #ifdef DEBUG
      fprintf(stderr, "check_login_uwnetid: hello\n");
- #endif 
  
      if( user == NULL || pass == NULL ) {
! #ifdef DEBUG
          fprintf(stderr, "check_login_uwnetid: user or pass absent\n");
! #endif 
          return(CHECK_LOGIN_RET_FAIL);
      }
  
! /*
!  * NOTE: Potential memory leak with message returned by auth_kdc
!  *       since it is strdup'd.
!  */
!     if( auth_kdc(user, pass) == NULL ) {
! #ifdef DEBUG
          fprintf(stderr, "check_login_uwnetid: auth_kdc say ok\n");
! #endif 
          clear_error("uwnetid-fail", "uwnetid auth ok");
          return(CHECK_LOGIN_RET_SUCCESS);
      }
!     else {
! #ifdef DEBUG
!         fprintf(stderr, "check_login_uwnetid: auth_kdc say fail\n");
  #endif
          return(CHECK_LOGIN_RET_FAIL);
-     }
  
  }
  
  char *check_login_securid(char *user, char *sid, int next, login_rec *l)
  {
! 
! #ifdef DEBUG
      fprintf(stderr, "check_login_securid: hello\n");
- #endif 
  
      if( user == NULL || sid == NULL ) {
! #ifdef DEBUG
          fprintf(stderr, "check_login_securid: user or sid absent\n");
- #endif 
          return(CHECK_LOGIN_RET_FAIL);
      }
  
- /*
-  * NOTE: Potential memory leak with message returned by auth_securid
-  *       since it is strdup'd.
-  */
      if( auth_securid(user, sid, next, l) == NULL ) {
! #ifdef DEBUG
          fprintf(stderr, "check_login_securid: auth_securid say ok\n");
- #endif 
          clear_error("securid-fail", "securid auth ok");
          return(CHECK_LOGIN_RET_SUCCESS);
      }
      else {
! #ifdef DEBUG
          fprintf(stderr, "check_login_securid: auth_securid say NOPE!\n");
- #endif 
          log_error(2, "securid-err", 1, "problem doing securid auth");
          return(CHECK_LOGIN_RET_FAIL);
      }
- 
- }
- 
- /*
-  * Authenticate an ITS username.
-  *
-  * Return NULL if user is authenticated, else an error message.
-  */
- char *check_login_uhnetid(const char *user, const char *pass)
- {
-     char *msg;
- #ifdef DEBUG
-     fprintf(stderr, "check_login_uhnetid: hello\n");
- #endif 
- 
-     if( user == NULL || pass == NULL ) {
- #ifdef DEBUG
-         fprintf(stderr, "check_login_uhnetid: user or pass absent\n");
- #endif 
-         return(CHECK_LOGIN_RET_FAIL);
-     }
- 
-     msg = auth_ldap(user, pass);
-     if( msg == NULL ) {
- #ifdef DEBUG
-         fprintf(stderr, "check_login_uhnetid: auth_ldap says ok\n");
- #endif 
-         clear_error("uwnetid-fail", "uhnetid auth ok");
-         return(CHECK_LOGIN_RET_SUCCESS);
-     }
-     else {
- #ifdef DEBUG
-         fprintf(stderr, "check_login_uhnetid: auth_ldap says fail: %s\n", msg);
  #endif
-         free(msg);  /* was strdup'd in index.cgi_ldap:auth_ldap */
-         return(CHECK_LOGIN_RET_FAIL);
-     }
- 
  }
  
  /* successful auth returns CHECK_LOGIN_RET_SUCCESS                            */
--- 759,836 ----
      return(0);  
  }
  
  char *check_login_uwnetid(const char *user, const char *pass)
  {
!   const char *reason=0;
!   if(login_debug)
      fprintf(stderr, "check_login_uwnetid: hello\n");
  
      if( user == NULL || pass == NULL ) {
!   if(login_debug)
          fprintf(stderr, "check_login_uwnetid: user or pass absent\n");
! 
          return(CHECK_LOGIN_RET_FAIL);
      }
  
!     /* "FILE:/etc/krb5.keytab" */
!     reason=kerberos5_verify_password(user,pass,"pubcookie","FILE:/usr/www/private/www_krb5.keytab");
!     if( reason == NULL ) {
!       if(login_debug)
          fprintf(stderr, "check_login_uwnetid: auth_kdc say ok\n");
! 
          clear_error("uwnetid-fail", "uwnetid auth ok");
          return(CHECK_LOGIN_RET_SUCCESS);
      }
!     
!   if(login_debug)
!     fprintf(stderr, "check_login_uwnetid: auth_kdc say fail err='%s'\n",reason);
! 
! #ifdef KRB4
!     reason=kerberos4_verify_password(user,pass,"pubcookie","/usr/www/private/srvtab");
!     if( reason == NULL ) {
!       time_t now=time(0L);
!       fprintf(stderr,"krb4_password:'%s' %s\n",user,ctime(&now));
!       if(login_debug)
!         fprintf(stderr, "check_login_uwnetid: auth4_kdc say ok\n");
! 
!         clear_error("uwnetid-fail", "uwnetid auth4 ok");
!         return(CHECK_LOGIN_RET_SUCCESS);
!     }
  #endif
+   
    return(CHECK_LOGIN_RET_FAIL);
  
  }
  
  char *check_login_securid(char *user, char *sid, int next, login_rec *l)
  {
!   if(login_debug)
!         fprintf(stderr, "check_login_securid: auth_securid say NOPE!\n");
!   log_error(2, "securid-err", 1, "problem doing securid auth");
!   return(CHECK_LOGIN_RET_FAIL);
! #ifdef RUBBISH
!   if(login_debug)
      fprintf(stderr, "check_login_securid: hello\n");
  
      if( user == NULL || sid == NULL ) {
!   if(login_debug)
          fprintf(stderr, "check_login_securid: user or sid absent\n");
          return(CHECK_LOGIN_RET_FAIL);
      }
  
      if( auth_securid(user, sid, next, l) == NULL ) {
!   if(login_debug)
          fprintf(stderr, "check_login_securid: auth_securid say ok\n");
          clear_error("securid-fail", "securid auth ok");
          return(CHECK_LOGIN_RET_SUCCESS);
      }
      else {
!   if(login_debug)
          fprintf(stderr, "check_login_securid: auth_securid say NOPE!\n");
          log_error(2, "securid-err", 1, "problem doing securid auth");
          return(CHECK_LOGIN_RET_FAIL);
      }
  #endif
  }
  
  /* successful auth returns CHECK_LOGIN_RET_SUCCESS                            */
***************
*** 844,852 ****
  {
      char	*ret;
  
! #ifdef DEBUG
      fprintf(stderr, "in check_login\n");
- #endif
  
      if( !(ret = malloc(100)) ) {
          abend("out of memory");
--- 838,845 ----
  {
      char	*ret;
  
!   if(login_debug)
      fprintf(stderr, "in check_login\n");
  
      if( !(ret = malloc(100)) ) {
          abend("out of memory");
***************
*** 857,865 ****
      if( l->creds == PBC_CREDS_UWNETID ) {
          strcpy(ret, check_login_uwnetid(l->user, l->pass));
      }
-     else if( l->creds == PBC_CREDS_UHNETID ) {
-         strcpy(ret, check_login_uhnetid(l->user, l->pass));
-     }
      else if( l->creds == PBC_CREDS_UWNETID_SECURID ) {
          strcpy(ret, check_login_securid(l->user, l->pass2, l->next_securid, l));
          if( !strcmp(ret, CHECK_LOGIN_RET_SUCCESS) ) {
--- 850,855 ----
***************
*** 885,893 ****
      char	*g_version;
      char	*l_version;
  
! #ifdef DEBUG
      fprintf(stderr, "check_l_cookie: hello\n");
- #endif
  
      if( !(cookie = malloc(PBC_4K)) ) {
          abend("out of memory");
--- 875,882 ----
      char	*g_version;
      char	*l_version;
  
!   if(login_debug)
      fprintf(stderr, "check_l_cookie: hello\n");
  
      if( !(cookie = malloc(PBC_4K)) ) {
          abend("out of memory");
***************
*** 910,918 ****
          return("couldn't decode login cookie");
      }
  
! #ifdef DEBUG
      fprintf(stderr, "in check_l_cookie ready to look at cookie contents %s\n", lc->user);
- #endif
  
      /* look at what we got back from the cookie */
      if( ! lc->user ) {
--- 899,906 ----
          return("couldn't decode login cookie");
      }
  
!   if(login_debug)
      fprintf(stderr, "in check_l_cookie ready to look at cookie contents %s\n", lc->user);
  
      /* look at what we got back from the cookie */
      if( ! lc->user ) {
***************
*** 929,937 ****
          return "expired";
      }
  
! #ifdef DEBUG
      fprintf(stderr, "in check_l_cookie ready to look at cookie creds %c\n", lc->creds);
! #endif
  
      if( lc->creds != l->creds ) {
          if( l->creds == PBC_CREDS_UWNETID ) {
--- 917,926 ----
          return "expired";
      }
  
!     if(login_debug) {
!       fprintf(stderr, "in check_l_cookie ready to look at cookie contents %s\n", lc->user);
        fprintf(stderr, "in check_l_cookie ready to look at cookie creds %c\n", lc->creds);
!     }
  
      if( lc->creds != l->creds ) {
          if( l->creds == PBC_CREDS_UWNETID ) {
***************
*** 1037,1053 ****
              EARLIEST_EVER);
      }
  
!     print_http_header();
! 
!     print_login_page_part1(NO_FOCUS);
!     print_out("<td valign=\"middle\">\n");
!     print_uwnetid_logo();
! 
      notok_f();
! 
!     print_out("</td>\n</tr>\n");
!     print_login_page_bottom();
! 
  }
  
  
--- 1026,1034 ----
              EARLIEST_EVER);
      }
  
!     tmpl_print_out(TMPL_FNAME "notok_part1");
      notok_f();
!     tmpl_print_out(TMPL_FNAME "notok_part2");
  }
  
  
***************
*** 1091,1204 ****
      return(1);
  }
  
- /*	################################### The beginning of the table        */
- void print_table_start()
- {
-     print_out("<table cellpadding=\"0\" cellspacing=\"0\" border=\"0\" width=\"580\">\n");
- 
- }
- 
- /*	################################### da copyright, it's ours!          */
- void print_copyright()
- {
-     print_out("<small>Copyright &#169; 2001 University of Washington</small>\n");
- 
- }
- 
- /*	################################### UWNetID Logo                      */
- void print_uwnetid_logo()
- {
-     print_out("<img src=\"/images/login.gif\" alt=\"\" height=\"64\" width=\"208\" oncontextmenu=\"return false\">\n");
- 
- }
- 
- 
- /*	################################### header stuff                      */
- void print_http_header()
- {
-         print_out("Pragma: No-Cache\n");
-         print_out("Cache-Control: no-store, no-cache, must-revalidate\n");
-         print_out("Expires: Sat, 1 Jan 2000 01:01:01 GMT\n");
-         print_out("Content-Type: text/html\n\n");
- 
- }
- 
- /*       ################################### part 1                           */
- void print_login_page_part1(int focus)
- {
-     print_out("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\n");
-     print_out("<html>\n");
-     print_out("<head>\n");
-     print_out("<title>UW NetID Login</title>\n");
-     print_out("</head>\n");
- 
-     if( focus ) {
-         print_out("<body bgcolor=\"#FFFFFF\" onLoad=\"document.query.user.focus()\">\n");
-     }
-     else {
-         print_out("<body bgcolor=\"#FFFFFF\">\n");
-     }
- 
-     print_out("<center>\n");
- 
-     print_table_start();
-     
-     print_out("<tr>\n");
- }
- 
- /*	################################### left hand side of big table       */
- void print_login_page_lhs1(char *message, char *reason, char *log_in_with)
- {
-     print_out("<td width=\"310\" valign=\"middle\">\n");
- 
-     print_uwnetid_logo();
- 
-     /* any additional messages and hints from the cgi */
-     if( reason != NULL ) 
-         print_out("<!-- %s -->\n\n", reason);
- 
-     /* open the form */
-     print_out("\n<form method=\"POST\" action=\"/\" enctype=\"application/x-www-form-urlencoded\" name=\"query\" autocomplete=\"off\">\n");
- 
-     /* text before the for fields */
-     if( message != NULL && strcmp(message, PRINT_LOGIN_PLEASE) ) {
-         print_out("%s", message);
-     }
-     else {
-         print_out("<P>The resource you requested requires you to log in ");
-         print_out(" with your %s.</P>\n", log_in_with);
-     }
- 
- }
- 
- /*	################################### more, left hand side of big table */
- void print_login_page_lhs2(login_rec *l)
- {
-     print_out("<p><strong><input type=\"SUBMIT\" name=\"submit\" value=\"Log in\">");
-     print_out("</strong>\n");
-     print_login_page_hidden_stuff(l);
-     print_out("</form>\n");
-     print_out("</td>\n");
-     print_out("<td width=\"9\">&nbsp;</td>\n");
- 
- }
- 
- /*	################################### centre of the page                */
- void print_login_page_centre()
- {
-     print_out("<td width=\"2\" bgcolor=\"#000000\">\n");
-     print_out("<img src=\"/images/1pixffcc33iystpiwfy.gif\" width=\"1\" height=\"1\" align=\"BOTTOM\" alt=\"\" oncontextmenu=\"return false\"></td>\n");
-     print_out("<td width=\"9\">&nbsp;</td>\n");
- 
- }
- 
- /*	################################### right hand side                   */
- void print_login_page_rhs()
- {
-     print_out("%s\n", LOGIN_PAGE_RHS_TEXT);
- 
- }
- 
  /*	################################### hidden stuff                      */
  void print_login_page_hidden_stuff(login_rec *l)
  {
--- 1072,1077 ----
***************
*** 1246,1274 ****
  
  }
  
- /*	################################### part 5                            */
- void print_login_page_bottom() 
- {
- 
-     print_out("<tr>\n");
-     print_out("<td colspan=\"5\" align=\"center\">\n");
-     print_copyright();
-     print_out("</td>\n");
-     print_out("</tr>\n");
-     print_out("</table>\n");
-     print_out("</center>\n");
-     print_out("</body>\n");
-     print_out("</html>\n");
- 
- }
- 
- /*	################################### part expire_info                  */
- void print_login_page_expire_info()
- {
-     print_out("%s\n", LOGIN_PAGE_BOTTOM_TEXT);
- 
- }
- 
  char *to_lower(char *in)
  {
      char	*p;
--- 1119,1124 ----
***************
*** 1334,1341 ****
--- 1184,1193 ----
      char		g_set_cookie[PBC_1K];
      char		l_set_cookie[PBC_1K];
      char		clear_g_req_cookie[PBC_1K];
+ /* these are used anymore due to the commenting out some code
      char		*post_stuff_lower = NULL;
      char		*p = NULL;
+  */
      int			g_res, l_res;
      int			limitations_mentioned = 0;
      char		*submit_value = NULL;
***************
*** 1422,1428 ****
  
      if( l->args ) {
          args_enc = calloc (1, strlen (l->args));
! 	base64_decode(l->args, args_enc);
          snprintf( redirect_final, PBC_4K-1, "%s?%s", redirect_dest, args_enc );
      } 
      else {
--- 1274,1280 ----
  
      if( l->args ) {
          args_enc = calloc (1, strlen (l->args));
! 	base64_decode((void*)l->args,(void*) args_enc);
          snprintf( redirect_final, PBC_4K-1, "%s?%s", redirect_dest, args_enc );
      } 
      else {
***************
*** 1455,1461 ****
              exit(0);
          }
  
!         print_http_header();
  
  	print_out("<HTML>");
  	/* when the page loads click on the last element */
--- 1307,1313 ----
              exit(0);
          }
  
! 	/*        print_http_header();*/
  
  	print_out("<HTML>");
  	/* when the page loads click on the last element */
***************
*** 1465,1472 ****
  
          /* depending on whether-or-not there is a SUBMIT field in the form */
          /* use the correct javascript to autosubmit the POST */
!         /* this should probably be upgraded to only look for submits as field */
!         /* names, not anywhere else */
          post_stuff_lower = strdup(l->post_stuff);
          for(p=post_stuff_lower; *p != '\0'; p++)
              *p = tolower(*p);
--- 1317,1324 ----
  
          /* depending on whether-or-not there is a SUBMIT field in the form */
          /* use the correct javascript to autosubmit the POST */
! /* for some unknown reason this is commented-out */
! /*
          post_stuff_lower = strdup(l->post_stuff);
          for(p=post_stuff_lower; *p != '\0'; p++)
              *p = tolower(*p);
***************
*** 1474,1484 ****
              print_out("document.query.submit.click()");
          else
              print_out("document.query.submit");
  
          print_out("\">\n");
  
  	print_out("<center>");
!         print_table_start();
  	print_out("<tr><td align=\"LEFT\">\n");
  
  	print_out("<form method=\"POST\" action=\"%s\" ", redirect_final);
--- 1326,1338 ----
              print_out("document.query.submit.click()");
          else
              print_out("document.query.submit");
+ */
+ 	print_out("document.query.submit()");
  
          print_out("\">\n");
  
  	print_out("<center>");
! 	/*        print_table_start(); */
  	print_out("<tr><td align=\"LEFT\">\n");
  
  	print_out("<form method=\"POST\" action=\"%s\" ", redirect_final);
***************
*** 1487,1496 ****
  
          c = cgiFormEntryFirst;
          while (c) {
              // in the perl version we had to make sure we were getting
              // rid of this header line
              //        c->attr =~ s%^\s*HTTP/1.1 100 Continue\s*%%mi;
! 
              /* if there is a " in the value string we have to put */
              /* in a TEXTAREA object that will be visible          */
              if( strstr(c->value, "\"") || strstr(c->value, "\r") || strstr(c->value, "\n") ) {
--- 1341,1351 ----
  
          c = cgiFormEntryFirst;
          while (c) {
+ #ifdef LIKE_CPP_COMMENTS 
              // in the perl version we had to make sure we were getting
              // rid of this header line
              //        c->attr =~ s%^\s*HTTP/1.1 100 Continue\s*%%mi;
! #endif
              /* if there is a " in the value string we have to put */
              /* in a TEXTAREA object that will be visible          */
              if( strstr(c->value, "\"") || strstr(c->value, "\r") || strstr(c->value, "\n") ) {
***************
*** 1520,1526 ****
  
  
          print_out("</td></tr>\n");
!         print_uwnetid_logo();
          print_out("<P>");
          print_out("%s\n", PBC_POST_NO_JS_TEXT);
          print_out("</td></tr></table>\n");
--- 1375,1381 ----
  
  
          print_out("</td></tr>\n");
! 	/*        print_uwnetid_logo(); */
          print_out("<P>");
          print_out("%s\n", PBC_POST_NO_JS_TEXT);
          print_out("</td></tr></table>\n");
***************
*** 1532,1560 ****
              print_out("<input type=\"submit\" value=\"%s\">\n", PBC_POST_NO_JS_BUTTON);
  
          print_out("</form>\n");
!         print_copyright();
          print_out("</center>");
          print_out("</BODY></HTML>\n");
      }
!     else {
!         /*                                                               */
!         /* non-post redirect area                 non-post redirect area */
!         /*                                                               */
!         print_http_header();
! 
!         print_out("<html><head>\n");
! 
!         print_out("<SCRIPT LANGUAGE=\"JavaScript\">\n");
!         print_out("window.location.replace(\"%s\");\n", redirect_final);
!         print_out("</SCRIPT> \n");
!         print_out("<NOSCRIPT>\n");
!         print_out("<meta http-equiv=\"Refresh\" content=\"%s;URL=%s\">\n", REFRESH, redirect_final);
!         print_out("</NOSCRIPT> \n");
! 
!         print_out("<BODY BGCOLOR=\"white\">");
!         print_out("<!--redirecting to %s-->", redirect_final);
!         print_out("</BODY></HTML>\n");
!     } /* end if post_stuff */
  
      free(g_cookie);
      free(l_cookie);
--- 1387,1398 ----
              print_out("<input type=\"submit\" value=\"%s\">\n", PBC_POST_NO_JS_BUTTON);
  
          print_out("</form>\n");
! 	/*        print_copyright(); */
          print_out("</center>");
          print_out("</BODY></HTML>\n");
      }
!     else
!       tmpl_print_out(TMPL_FNAME "nonpost_redirect", REFRESH, redirect_final,redirect_final);
  
      free(g_cookie);
      free(l_cookie);
***************
*** 1592,1600 ****
              return(NULL);
          }
          g_req_clear = decode_granting_request(g_req);
! #ifdef DEBUG
          fprintf(stderr, "get_query: decoded granting request: %s\n", g_req_clear);
- #endif
          if( cgiParseFormInput(g_req_clear, strlen(g_req_clear)) 
                     != cgiParseSuccess ) {
              log_error(5, "misc", 0, "couldn't parse the decoded granting request cookie");
--- 1430,1437 ----
              return(NULL);
          }
          g_req_clear = decode_granting_request(g_req);
!   if(login_debug)
          fprintf(stderr, "get_query: decoded granting request: %s\n", g_req_clear);
          if( cgiParseFormInput(g_req_clear, strlen(g_req_clear)) 
                     != cgiParseSuccess ) {
              log_error(5, "misc", 0, "couldn't parse the decoded granting request cookie");
***************
*** 1633,1639 ****
          }
      }
  
! #ifdef DEBUG 
      fprintf(stderr, "from login user: %s\n", l->user);
      fprintf(stderr, "from login version: %s\n", l->version);
      fprintf(stderr, "from login creds: %c\n", l->creds);
--- 1470,1476 ----
          }
      }
  
!     if(login_debug) {
      fprintf(stderr, "from login user: %s\n", l->user);
      fprintf(stderr, "from login version: %s\n", l->version);
      fprintf(stderr, "from login creds: %c\n", l->creds);
***************
*** 1643,1649 ****
      fprintf(stderr, "from login next_securid: %d\n", l->next_securid);
      fprintf(stderr, "from login first_kiss: %d\n", (int)l->first_kiss);
      fprintf(stderr, "from login post_stuff: %s\n", l->post_stuff);
! #endif
  
      return(l);
  
--- 1480,1486 ----
      fprintf(stderr, "from login next_securid: %d\n", l->next_securid);
      fprintf(stderr, "from login first_kiss: %d\n", (int)l->first_kiss);
      fprintf(stderr, "from login post_stuff: %s\n", l->post_stuff);
!     }
  
      return(l);
  
