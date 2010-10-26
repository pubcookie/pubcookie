*** mod_pubcookie.c	Wed Oct 17 15:17:56 2001
--- ../../pubcookie-v1-cmu2/mod_pubcookie-1.54/mod_pubcookie.c	Tue Jun 26 13:51:53 2001
***************
*** 1,4 ****
- /* 09/04/01, Russell Tokuyama (UH ITS); Localized for UH. */
  /*
  
      Copyright 1999, University of Washington.  All rights reserved.
--- 1,3 ----
***************
*** 11,17 ****
  
  
      All comments and suggestions to pubcookie@cac.washington.edu
!     More info: http://www.washington.edu/computing/pubcookie/
      Written by the Pubcookie Team
  
      this is the pubcookie apache module
--- 10,16 ----
  
  
      All comments and suggestions to pubcookie@cac.washington.edu
!     More info: https:/www.washington.edu/pubcookie/
      Written by the Pubcookie Team
  
      this is the pubcookie apache module
***************
*** 19,25 ****
   */
  
  /*
!     $Id: diff.mod_pubcookie.c,v 1.1 2001/12/14 00:38:59 willey Exp $
   */
  
  /* apache includes */
--- 18,24 ----
   */
  
  /*
!     $Id: diff.mod_pubcookie.c,v 1.1 2001/12/14 00:38:59 willey Exp $
   */
  
  /* apache includes */
***************
*** 146,154 ****
  
  /*                                                                            */
  unsigned char *get_app_path(request_rec *r, const char *path) {
-     char *ptr;
      char *path_out;
-     int i;
      int truncate;
      pool *p = r->pool;
      pubcookie_server_rec *scfg;
--- 145,151 ----
***************
*** 395,401 ****
--- 392,400 ----
      const char *ctype = table_get(r->headers_in, "Content-type");
      const char *lenp = table_get(r->headers_in, "Content-Length");
  #else
+ #ifdef PHASEII
      char                 *tmp = ap_palloc(r->pool, PBC_1K);
+ #endif
      char                 *refresh = ap_palloc(r->pool, PBC_1K);
      char                 *pre_s = ap_palloc(r->pool, PBC_1K);
      char                 *pre_s_cookie = ap_palloc(r->pool, PBC_1K);
***************
*** 854,859 ****
--- 853,862 ----
    }
  
    blank_cookie (r, name);
+ 
+   libpbc_debug("found cookie '%s' value '%s'\n",
+ 	       name,cookie);
+ 
    return cookie;
  }
  
***************
*** 883,888 ****
--- 886,893 ----
  #endif
  
    scfg->c_stuff = libpbc_init_crypt(fname);
+   if(scfg->c_stuff==0)
+     ap_log_error(APLOG_MARK,APLOG_EMERG,s,"cant read init crypt file '%s'",fname);
  
    /* read and init session public key */
  
***************
*** 895,900 ****
--- 900,907 ----
  #endif
  
    scfg->session_verf_ctx_plus = libpbc_verify_init(fname);
+   if(scfg->session_verf_ctx_plus==0 )
+     ap_log_error(APLOG_MARK,APLOG_EMERG,s,"cant read session cert file '%s'",fname);
  
    /* read and init session private key */
  
***************
*** 907,912 ****
--- 914,922 ----
  #endif
  
    scfg->session_sign_ctx_plus = libpbc_sign_init(fname);
+   if(scfg->session_sign_ctx_plus==0 )
+     ap_log_error(APLOG_MARK,APLOG_EMERG,s,"cant read session crypt file '%s'",fname);
+ 
  
    /* read and init granting public key */
  
***************
*** 919,931 ****
  #endif
  
    scfg->granting_verf_ctx_plus = libpbc_verify_init(fname);
! 
  }
  
  /*                                                                            */
  static void *pubcookie_server_create(pool *p, server_rec *s) {
    pubcookie_server_rec *scfg;
-   struct stat sb;
  #ifdef APACHE1_2
    scfg = (pubcookie_server_rec *) pcalloc(p, sizeof(pubcookie_server_rec));
  #else
--- 929,941 ----
  #endif
  
    scfg->granting_verf_ctx_plus = libpbc_verify_init(fname);
!   if(scfg->granting_verf_ctx_plus==0 )
!     ap_log_error(APLOG_MARK,APLOG_EMERG,s,"cant read granting crypt file '%s'",fname);
  }
  
  /*                                                                            */
  static void *pubcookie_server_create(pool *p, server_rec *s) {
    pubcookie_server_rec *scfg;
  #ifdef APACHE1_2
    scfg = (pubcookie_server_rec *) pcalloc(p, sizeof(pubcookie_server_rec));
  #else
***************
*** 1010,1015 ****
--- 1020,1035 ----
  
  }
  
+ /* make sure the creds from the cookie are adequate for the server requiremnts*/
+ int check_creds(int need, int got) {
+ 
+     if( (need & got) == need )
+         return PBC_OK;
+     else
+         return PBC_FAIL;
+ 
+ }
+ 
  /*                                                                            */
  static int pubcookie_user(request_rec *r) {
    pubcookie_dir_rec *cfg;
***************
*** 1053,1061 ****
    if( strcasecmp(at, PBC_UWNETID_AUTHTYPE) == 0 ) {
      cfg->creds = PBC_CREDS_UWNETID;
    }
-   else if( strcasecmp(at, PBC_UHNETID_AUTHTYPE) == 0 ) {
-     cfg->creds = PBC_CREDS_UHNETID;
-   }
  #ifdef USE_SECURID
    /* securid must be used with uwnetid passwd */
    else if( strcasecmp(at, PBC_SECURID_AUTHTYPE) == 0 ) {
--- 1073,1078 ----
***************
*** 1257,1263 ****
    }
  
    /* check creds */
!   if( cfg->creds != cookie_data->broken.creds ) {
      libpbc_debug("pubcookie_user: wrong creds; required: %c cookie: %c uri: %s\n", cfg->creds, (*cookie_data).broken.creds, r->uri);
      cfg->failed = PBC_BAD_AUTH;
      cfg->redir_reason_no = PBC_RR_WRONGCREDS_CODE;
--- 1274,1281 ----
    }
  
    /* check creds */
!   if( check_creds( atoi(&cfg->creds), atoi(&(*cookie_data).broken.creds) ) 
! 		== PBC_FAIL ) {
      libpbc_debug("pubcookie_user: wrong creds; required: %c cookie: %c uri: %s\n", cfg->creds, (*cookie_data).broken.creds, r->uri);
      cfg->failed = PBC_BAD_AUTH;
      cfg->redir_reason_no = PBC_RR_WRONGCREDS_CODE;
***************
*** 1361,1367 ****
         in the app
       */
      if( cfg->inact_exp > 0 || first_time_in_session ) {
-       request_rec *rmain = main_rrec (r);
  
        /* make session cookie */
        cookie = libpbc_get_cookie_p(r->pool, 
--- 1379,1384 ----
***************
*** 1443,1449 ****
      while (nextcookie) {
          char *c = nextcookie;
  
!         if (nextcookie = strchr (c, ';')) {
              *nextcookie++ = '\0';
              while (*nextcookie && *nextcookie == ' ')
                  ++nextcookie;
--- 1460,1467 ----
      while (nextcookie) {
          char *c = nextcookie;
  
! 	nextcookie = strchr (c, ';');
!         if (nextcookie!=0) {
              *nextcookie++ = '\0';
              while (*nextcookie && *nextcookie == ' ')
                  ++nextcookie;
***************
*** 1703,1709 ****
  const char *pubcookie_set_crypt_keyf(cmd_parms *cmd, void *mconfig, char *v) {
      server_rec *s = cmd->server;
      pubcookie_server_rec *scfg;
-     struct stat sb;
  
  #ifdef APACHE1_2
      scfg = (pubcookie_server_rec *) get_module_config(s->module_config,
--- 1721,1726 ----
***************
*** 1740,1752 ****
      server_rec *s = cmd->server;
      pubcookie_server_rec *scfg;
  #ifdef APACHE1_2
-     pool *p = cmd->pool;
- 
      scfg = (pubcookie_server_rec *) get_module_config(s->module_config,
                                                     &pubcookie_module);
  #else
-     ap_pool *p = cmd->pool;
- 
      scfg = (pubcookie_server_rec *) ap_get_module_config(s->module_config,
                                                     &pubcookie_module);
  #endif
--- 1757,1765 ----
