/* Pubcookie login relay */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>

typedef void pool;

#ifdef WIN32
# include <Windows.h>
# include <httpfilt.h>
# include "pbc_config.h"
# include "pubcookie.h"
# include "PubCookieFilter.h"
pubcookie_dir_rec *p = NULL;
#else
#include "pbc_config.h"
pool *p = NULL;
#endif

#include "pbc_configure.h"

char *relay_domain = NULL;
char *login_uri = NULL;
char *relay_uri = NULL;

/* See:  http://staff.washington.edu/fox/webtpl/ */
#include "webtpl.h"

/* Get a template from a path and name */

static void get_template(WebTemplate W, char *name,  char *file)
{
   char *buf;
   char *e;
   int pl = (int)strlen(PBC_TEMPLATES_PATH) + (int)strlen(file);
 
   buf = (char*) malloc(pl+2);
   strcpy(buf, PBC_TEMPLATES_PATH);
   for (e=buf+strlen(buf)-1; e>buf; e--) if (!isspace(*e)) break;
   if (*e!='/') *++e = '/';
   e++;
   strcpy(e, file);
   WebTemplate_get_by_name(W, name, buf);
   free(buf);
}
   
/* Requests from an application will have a granting request
   and possibly post data.  Relay these to the login server. */
   
void relay_granting_request(WebTemplate W, char *greq)
{
   char *post;

   /* clear the granting request cookie */
   WebTemplate_set_cookie(W, PBC_G_REQ_COOKIENAME,
      "", 0, relay_domain, "/", 1);

   get_template(W, "page", "tologin.tpl");
   WebTemplate_assign(W, "LOGIN", login_uri);
   WebTemplate_assign(W, "G_REQUEST", greq);

   if (post = WebTemplate_get_arg(W, PBC_GETVAR_POST_STUFF)) {
      WebTemplate_assign(W, "POSTSTUFF", post);
   }

   WebTemplate_assign(W, "RELAYURL", relay_uri);

}


/* Requests from the login server will have a granting reply
   and post data.  Relay these to the application. */


static int need_area(char *in)
{
  for (; *in; in++) {
      if (*in=='"') return (1);
      if (*in=='\n') return (1);
      if (*in=='\r') return (1);
  }
  return (0);
}

void relay_granting_reply(WebTemplate W, char *grpl)
{ 
   char *post, *url, *arg, *furl;
   time_t expire;

   get_template(W, "page", "toapp.tpl");
  
   expire = time(NULL) + PBC_GRANTING_EXPIRE;
   WebTemplate_set_cookie(W, PBC_G_COOKIENAME,
      grpl, expire, relay_domain, "/", 1);
  
   WebTemplate_assign(W, "LOGIN", login_uri);
   /* WebTemplate_assign(W, "LOGO", "login.gif"); */
  
   /* Build the final redirection */
   url = WebTemplate_get_arg(W, "redirect_url");
   if (!url) url = "/badcall.html";
   arg = WebTemplate_html2text(WebTemplate_get_arg(W, "get_args"));

   if (arg && *arg) {
      furl = (char*) malloc(strlen(url) + strlen(arg) + 5);
      sprintf(furl, "%s?%s", url, arg);
   } else furl = strdup(url);

   WebTemplate_assign(W, "APP_URL", furl);
   free(furl);
  
   /* Look for posted data - split it into the form */
   if ((post=WebTemplate_get_arg(W, PBC_GETVAR_POST_STUFF)) && *post) {
      char *a, *v;
      char *p;
      int needclick = 0;
      do {
         if (a=strchr(post, '&')) *a++ = '\0';
         if (*post) {
            if (v=strchr(post, '=')) *v++ = '\0';
            WebTemplate_assign(W, "ARGNAME", post);
            p = WebTemplate_html2text(v);
            WebTemplate_assign(W, "ARGVAL", p);
            if (need_area(p)) {
               WebTemplate_parse_dynamic(W, "page.post.area");
            } else {
               WebTemplate_parse_dynamic(W, "page.post.arg");
            }
            if (!strcmp(post,"submit")) needclick = 1;
         }
      } while (post = a);
      if (needclick) WebTemplate_parse_dynamic(W, "page.post.click");
      else WebTemplate_parse_dynamic(W, "page.post.submit");
      WebTemplate_parse_dynamic(W, "page.post");

   /* Else is a GET */
   } else WebTemplate_parse_dynamic(W, "page.get");

}



/* Logout requests from an application will have a the
   logout action variable.  Relay to the login server. */
   
void relay_logout_request(WebTemplate W, char *act)
{
   char *a1, *a2;
   char *furl;
   size_t l;

   /* clear any granting request cookie */
   WebTemplate_set_cookie(W, PBC_G_REQ_COOKIENAME,
      "", 0, relay_domain, "/", 1);

   /* Reuse the GET redirection of the to-app template */
   get_template(W, "page", "toapp.tpl");

   /* Build the redirection */
   a1 = WebTemplate_get_arg(W, "one");
   if (!a1) a1 = "";
   a2 = WebTemplate_get_arg(W, "two");
   if (!a2) a2 = "";
   l = strlen(login_uri) + 
         strlen(PBC_GETVAR_LOGOUT_ACTION) + strlen(act) +
         strlen(a1) + strlen(a2) + 32;
   furl = (char*) malloc(l);
   sprintf(furl, "%s?%s=%s&one=%s&two=%s", login_uri,
           PBC_GETVAR_LOGOUT_ACTION, act, a1, a2);

   WebTemplate_assign(W, "APP_URL", furl);
   WebTemplate_parse_dynamic(W, "page.get");
   free(furl);

}

main()
{
  WebTemplate W = newWebTemplate();
  char *req;
  char *host, *port, *uri, *qs;
  char *uport;
  int ishttps;

# ifdef WIN32
  p = (pubcookie_dir_rec *)malloc(sizeof(pubcookie_dir_rec));
  memset(p,0,sizeof(pubcookie_dir_rec));
  strncpy(p->instance_id,PBC_RELAY_WEB_KEY,MAX_INSTANCE_ID);
# endif

  WebTemplate_set_comments(W, "#", NULL);
  WebTemplate_add_header(W, "Pragma", "No-Cache");
  WebTemplate_add_header(W, "Cache-Control",
        "no-store, no-cache, must-revalidate");
  WebTemplate_add_header(W, "Expires", "Sat, 1 Jan 2000 01:01:01 GMT");
  WebTemplate_get_args(W);
 
  libpbc_config_init(p, NULL, "relay");

  relay_domain = WebTemplate_get_arg(W, "domain");
  if (!relay_domain) { 
      relay_domain = strdup((char*)PBC_ENTRPRS_DOMAIN);
  }

  uri = (char*)PBC_RELAY_LOGIN_URI;
  if (!*uri) uri = (char*)PBC_LOGIN_URI;
  login_uri = strdup(uri);  

  /* figure out relay uri */

  if (getenv("HTTPS")) ishttps = 1;
  else ishttps = 0;

  if (!(host=getenv("HTTP_HOST"))) host = "nohost";
  if (!(uri=getenv("SCRIPT_NAME"))) uri = "/";
  if (!(qs=getenv("QUERY_STRING"))) qs = "";

  if ((port=getenv("SERVER_PORT")) && strcmp(port,ishttps?"443":"80")) {
     uport = (char*) malloc(2+strlen(port));
     sprintf(uport,":%s", port);
  } else uport = strdup("");
  
  relay_uri = (char*) malloc(24 + strlen(host) + strlen(uport) + 
                        strlen(uri) + strlen(qs));
  sprintf(relay_uri, "http%c://%s%s%s%s%s",
           ishttps?'s':'\0', host, uport, uri,
           *qs?"?":"", qs);

  /* A logout request to the login server will have a
     logout action variable */

  if (req = WebTemplate_get_arg(W, PBC_GETVAR_LOGOUT_ACTION)) {
      relay_logout_request(W, req);

  /* A login reply to the application will have a granting
     cookie in posted form data */

  } else if (req = WebTemplate_get_arg(W, PBC_G_COOKIENAME)) {
      relay_granting_reply(W, req);

  /* A login request from an application will have a granting 
     request cookie */

  } else if (req = WebTemplate_get_cookie(W, PBC_G_REQ_COOKIENAME)) {
      relay_granting_request(W, req);

  /* Otherwise this is an invalid request */

  } else {
 
     get_template(W, "page", "hello.tpl");

  }

  WebTemplate_parse(W, "PAGE", "page");
  WebTemplate_write(W, "PAGE");

# ifdef WIN32
  free(p);
# endif

}
