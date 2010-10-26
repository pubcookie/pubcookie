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

/* Misc html used by the pubcookie module */

/* Null body */

static char *nullpage_html =
    "<html>\n" "<body bgcolor=\"#ffffff\">\n" "</body>\n" "</html>\n";


/* Generic redirect, used by logout */

static char *redirect_html =
    "<html>\n"
    "<head>\n"
    "<meta http-equiv=\"Refresh\" content=\"%s\">\n"
    "</head>\n" "<body bgcolor=\"#ffffff\">\n" "</body>\n" "</html>\n";


/* Local error page, used by stop_the_show */

static char *stop_html =
    "<head>\n"
    "<title>A problem has occurred</title>\n"
    "</head>\n"
    "<body bgcolor=\"#ffffff\">\n"
    "<h1>A problem has occurred</H1>\n"
    "<p>Please contact %s</p>\n"
    "<p>Error message: \"%s\"</p>\n"
    "<p>Hitting Refresh will attempt to resubmit your request</p>\n"
    "</BODY>\n" "</HTML>\n";


/* Post method granting redirect.

   Args:  login server url
          granting cookie contents
          post_stuff
          reply url: host, port_text, rest
     */

static char *post_request_html =
    "<html>\n"
    "<head>\n"
    "</head>\n"
    "<body onLoad=\"document.relay.submit()\">\n"
    "<form method=post action=\"%s\" name=relay>\n"
    "<input type=hidden name=pubcookie_g_req value=\"%s\">\n"
    "<input type=hidden name=post_stuff value=\"%s\">\n"
    "<input type=hidden name=relay_url value=\"https://%s%s/%s\">\n"
    "<noscript>\n"
    "<p align=center>You do not have Javascript turned on,"
    "   please click the button to continue.\n"
    "<p align=center>\n"
    "<input type=submit name=go value=Continue>\n"
    "</noscript>\n" "</form>\n" "</html>\n";



/* Get method (with post data) granting redirect 
   Args:  login server url
          post data
          logo image
          submit button text
  */



static char *get_post_request_html =
    "<html>\n"
    "<head>\n"
    "</head>\n"
    "<body bgcolor=\"white\" onLoad=\"document.query.submit.click()\">\n"
    "\n"
    "<center>\n"
    "<form method=\"post\" action=\"%s\" name=\"query\">\n"
    " <input type=\"hidden\" name=\"post_stuff\" value=\"%s\">\n"
    "  <table cellpadding=0 cellspacing=0 border=0 width=520>\n"
    "   <tr><td width=300 valign=\"middle\">\n"
    "    <img src=\"%s%s\" alt=\"UW NetID Login\" height=\"64\" width=\"208\">\n"
    "     <script language=\"javascript\">\n"
    "       document.write(\"<p>Your browser should move to the next page in a few seconds.  If it doesn't, please click the button to continue.<p>\")\n"
    "     </script>\n"
    "     <noscript>\n"
    "     <p>You do not have javascript turned on, "
    "          please click the button to continue.<p>\n"
    "     </noscript>\n"
    "   </td></tr>\n"
    "  </table>\n"
    " <input type=\"submit\" name=\"submit\" value=\"%s\"\">\n"
    "</form>\n" "</center>\n" "</body>\n" "</html>\n";


/* Post method granting reply part 1 */

#define POST_REPLY_SUBMIT "document.relay.submit();"
#define POST_REPLY_CLICK "document.relay.elements[0].click();"

/* Args:

   POST_REPLY_SUBMIT or POST_REPLY_CLICK
   destination uri
 */

static char *post_reply_1_html =
    "<html>\n"
    "<head>\n"
    "<script language=javascript>\n"
    "  function showtheclick() {   /* In case the auto-click doesn't work */\n"
    "    document.relay.elements[0].style.visibility=\"visible\";\n"
    "    document.getElementById('message').style.visibility=\"visible\";\n"
    "  }\n"
    "  function dotheclick() {\n"
    "    setTimeout( \"showtheclick()\", 2000);\n"
    "    %s\n"
    "  }\n"
    "</script>\n"
    "</head>\n"
    "<body onLoad=\"dotheclick();\">\n"
    "<p id=message  style=\"visibility:hidden\" align=center>\n"
    " Your browser was not able to continue to your destination automatically.\n"
    "<br>\n"
    "  Click the button to continue.\n"
    "<p>\n"
    "<form method=post action=\"%s\" name=relay>\n"
    "<p align=center><input type=submit value=\"Continue\"\n"
    "   style=\"visibility:hidden\">\n";


/* Post reply form elements. args: name value */

static char *post_reply_arg_html =
    "<input type=hidden name=\"%s\" value=\"%s\">\n";

static char *post_reply_area_html =
    "<textarea name=\"%s\" style=\"visibility:hidden\">%s</textarea>\n";


/* End of post reply */

static char *post_reply_2_html =
    "<noscript>\n"
    "<p align=center>You do not have Javascript turned on,\n"
    "  please click the button to continue.\n"
    "<input type=submit value=\"Continue\">\n"
    "</noscript>\n" "</form>\n" "</html>\n";
