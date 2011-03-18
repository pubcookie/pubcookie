<%@ EnableSessionState=False%>
<% 
' Default.asp
%>
<HTML>
<HEAD>
<TITLE>generic testsuite output page </TITLE>
</HEAD>
<BODY BGCOLOR="#FFFFFF">
<p>You logged in as user:<b> 
  <% = Request.ServerVariables("HTTP_PUBCOOKIE_USER") %>
  </b></p>

<p>HTTP Cookies: <b> 
  <% = Request.ServerVariables("HTTP_COOKIE") %>
  </b></p>
<p>Pubcookie Appid: <b>
  <% = Request.ServerVariables("HTTP_PUBCOOKIE_APPID") %>
  </b></p>
<p>Pubcookie User: <b> 
  <% = Request.ServerVariables("HTTP_PUBCOOKIE_USER") %>
  </b></p>
<p>Pubcookie Creds: <b>
  <% = Request.ServerVariables("HTTP_PUBCOOKIE_CREDS") %>
  </b></p>
<p>Pubcookie Version: <b>
  <% = Request.ServerVariables("HTTP_PUBCOOKIE_FILTER_VERSION") %>
  </b></p>
<p>Time: <b> 
  <% = Time %>
  on 
  <% = Date %>
  </b></p>
<p>You were authenticated using: <b> 
  <% = Request.ServerVariables("AUTH_TYPE") %>
  </b></p>
<p>Virtual Server: <B> 
  <% = Request.ServerVariables("HTTP_HOST") %>
  </B></p>
<p>Actual Server: <B>
  <% = Request.ServerVariables("HTTP_PUBCOOKIE_SERVER") %>
  </B></p>
<p>Web Instance: <B>
  <% = Request.ServerVariables("INSTANCE_ID") %>
  </B></p>
<p>URL: <B>
  <% = Request.ServerVariables("URL") %>
  </B></p>
</BODY>
</HTML>