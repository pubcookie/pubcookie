# pubcookie relay pages
# blank page version

# redirection to the login server

<html>
<head>
</head>

<body onLoad="document.relay.submit()"> 

<form method=post action="{LOGIN}" name=relay>

<input type=hidden name=pubcookie_g_req value="{G_REQUEST}">
<input type=hidden name=post_stuff value="{POSTSTUFF}">
<input type=hidden name=relay_url value="{RELAYURL}">

<noscript>
<p align=center>You do not have Javascript turned on,
please click the button to continue.
<p align=center> <input type=submit name=go value="Continue">
</noscript>

</form>
</html>
 



