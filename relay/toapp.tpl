# pubcookie relay pages

# redirection to the application
# blank page version

# GET method

<!-- BDB: get -->
<html>
<head>
      <meta http-equiv="Refresh" content="0;URL={APP_URL}">
</head>
</html>
<!-- EDB: get -->
 

# POST method

<!-- BDB: post -->
<html>
<head>
<script language=javascript>
function showtheclick() {   /* In case the auto-click doesn't work */
  document.relay.elements[0].style.visibility="visible";
  document.getElementById('message').style.visibility="visible";
}
function dotheclick() {
  setTimeout( "showtheclick()", 2000);
<!-- BDB: submit -->
  document.relay.submit();
<!-- EDB: submit -->
<!-- BDB: click -->
  document.relay.elements[0].click();
<!-- EDB: click -->
}
</script>
</head>

<body onLoad="dotheclick();">

<p id=message  style="visibility:hidden" align=center>
Your browser was not able to continue to your destination automatically.
<br>
Click the button to continue.
<p>

<form method=post action="{APP_URL}" name=relay>
<p align=center><input type=submit value="Continue"
        style="visibility:hidden">

# original args
<!-- BDB: arg -->
<input type=hidden name="{ARGNAME}" value="{ARGVAL}">
<!-- EDB: arg -->

<!-- BDB: area -->
<textarea name="{ARGNAME}" style="visibility:hidden">
{ARGVAL}</textarea>
<!-- EDB: area -->

<noscript>
<p align=center>You do not have Javascript turned on,
please click the button to continue.
<input type=submit value="Continue">
</noscript>


</form>
</html>
<!-- EDB: post -->
 



