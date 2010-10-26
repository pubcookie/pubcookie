'This script finds the webroot of the first numbered instance of a web server

Done = 0
On Error Resume Next
Set MyObject = GetObject("IIS://Localhost/W3SVC")

If Err = 0 Then
    For x = 1 to 100
      Set SiteObj = GetObject("IIS://Localhost/W3SVC/" & x ) 
      If Err = 0 Then

          Set RootObj = GetObject("IIS://Localhost/W3SVC/" & x & "/Root") 
          session.TargetPath("WEBROOT") = RootObj.Path
	  Done = 1 
          Exit For

      End If
    Next
    If Done = 0 Then
        msgbox("Could not find a web site.  Make sure that a web site has been defined in the Computer Management MMC snap-in.")
    End If
Else
    msgbox("Could not open metabase, error: " & Err & ".")
End If
