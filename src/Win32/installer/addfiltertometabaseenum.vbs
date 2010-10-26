'This script adds the Pubcookie filter to the first enumerated instance of a web server
'Option Explict
Dim MyObject
Dim Child 
Dim Container 
Dim ServerComment
Dim message, title, defaultValue 
Dim myValue 
Dim FilterLoadOrder
Dim ret
Dim NewChild

On Error Resume Next
Set MyObject = GetObject("IIS://Localhost/W3SVC")
Set Container = MyObject
 
If Err = 0 Then
    For Each Child in Container
      If Child.Class = "IIsWebServer" Then
          Set FilterLoadOrder = Child.FilterLoadOrder
          Set ret = Instr(1, FilterLoadOrder, "pubcookie", 1)
          
          'Child.Create "ServerComment2", "Default"
          Set foo = GetObject("IIS://Localhost/W3SVC/1/Root")
          Set NewChild = foo.Create ("IIsWebVirtualDir", "NewVDir")
          Wscript.Echo("Tried to add test, foo to " & Child.ServerComment & ". Error Status: " & Err & ".")

          'Set the property.
          'Child.Put(sPropertyName, sValue)

          'Save the changes.
          Child.SetInfo()

          If Err = 0 Then
              Wscript.Echo("Added Pubcookie filter to " & Child.ServerComment & ".")
		  Else
	          Wscript.Echo("Problem encountered adding Pubcookie filter to " & Child.ServerComment & ", error: " & Err & ".")
		  End If
          Exit For
      End If
    Next
Else
    Wscript.Echo("Could not open metabase, error: " & Err & ". Pubcookie filter has not been added to any web server instances.")
End If
				'Wscript.Echo("Chunk = " & Chunk & " x = " & x & " p = " & p & " q = " & q ) 'debug
