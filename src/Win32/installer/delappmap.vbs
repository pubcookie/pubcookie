option Explicit
Const DebugMode = false
Const COMMAND_VIEW       = 0
Const COMMAND_ADD    = 1
Const COMMAND_DELETE      = 2
Const COMMAND_ReplaceFromfile     = 3
Dim ScriptMap
Dim ObjectPath
Dim MyObject
Dim Child 
Dim Container 

'On Error Resume Next
Set MyObject = GetObject("IIS://Localhost/W3SVC")
Set Container = MyObject
 
If Err = 0 Then
	ObjectPath = "IIS://localHost/W3SVC"
	DoDel(ObjectPath)

    For Each Child in Container
      If Child.Class = "IIsWebServer" Then
		ObjectPath = "IIS://localHost/W3SVC/" & Child.Name & "/ROOT"
		DoDel(ObjectPath)
      End If
    Next
Else
    WScript.Echo("Could not open metabase, error: " & Err & ". Application maps have not been added.")
End If


Function VerifyScriptMapToAdd()
    Dim ArgExt, ArgPath, ArgOption, ArgExclusions, Bits, pos
	' We need to split the line up into its components and check each one.
	Bits = split(ScriptMap, ",")
	if (UBound(Bits) > 1) then
		ArgExt = bits(0)
		VerifyScriptMapToAdd = ArgExt
		ArgPath = bits(1)
		ArgOption = Bits(2)
		for pos = 3 to UBound(Bits)
			if (Pos > 3) then
				ArgExclusions = ArgExclusions & ","
			end if
			ArgExclusions = ArgExclusions & Bits(pos)
		next
	else
		WScript.Echo( "* Invalid Script Map to add, insufficiant parts to the script map!")
		VerifyScriptMapToAdd = ""
		exit Function
	end if
end Function

Function DoesScriptMapExist(IISOBJ, Extension)
    Dim Pos, Items, Ext, ScriptMaps
	DoesScriptMapExist = -1
	Ext = ucase(Extension)
	ScriptMaps = IISOBJ.Scriptmaps
	for pos = lbound(ScriptMaps) to UBOund(ScriptMaps)
		Items = Split(Scriptmaps(Pos), ",")
        if (ucase(items(0)) = Ext) then
			DoesScriptMapExist = pos
			exit Function
		end if
	next
end function

Function DoView(IISOBJ)
	Dim Pos, ScriptMaps
	WScript.Echo( "Script Maps on " & ObjectPath & vbcrlf)
    ScriptMaps = IISOBJ.ScriptMaps
	for pos = lbound(ScriptMaps) to UBOund(ScriptMaps)
          WScript.Echo(  Pos & " = " & ScriptMaps(POS))
	next
end Function

Function DoAdd(ObjectPath)
  Dim Ext, NewScriptMaps, IISOBJ, MapPos
  
  SET IISOBJ = getObject(ObjectPath)

  Ext = VerifyScriptMapToAdd
  NewScriptMaps = IISOBJ.ScriptMaps
  MapPos = DoesScriptMapExist(IISOBJ, Ext)
  
  if (MapPos = -1) then	
	Redim preserve NewScriptMaps(Ubound(NewScriptMaps)+1)
	NewScriptMaps(ubound(NewScriptMaps)) = ScriptMap
	'WScript.Echo( "New Script Map added for extension " & Ext & vbcrlf  & vbcrlf & ScriptMap)
  else
    NewScriptMaps(MapPos) = ScriptMap
   	'WScript.Echo( "Script Map modified for extension " & Ext & vbcrlf  & vbcrlf & ScriptMap)
  end if


  ' Save the added/modified script map
  IISOBJ.ScriptMaps = NewScriptMaps
  IISOBJ.SetInfo
  if (ERR <> 0) then
    WScript.Echo( "Error setting data - " & Err.Description & " (" & Err & ")")
    exit Function
  end if
  
  IISOBJ.GetInfo
  'DoView(IISOBJ)
  SET IISOBJ = Nothing
end Function

Function DoDel(ObjectPath)
  Dim Ext, ScriptMaps, NewScriptMaps, IISOBJ, MapPos, xpos, pos, items
  
  SET IISOBJ = getObject(ObjectPath)

  Ext=".PUBCOOKIE3"
  ScriptMaps = IISOBJ.ScriptMaps
  xpos = 0
  for pos = lbound(ScriptMaps) to UBOund(ScriptMaps)
	items = Split(Scriptmaps(pos), ",")
    if (ucase(items(0)) <> Ext) then
		if (xpos = 0) then
			reDim NewScriptMaps(0)
		else
			Redim Preserve NewScriptMaps(UBound(NewScriptMaps)+1)
		end if
        NewScriptMaps(UBound(NewScriptMaps)) = ScriptMaps(pos)
		xpos = xpos + 1
	'else
   	    'WScript.Echo( "Script Map deleted for extension " & Ext )
	end if
  next
  
  DoDel = NewScriptMaps
  
  ' Save the added/modified script map
  IISOBJ.ScriptMaps = NewScriptMaps
  IISOBJ.SetInfo
  if (ERR <> 0) then
    WScript.Echo( "Error setting data - " & Err.Description & " (" & Err & ")")
    exit Function
  end if
  
  IISOBJ.GetInfo
  'DoView(IISOBJ)
  SET IISOBJ = Nothing
end Function




