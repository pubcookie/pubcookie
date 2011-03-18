'This script removes the Pubcookie filter to the main key for IIS
'It then removes any found instance from enumerated web servers.

On Error Resume Next
Set Container = GetObject("IIS://Localhost/W3SVC")

If Err = 0 Then
    'Delete Pubcookie3 to root filter list 
    Set ChildFilters = GetObject("IIS://Localhost/W3SVC/Filters")
    pbc_delete Container, ChildFilters

    If Err = 0 Then
	 'nm
    Else
       msgbox("Problem encountered removing Pubcookie filter from root filter list, error: " & Err )
    End If

    'Remove any pubcookie filters from any web server instance
    For Each Child in Container
      If Child.Class = "IIsWebServer" Then
		Set ChildFilters = GetObject("IIS://Localhost/W3SVC/" & Child.Name & "/Filters")
      	pbc_delete Child, ChildFilters
      End If
    Next
Else
    msgbox("Could not open metabase, error: " & Err & ". Pubcookie filter may still appear in root filter list.")
End If

Sub pbc_delete (Child, ChildFilters)
   On Error Resume Next
    
     FilterLoadOrder = ChildFilters.FilterLoadOrder
     If FilterLoadOrder <> "" Then
       q = 1
		Do
			p = Instr(q, FilterLoadOrder, ",", 1)
			If p > 0 Then
				Chunk = Mid(FilterLoadOrder,q,p-q)
      			Found = Instr(1, Chunk, "pubcookie", 1)
			Else
				l = len(FilterLoadOrder) - q + 1
				Chunk = Mid(FilterLoadOrder,q,l)
				Found = Instr(q, FilterLoadOrder, "pubcookie", 1)
			End If
			If Found = 0 Then  
			  'Look for pubcookie in filter filename as well
                    Set FilterObj = GetObject("IIS://Localhost/W3SVC/" & Child.Name & "/Filters/" & Chunk)
                    Found = Instr(1,FilterObj.FilterPath,"pubcookie",1)
			End If
                  Err = 0 'In case of bad metabase paths in above tests
				
			If Found > 0 Then
			  'Delete current filter instance 
				 ChildFilters.Delete "IIsFilter",Chunk 
				 If Err <> 0 Then
					'Messy, but not fatal
					Err = 0
				 End If 
                    'Remove string from load order
                         FilterLoadOrder = Replace(FilterLoadOrder,Chunk & ",","")
                         FilterLoadOrder = Replace(FilterLoadOrder,"," & Chunk,"")
                         FilterLoadOrder = Replace(FilterLoadOrder,Chunk,"")
                         ChildFilters.FilterLoadOrder = FilterLoadOrder    
			End If
			q = p + 1
		Loop While p > 0
		ChildFilters.SetInfo
            Child.SetInfo
     End If
End Sub

