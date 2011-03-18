<%@ EnableSessionState=False%>

<% 
' Dumpvars.asp
%>
<HTML>
<HEAD><TITLE>HTTP Server Variables</TITLE></HEAD>
<BODY BGCOLOR=#FFFFFF>
<H1>HTTP Server Variables</H1>

<TABLE BORDER=1>
<TR><TD VALIGN=TOP><B>Variable</B></TD><TD VALIGN=TOP><B>Value</B></TD></TR>
<% For Each key in Request.ServerVariables %>
	<TR>
	<TD><% = key %></TD>
	<TD>
	<%
	if Request.ServerVariables(key) = "" Then
		Response.Write "&nbsp" ' To force border around table cell
	else		
		Response.Write Request.ServerVariables(key)
	end if
	Response.Write "</TD>"
	%>
	</TR>
<% Next %>
</TABLE>
<BR>
</BODY>
</HTML>