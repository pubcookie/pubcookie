#define NUM_DIRECTIVES 16
#ifdef SERVER_VALS_INIT
	wchar_t dbuffer[BUFFSIZE];

	directive[0].name         = L"Debug_Trace";
	directive[0].type         = D_BOUND_INT;
	directive[0].value        = _itow(PBC_DEBUG_TRACE,dbuffer,10);
	directive[0].defined_in   = defined_in;
	directive[0].description  = L"Debug level:\n-1 : Errors Only\n 0 : Warnings and Errors\n 1 : Informational\n 2+ : More Debugging";
	directive[0].bound_val[0] = L"-1";
	directive[0].bound_val[1] = L"0";
	directive[0].bound_val[2] = L"1";
	directive[0].bound_val[3] = L"2";
	directive[0].bound_val[4] = L"3";

	directive[1].name         = L"Login_URI";
	directive[1].type         = D_FREE_STRING;
	directive[1].value        = PBC_LOGIN_URI;
	directive[1].defined_in   = defined_in;
	directive[1].description  = L"URL of Pubcookie login server.";

	directive[2].name         = L"Keymgt_URI";
	directive[2].type         = D_FREE_STRING;
	directive[2].value        = PBC_KEYMGT_URI;
	directive[2].defined_in   = defined_in;
	directive[2].description  = L"URL of Pubcookie keyserver.";

	directive[3].name         = L"AuthTypeName0";
	directive[3].type         = D_FREE_STRING;
	directive[3].value        = PBC_AUTHTYPE0;
	directive[3].defined_in   = defined_in;
	directive[3].description  = L"Name of authentication type that corresponds to no authentication.";

	directive[4].name         = L"AuthTypeName1";
	directive[4].type         = D_FREE_STRING;
	directive[4].value        = PBC_AUTHTYPE1;
	directive[4].defined_in   = defined_in;
	directive[4].description  = L"Name of authentication type that corresponds to your login server's first login flavor (e.g. flavor_basic).";

	directive[5].name         = L"AuthTypeName2";
	directive[5].type         = D_FREE_STRING;
	directive[5].value        = PBC_AUTHTYPE2;
	directive[5].defined_in   = defined_in;
	directive[5].description  = L"Name of authentication type that corresponds to your login server's second login flavor";

	directive[6].name         = L"AuthTypeName3";
	directive[6].type         = D_FREE_STRING;
	directive[6].value        = PBC_AUTHTYPE3;
	directive[6].defined_in   = defined_in;
	directive[6].description  = L"Name of authentication type that corresponds to your login server's third login flavor.";

	directive[7].name         = L"PUBLIC_dir_name";
	directive[7].type         = D_FREE_STRING;
	directive[7].value        = PBC_PUBLIC_NAME;
	directive[7].defined_in   = defined_in;
	directive[7].description  = L"If LegacyDirNames names is enabled, a directory with this name implicitly sets the ";
	directive[7].description  += PBC_AUTHTYPE0;
	directive[7].description  += L" authentication type and SetHeaderValues will be enabled.";

	directive[8].name         = L"NETID_dir_name";
	directive[8].type         = D_FREE_STRING;
	directive[8].value        = PBC_NETID_NAME;
	directive[8].defined_in   = defined_in;
	directive[8].description  = L"If LegacyDirNames names is enabled, a directory with this name implicitly sets the ";
	directive[8].description  += PBC_AUTHTYPE1;
	directive[8].description  += L" authentication type.";

	directive[9].name         = L"SECURID_dir_name";
	directive[9].type         = D_FREE_STRING;
	directive[9].value        = PBC_SECURID_NAME;
	directive[9].defined_in   = defined_in;
	directive[9].description  = L"If LegacyDirNames names is enabled, a directory with this name implicitly sets the ";
	directive[9].description  += PBC_AUTHTYPE3;
	directive[9].description  += L" authentication type.";

	directive[10].name         = L"ClientLogFormat";
	directive[10].type         = D_FREE_STRING;
	directive[10].value        = PBC_CLIENT_LOG_FMT;
	directive[10].defined_in   = defined_in;
	directive[10].description  = L"Format used to log the client username. Use %w for Windows user and %p for Pubcookie user.";

	directive[11].name         = L"WebVarLocation";
	directive[11].type         = D_FREE_STRING;
	directive[11].value        = PBC_WEB_VAR_LOCATION;
	directive[11].defined_in   = defined_in;
	directive[11].description  = L"Location of the Pubcookie directive database within the Windows registry.\nUse this if you wish to keep completely separate file and folder directives for the target web site.";

	/*directive[12].name         = L"Enterprise_Domain";
	directive[12].type         = D_FREE_STRING;
	directive[12].value        = PBC_ENTRPRS_DOMAIN;
	directive[12].defined_in   = defined_in;
	directive[12].description  = L"Domain for scoping granting request cookie.";*/

	directive[12].name         = L"Default_App_Name";
	directive[12].type         = D_FREE_STRING;
	directive[12].value        = PBC_DEFAULT_APP_NAME;
	directive[12].defined_in   = defined_in;
	directive[12].description  = L"Name to assign if application name cannot be determined (e.g. on a request to /).";

	directive[13].name         = L"Ignore_Poll";
	directive[13].type         = D_BOUND_INT;
	directive[13].value        = _itow(PBC_IGNORE_POLL,dbuffer,10);
	directive[13].defined_in   = defined_in;
	directive[13].description  = L"Set to 1 to ignore Network Dispatcher \"/\" polls.";
	directive[13].bound_val[0] = L"0";
	directive[13].bound_val[1] = L"1";

	directive[14].name         = L"LegacyDirNames";
	directive[14].type         = D_BOUND_INT;
	directive[14].value        = _itow(PBC_LEGACY_DIR_NAMES,dbuffer,10);
	directive[14].defined_in   = defined_in;
	directive[14].description  = L"Set to 1 to support legacy directory names.";
	directive[14].bound_val[0] = L"0";
	directive[14].bound_val[1] = L"1";

	directive[15].name         = L"System_Root";
	directive[15].type         = D_FREE_STRING;
	directive[15].value        = L"";
	directive[15].defined_in   = L"(Program Default)";
	directive[15].description  = L"Base directory for Pubcookie debug and config files. Leave blank to use the Windows system directory.";

/*	directive[17].name         = L"Relay_URI";
	directive[17].type         = D_FREE_STRING;
	directive[17].value        = PBC_RELAY_URI;
	directive[17].defined_in   = defined_in;
	directive[17].description  = L"Location of an optional Pubcookie relay CGI.";

	directive[18].name         = L"Relay_Template_Path";
	directive[18].type         = D_FREE_STRING;
	directive[18].value        = PBC_TEMPLATES_PATH;
	directive[18].defined_in   = defined_in;
	directive[18].description  = L"Path to templates used by optional Pubcookie relay CGI"; */

#endif



