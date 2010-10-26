#define NUM_DIRECTIVES 12
#ifdef DIRECTIVE_INIT
	wchar_t dbuffer[BUFFSIZE];

	directive[0].name         = L"Inactive_Timeout";
	directive[0].type         = D_FREE_INT;
	directive[0].value        = _itow(PBC_DEFAULT_INACT_EXPIRE,dbuffer,10);
	directive[0].description  = L"Session cookie times out after this number of seconds without session activity.";
	directive[0].defined_in   = L"(Program Default)";

	directive[1].name         = L"Hard_Timeout";
	directive[1].type         = D_FREE_INT;
	directive[1].value        = _itow(PBC_DEFAULT_HARD_EXPIRE,dbuffer,10);
	directive[1].description  = L"Session cookie times out after this value in seconds regardless of session activity.";
	directive[1].defined_in   = L"(Program Default)";

	directive[2].name         = L"Session_Reauth";
	directive[2].type         = D_FREE_INT;
	directive[2].value        = L"0";
	directive[2].description  = L"Require re-authentication for this resource even with valid login cookie.\n  0 : false\n  1 : true\n  2+ : number of seconds grace period before re-authentication is required";
	directive[2].defined_in   = L"(Program Default)";

	directive[3].name         = L"AuthType";
	directive[3].type         = D_BOUND_STRING;
	directive[3].value        = PBC_AUTHTYPE0;
	directive[3].description  = L"Authentication type, as offered by your login server. The string is case-insensitive.\nThese strings can be redefined at the server or web instance level.";
	directive[3].bound_val[0] = PBC_AUTHTYPE0;
	directive[3].bound_val[1] = PBC_AUTHTYPE1;
	directive[3].bound_val[2] = PBC_AUTHTYPE2;
	directive[3].bound_val[3] = PBC_AUTHTYPE3;
	directive[3].defined_in   = L"(Program Default)";

	directive[4].name         = L"Logout_Action";
	directive[4].type         = D_BOUND_INT;
	directive[4].value        = L"0";
    directive[4].description  = L"Logout action on this node:\n  0 : No logout action\n  1 : Clear session cookie and serve page; implicitly sets AuthType to ";
    directive[4].description  += PBC_AUTHTYPE0;
    directive[4].description  += L"\n  2 : Clear session cookie and redirect to login server\n  3 : Clear session cookie and redirect to login server to clear login cookie";
	directive[4].bound_val[0] = L"0";
	directive[4].bound_val[1] = L"1";
	directive[4].bound_val[2] = L"2";
	directive[4].bound_val[3] = L"3";
	directive[4].defined_in   = L"(Program Default)";

	directive[5].name         = L"Login_URI";
	directive[5].type         = D_FREE_STRING;
	directive[5].value        = PBC_LOGIN_URI;
	directive[5].description  = L"URL of Pubcookie login server.";
	directive[5].defined_in   = defined_in;

	directive[6].name         = L"Web_Login";
	directive[6].type         = D_FREE_STRING;
	directive[6].description  = L"*Deprecated*\n\nUse Login_URI instead. Login_URI takes precedence if both are set.";
	directive[6].value        = PBC_LOGIN_URI;
	directive[6].defined_in   = defined_in;

	/*directive[7].name         = L"Enterprise_Domain";
	directive[7].type         = D_FREE_STRING;
	directive[7].value        = PBC_ENTRPRS_DOMAIN;
	directive[7].description  = L"Domain for scoping granting request cookie.";
	directive[7].defined_in   = defined_in;*/

	directive[7].name         = L"Error_Page";
	directive[7].type         = D_FREE_STRING;
	directive[7].description  = L"Partial URL path for errors than halt the Pubcookie process.";
	directive[7].defined_in   = L"(Program Default)";

	directive[8].name         = L"SetHeaderValues";
	directive[8].type         = D_BOUND_INT;
	directive[8].value        = L"0";
	directive[8].description  = L"Set to 1 to enable Pubcookie header values even if not using Pubcookie authentication.";
	directive[8].bound_val[0] = L"0";
	directive[8].bound_val[1] = L"1";
	directive[8].defined_in   = L"(Program Default)";

	directive[9].name         = L"AppId";
	directive[9].type         = D_FREE_STRING;
	directive[9].value        = PBC_DEFAULT_APP_NAME;
	directive[9].description  = L"Application ID. A case-insensitive string.\nDefaults to first directory node or ";
	directive[9].description  += PBC_DEFAULT_APP_NAME;
	directive[9].description  += L" if in root directory.";
	directive[9].defined_in   = L"(Root Directory Value)";

	directive[10].name         = L"No_Prompt";
	directive[10].type         = D_BOUND_INT;
	directive[10].value        = L"0";
	directive[10].description  = L"Set to 1 to enable empty string for pubcookie user ID in the case of no login cookie.";
	directive[10].bound_val[0] = L"0";
	directive[10].bound_val[1] = L"1";
	directive[10].defined_in   = L"(Program Default)";

	directive[11].name         = L"Encryption_Method";
	directive[11].type         = D_BOUND_STRING;
	directive[11].value        = PBC_ENCRYPT_METHOD;
	directive[11].defined_in   = defined_in;
	directive[11].description  = L"Defines the encryption algorithm used by the module to encrypt and decrypt private data. The same 2048-byte key suffices for either encryption method. Use DES for backward compatibility with older login servers.";
	directive[11].bound_val[0] = L"AES";
	directive[11].bound_val[1] = L"DES";

#endif



