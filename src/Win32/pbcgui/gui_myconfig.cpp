#include "../../pbc_config.h"
#include <windows.h>
#include <time.h>
#include "CPBC_PropSheet.h"
#include "resource.h"
#include <strsafe.h>
using namespace std;

#define KEY_SIZE 1024

static void fatal(const LPTSTR s, int ex)
{
	MessageBox(NULL,s,L"Pubcookie Property Error",MB_OK | MB_ICONEXCLAMATION);
    exit(ex);
}


LPTSTR libpbc_myconfig_copystring(LPTSTR outputstring, LPCTSTR inputstring, int size)
{
	if (inputstring != NULL) {
		wcsncpy(outputstring,inputstring,MAX_REG_BUFF);  
	}
	else {
		free(outputstring);
		outputstring = NULL;
	}
	return outputstring;
}

LPTSTR CPBC_PropSheet::libpbc_myconfig_getstring(LPTSTR strbuff, LPCTSTR key, LPCTSTR def)
{
	wchar_t keyBuff[KEY_SIZE];
	HKEY hKey;
	DWORD dsize;

	dsize = MAX_REG_BUFF;
	defined_in = STR_PROGRAM_DEFAULT;

	/* First look in this instance if it exists */
	if (pwzInstance) {
	  if (wcslen(pwzInstance)) {
		StringCbCopy(keyBuff,KEY_SIZE,_T(PBC_FILTER_KEY));
		StringCbCat (keyBuff,KEY_SIZE,L"\\");
		StringCbCat (keyBuff,KEY_SIZE,_T(PBC_INSTANCE_KEY));
		StringCbCat (keyBuff,KEY_SIZE,L"\\");
		StringCbCat (keyBuff,KEY_SIZE,pwzInstance); 
		hKey = OpenKey(keyBuff,KEY_READ,0);
		if (hKey) {
			if (RegQueryValueEx(hKey, key, NULL, NULL, (UCHAR *)strbuff,
				&dsize) == ERROR_SUCCESS) {
					RegCloseKey(hKey);
					defined_in = STR_THIS_WEB_INSTANCE;
					return strbuff;  /* Note that this must have been allocated by the calling process */
				}
				RegCloseKey(hKey);
		}
	  }
	}

	StringCbCopy(keyBuff,KEY_SIZE,_T(PBC_FILTER_KEY));  /* Then main pubcookie service key */
	hKey = OpenKey(keyBuff,KEY_READ,0);
	if (!hKey) {
		libpbc_myconfig_copystring(strbuff,def,MAX_REG_BUFF);  
	}
	else {
		if (RegQueryValueEx(hKey, key, NULL, NULL, (UCHAR *)strbuff,
			&dsize) != ERROR_SUCCESS)
		{
			libpbc_myconfig_copystring(strbuff,def,MAX_REG_BUFF);
		} else {
			defined_in = STR_SERVER_DEFAULT;  /* strbuff now has read value */
		}
		RegCloseKey(hKey);
	}
	return strbuff;  /* Note that this must have been allocated by the calling process */
}


int CPBC_PropSheet::libpbc_myconfig_getint(LPTSTR strbuff, LPCTSTR key, int def)
{
	wchar_t keyBuff[KEY_SIZE];
	HKEY hKey;
	DWORD dsize;
	DWORD value;

	dsize = sizeof(DWORD);

	defined_in = STR_PROGRAM_DEFAULT;

	/* First look in this instance if it exists */
	if (pwzInstance) {
	  if (wcslen(pwzInstance)) {
		StringCbCopy(keyBuff,KEY_SIZE,_T(PBC_FILTER_KEY));
		StringCbCat (keyBuff,KEY_SIZE,L"\\");
		StringCbCat (keyBuff,KEY_SIZE,_T(PBC_INSTANCE_KEY));
		StringCbCat (keyBuff,KEY_SIZE,L"\\");
		StringCbCat (keyBuff,KEY_SIZE,pwzInstance); 
		hKey = OpenKey(keyBuff,KEY_READ,0);
		if (hKey) {
			if (RegQueryValueEx(hKey, key, NULL, NULL, (LPBYTE)&value,
				&dsize) == ERROR_SUCCESS) {
					defined_in = STR_THIS_WEB_INSTANCE;
					RegCloseKey(hKey);
					return (int)value;   // if we find it here, we're done
				}
				RegCloseKey(hKey);
		}
	  }
	}

	StringCbCopy (keyBuff,KEY_SIZE,_T(PBC_FILTER_KEY));  /* config. settings in main pubcookie service key */

	hKey = OpenKey(keyBuff,KEY_READ,0);
	if (!hKey) 
	{
		return def;  
	}

	if (RegQueryValueEx(hKey, key, NULL, NULL, (LPBYTE)&value,
		&dsize) != ERROR_SUCCESS) 
	{
		RegCloseKey(hKey);
		return def;
	}

	defined_in = STR_SERVER_DEFAULT;
	RegCloseKey(hKey);
	return (int)value;
}

