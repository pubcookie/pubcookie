
#include <windows.h>
#include "pbc_config.h"
#include "gui_myconfig.h"
#include "CPBC_PropSheet.h"
#include "resource.h"
#include "globals.h"
#include <crtdbg.h>
#include <string>
#include <tchar.h>
#include <strsafe.h>
using namespace std;

#define libpbc_config_getint(p,n,d) libpbc_myconfig_getint(p,_T(n),d)
#define libpbc_config_getstring(p,n,d) libpbc_myconfig_getstring(p,_T(n),_T(d))


void debug(LPCTSTR msg) {
	MessageBox(NULL, msg, L"Debug Notification", MB_OK);
}

void CPBC_PropSheet::GetEffectiveValue(int i) {

	wchar_t key[BUFFSIZE+MAX_PATH], wszBuff[BUFFSIZE];
	wchar_t wszKey[BUFFSIZE+MAX_PATH], wszPath[BUFFSIZE+MAX_PATH],
		wszRootAppId[BUFFSIZE], wszLastAppId[BUFFSIZE], 
		wszDefaultAppId[BUFFSIZE],wszLastDefinedIn[BUFFSIZE];

	wchar_t *ptr,*nptr;
	wstring defined_in_val;
    int inRegistry = 0, isRootAppIdSet = 0, foundAppId = 0;

	// First look in default key
    StringCbCopy (key, BUFFSIZE+MAX_PATH, PBC_WEB_VAR_LOCATION);
	StringCbCat  (key, BUFFSIZE+MAX_PATH, L"\\");
	StringCbCat  (key, BUFFSIZE+MAX_PATH, _T(PBC_DEFAULT_KEY));

	ReadValAsString(key,i,L"/",inRegistry, 0);

	StringCbCopy (wszDefaultAppId, BUFFSIZE, directive[i].value.c_str());


	// Then traverse pwzRegPath
	StringCbCopy (key, BUFFSIZE, PBC_WEB_VAR_LOCATION);
	StringCbCat  (key, BUFFSIZE+MAX_PATH, L"\\");
	ptr = pwzRegPath;
	

	//if default web has a registry item set
	if ( !wcsicmp(directive[i].name.c_str(),L"AppID") && inRegistry ) {
		isRootAppIdSet = 1;
		StringCbCopy (wszRootAppId, BUFFSIZE, directive[i].value.c_str());
	}
	

	int first_node = 1;

	while ( ptr ) { // while we still have a '/' left to deal with

		nptr = ptr;
		ptr = wcschr(nptr,L'/');

		
		if (ptr) {			
			wcsncpy(wszBuff, nptr, ptr-nptr);
			wszBuff[ptr-nptr] = NULL;			
		}
		else {						
			StringCbCopy(wszBuff,BUFFSIZE,nptr);			
		}

		if (!wcslen(wszBuff)) {
			break;
		}

		defined_in_val += L"/";
		defined_in_val += wszBuff;
		

		//root level 
		if ( !wcsicmp(directive[i].name.c_str(),L"AppID") && first_node) {

			
			directive[i].value = wszBuff;
			directive[i].defined_in = defined_in_val;
			directive[i].defined_in += L"\n(default AppID node)";


		}

		first_node = 0;

		// Legacy hack for special tokens PBC_PUBLIC, UWNETID and SECURID
		if ((PBC_LEGACY_DIR_NAMES) && !wcsicmp(directive[i].name.c_str(),L"authtype")) {
			if ( !wcsicmp(wszBuff, PBC_NETID_NAME)) {
				directive[i].value = PBC_AUTHTYPE1;
				directive[i].defined_in = defined_in_val;
				directive[i].defined_in += L"\n(legacy directory name)";
			} else if (!wcsicmp(wszBuff, PBC_SECURID_NAME) ) {
				directive[i].value = PBC_AUTHTYPE3;
				directive[i].defined_in = defined_in_val;
				directive[i].defined_in += L"\n(legacy directory name)";
			} else if (!wcsicmp(wszBuff, PBC_PUBLIC_NAME) ) {
				directive[i].value = PBC_AUTHTYPE0;
				directive[i].defined_in = defined_in_val;
				directive[i].defined_in += L"\n(legacy directory name)";
			}
		}
		// Legacy hack for special tokens PBC_PUBLIC, UWNETID and SECURID
		if ((PBC_LEGACY_DIR_NAMES) && !wcsicmp(directive[i].name.c_str(),L"SetHeaderValues")) {
			if ( !wcsicmp(wszBuff, PBC_PUBLIC_NAME) ) {
				directive[i].value = L"1";
				directive[i].defined_in = defined_in_val;
				directive[i].defined_in += L"\n(legacy directory name)";
			}
		}

		StringCbCat(key,BUFFSIZE,L"\\");
		StringCbCat(key,BUFFSIZE, wszBuff);				

       
		ReadValAsString(key,i,defined_in_val.c_str(),inRegistry, 0);
	
			
		if ( !wcsicmp(directive[i].name.c_str(),L"AppID")) {	
			int atRoot = 0;
			wchar_t *dir;

            //if root appid is set and no registry for the current node				
			if (isRootAppIdSet) {				
				StringCbCat( wszPath, BUFFSIZE+MAX_PATH, wszBuff);
				StringCbCat (wszPath, BUFFSIZE+MAX_PATH, L"\\");

				//loop through nodes and find next parent with appid set
				StringCbCopy (wszKey, BUFFSIZE+MAX_PATH, PBC_WEB_VAR_LOCATION);
				StringCbCat (wszKey, BUFFSIZE+MAX_PATH, L"\\");
				StringCbCat (wszKey, BUFFSIZE+MAX_PATH, wszPath);
				ReadValAsString(wszKey,i,defined_in_val.c_str(),inRegistry, 1);
				
				
				if (inRegistry) {
					StringCbCopy (wszLastAppId, BUFFSIZE, directive[i].value.c_str());					
					//remove trailing slash '\'
					wcsncpy (wszLastDefinedIn, wszPath, wcslen(wszPath)-1);
					foundAppId = 1;
				}else{					
					if (!foundAppId) {
						StringCbCopy (wszLastAppId, BUFFSIZE, wszRootAppId);
					}
				}
	

				if (wszLastAppId == L"") {						
					directive[i].value = wszRootAppId;	
					directive[i].defined_in = L"/";
					directive[i].defined_in += L"\n(default AppID node)";
				}else{
					directive[i].value = wszLastAppId;
					if (!inRegistry && isRootAppIdSet) {						
						directive[i].defined_in = L"/";
						
						//replace '\' with '/'						
						wstring tmp((wchar_t *) wszLastDefinedIn);
						wstring::size_type begidx = tmp.find((wchar_t*) "\\");
						while(begidx != wstring::npos) {
							tmp.replace(begidx, 1, (wchar_t*) "/");
							begidx = tmp.find_first_of((wchar_t*) "\\", begidx+1, begidx);
						}
						
						StringCbCopy (wszLastDefinedIn, BUFFSIZE, tmp.c_str());
						directive[i].defined_in += wszLastDefinedIn;							
					}
				}

				
				
			}else{
				//no root appid is set and no registry entry
				if (!inRegistry) {						
					dir = wcschr(pwzParentPath, L'/');
					//is this file/folder off root
					if (!dir) {
						
						atRoot = 1;

						//check if root file/folder											
						wchar_t wszPath[BUFFSIZE+MAX_PATH];						
						StringCbCat  (wszPath, BUFFSIZE+MAX_PATH, pwzMetaPath);

						//definitions
						HRESULT hr;
						IMSAdminBase *pBase;						
						METADATA_HANDLE hLM;
						METADATA_RECORD mdRec;
						DWORD dwBuffer = 65535;
						PBYTE pbBuffer = new BYTE[dwBuffer];
						DWORD buffer = 0;						
						DWORD dwReqBufLen = 0;						

						CoInitialize(0);
						hr = CoCreateInstance(CLSID_MSAdminBase, 
							NULL,
							CLSCTX_LOCAL_SERVER,
							IID_IMSAdminBase,
							(void**) &pBase);

						if (FAILED(hr)) {															
							pBase->Release();
							return;
						}

						hr = pBase->OpenKey(METADATA_MASTER_ROOT_HANDLE,
							L"",
							//L"/LM/W3SVC",
							//L"/LM/W3SVC/1/Root",
							METADATA_PERMISSION_READ,
							20,
							&hLM);
						if (FAILED(hr)) {								
							pBase->CloseKey(hLM);
							pBase->Release();
							return;
						}	

						if (SUCCEEDED(hr)) {							
							mdRec.dwMDIdentifier = MD_VR_PATH;
							mdRec.dwMDAttributes = METADATA_INHERIT;
							mdRec.dwMDUserType = IIS_MD_UT_FILE;
							mdRec.dwMDDataType = STRING_METADATA;
							mdRec.pbMDData = pbBuffer;
							mdRec.dwMDDataLen = dwBuffer;

	
							hr = pBase->GetData(hLM, wszPath, &mdRec, &buffer);

							int validFolder = 0;
							if (SUCCEEDED(hr)) {
								validFolder = 1;
							}
							
							if (FAILED(hr)){	
								
								//this is good!  this means, it's a file, then inherit default appid								
								
								//keep for debugging
								switch (hr & 0x0000ffff)
								{
									case ERROR_ACCESS_DENIED:
										//debug (L"Access was denied.\n");
										break;

									case ERROR_INSUFFICIENT_BUFFER:
										//debug (L"insufficent buffer.\n");
										break;
									
									case E_INVALIDARG:
										//debug (L"invalid arg.\n");
										break;
									
									case ERROR_PATH_NOT_FOUND:
										pBase->CloseKey(hLM);
										pBase->Release();																			

										
										wchar_t *f;
										f = wcschr(nptr,L'.');

										if (f) {
											directive[i].value = wszDefaultAppId;
											directive[i].defined_in = L"/";
											directive[i].defined_in += L"\n(default AppID node)";
										}

										break;

									case MD_ERROR_DATA_NOT_FOUND:
										//debug (L"md data not found.\n");
										break;
									default:
										//debug (L"generic error.\n");
										break;
								}

								pBase->CloseKey(hLM);
								pBase->Release();
								
								


							}
							
						}


						pBase->CloseKey(hLM);
						pBase->Release();
					
					}
				}
			}
			
		}

		
		

		if (!ptr) {break;}
		ptr++;
		
		
		
	}	
		
	
	
}


void CPBC_PropSheet::Set_Delete_Button(int i) {

	if (!_wcsicmp((directive[i].defined_in.c_str() + 1),pwzRegPath)) {
		EnableWindow(hDelete,TRUE);
	} else {
		EnableWindow(hDelete,FALSE);
	}
}

void CPBC_PropSheet::ReadSelectedValue() {

#	define DIRECTIVE_INIT
#	include "pbc_directives.h"
#	undef DIRECTIVE_INIT
	int i;

	for (i=0;i<NUM_DIRECTIVES;i++) {
		GetEffectiveValue(i);
	}

	DWORD index = SendMessage(hProps, CB_GETCURSEL, 0,0); 
	i = SendMessage(hProps, CB_GETITEMDATA, (WPARAM)index, 0 );
	directive[i].new_value = directive[i].value;

}

void CPBC_PropSheet::ReadCurrentValues() {

#	define DIRECTIVE_INIT
#	include "pbc_directives.h"
#	undef DIRECTIVE_INIT

	for (int i=0;i<NUM_DIRECTIVES;i++) {
		GetEffectiveValue(i);
		directive[i].new_value = directive[i].value;
	}
}

void CPBC_PropSheet::WriteValues() {
	wstring RegPath;

	if  (wcslen(pwzRegPath)) {
		RegPath = pwzRegPath;
	} else {
		RegPath = _T(PBC_DEFAULT_KEY);
	}

	for (int i=0;i<NUM_DIRECTIVES;i++) {
		if (wcscmp(STR_PENDING_DELETION,directive[i].new_value.c_str())){
			if (wcsicmp(directive[i].value.c_str(),directive[i].new_value.c_str())) {
				if (directive[i].type == D_BOUND_INT || directive[i].type == D_FREE_INT) {
					WriteRegInt(RegPath.c_str(), directive[i].name.c_str(), directive[i].new_value.c_str());
				} else {
					WriteRegString(RegPath.c_str(), directive[i].name.c_str(), directive[i].new_value.c_str());
				}
			}
		} else { // Commit Delete
			if (!wcslen(pwzRegPath)) {  //Delete root directory values from default key only
				DeleteRegVal(_T(PBC_DEFAULT_KEY),directive[i].name.c_str());
			} else {
				DeleteRegVal(pwzRegPath,directive[i].name.c_str());
			}
		}
	}

}

HKEY CPBC_PropSheet::OpenPBCKey(LPCTSTR szKey, REGSAM samDesired) {
	_TCHAR szKeyBuf[BUFFSIZE] ;

	StringCbCopy (szKeyBuf, BUFFSIZE, PBC_WEB_VAR_LOCATION);
	StringCbCat  (szKeyBuf, BUFFSIZE+MAX_PATH, L"\\");
	StringCbCat(szKeyBuf,BUFFSIZE,szKey);
	ReplaceSlashes(szKeyBuf);

	return(OpenKey(szKeyBuf,samDesired,0));

}
