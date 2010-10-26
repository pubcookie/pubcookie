
#ifndef _CPBC_PropSheet
#define _CPBC_PropSheet

#include <tchar.h>
#include <mmc.h>
#include <string>

#include <iadmw.h> // COM Interface header 
#include <iiscnfg.h>// MD_ & IIS_MD_ #defines 

using namespace std;

#define D_FREE_STRING 0
#define D_FREE_INT 1
#define D_BOUND_INT 2
#define D_BOUND_STRING 3

#define NUM_BOUND_VAL 4
typedef wchar_t pool;
#define BUFFSIZE 4096
#define MAX_REG_BUFF 2048 /* Using a fixed size saves a registy lookup and malloc */

#define STR_THIS_WEB_INSTANCE L"(This web instance)"
#define STR_SERVER_DEFAULT    L"(Server Default)"
#define STR_PROGRAM_DEFAULT   L"(Program Default)"
#define STR_PENDING_DELETION  L"(Pending Removal)"

#define debug_break() MessageBox(NULL,L"Break",L"Break",MB_OK);

struct directive_t {
		wstring name;
		wstring display_name;
		char type; 
		wstring value;
		wstring new_value;
		wstring defined_in;
		wstring description;
		wstring bound_val[NUM_BOUND_VAL];
};		

class CPBC_PropSheet : public IExtendPropertySheet
{
    
private:
    ULONG				m_cref;
    
    // clipboard format
    static UINT s_cfDisplayName;
    static UINT s_cfSnapInCLSID;
    static UINT s_cfNodeType;

    
public:
    CPBC_PropSheet();
    ~CPBC_PropSheet();

	HWND hwndDlg;
	LPWSTR pwzRegPath;
	LPWSTR pwzMachineName;
	#include "pbc_directives.h"
	directive_t directive[NUM_DIRECTIVES];

	void SetupPropSheet();
	void PopulatePage();
	BOOL UpdateNewValue();
	void ReadValAsString(LPTSTR key, int i, LPCTSTR defined_in, int &inreg, int readonly);
	int  libpbc_myconfig_getint(LPTSTR strbuff, LPCTSTR key, int def);
	LPTSTR libpbc_myconfig_getstring(LPTSTR strbuff, LPCTSTR key, LPCTSTR def);
	

	///////////////////////////////
    // Interface IUnknown
    ///////////////////////////////
    STDMETHODIMP QueryInterface(REFIID riid, LPVOID *ppv);
    STDMETHODIMP_(ULONG) AddRef();
    STDMETHODIMP_(ULONG) Release();
    
    ///////////////////////////////
    // Interface IExtendPropertySheet
    ///////////////////////////////
    virtual /* [helpstring] */ HRESULT STDMETHODCALLTYPE CreatePropertyPages( 
        /* [in] */ LPPROPERTYSHEETCALLBACK lpProvider,
        /* [in] */ LONG_PTR handle,
        /* [in] */ LPDATAOBJECT lpIDataObject);
        
    virtual /* [helpstring] */ HRESULT STDMETHODCALLTYPE QueryPagesFor( 
        /* [in] */ LPDATAOBJECT lpDataObject);

    
private:
    LONG_PTR m_ppHandle;
	LPWSTR pwzInstance;
	LPWSTR pwzMetaPath;
	LPWSTR pwzNode;
	LPWSTR pwzParentPath;
	LPWSTR pwzService;
    pool   p[BUFFSIZE];
	wstring defined_in;

	HWND hValueBox;      
	HWND hValueEdit;
	HWND hInheritedFrom;
	HWND hMoreInfo;
	HWND hProps;	
	HWND hDelete;

	static BOOL CALLBACK DialogProc(HWND hwndDlg,  // handle to dialog box
        UINT uMsg,     // message
        WPARAM wParam, // first message parameter
        LPARAM lParam  // second message parameter
        );

	HKEY OpenKey(LPCTSTR szKey, REGSAM samDesired, int readonly);
	HKEY OpenPBCKey(LPCTSTR szKey, REGSAM samDesired);
	BOOL WriteRegString(const _TCHAR* szKey,
              const _TCHAR* szValueName,
              const _TCHAR* szValue);
	BOOL WriteRegInt(const _TCHAR* szKey,
              const _TCHAR* szValueName,
              const _TCHAR* szValue);
    
    void PopulateComboBox();
	void WriteValues();
	void GetEffectiveValue(int i);
	void ReplaceSlashes(_TCHAR * buf);
	void ReadCurrentValues();
	void DeleteRegVal(const _TCHAR* szKey, const _TCHAR* szValueName);
	void DeleteValue();
	void Set_Delete_Button(int i);
	void ReadSelectedValue();
	void GetHandles();		


    ///////////////////////////////
    // Private IDataObject support bits
    ///////////////////////////////
    HRESULT ExtractData( IDataObject* piDataObject,
        CLIPFORMAT   cfClipFormat,
        BYTE*        pbData,
        DWORD        cbData );
    
    HRESULT ExtractString( IDataObject *piDataObject,
        CLIPFORMAT   cfClipFormat,
        _TCHAR       *pstr,
        DWORD        cchMaxLength)
    {
        return ExtractData( piDataObject, cfClipFormat, (PBYTE)pstr, cchMaxLength );
    }
    
    HRESULT ExtractSnapInCLSID( IDataObject* piDataObject, CLSID* pclsidSnapin )
    {
        return ExtractData( piDataObject, s_cfSnapInCLSID, (PBYTE)pclsidSnapin, sizeof(CLSID) );
    }
    
    HRESULT ExtractObjectTypeGUID( IDataObject* piDataObject, GUID* pguidObjectType )
    {
        return ExtractData( piDataObject, s_cfNodeType, (PBYTE)pguidObjectType, sizeof(GUID) );
    }
};


#endif _CPBC_PropSheet_H_
