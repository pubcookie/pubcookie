#define IO_BUFFER_SIZE  0x10000



#define DLL_NAME TEXT("Secur32.dll")

#define NT4_DLL_NAME TEXT("Security.dll")

BOOL LoadSecurityLibrary(SecurityFunctionTable ** lpSecurityFunc);

SECURITY_STATUS

CreateCredentials(

    LPSTR pszUserName,

    PCredHandle phCreds);



INT

ConnectToServer(

    LPSTR pszServerName,

    INT   iPortNumber,

    SOCKET *pSocket);



SECURITY_STATUS

PerformClientHandshake(

    SOCKET          Socket,

    PCredHandle     phCreds,

    LPSTR           pszServerName,

    CtxtHandle *    phContext,

    SecBuffer *     pExtraData);



SECURITY_STATUS

ClientHandshakeLoop(

    SOCKET          Socket,

    PCredHandle     phCreds,

    CtxtHandle *    phContext,

    BOOL            fDoInitialRead,

    SecBuffer *     pExtraData);



SECURITY_STATUS

HttpsGetFile(

    SOCKET          Socket,

    PCredHandle     phCreds,

    CtxtHandle *    phContext,

    LPSTR           pszFileName,

	LPSTR      *    pszReply);



void

DisplayCertChain(

    PCCERT_CONTEXT  pServerCert,

    BOOL            fLocal);



DWORD

VerifyServerCertificate(

    PCCERT_CONTEXT  pServerCert,

    PSTR            pszServerName,

    DWORD           dwCertFlags);



void

WriteDataToFile(

    PSTR  pszFilename,

    PBYTE pbData,

    DWORD cbData);



LONG

DisconnectFromServer(

    SOCKET          Socket, 

    PCredHandle     phCreds,

    CtxtHandle *    phContext);



void

DisplayConnectionInfo(

    CtxtHandle *phContext);



void

GetNewClientCredentials(

    CredHandle *phCreds,

    CtxtHandle *phContext);



void PrintHexDump(DWORD length, PBYTE buffer);



void CertCloseMyStore(); 

