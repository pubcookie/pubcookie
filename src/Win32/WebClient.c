/*++

THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
PARTICULAR PURPOSE.

Copyright (C) 1999 - 2000 Microsoft Corporation.  All rights reserved.
Modifications Copyright 2003 University of Washington
Module Name:

    webclient.c

Abstract:

    Schannel web client sample application, adapted to interface with Pubcookie keyserver.


--*/

#include <stdio.h>
#include <stdlib.h>
#include <windows.h> 
#include <winsock.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <schannel.h>
#include <sspi.h>
#include <tchar.h>

#include "WebClient.h"

LPSTR   pszProxyServer  = "proxy";
INT     iProxyPort      = 80;

// User options.
LPSTR   pszServerName   = NULL;
INT     iPortNumber     = 443;
LPSTR   pszFileName     = "default.htm";
BOOL    fVerbose        = FALSE;
BOOL    fUseProxy       = FALSE;
LPSTR   pszUserName     = NULL;
DWORD   dwProtocol      = SP_PROT_TLS1;
ALG_ID  aiKeyExch       = 0;

HCERTSTORE      hMyCertStore = NULL;
SCHANNEL_CRED   SchannelCred;

HMODULE g_hSecurity = NULL;

SecurityFunctionTable g_SecurityFunc;

void vmessage( const char * format, va_list args )
{
	char msgbuf[4096];
	_vsnprintf(msgbuf,4096,format,args);
#ifdef _DEBUG
	MessageBox(NULL,msgbuf,"Keyclient Debug Message",MB_OK);
#endif
}

void message(const char *format, ...) {

    va_list   args;

    va_start(args, format);

    vmessage( format, args );

    va_end(args);

}


/*****************************************************************************/
BOOL
LoadSecurityLibrary(SecurityFunctionTable ** lpSecurityFunc)
{
    PSecurityFunctionTable          pSecurityFunc;
    INIT_SECURITY_INTERFACE         pInitSecurityInterface;
    OSVERSIONINFO VerInfo;
    UCHAR lpszDLL[MAX_PATH];

    //
    //  Find out which security DLL to use, depending on
    //  whether we are on Win2K, NT or Win9x
    //

    VerInfo.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);
    if (!GetVersionEx (&VerInfo))   
    {
        return FALSE;
    }

    if (VerInfo.dwPlatformId == VER_PLATFORM_WIN32_NT 
        && VerInfo.dwMajorVersion == 4)
    {
        strcpy (lpszDLL, NT4_DLL_NAME );
    }
    else if (VerInfo.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS ||
          VerInfo.dwPlatformId == VER_PLATFORM_WIN32_NT )
    {
        strcpy (lpszDLL, DLL_NAME );
    }
    else
    {
        return FALSE;
    }

    //
    //  Load Security DLL
    //

    g_hSecurity = LoadLibrary(lpszDLL);
    if(g_hSecurity == NULL)
    {
        message("Error 0x%x loading %s.\n", GetLastError(), lpszDLL);
        return FALSE;
    }

    pInitSecurityInterface = (INIT_SECURITY_INTERFACE)GetProcAddress(
                                    g_hSecurity,
                                    "InitSecurityInterfaceA");
    
    if(pInitSecurityInterface == NULL)
    {
        message("Error 0x%x reading InitSecurityInterface entry point.\n", 
               GetLastError());
        return FALSE;
    }

    pSecurityFunc = pInitSecurityInterface();

    if(pSecurityFunc == NULL)
    {
        message("Error 0x%x reading security interface.\n",
               GetLastError());
        return FALSE;
    }

    CopyMemory(&g_SecurityFunc, pSecurityFunc, sizeof(g_SecurityFunc));

	*lpSecurityFunc = &g_SecurityFunc;

    return TRUE;
}

/*****************************************************************************/
void
UnloadSecurityLibrary(void)
{
    FreeLibrary(g_hSecurity);
    g_hSecurity = NULL;
}




void
CertCloseMyStore() 
{
    // Close "MY" certificate store.
    if(hMyCertStore)
    {
        CertCloseStore(hMyCertStore, 0);
    }
}

void 
GetCertInfoString(LPSTR pszType, PCCERT_CONTEXT *pCertContext, LPSTR *pszValue)
{
	
	//LPTSTR pszName;

	

	

	//pszValue = pszName;

	//free(pszName);
}

// compare HostName against the Cert's CN
// CN can be a wildcard "*.dom.ain"
static int
matchHostWithCommonName(LPSTR pszHostName, LPTSTR pszCommonName)
{
	char *cn_p, *host_p;

	cn_p = strchr(pszCommonName, '*');
	if (cn_p) {
		if (cn_p > pszCommonName) {
			message("**** mal-formed wildcard CN in certificate\n");
			return 0;
		}
		++cn_p;
		if (strlen(cn_p) > strlen(pszHostName))
			return 0;
		host_p = pszHostName + strlen(pszHostName) - strlen(cn_p);
		if (stricmp(host_p, cn_p) == 0) {
			return 1;
		}
	} else if (stricmp(pszHostName, pszCommonName) == 0) {
		return 1;
	}

	return 0;
}


/*****************************************************************************/
SECURITY_STATUS
CreateCredentials(
    LPSTR pszHostName,              // in
	BOOL bBestGuess,				// called by installer, make a best guess
									// about which cert to use
    PCredHandle phCreds)            // out
{
    TimeStamp       tsExpiry;
    SECURITY_STATUS Status;

    DWORD           cSupportedAlgs = 0;
    ALG_ID          rgbSupportedAlgs[16];

    PCCERT_CONTEXT  pCertContext = NULL;	
	PCCERT_CONTEXT  pCertContextDup = NULL;	
	PCCERT_CONTEXT *pCertContexts = (PCCERT_CONTEXT*) malloc(2 * sizeof(PCCERT_CONTEXT));
	
	DWORD cbSize;
	LPTSTR pszCertSubAltDNSName;
	LPTSTR pszCertSubCommonName;
	LPTSTR pszCertIssuerName;

	UINT uiResponse;
	
	TCHAR szBufDateB[255];
	TCHAR szBufDate[255];

	int iLooper;
	int iCounter = 0;

	SYSTEMTIME stExpDate;
	SYSTEMTIME stBegDate;
	FILETIME ftSystemTime;
	FILETIME ftExpDate;

	LONG lTimeDiff;
    
	char currBuff[20];
	char totalBuff[20];

	BOOL bSelectedACert = FALSE;	
	BOOL bSearchBySubjectAltName = TRUE;
	BOOL bTriedBySubjectCommonName = FALSE;

	char* currCert;
	char* totalCerts;

	const DWORD dwNameToStrFlags =	CERT_X500_NAME_STR | 
									CERT_NAME_STR_NO_PLUS_FLAG |
									CERT_NAME_STR_CRLF_FLAG;


    // Open the "MY" certificate store, which is where Internet Explorer
    // stores its client certificates.
	if(hMyCertStore == NULL)
	{
		hMyCertStore = CertOpenStore(
			CERT_STORE_PROV_SYSTEM, // system store will be a 
									//  virtual store
			0,                      // encoding type not needed with this PROV
			(HCRYPTPROV)NULL,       // accept the default HCRYPTPROV
			CERT_SYSTEM_STORE_LOCAL_MACHINE,
									// set the system store location in the
									//  registry
			L"MY");                 // could have used other predefined 
									//  system stores
									//  including Trust, CA, or Root
			if(!hMyCertStore)
			{
				message("**** Error 0x%x returned by CertOpenSystemStore\n", 
					GetLastError());
				return SEC_E_NO_CREDENTIALS;
			}
	}

    //
    // If a user name is specified, then attempt to find a client
    //

    if(pszHostName)
    {
        /* Find client certificate. */
		/*
			1) Search for all certificates with Subject Alt Name of type
				DNS Name is equal to -H option parameter

			2) If none exist, then find with Subject of type CN is equal to -H option
				
			3) If multiple are found, then loop through the certificates and
				give the user the option to select which cert to use.			
		*/

        /* Find all the certs */		
CertSearchLoop:
		iCounter = 0;

		while(pCertContext = CertEnumCertificatesInStore(hMyCertStore, pCertContext))
		{

			// Search is by Subject Alt Name
			if (bSearchBySubjectAltName == TRUE)
			{
			
				/* Check Subject Alt Name */
				cbSize = CertGetNameString(pCertContext,
					CERT_NAME_SIMPLE_DISPLAY_TYPE,
					0,
					NULL,
					NULL,
					0);

				pszCertSubAltDNSName = (LPTSTR) malloc (cbSize * sizeof(TCHAR));
				
				CertGetNameString(pCertContext, 
					CERT_NAME_SIMPLE_DISPLAY_TYPE,
					0,
					NULL,
					pszCertSubAltDNSName,
					cbSize);
				
				if (!matchHostWithCommonName(pszHostName, pszCertSubAltDNSName))
				{							
					free(pszCertSubAltDNSName);	
					continue;
				}

				ZeroMemory(&ftSystemTime, sizeof(&ftSystemTime));

				// Validate dates
				if(CertVerifyTimeValidity(NULL, pCertContext->pCertInfo) != 0)
				{
					free(pszCertSubAltDNSName);
					continue;
				}				
								

				free(pszCertSubAltDNSName);

				/* Put all valid certs into array */
				/* reallocate array */
				pCertContexts = (PCCERT_CONTEXT*) realloc(pCertContexts, (iCounter + 1) * sizeof(PCCERT_CONTEXT));

				/* use CertDuplicateCertificateContext to context is not NULL(ed) automatically */
				pCertContexts[iCounter] = CertDuplicateCertificateContext(pCertContext);
				
				iCounter++; //# of found certs
			
			} // if search by SubjectAltName
			else
			{		

				bTriedBySubjectCommonName = TRUE;

				/* Check Subject Common Name */
				cbSize = CertGetNameString(pCertContext,
					CERT_NAME_ATTR_TYPE,
					0,
					szOID_COMMON_NAME,
					NULL,
					0);

				pszCertSubCommonName = (LPTSTR) malloc (cbSize * sizeof(TCHAR));
				
				CertGetNameString(pCertContext, 
					CERT_NAME_ATTR_TYPE,
					0,
					szOID_COMMON_NAME,
					pszCertSubCommonName,
					cbSize);
				
				if (!matchHostWithCommonName(pszHostName, pszCertSubCommonName))
				{							
					free(pszCertSubCommonName);	
					continue;
				}


				ZeroMemory(&ftSystemTime, sizeof(&ftSystemTime));

				if(CertVerifyTimeValidity(NULL, pCertContext->pCertInfo) != 0)
				{
					free(pszCertSubAltDNSName);
					continue;
				}
				
				free(pszCertSubCommonName);

				/* reallocate array */
				pCertContexts = (PCCERT_CONTEXT*) realloc(pCertContexts, (iCounter + 1) * sizeof(PCCERT_CONTEXT));

				/* use CertDuplicateCertificateContext to context is not NULL(ed) automatically */
				pCertContexts[iCounter] = CertDuplicateCertificateContext(pCertContext);
				
				iCounter++; //# of found certs

			}


		} /* end while */

		
		/* if just one, then use it! otherwise let them pick one */        
		if (iCounter > 0)
		{
			for(iLooper=0; iLooper<iCounter; iLooper++)
			{

				if (bSearchBySubjectAltName == TRUE)
				{

					pCertContext = pCertContexts[iLooper];


					/* if just one, use this certificate context */
					if (iCounter == 1 || bBestGuess)
					{
						bSelectedACert = TRUE;
						break;
					}


					/* Check Subject Alt Name */
					cbSize = CertGetNameString(pCertContext,
						CERT_NAME_SIMPLE_DISPLAY_TYPE,
						0,
						NULL,
						NULL,
						0);

					pszCertSubAltDNSName = (LPTSTR) malloc (cbSize * sizeof(TCHAR));
					
					CertGetNameString(pCertContext, 
						CERT_NAME_SIMPLE_DISPLAY_TYPE,
						0,
						NULL,
						pszCertSubAltDNSName,
						cbSize);

					
	

					///* format the date */
					ZeroMemory(&stExpDate, sizeof(&stExpDate));
 
					ftExpDate = pCertContext->pCertInfo->NotAfter;

					/* must do this thing otherwise dates are off because of daylight savings */
					FileTimeToLocalFileTime(&ftExpDate, &ftExpDate);

					FileTimeToSystemTime(&ftExpDate, &stExpDate);


					GetDateFormat(
						NULL,
						DATE_LONGDATE,

						&stExpDate,
						NULL,
						szBufDate,
						254);	


					cbSize = CertNameToStr(pCertContext->dwCertEncodingType,
					&pCertContext->pCertInfo->Issuer,
					dwNameToStrFlags,
					NULL,
					0);

				
				

					pszCertIssuerName = (LPTSTR) malloc (cbSize * sizeof(TCHAR));

					CertNameToStr(pCertContext->dwCertEncodingType, 
						&pCertContext->pCertInfo->Issuer, 
						CERT_NAME_ISSUER_FLAG, 
						pszCertIssuerName,
						cbSize);


					_snprintf(currBuff, sizeof(currBuff), "%d", iLooper+1);
					currCert = currBuff;
					_snprintf(totalBuff, sizeof(totalBuff), "%d", iCounter);
					totalCerts = totalBuff;

					uiResponse = MessageYesNo("Found %s of %s valid certificates, use this one?\n\nDNS = %s\nIssuer = %s\nExpiration Date = %s \n", 
						currCert,
						totalCerts,	
						pszCertSubAltDNSName,
						pszCertIssuerName,
						szBufDate);

					if (uiResponse == IDYES)
					{
						//use this cert
						bSelectedACert = TRUE;
						break;
					}
					else
					{
						continue;
					}				


					//clean up
					free(pszCertSubAltDNSName);
					free(pszCertIssuerName);
					CertFreeCertificateContext(pCertContexts[iLooper]);
					free(pCertContexts[iLooper]);
				}
				else
				{
					/* Search by Subject Common Name */
					//pCertContext = CertDuplicateCertificateContext(pCertContexts[iLooper]);
					pCertContext = pCertContexts[iLooper];


					/* if just one, use this certificate context */
					if (iCounter == 1)
					{
						bSelectedACert = TRUE;
						break;
					}

					/* Check Subject Alt Name */
					cbSize = CertGetNameString(pCertContext,
						CERT_NAME_ATTR_TYPE,
						0,
						szOID_COMMON_NAME,
						NULL,
						0);

					pszCertSubCommonName = (LPTSTR) malloc (cbSize * sizeof(TCHAR));
					
					CertGetNameString(pCertContext, 
						CERT_NAME_ATTR_TYPE,
						0,
						szOID_COMMON_NAME,
						pszCertSubCommonName,
						cbSize);


					///* format the date */
					FileTimeToSystemTime(&(pCertContext->pCertInfo->NotAfter), &stExpDate);

					GetDateFormat(
						NULL,
						DATE_LONGDATE,
						&stExpDate,
						NULL,
						szBufDate,
						254);	
					

					cbSize = CertNameToStr(pCertContext->dwCertEncodingType,
					&pCertContext->pCertInfo->Issuer,
					dwNameToStrFlags,
					NULL,
					0);

				
				

					pszCertIssuerName = (LPTSTR) malloc (cbSize * sizeof(TCHAR));

					CertNameToStr(pCertContext->dwCertEncodingType, 
						&pCertContext->pCertInfo->Issuer, 
						CERT_NAME_ISSUER_FLAG, 
						pszCertIssuerName,
						cbSize);


					_snprintf(currBuff, sizeof(currBuff), "%d", iLooper+1);
					currCert = currBuff;
					_snprintf(totalBuff, sizeof(totalBuff), "%d", iCounter);
					totalCerts = totalBuff;


					uiResponse = MessageYesNo("Found %s of %s valid certificates, use this one?\n\nDNS = %s\nIssuer = %s\nExpiration Date = %s \n", 
						currCert,
						totalCerts,
						pszCertSubAltDNSName,
						pszCertIssuerName,
						szBufDate);

					if (uiResponse == IDYES)
					{
						//use this cert
						bSelectedACert = TRUE;
						break;
					}
					else
					{
						continue;
					}				


					//clean up
					free(pszCertSubAltDNSName);
					free(pszCertIssuerName);
					CertFreeCertificateContext(pCertContexts[iLooper]);
					free(pCertContexts[iLooper]);


				}

					
			}

			

			
		}
		else
		{
			/* if none found then search the Subject CN == pszHostName */
			bSearchBySubjectAltName = FALSE;
			
			if (!bTriedBySubjectCommonName)
			{	
				if (iCounter > 0)
				{
					goto CertSearchLoop;
				}

			}
		}
		
		/* Could not find a valid certificate for 
			1) Subject Alt Name DNS Name = hostname 
			2) Subject CN = hostname 
		*/
		if (bSelectedACert == FALSE)
		{
			return SEC_E_NO_CREDENTIALS;
		}

		free(pCertContexts);
		
    }
	else
	{
		// We could continue with a NULL credential, but that isn't secure enough for this application
        return SEC_E_NO_CREDENTIALS;
	}



    //
    // Build Schannel credential structure. 
    //

    ZeroMemory(&SchannelCred, sizeof(SchannelCred));

    SchannelCred.dwVersion  = SCHANNEL_CRED_VERSION;
    if(pCertContext)
    {
        SchannelCred.cCreds     = 1;
        SchannelCred.paCred     = &pCertContext;
    }

    SchannelCred.grbitEnabledProtocols = dwProtocol;

    if(aiKeyExch)
    {
        rgbSupportedAlgs[cSupportedAlgs++] = aiKeyExch;
    }

    if(cSupportedAlgs)
    {
        SchannelCred.cSupportedAlgs    = cSupportedAlgs;
        SchannelCred.palgSupportedAlgs = rgbSupportedAlgs;
    }

    SchannelCred.dwFlags |= SCH_CRED_NO_DEFAULT_CREDS;
    SchannelCred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;


    //
    // Create an SSPI credential.
    //

    Status = g_SecurityFunc.AcquireCredentialsHandleA(
                        NULL,                   // Name of principal    
                        UNISP_NAME_A,           // Name of package
                        SECPKG_CRED_OUTBOUND,   // Flags indicating use
                        NULL,                   // Pointer to logon ID
                        &SchannelCred,          // Package specific data
                        NULL,                   // Pointer to GetKey() func
                        NULL,                   // Value to pass to GetKey()
                        phCreds,                // (out) Cred Handle
                        &tsExpiry);             // (out) Lifetime (optional)
    if(Status != SEC_E_OK)
    {
        message("**** Error 0x%x returned by AcquireCredentialsHandle\n", Status);
        return Status;
    }


    //
    // Free the certificate context. Schannel has already made its own copy.
    //

    if(pCertContext)
    {
        CertFreeCertificateContext(pCertContext);
    }


    return SEC_E_OK;
}

/*****************************************************************************/
INT
ConnectToServer(
    LPSTR    pszServerName, // in
    INT      iPortNumber,   // in
    SOCKET * pSocket)       // out
{
    SOCKET Socket;
    struct sockaddr_in sin;
    struct hostent *hp;

    Socket = socket(PF_INET, SOCK_STREAM, 0);
    if(Socket == INVALID_SOCKET)
    {
        message("**** Error %d creating socket\n", WSAGetLastError());
        return WSAGetLastError();
    }

    if(fUseProxy)
    {
        sin.sin_family = AF_INET;
        sin.sin_port = ntohs((u_short)iProxyPort);

        if((hp = gethostbyname(pszProxyServer)) == NULL)
        {
            message("**** Error %d returned by gethostbyname\n", WSAGetLastError());
            return WSAGetLastError();
        }
        else
        {
            memcpy(&sin.sin_addr, hp->h_addr, 4);
        }
    }
    else
    {
        sin.sin_family = AF_INET;
        sin.sin_port = htons((u_short)iPortNumber);

        if((hp = gethostbyname(pszServerName)) == NULL)
        {
            message("**** Error %d returned by gethostbyname\n", WSAGetLastError());
            return WSAGetLastError();
        }
        else
        {
            memcpy(&sin.sin_addr, hp->h_addr, 4);
        }
    }

    if(connect(Socket, (struct sockaddr *)&sin, sizeof(sin)) == SOCKET_ERROR)
    {
		int wsaerrornum;
		wsaerrornum = WSAGetLastError();
        message("**** Error %d connecting to \"%s\" (%s)\n", 
            wsaerrornum,
            pszServerName, 
            inet_ntoa(sin.sin_addr));
        closesocket(Socket);
        return wsaerrornum;
    }

    if(fUseProxy)
    {
        BYTE  pbMessage[200]; 
        DWORD cbMessage;

        // Build message for proxy server
        strcpy(pbMessage, "CONNECT ");
        strcat(pbMessage, pszServerName);
        strcat(pbMessage, ":");
        _itoa(iPortNumber, pbMessage + strlen(pbMessage), 10);
        strcat(pbMessage, " HTTP/1.0\r\nUser-Agent: webclient\r\n\r\n");
        cbMessage = (DWORD)strlen(pbMessage);

        // Send message to proxy server
        if(send(Socket, pbMessage, cbMessage, 0) == SOCKET_ERROR)
        {
            message("**** Error %d sending message to proxy!\n", WSAGetLastError());
            return WSAGetLastError();
        }

        // Receive message from proxy server
        cbMessage = recv(Socket, pbMessage, 200, 0);
        if(cbMessage == SOCKET_ERROR)
        {
            message("**** Error %d receiving message from proxy\n", WSAGetLastError());
            return WSAGetLastError();
        }

        // this sample is limited but in normal use it 
        // should continue to receive until CR LF CR LF is received
    }

    *pSocket = Socket;

    return SEC_E_OK;
}

/*****************************************************************************/
LONG
DisconnectFromServer(
    SOCKET          Socket, 
    PCredHandle     phCreds,
    CtxtHandle *    phContext)
{
    DWORD           dwType;
    PBYTE           pbMessage;
    DWORD           cbMessage;
    DWORD           cbData;

    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    DWORD           Status;

    //
    // Notify schannel that we are about to close the connection.
    //

    dwType = SCHANNEL_SHUTDOWN;

    OutBuffers[0].pvBuffer   = &dwType;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = sizeof(dwType);

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    Status = g_SecurityFunc.ApplyControlToken(phContext, &OutBuffer);

    if(FAILED(Status)) 
    {
        message("**** Error 0x%x returned by ApplyControlToken\n", Status);
        goto cleanup;
    }

    //
    // Build an SSL close notify message.
    //

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_RET_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
                  ISC_REQ_STREAM;

    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = 0;

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    Status = g_SecurityFunc.InitializeSecurityContextA(
                    phCreds,
                    phContext,
                    NULL,
                    dwSSPIFlags,
                    0,
                    SECURITY_NATIVE_DREP,
                    NULL,
                    0,
                    phContext,
                    &OutBuffer,
                    &dwSSPIOutFlags,
                    &tsExpiry);

    if(FAILED(Status)) 
    {
        message("**** Error 0x%x returned by InitializeSecurityContext\n", Status);
        goto cleanup;
    }

    pbMessage = OutBuffers[0].pvBuffer;
    cbMessage = OutBuffers[0].cbBuffer;


    //
    // Send the close notify message to the server.
    //

    if(pbMessage != NULL && cbMessage != 0)
    {
        cbData = send(Socket, pbMessage, cbMessage, 0);
        if(cbData == SOCKET_ERROR || cbData == 0)
        {
            Status = WSAGetLastError();
            message("**** Error %d sending close notify\n", Status);
            goto cleanup;
        }

        message("Sending Close Notify\n");
        message("%d bytes of handshake data sent\n", cbData);

        if(fVerbose)
        {
            PrintHexDump(cbData, pbMessage);
        }

        // Free output buffer.
        g_SecurityFunc.FreeContextBuffer(pbMessage);
    }
    

cleanup:

    // Free the security context.
    g_SecurityFunc.DeleteSecurityContext(phContext);

    // Close the socket.
    closesocket(Socket);

    return Status;
}

/*****************************************************************************/
SECURITY_STATUS
PerformClientHandshake(
    SOCKET          Socket,         // in
    PCredHandle     phCreds,        // in
    LPSTR           pszServerName,  // in
    CtxtHandle *    phContext,      // out
    SecBuffer *     pExtraData)     // out
{
    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    SECURITY_STATUS scRet;
    DWORD           cbData;

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_RET_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
                  ISC_REQ_STREAM;

    //
    //  Initiate a ClientHello message and generate a token.
    //

    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = 0;

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    scRet = g_SecurityFunc.InitializeSecurityContextA(
                    phCreds,
                    NULL,
                    pszServerName,
                    dwSSPIFlags,
                    0,
                    SECURITY_NATIVE_DREP,
                    NULL,
                    0,
                    phContext,
                    &OutBuffer,
                    &dwSSPIOutFlags,
                    &tsExpiry);

    if(scRet != SEC_I_CONTINUE_NEEDED)
    {
        message("**** Error %d returned by InitializeSecurityContext (1)\n", scRet);
        return scRet;
    }

    // Send response to server if there is one.
    if(OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
    {
        cbData = send(Socket,
                      OutBuffers[0].pvBuffer,
                      OutBuffers[0].cbBuffer,
                      0);
        if(cbData == SOCKET_ERROR || cbData == 0)
        {
            message("**** Error %d sending data to server (1)\n", WSAGetLastError());
            g_SecurityFunc.FreeContextBuffer(OutBuffers[0].pvBuffer);
            g_SecurityFunc.DeleteSecurityContext(phContext);
            return SEC_E_INTERNAL_ERROR;
        }

        message("%d bytes of handshake data sent\n", cbData);

        if(fVerbose)
        {
            PrintHexDump(cbData, OutBuffers[0].pvBuffer);
        }

        // Free output buffer.
        g_SecurityFunc.FreeContextBuffer(OutBuffers[0].pvBuffer);
        OutBuffers[0].pvBuffer = NULL;
    }


    return ClientHandshakeLoop(Socket, phCreds, phContext, TRUE, pExtraData);
}

/*****************************************************************************/
static
SECURITY_STATUS
ClientHandshakeLoop(
    SOCKET          Socket,         // in
    PCredHandle     phCreds,        // in
    CtxtHandle *    phContext,      // in, out
    BOOL            fDoInitialRead, // in
    SecBuffer *     pExtraData)     // out
{
    SecBufferDesc   InBuffer;
    SecBuffer       InBuffers[2];
    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           dwSSPIOutFlags;
    TimeStamp       tsExpiry;
    SECURITY_STATUS scRet;
    DWORD           cbData;

    PUCHAR          IoBuffer;
    DWORD           cbIoBuffer;
    BOOL            fDoRead;


    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_RET_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
                  ISC_REQ_STREAM;

    //
    // Allocate data buffer.
    //

    IoBuffer = LocalAlloc(LMEM_FIXED, IO_BUFFER_SIZE);
    if(IoBuffer == NULL)
    {
        message("**** Out of memory (1)\n");
        return SEC_E_INTERNAL_ERROR;
    }
    cbIoBuffer = 0;

    fDoRead = fDoInitialRead;


    // 
    // Loop until the handshake is finished or an error occurs.
    //

    scRet = SEC_I_CONTINUE_NEEDED;

    while(scRet == SEC_I_CONTINUE_NEEDED        ||
          scRet == SEC_E_INCOMPLETE_MESSAGE     ||
          scRet == SEC_I_INCOMPLETE_CREDENTIALS) 
   {

        //
        // Read data from server.
        //

        if(0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            if(fDoRead)
            {
                cbData = recv(Socket, 
                              IoBuffer + cbIoBuffer, 
                              IO_BUFFER_SIZE - cbIoBuffer, 
                              0);
                if(cbData == SOCKET_ERROR)
                {
                    message("**** Error %d reading data from server\n", WSAGetLastError());
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }
                else if(cbData == 0)
                {
                    message("**** Server unexpectedly disconnected\n");
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }

                message("%d bytes of handshake data received\n", cbData);

                if(fVerbose)
                {
                    PrintHexDump(cbData, IoBuffer + cbIoBuffer);
                }

                cbIoBuffer += cbData;
            }
            else
            {
                fDoRead = TRUE;
            }
        }


        //
        // Set up the input buffers. Buffer 0 is used to pass in data
        // received from the server. Schannel will consume some or all
        // of this. Leftover data (if any) will be placed in buffer 1 and
        // given a buffer type of SECBUFFER_EXTRA.
        //

        InBuffers[0].pvBuffer   = IoBuffer;
        InBuffers[0].cbBuffer   = cbIoBuffer;
        InBuffers[0].BufferType = SECBUFFER_TOKEN;

        InBuffers[1].pvBuffer   = NULL;
        InBuffers[1].cbBuffer   = 0;
        InBuffers[1].BufferType = SECBUFFER_EMPTY;

        InBuffer.cBuffers       = 2;
        InBuffer.pBuffers       = InBuffers;
        InBuffer.ulVersion      = SECBUFFER_VERSION;

        //
        // Set up the output buffers. These are initialized to NULL
        // so as to make it less likely we'll attempt to free random
        // garbage later.
        //

        OutBuffers[0].pvBuffer  = NULL;
        OutBuffers[0].BufferType= SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer  = 0;

        OutBuffer.cBuffers      = 1;
        OutBuffer.pBuffers      = OutBuffers;
        OutBuffer.ulVersion     = SECBUFFER_VERSION;

        //
        // Call InitializeSecurityContext.
        //

        scRet = g_SecurityFunc.InitializeSecurityContextA(phCreds,
                                          phContext,
                                          NULL,
                                          dwSSPIFlags,
                                          0,
                                          SECURITY_NATIVE_DREP,
                                          &InBuffer,
                                          0,
                                          NULL,
                                          &OutBuffer,
                                          &dwSSPIOutFlags,
                                          &tsExpiry);

        //
        // If InitializeSecurityContext was successful (or if the error was 
        // one of the special extended ones), send the contends of the output
        // buffer to the server.
        //

        if(scRet == SEC_E_OK                ||
           scRet == SEC_I_CONTINUE_NEEDED   ||
           FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))
        {
            if(OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
            {
                cbData = send(Socket,
                              OutBuffers[0].pvBuffer,
                              OutBuffers[0].cbBuffer,
                              0);
                if(cbData == SOCKET_ERROR || cbData == 0)
                {
                    message("**** Error %d sending data to server (2)\n", 
                        WSAGetLastError());
                    g_SecurityFunc.FreeContextBuffer(OutBuffers[0].pvBuffer);
                    g_SecurityFunc.DeleteSecurityContext(phContext);
                    return SEC_E_INTERNAL_ERROR;
                }

                message("%d bytes of handshake data sent\n", cbData);

                if(fVerbose)
                {
                    PrintHexDump(cbData, OutBuffers[0].pvBuffer);
                }

                // Free output buffer.
                g_SecurityFunc.FreeContextBuffer(OutBuffers[0].pvBuffer);
                OutBuffers[0].pvBuffer = NULL;
            }
        }


        //
        // If InitializeSecurityContext returned SEC_E_INCOMPLETE_MESSAGE,
        // then we need to read more data from the server and try again.
        //

        if(scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            continue;
        }


        //
        // If InitializeSecurityContext returned SEC_E_OK, then the 
        // handshake completed successfully.
        //

        if(scRet == SEC_E_OK)
        {
            //
            // If the "extra" buffer contains data, this is encrypted application
            // protocol layer stuff. It needs to be saved. The application layer
            // will later decrypt it with DecryptMessage.
            //

            message("Handshake was successful\n");

            if(InBuffers[1].BufferType == SECBUFFER_EXTRA)
            {
                pExtraData->pvBuffer = LocalAlloc(LMEM_FIXED, 
                                                  InBuffers[1].cbBuffer);
                if(pExtraData->pvBuffer == NULL)
                {
                    message("**** Out of memory (2)\n");
                    return SEC_E_INTERNAL_ERROR;
                }

                MoveMemory(pExtraData->pvBuffer,
                           IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                           InBuffers[1].cbBuffer);

                pExtraData->cbBuffer   = InBuffers[1].cbBuffer;
                pExtraData->BufferType = SECBUFFER_TOKEN;

                message("%d bytes of app data was bundled with handshake data\n",
                    pExtraData->cbBuffer);
            }
            else
            {
                pExtraData->pvBuffer   = NULL;
                pExtraData->cbBuffer   = 0;
                pExtraData->BufferType = SECBUFFER_EMPTY;
            }

            //
            // Bail out to quit
            //

            break;
        }


        //
        // Check for fatal error.
        //

        if(FAILED(scRet))
        {
            message("**** Error 0x%x returned by InitializeSecurityContext (2)\n", scRet);
            break;
        }


        //
        // If InitializeSecurityContext returned SEC_I_INCOMPLETE_CREDENTIALS,
        // then the server just requested client authentication. 
        //

        if(scRet == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            //
            // Display trusted issuers info. 
            //

            GetNewClientCredentials(phCreds, phContext);


            //
            // Now would be a good time perhaps to prompt the user to select
            // a client certificate and obtain a new credential handle, 
            // but I don't have the energy nor inclination.
            //
            // As this is currently written, Schannel will send a "no 
            // certificate" alert to the server in place of a certificate. 
            // The server might be cool with this, or it might drop the 
            // connection.
            // 

            // Go around again.
            fDoRead = FALSE;
            scRet = SEC_I_CONTINUE_NEEDED;
            continue;
        }


        //
        // Copy any leftover data from the "extra" buffer, and go around
        // again.
        //

        if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
        {
            MoveMemory(IoBuffer,
                       IoBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                       InBuffers[1].cbBuffer);

            cbIoBuffer = InBuffers[1].cbBuffer;
        }
        else
        {
            cbIoBuffer = 0;
        }
    }

    // Delete the security context in the case of a fatal error.
    if(FAILED(scRet))
    {
        g_SecurityFunc.DeleteSecurityContext(phContext);
    }

    LocalFree(IoBuffer);

    return scRet;
}


/*****************************************************************************/
SECURITY_STATUS
HttpsGetFile(
    SOCKET          Socket,         // in
    PCredHandle     phCreds,        // in
    CtxtHandle *    phContext,      // in
    LPSTR           pszFileName,
	LPSTR      *    pszReply)       // out
{
    SecPkgContext_StreamSizes Sizes;
    SECURITY_STATUS scRet;
    SecBufferDesc   Message;
    SecBuffer       Buffers[4];
    SecBuffer *     pDataBuffer;
    SecBuffer *     pExtraBuffer;
    SecBuffer       ExtraBuffer;

    PBYTE pbIoBuffer;
    DWORD cbIoBuffer;
    DWORD cbIoBufferLength;
    PBYTE pbMessage;
    DWORD cbMessage;

    DWORD cbData;
    INT   i;
	unsigned int cbReply = 0;
	unsigned int sizeof_Reply = 0;

    //
    // Read stream encryption properties.
    //

    scRet = g_SecurityFunc.QueryContextAttributes(phContext,
                                   SECPKG_ATTR_STREAM_SIZES,
                                   &Sizes);
    if(scRet != SEC_E_OK)
    {
        message("**** Error 0x%x reading SECPKG_ATTR_STREAM_SIZES\n", scRet);
        return scRet;
    }

    message("\nHeader: %d, Trailer: %d, MaxMessage: %d\n",
        Sizes.cbHeader,
        Sizes.cbTrailer,
        Sizes.cbMaximumMessage);

    //
    // Allocate a working buffer. The plaintext sent to EncryptMessage
    // should never be more than 'Sizes.cbMaximumMessage', so a buffer 
    // size of this plus the header and trailer sizes should be safe enough.
    // 

    cbIoBufferLength = Sizes.cbHeader + 
                       Sizes.cbMaximumMessage +
                       Sizes.cbTrailer;

    pbIoBuffer = LocalAlloc(LMEM_FIXED, cbIoBufferLength);
    if(pbIoBuffer == NULL)
    {
        message("**** Out of memory (2)\n");
        return SEC_E_INTERNAL_ERROR;
    }


    //
    // Build an HTTP request to send to the server.
    //

    // Remove the trailing backslash from the filename, should one exist.
    if(pszFileName && 
       strlen(pszFileName) > 1 && 
       pszFileName[strlen(pszFileName) - 1] == '/')
    {
        pszFileName[strlen(pszFileName)-1] = 0;
    }

    // Build the HTTP request offset into the data buffer by "header size"
    // bytes. This enables Schannel to perform the encryption in place,
    // which is a significant performance win.
    pbMessage = pbIoBuffer + Sizes.cbHeader;

    // Build HTTP request. Note that I'm assuming that this is less than
    // the maximum message size. If it weren't, it would have to be broken up.
    sprintf(pbMessage, 
            "GET /%s HTTP/1.0\r\nUser-Agent: Keyclient\r\nAccept:*/*\r\n\r\n", 
            pszFileName);
    message("\nHTTP request: %s\n", pbMessage);

    cbMessage = (DWORD)strlen(pbMessage);

    message("Sending plaintext: %d bytes\n", cbMessage);

    if(fVerbose)
    {
        PrintHexDump(cbMessage, pbMessage);
    }

    //
    // Encrypt the HTTP request.
    //

    Buffers[0].pvBuffer     = pbIoBuffer;
    Buffers[0].cbBuffer     = Sizes.cbHeader;
    Buffers[0].BufferType   = SECBUFFER_STREAM_HEADER;

    Buffers[1].pvBuffer     = pbMessage;
    Buffers[1].cbBuffer     = cbMessage;
    Buffers[1].BufferType   = SECBUFFER_DATA;

    Buffers[2].pvBuffer     = pbMessage + cbMessage;
    Buffers[2].cbBuffer     = Sizes.cbTrailer;
    Buffers[2].BufferType   = SECBUFFER_STREAM_TRAILER;

    Buffers[3].BufferType   = SECBUFFER_EMPTY;

    Message.ulVersion       = SECBUFFER_VERSION;
    Message.cBuffers        = 4;
    Message.pBuffers        = Buffers;

    scRet = g_SecurityFunc.EncryptMessage(phContext, 0, &Message, 0);

    if(FAILED(scRet))
    {
        message("**** Error 0x%x returned by EncryptMessage\n", scRet);
        return scRet;
    }


    // 
    // Send the encrypted data to the server.
    //

    cbData = send(Socket,
                  pbIoBuffer,
                  Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer,
                  0);
    if(cbData == SOCKET_ERROR || cbData == 0)
    {
        message("**** Error %d sending data to server (3)\n", 
            WSAGetLastError());
        g_SecurityFunc.DeleteSecurityContext(phContext);
        return SEC_E_INTERNAL_ERROR;
    }

    message("%d bytes of application data sent\n", cbData);

    if(fVerbose)
    {
        PrintHexDump(cbData, pbIoBuffer);
    }

    //
    // Read data from server until done.
    //

    cbIoBuffer = 0;

    while(TRUE)
    {
        //
        // Read some data.
        //

        if(0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            cbData = recv(Socket, 
                          pbIoBuffer + cbIoBuffer, 
                          cbIoBufferLength - cbIoBuffer, 
                          0);
            if(cbData == SOCKET_ERROR)
            {
                message("**** Error %d reading data from server\n", WSAGetLastError());
                scRet = SEC_E_INTERNAL_ERROR;
                break;
            }
            else if(cbData == 0)
            {
                // Server disconnected.
                if(cbIoBuffer)
                {
                    message("**** Server unexpectedly disconnected\n");
                    scRet = SEC_E_INTERNAL_ERROR;
                    return scRet;
                }
                else
                {
                    break;
                }
            }
            else
            {
                message("%d bytes of (encrypted) application data received\n", cbData);

                if(fVerbose)
                {
                    PrintHexDump(cbData, pbIoBuffer + cbIoBuffer);
                }

                cbIoBuffer += cbData;
            }
        }

        // 
        // Attempt to decrypt the received data.
        //

        Buffers[0].pvBuffer     = pbIoBuffer;
        Buffers[0].cbBuffer     = cbIoBuffer;
        Buffers[0].BufferType   = SECBUFFER_DATA;

        Buffers[1].BufferType   = SECBUFFER_EMPTY;
        Buffers[2].BufferType   = SECBUFFER_EMPTY;
        Buffers[3].BufferType   = SECBUFFER_EMPTY;

        Message.ulVersion       = SECBUFFER_VERSION;
        Message.cBuffers        = 4;
        Message.pBuffers        = Buffers;

        scRet = g_SecurityFunc.DecryptMessage(phContext, &Message, 0, NULL);

        if(scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            // The input buffer contains only a fragment of an
            // encrypted record. Loop around and read some more
            // data.
            continue;
        }

        // Server signalled end of session
        if(scRet == SEC_I_CONTEXT_EXPIRED)
            break;

        if( scRet != SEC_E_OK && 
            scRet != SEC_I_RENEGOTIATE && 
            scRet != SEC_I_CONTEXT_EXPIRED)
        {
            message("**** Error 0x%x returned by DecryptMessage\n", scRet);
            return scRet;
        }

        // Locate data and (optional) extra buffers.
        pDataBuffer  = NULL;
        pExtraBuffer = NULL;
        for(i = 1; i < 4; i++)
        {

            if(pDataBuffer == NULL && Buffers[i].BufferType == SECBUFFER_DATA)
            {
                pDataBuffer = &Buffers[i];
                message("Buffers[%d].BufferType = SECBUFFER_DATA\n",i);
            }
            if(pExtraBuffer == NULL && Buffers[i].BufferType == SECBUFFER_EXTRA)
            {
                pExtraBuffer = &Buffers[i];
            }
        }

        // Display or otherwise process the decrypted data.
        if(pDataBuffer)
        {
            message("Decrypted data: %d bytes\n", pDataBuffer->cbBuffer);
			
			if (cbReply+pDataBuffer->cbBuffer+1 > sizeof_Reply) {  // +1 for null terminator
				sizeof_Reply = cbReply + pDataBuffer->cbBuffer + 1024;
				*pszReply = realloc(*pszReply,(sizeof_Reply * sizeof **pszReply));
			}
			memcpy((*pszReply)+cbReply,pDataBuffer->pvBuffer,pDataBuffer->cbBuffer);
			cbReply += pDataBuffer->cbBuffer;
			*(*pszReply+cbReply) = '\0';

            if(fVerbose)
            {
                PrintHexDump(pDataBuffer->cbBuffer, pDataBuffer->pvBuffer);
            }
        }

        // Move any "extra" data to the input buffer.
        if(pExtraBuffer)
        {
            MoveMemory(pbIoBuffer, pExtraBuffer->pvBuffer, pExtraBuffer->cbBuffer);
            cbIoBuffer = pExtraBuffer->cbBuffer;
        }
        else
        {
            cbIoBuffer = 0;
        }

        if(scRet == SEC_I_RENEGOTIATE)
        {
            // The server wants to perform another handshake
            // sequence.

            message("Server requested renegotiate!\n");

            scRet = ClientHandshakeLoop(Socket, 
                                        phCreds, 
                                        phContext, 
                                        FALSE, 
                                        &ExtraBuffer);
            if(scRet != SEC_E_OK)
            {
                return scRet;
            }

            // Move any "extra" data to the input buffer.
            if(ExtraBuffer.pvBuffer)
            {
                MoveMemory(pbIoBuffer, ExtraBuffer.pvBuffer, ExtraBuffer.cbBuffer);
                cbIoBuffer = ExtraBuffer.cbBuffer;
            }
        }
    }

    return SEC_E_OK;
}

/*****************************************************************************/
void
DisplayCertChain(
    PCCERT_CONTEXT  pServerCert,
    BOOL            fLocal)
{
    CHAR szName[1000];
    PCCERT_CONTEXT pCurrentCert;
    PCCERT_CONTEXT pIssuerCert;
    DWORD dwVerificationFlags;

    // display leaf name
    if(!CertNameToStr(pServerCert->dwCertEncodingType,
                      &pServerCert->pCertInfo->Subject,
                      CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                      szName, sizeof(szName)))
    {
        message("**** Error 0x%x building subject name\n", GetLastError());
    }
    if(fLocal)
    {
        message("Client subject: %s\n", szName);
    }
    else
    {
        message("Server subject: %s\n", szName);
    }
    if(!CertNameToStr(pServerCert->dwCertEncodingType,
                      &pServerCert->pCertInfo->Issuer,
                      CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                      szName, sizeof(szName)))
    {
        message("**** Error 0x%x building issuer name\n", GetLastError());
    }
    if(fLocal)
    {
        message("Client issuer: %s\n", szName);
    }
    else
    {
        message("Server issuer: %s\n\n", szName);
    }


    // display certificate chain
    pCurrentCert = pServerCert;
    while(pCurrentCert != NULL)
    {
        dwVerificationFlags = 0;
        pIssuerCert = CertGetIssuerCertificateFromStore(pServerCert->hCertStore,
                                                        pCurrentCert,
                                                        NULL,
                                                        &dwVerificationFlags);
        if(pIssuerCert == NULL)
        {
            if(pCurrentCert != pServerCert)
            {
                CertFreeCertificateContext(pCurrentCert);
            }
            break;
        }

        if(!CertNameToStr(pIssuerCert->dwCertEncodingType,
                          &pIssuerCert->pCertInfo->Subject,
                          CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                          szName, sizeof(szName)))
        {
            message("**** Error 0x%x building subject name\n", GetLastError());
        }
        message("CA subject: %s\n", szName);
        if(!CertNameToStr(pIssuerCert->dwCertEncodingType,
                          &pIssuerCert->pCertInfo->Issuer,
                          CERT_X500_NAME_STR | CERT_NAME_STR_NO_PLUS_FLAG,
                          szName, sizeof(szName)))
        {
            message("**** Error 0x%x building issuer name\n", GetLastError());
        }
        message("CA issuer: %s\n\n", szName);

        if(pCurrentCert != pServerCert)
        {
            CertFreeCertificateContext(pCurrentCert);
        }
        pCurrentCert = pIssuerCert;
        pIssuerCert = NULL;
    }
}


/*****************************************************************************/
static
void
DisplayWinVerifyTrustError(DWORD Status)
{
    LPSTR pszName = NULL;

    switch(Status)
    {
    case CERT_E_EXPIRED:                pszName = "CERT_E_EXPIRED";                 break;
    case CERT_E_VALIDITYPERIODNESTING:  pszName = "CERT_E_VALIDITYPERIODNESTING";   break;
    case CERT_E_ROLE:                   pszName = "CERT_E_ROLE";                    break;
    case CERT_E_PATHLENCONST:           pszName = "CERT_E_PATHLENCONST";            break;
    case CERT_E_CRITICAL:               pszName = "CERT_E_CRITICAL";                break;
    case CERT_E_PURPOSE:                pszName = "CERT_E_PURPOSE";                 break;
    case CERT_E_ISSUERCHAINING:         pszName = "CERT_E_ISSUERCHAINING";          break;
    case CERT_E_MALFORMED:              pszName = "CERT_E_MALFORMED";               break;
    case CERT_E_UNTRUSTEDROOT:          pszName = "CERT_E_UNTRUSTEDROOT";           break;
    case CERT_E_CHAINING:               pszName = "CERT_E_CHAINING";                break;
    case TRUST_E_FAIL:                  pszName = "TRUST_E_FAIL";                   break;
    case CERT_E_REVOKED:                pszName = "CERT_E_REVOKED";                 break;
    case CERT_E_UNTRUSTEDTESTROOT:      pszName = "CERT_E_UNTRUSTEDTESTROOT";       break;
    case CERT_E_REVOCATION_FAILURE:     pszName = "CERT_E_REVOCATION_FAILURE";      break;
    case CERT_E_CN_NO_MATCH:            pszName = "CERT_E_CN_NO_MATCH";             break;
    case CERT_E_WRONG_USAGE:            pszName = "CERT_E_WRONG_USAGE";             break;
    default:                            pszName = "(unknown)";                      break;
    }

    message("Error 0x%x (%s) returned by CertVerifyCertificateChainPolicy!\n", 
        Status, pszName);
}

/*****************************************************************************/
DWORD
VerifyServerCertificate(
    PCCERT_CONTEXT  pServerCert,
    PSTR            pszServerName,
    DWORD           dwCertFlags)
{
    HTTPSPolicyCallbackData  polHttps;
    CERT_CHAIN_POLICY_PARA   PolicyPara;
    CERT_CHAIN_POLICY_STATUS PolicyStatus;
    CERT_CHAIN_PARA          ChainPara;
    PCCERT_CHAIN_CONTEXT     pChainContext = NULL;

    DWORD   Status;
    PWSTR   pwszServerName;
    DWORD   cchServerName;

    if(pServerCert == NULL)
    {
        return SEC_E_WRONG_PRINCIPAL;
    }


    //
    // Convert server name to unicode.
    //

    if(pszServerName == NULL || strlen(pszServerName) == 0)
    {
        return SEC_E_WRONG_PRINCIPAL;
    }

    cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName, -1, NULL, 0);
    pwszServerName = LocalAlloc(LMEM_FIXED, cchServerName * sizeof(WCHAR));
    if(pwszServerName == NULL)
    {
        return SEC_E_INSUFFICIENT_MEMORY;
    }
    cchServerName = MultiByteToWideChar(CP_ACP, 0, pszServerName, -1, pwszServerName, cchServerName);
    if(cchServerName == 0)
    {
        return SEC_E_WRONG_PRINCIPAL;
    }


    //
    // Build certificate chain.
    //

    ZeroMemory(&ChainPara, sizeof(ChainPara));
    ChainPara.cbSize = sizeof(ChainPara);

    if(!CertGetCertificateChain(
                            NULL,
                            pServerCert,
                            NULL,
                            pServerCert->hCertStore,
                            &ChainPara,
                            0,
                            NULL,
                            &pChainContext))
    {
        Status = GetLastError();
        message("Error 0x%x returned by CertGetCertificateChain!\n", Status);
        goto cleanup;
    }


    //
    // Validate certificate chain.
    // 

    ZeroMemory(&polHttps, sizeof(HTTPSPolicyCallbackData));
    polHttps.cbStruct           = sizeof(HTTPSPolicyCallbackData);
    polHttps.dwAuthType         = AUTHTYPE_SERVER;
    polHttps.fdwChecks          = dwCertFlags;
    polHttps.pwszServerName     = pwszServerName;

    memset(&PolicyPara, 0, sizeof(PolicyPara));
    PolicyPara.cbSize            = sizeof(PolicyPara);
    PolicyPara.pvExtraPolicyPara = &polHttps;

    memset(&PolicyStatus, 0, sizeof(PolicyStatus));
    PolicyStatus.cbSize = sizeof(PolicyStatus);

    if(!CertVerifyCertificateChainPolicy(
                            CERT_CHAIN_POLICY_SSL,
                            pChainContext,
                            &PolicyPara,
                            &PolicyStatus))
    {
        Status = GetLastError();
        message("Error 0x%x returned by CertVerifyCertificateChainPolicy!\n", Status);
        goto cleanup;
    }

    if(PolicyStatus.dwError)
    {
        Status = PolicyStatus.dwError;
        DisplayWinVerifyTrustError(Status); 
        goto cleanup;
    }


    Status = SEC_E_OK;

cleanup:

    if(pChainContext)
    {
        CertFreeCertificateChain(pChainContext);
    }

    return Status;
}


/*****************************************************************************/
static void
WriteDataToFile(
    PSTR  pszFilename,
    PBYTE pbData,
    DWORD cbData)
{
    FILE *file;

    file = fopen(pszFilename, "wb");
    if(file == NULL)
    {
        message("**** Error opening file '%s'\n", pszFilename);
        return;
    }

    if(fwrite(pbData, 1, cbData, file) != cbData)
    {
        message("**** Error writing to file\n");
        return;
    }

    fclose(file);
}


/*****************************************************************************/
static
void
DisplayConnectionInfo(
    CtxtHandle *phContext)
{
    SECURITY_STATUS Status;
    SecPkgContext_ConnectionInfo ConnectionInfo;

    Status = g_SecurityFunc.QueryContextAttributes(phContext,
                                    SECPKG_ATTR_CONNECTION_INFO,
                                    (PVOID)&ConnectionInfo);
    if(Status != SEC_E_OK)
    {
        message("Error 0x%x querying connection info\n", Status);
        return;
    }

    switch(ConnectionInfo.dwProtocol)
    {
        case SP_PROT_TLS1_CLIENT:
            message("Protocol: TLS1\n");
            break;

        case SP_PROT_SSL3_CLIENT:
            message("Protocol: SSL3\n");
            break;

        case SP_PROT_PCT1_CLIENT:
            message("Protocol: PCT\n");
            break;

        case SP_PROT_SSL2_CLIENT:
            message("Protocol: SSL2\n");
            break;

        default:
            message("Protocol: 0x%x\n", ConnectionInfo.dwProtocol);
    }

    switch(ConnectionInfo.aiCipher)
    {
        case CALG_RC4: 
            message("Cipher: RC4\n");
            break;

        case CALG_3DES: 
            message("Cipher: Triple DES\n");
            break;

        case CALG_RC2: 
            message("Cipher: RC2\n");
            break;

        case CALG_DES: 
        case CALG_CYLINK_MEK:
            message("Cipher: DES\n");
            break;

        case CALG_SKIPJACK: 
            message("Cipher: Skipjack\n");
            break;

        default: 
            message("Cipher: 0x%x\n", ConnectionInfo.aiCipher);
    }

    message("Cipher strength: %d\n", ConnectionInfo.dwCipherStrength);

    switch(ConnectionInfo.aiHash)
    {
        case CALG_MD5: 
            message("Hash: MD5\n");
            break;

        case CALG_SHA: 
            message("Hash: SHA\n");
            break;

        default: 
            message("Hash: 0x%x\n", ConnectionInfo.aiHash);
    }

    message("Hash strength: %d\n", ConnectionInfo.dwHashStrength);

    switch(ConnectionInfo.aiExch)
    {
        case CALG_RSA_KEYX: 
        case CALG_RSA_SIGN: 
            message("Key exchange: RSA\n");
            break;

        case CALG_KEA_KEYX: 
            message("Key exchange: KEA\n");
            break;

        case CALG_DH_EPHEM:
            message("Key exchange: DH Ephemeral\n");
            break;

        default: 
            message("Key exchange: 0x%x\n", ConnectionInfo.aiExch);
    }

    message("Key exchange strength: %d\n", ConnectionInfo.dwExchStrength);
}


/*****************************************************************************/
static
void
GetNewClientCredentials(
    CredHandle *phCreds,
    CtxtHandle *phContext)
{
    CredHandle hCreds;
    SecPkgContext_IssuerListInfoEx IssuerListInfo;
    PCCERT_CHAIN_CONTEXT pChainContext;
    CERT_CHAIN_FIND_BY_ISSUER_PARA FindByIssuerPara;
    PCCERT_CONTEXT  pCertContext;
    TimeStamp       tsExpiry;
    SECURITY_STATUS Status;

    //
    // Read list of trusted issuers from schannel.
    //

    Status = g_SecurityFunc.QueryContextAttributes(phContext,
                                    SECPKG_ATTR_ISSUER_LIST_EX,
                                    (PVOID)&IssuerListInfo);
    if(Status != SEC_E_OK)
    {
        message("Error 0x%x querying issuer list info\n", Status);
        return;
    }

    //
    // Enumerate the client certificates.
    //

    ZeroMemory(&FindByIssuerPara, sizeof(FindByIssuerPara));

    FindByIssuerPara.cbSize = sizeof(FindByIssuerPara);
    FindByIssuerPara.pszUsageIdentifier = szOID_PKIX_KP_CLIENT_AUTH;
    FindByIssuerPara.dwKeySpec = 0;
    FindByIssuerPara.cIssuer   = IssuerListInfo.cIssuers;
    FindByIssuerPara.rgIssuer  = IssuerListInfo.aIssuers;

    pChainContext = NULL;

    while(TRUE)
    {
        // Find a certificate chain.
        pChainContext = CertFindChainInStore(hMyCertStore,
                                             X509_ASN_ENCODING,
                                             0,
                                             CERT_CHAIN_FIND_BY_ISSUER,
                                             &FindByIssuerPara,
                                             pChainContext);
        if(pChainContext == NULL)
        {
            message("Error 0x%x finding cert chain\n", GetLastError());
            break;
        }
        message("\ncertificate chain found\n");

        // Get pointer to leaf certificate context.
        pCertContext = pChainContext->rgpChain[0]->rgpElement[0]->pCertContext;

        // Create schannel credential.
        SchannelCred.cCreds = 1;
        SchannelCred.paCred = &pCertContext;

        Status = g_SecurityFunc.AcquireCredentialsHandleA(
                            NULL,                   // Name of principal
                            UNISP_NAME_A,           // Name of package
                            SECPKG_CRED_OUTBOUND,   // Flags indicating use
                            NULL,                   // Pointer to logon ID
                            &SchannelCred,          // Package specific data
                            NULL,                   // Pointer to GetKey() func
                            NULL,                   // Value to pass to GetKey()
                            &hCreds,                // (out) Cred Handle
                            &tsExpiry);             // (out) Lifetime (optional)
        if(Status != SEC_E_OK)
        {
            message("**** Error 0x%x returned by AcquireCredentialsHandle\n", Status);
            continue;
        }
        message("\nnew schannel credential created\n");

        // Destroy the old credentials.
        g_SecurityFunc.FreeCredentialsHandle(phCreds);

        *phCreds = hCreds;

        break;
    }
}
    

/*****************************************************************************/
static void 
PrintHexDump(DWORD length, PBYTE buffer)
{
    DWORD i,count,index;
    CHAR rgbDigits[]="0123456789abcdef";
    CHAR rgbLine[100];
    char cbLine;

    for(index = 0; length; length -= count, buffer += count, index += count) 
    {
        count = (length > 16) ? 16:length;

        sprintf(rgbLine, "%4.4x  ",index);
        cbLine = 6;

        for(i=0;i<count;i++) 
        {
            rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
            rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
            if(i == 7) 
            {
                rgbLine[cbLine++] = ':';
            } 
            else 
            {
                rgbLine[cbLine++] = ' ';
            }
        }
        for(; i < 16; i++) 
        {
            rgbLine[cbLine++] = ' ';
            rgbLine[cbLine++] = ' ';
            rgbLine[cbLine++] = ' ';
        }

        rgbLine[cbLine++] = ' ';

        for(i = 0; i < count; i++) 
        {
            if(buffer[i] < 32 || buffer[i] > 126) 
            {
                rgbLine[cbLine++] = '.';
            } 
            else 
            {
                rgbLine[cbLine++] = buffer[i];
            }
        }

        rgbLine[cbLine++] = 0;
        message("%s\n", rgbLine);
    }
}

