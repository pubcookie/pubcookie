// ========================================================================
// Copyright 2009 University of Washington
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ========================================================================
//

/*
  $Id: winkeyclient.c,v 1.20 2009/06/26 17:35:45 dors Exp $
 */
#include <stdio.h>
#include <stdlib.h>
#include <windows.h> 
#include <winsock.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <schannel.h>
#include <tchar.h>

typedef void pool;

#include <sspi.h>

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */

#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif /* HAVE_ARPA_INET_H */

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif /* HAVE_NETDB_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#include <httpfilt.h>
//todo #include <strsafe.h>

#include "../pubcookie.h"
#include "../pbc_config.h"
#include "PubCookieFilter.h"
#include "getopt.h"
#include "../libpubcookie.h"
#include "../strlcpy.h"
#include "../snprintf.h"
#include "../pbc_myconfig.h"
#include "../pbc_configure.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>

#  ifdef __STDC__
extern char * optarg;
#  endif /* __STDC__ */
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

#  include "debug.h"
#  include "WebClient.h"
#  include <process.h>
#  include <io.h>
#  define pid_t int
#  define snprintf _snprintf

#define MAX_REG_BUFF 2048

/* globals */
int noop = 0;
int newkeyp = 1;
pubcookie_dir_rec   ppool;
pubcookie_dir_rec  *p=&ppool;
char *hostname = NULL;
BOOL silent = FALSE;
BOOL runByInstaller = FALSE;
char *gcert = NULL;
char *keyserver = NULL;
char *default_keyserver = "https://weblogin.washington.edu:2222";
char *filter_key = "System\\CurrentControlSet\\Services\\PubcookieFilter";



WSADATA wsaData;
SOCKET  Socket;
CtxtHandle hContext;
SecBuffer  ExtraData;
SECURITY_STATUS Status;
SecurityFunctionTable *lpSecurityFunc = NULL;
PCCERT_CONTEXT pRemoteCertContext = NULL;
CredHandle hClientCreds;


int Messagef(const char * format, ...){
    char msg[2048];

	if (!silent) {

		va_list   args;

		va_start(args, format);

		_vsnprintf(msg, sizeof(msg), format, args);
		msg[sizeof(msg)-1] = '\0';

		MessageBox(NULL,msg,"Keyclient",MB_ICONINFORMATION);

		va_end(args);
	}
    return 1;
}

UINT MessageYesNo(const char * format, ...) {
	UINT uiResponse = NULL;
	char msg[2048];


	va_list   args;

	va_start(args, format);

	_vsnprintf(msg, sizeof(msg), format, args);
	msg[sizeof(msg)-1] = '\0';

	uiResponse = MessageBox(NULL,msg, "Keyclient found more than one valid certificate.", MB_YESNO);


	va_end(args);

	return uiResponse;
}

void exitf(int return_code, const char * format, ...) {
	char msg[2048];
	UINT boxtype;
	va_list   args;

	if (!silent) {
		if (return_code != ERROR_SUCCESS) {
			boxtype=MB_ICONWARNING;
		} 
		else {
			boxtype=MB_OK;
		}

		if (strcmp("",format)) {
			va_start(args, format);
			_vsnprintf(msg, sizeof(msg)-1, format, args);
			MessageBox(NULL,msg,"Keyclient",boxtype);
			va_end(args);
		}

		if (return_code != ERROR_SUCCESS) {
			if (gcert) {
				Messagef("Unable to automatically obtain granting certificate.\nYou will need to manually obtain your granting certificate and save it as: %s", gcert );
			}
			else {
				Messagef("You will need to sucessfully run keyclient before using the Pubcookie filter.");
			}
		}
	}

	DisconnectFromServer(Socket, &hClientCreds, &hContext);

	// Free SSPI credentials handle.
	lpSecurityFunc->FreeCredentialsHandle(&hClientCreds);

	// Close socket.
	closesocket(Socket);

	// Shutdown WinSock subsystem.
	WSACleanup();

	// Close certificate store.
	CertCloseMyStore();

	// free memory pool
	free(p);

    exit (return_code);
}

/* destructively returns the value of the CN */
static char *extract_cn(char *s)
{
    char *pp = strstr(s, "CN=");
    char *q;

    if (pp) {
        pp += 3;
        q = strstr(pp, "/Email=");
        if (q) {
            *q = '\0';
        }
        /* fix for subjects that go leaf -> root */
        q = strchr(pp, '/');
        if (q) {
            *q = '\0';
        }
    }

    return pp;
}

/**
 * generates the filename that stores the DES key
 * @param peername the certificate name of the peer
 * @param buf a buffer of at least 1024 characters which gets the filename
 * @return always succeeds
 */
static void make_crypt_keyfile(pool *p, const char *peername, char *buf)
{
    strlcpy(buf, PBC_KEY_DIR, 1024);

	if (buf[strlen(buf)-1] != '\\') {
        strlcat(buf, "\\", 1024);
    }
    strlcat(buf, peername, 1024);
}

/**
 * writes the key 'key' to disk for peer 'peer'
 * @param a pointer to the PB_C_DES_KEY_BUF-sized key
 * @param peer the certificate name of the peer
 * @return PBC_OK for success, PBC_FAIL for failure
 */
int set_crypt_key(const char *key, const char *peer)
{
    char keyfile[1024];
    FILE *f;

    make_crypt_keyfile(p, peer, keyfile);
    if (!(f = fopen(keyfile, "wb"))) {
	return PBC_FAIL;
    }
    fwrite(key, sizeof(char), PBC_DES_KEY_BUF, f);
    fclose(f);

    return PBC_OK;
}

/*                                                                           */
int get_crypt_key(crypt_stuff *c_stuff, const char *peer)
{
    FILE             *fp;
    char             *key_in;
    char keyfile[1024];


    make_crypt_keyfile(p, peer, keyfile);

    key_in = (char *)malloc(PBC_DES_KEY_BUF);

    if( ! (fp = fopen(keyfile, "rb")) ) { /* win32 - must be binary read */
        Messagef("get_crypt_key: Failed open: %s\n", keyfile);
        return PBC_FAIL;
    }
    
    if( fread(key_in, sizeof(char), PBC_DES_KEY_BUF, fp) != PBC_DES_KEY_BUF) {
        Messagef("get_crypt_key: Failed read: %s\n", keyfile);
	fclose(fp);
	return PBC_FAIL;
    }
    fclose(fp);

    memcpy(c_stuff->key_a, key_in, sizeof(c_stuff->key_a));
    free(key_in);

    return PBC_OK;
}
void ParseCmdLine(LPSTR lpCmdLine) {
	int c;

	while ((c = getopt(__argc, __argv, "sudiH:G:")) != -1) {
        switch (c) {
			case 's':
				/* silent mode */
				silent = TRUE;
				break;

            case 'd':
                /* download, don't generate a new key */
                newkeyp = 0;
                break;

            case 'u':
                /* upload, don't generate a new key */
                newkeyp = -1;
                break;

			case 'i':
				/* executed by Installer */
				/*
					if this is called by the installer, then this
					will execute keyclient twice (one for getting Granting Cert,
					another to get the key).  This can potentially lead to
					the user seeing the message box to pick the certificate from
					MyStore twice.  If it's executed by the Installer then
					do a best guess and pick the first valid cert instead of prompting
					the user to select the one they want to use
				*/
				runByInstaller = TRUE;
				break;
            case 'G':
				/* get granting cert, don't generate a new key */
                gcert = strdup(optarg);
                newkeyp = -1;
                break;

            case 'H':
				/* Application server hostname
				   Default is gethostbyname() if not specified here */
                hostname = strdup(optarg);
                break;
            case '?':
            default:
                break;
        }
    }
}


int APIENTRY WinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPSTR     lpCmdLine,
                     int       nCmdShow)
{
    char *cp;
	char buf[8 * PBC_DES_KEY_BUF]; /* plenty of room for key or cert */
    unsigned char thekey[PBC_DES_KEY_BUF];
    crypt_stuff c_stuff;
	struct hostent *h;
    int ret;
    int done = 0;
    const char *keymgturi = NULL;
    char *keyhost = NULL;
	char *keymgtpath = NULL;
    int keyport = 443;
	char *Reply = NULL;
	char sztmp[1024];

	if( WSAStartup((WORD)0x0101, &wsaData ) ) 
	{  
		Messagef("Unable to initialize WINSOCK: %d\n", WSAGetLastError() );
		return ERROR_INSTALL_FAILURE;
	}
    if(!LoadSecurityLibrary(&lpSecurityFunc))
    {
        Messagef("Error initializing the security library\n");
        return ERROR_INSTALL_FAILURE;
    }

	libpbc_config_init(p,"","keyclient");

	ParseCmdLine(lpCmdLine);

	if (!hostname) { 
		gethostname(sztmp, sizeof(sztmp)-1);
		h = gethostbyname(sztmp);
		hostname = strdup(h->h_name);
	}

    //
    // Create credentials.
    //

	if(Status = CreateCredentials(hostname, runByInstaller, &hClientCreds))
	{
		if (Status == SEC_E_NO_CREDENTIALS) {
			//Messagef("Error creating credentials.  Could not find server certificate for %s",hostname);
			//return ERROR_INSTALL_FAILURE;			
			exitf(ERROR_INSTALL_FAILURE,"Could not find server certificate for %s",hostname);
		}
		else {
			//Messagef("Error creating credentials. Error code: 0x%x\n", Status);
			//return ERROR_INSTALL_FAILURE;		
			exitf(ERROR_INSTALL_FAILURE,"Error creating credentials. Error code: 0x%x\n", Status);
		}
	}


    /* figure out the key management server */
	keymgturi = strdup(PBC_KEYMGT_URI);
	message("Keyserver is %s", keymgturi);	
    keyhost = strdup(keymgturi);

    if (!strncmp(keyhost, "https://", 8)) keyhost += 8;
    cp = strchr(keyhost, '/');
    if (cp) {
		keymgtpath = strdup(cp);
        *cp = '\0';
    }

    cp = strchr(keyhost, ':');
    if (cp) {
        *cp++ = '\0';
        keyport = atoi(cp);
    }

    /* connect to the keyserver */

    if(ret = ConnectToServer(keyhost, keyport, &Socket))
    {
		Messagef("Cannot connect to %s:%u\n",keyhost,keyport);
        return ERROR_INSTALL_FAILURE;
    }


    //
    // Perform handshake
    //

    if(PerformClientHandshake(Socket,
                              &hClientCreds,
                              keyhost,
                              &hContext,
                              &ExtraData))
    {
        exitf(ERROR_INSTALL_FAILURE,"Could not build a secure connection to keyserver.");
    }


    //
    // Authenticate server's credentials.
    //

    // Get server's certificate.
    Status = lpSecurityFunc->QueryContextAttributes(&hContext,
                                    SECPKG_ATTR_REMOTE_CERT_CONTEXT,
                                    (PVOID)&pRemoteCertContext);
    if(Status != SEC_E_OK)
    {
        exitf(ERROR_INSTALL_FAILURE,"Error 0x%x querying remote certificate\n", Status);
    }

    // Display server certificate chain.
    // DisplayCertChain(pRemoteCertContext, FALSE);

    // Attempt to validate server certificate.
    Status = VerifyServerCertificate(pRemoteCertContext,
                                     keyhost,
                                     0);

	if(Status)
    {
        exitf(ERROR_INSTALL_FAILURE,"Error authenticating server credentials.  Check to make sure that your server has a certificate that is trusted by your machine.\n");
    }



 
	 /* make the HTTP query */
    /* newkeyp = 1 means generate and get a key 
       newkeyp = 0 means get a key 
       newkeyp = -1 means something else
     */

   	if (newkeyp == -1) {
		char enckey[PBC_DES_KEY_BUF * 2];

		if (gcert) { /* get the granting cert */
			snprintf(buf, sizeof(buf),
				"GET %s?genkey=getgc;\r\n\r\n",
				keymgturi);
			buf[sizeof(buf)-1] = '\0';

		} else {   /* set the key */
			if (get_crypt_key(&c_stuff, hostname) != PBC_OK) {
				exitf(ERROR_INSTALL_FAILURE,"Couldn't retrieve key");
			}

			libpbc_base64_encode(p, c_stuff.key_a, (unsigned char *) enckey, PBC_DES_KEY_BUF);

			/* we're uploading! */
			snprintf(buf, sizeof(buf),
				"%s?genkey=put&setkey=%s;%s",
				keymgtpath, hostname, enckey);
			buf[sizeof(buf)-1] = '\0';
		}
	} else {
		snprintf(buf, sizeof(buf), 
			"%s?genkey=%s", keymgtpath,
			newkeyp ? "yes" : "no");
		buf[sizeof(buf)-1] = '\0';
	}


    if (noop && newkeyp) {
        Messagef("-n specified; not performing any writes:\n");
        Messagef("%s", buf);
        exit(ERROR_SUCCESS);
    }
    if(HttpsGetFile(Socket, 
                    &hClientCreds,
                    &hContext, 
                    buf,
					&Reply))
    {
        Messagef("Error fetching file from server.\n");
        return ERROR_INSTALL_FAILURE;
    }

	cp = Reply;

	/* look for the 'OK' */
	while (*cp) {
		if (cp[0] == '\r' && cp[1] == '\n' &&
			cp[2] == 'O' && cp[3] == 'K' &&
			cp[4] == ' ') {
				char *s;
				cp += 5;

				if (newkeyp != -1) {
					/* If getting a key, cp points to a base64 key to decode */
					if (strlen(cp) >= (4 * PBC_DES_KEY_BUF + 100) / 3) {
						exitf(ERROR_INSTALL_FAILURE,"key too long\n");
					}

					if (s=strchr(cp, '\r')) *s = '\0';
					if (s=strchr(cp, '\n')) *s = '\0';

					if (noop) {
						printf("would have set key to '%s'\n", cp);
					} else {
						int osize = 0;
						int ret;
						if (s=strchr(cp, '\r')) *s = '\0';
						ret = libpbc_base64_decode(p, (unsigned char *) cp, thekey, &osize);
						if (osize != PBC_DES_KEY_BUF) {
							exitf(ERROR_INSTALL_FAILURE,"keyserver returned wrong key size: expected %d got %d\n", PBC_DES_KEY_BUF, osize);
						}

						if (! ret) {
							exitf(ERROR_INSTALL_FAILURE,"Bad base64 decode.\n" );
						}

						if (set_crypt_key((const char *) thekey, hostname) != PBC_OK) {
							exitf(ERROR_INSTALL_FAILURE,"Could not set key for %s\nCheck file permissions.\n",hostname);
						} else {
							Messagef("Created and stored encryption key for %s.\n",hostname);
						}

					}
				} else if (gcert) {
					/* If getting a cert, cp points to start of PEM cert */
					FILE *cf = fopen(gcert, "w");
					if (!cf) {
						exitf(ERROR_INSTALL_FAILURE,"Unable to open granting certificate file for writing.\n File: %s",gcert);
					}
					fputs(cp, cf);
					fclose(cf);
					
					Messagef("Granting cert saved to %s\n", gcert);
				}

				done = 1;
				exitf(ERROR_SUCCESS,"");
			}
			cp++;
	}

	if (!done) {
		exitf(ERROR_INSTALL_FAILURE,"Operation failed.\nServer Reply:\n%s", Reply);
	}

	exitf(ERROR_SUCCESS,"");
	return(0);  //Just here to make the compiler happy.  exitf does not return.
}
