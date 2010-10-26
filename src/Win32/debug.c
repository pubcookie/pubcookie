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

//
//  $Id: debug.c,v 1.23 2009/06/26 17:35:44 dors Exp $
//

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <time.h>
#include <direct.h>

#include <pem.h>
#include <httpfilt.h>
typedef void pool;
#include "pubcookie.h"
#include "pbc_config.h"
#include "PubCookieFilter.h"
#include "libpubcookie.h"
#include "pbc_version.h"
#include "pbc_myconfig.h"
#include "pbc_configure.h"
#include "debug.h"

#define BUFFSIZE 4096

extern void filter_log_activity (pubcookie_dir_rec *p, const char * source, int logging_level, const char * format, va_list args )
{

    char      log[BUFFSIZE];
	HANDLE hEvent;
	//PTSTR pszaStrings[1];	
	unsigned short errortype;
	DWORD eventid=PBC_ERR_ID_SIMPLE;
	pubcookie_dir_rec *pp=NULL;	

	if (!p) {
		syslog(LOG_INFO, "filter_log_activity(p,%s,%d,%s,...) called without an allocated pool",source,logging_level,format);
		pp = (pubcookie_dir_rec *)malloc(sizeof(pubcookie_dir_rec));
		bzero(pp,sizeof(pubcookie_dir_rec));
	}
	else {
		pp = p;
	}

    if (logging_level <= (libpbc_config_getint(pp,"Debug_Trace", LOG_WARN)))    {
		
		switch (logging_level) {
		case LOG_INFO:
            errortype = EVENTLOG_INFORMATION_TYPE;
            break;
		case LOG_DEBUG:
            errortype = EVENTLOG_INFORMATION_TYPE;
			eventid = PBC_ERR_ID_DEBUG;
            break;
		case LOG_ERR:
            errortype = EVENTLOG_ERROR_TYPE;
			break;
		case LOG_WARN:
		default:
			errortype = EVENTLOG_WARNING_TYPE;
			
		}
        _vsnprintf(log, BUFFSIZE, format, args);
	log[BUFFSIZE - 1] = '\0';
		//pszaStrings[0] = log;
		hEvent = RegisterEventSource(NULL,source);
		if (hEvent) 
		{
			LPCSTR messages[] = {log, NULL};
			/*
			ReportEvent(hEvent, errortype, 0, eventid, NULL, (WORD)1, 0,                  
                (const char **)pszaStrings, NULL); 				
			*/
			ReportEvent(hEvent, errortype, 0, eventid, NULL, 1, 0,                  
                messages, NULL); 
			DeregisterEventSource(hEvent);
		}
	}
	if (!p) {
		free(pp);
	}


}

void pbc_vlog_activity(pubcookie_dir_rec *p, int logging_level, const char * format, va_list args )
{
	filter_log_activity (p, "Pubcookie", logging_level, format, args);
}

/* Called whenever you don't have a pool yet available */
extern void syslog(int whichlog, const char *message, ...) {

	pubcookie_dir_rec *p;
	va_list   args;

	p = malloc(sizeof(pubcookie_dir_rec)); 
	bzero(p,sizeof(pubcookie_dir_rec));

    va_start(args, message);

    pbc_vlog_activity(p, whichlog, message, args );

    va_end(args);

	free(p);

}

/* Called from libpubcookie, we can't trust its pool pointer */
extern void pbc_log_activity(pubcookie_dir_rec *p, int logging_level, const char *message,...)
{
	pubcookie_dir_rec *pp; 
    va_list   args;

	if (p) {
		pp=p;
	} else {
		pp = malloc(sizeof(pubcookie_dir_rec)); 
		bzero(pp,sizeof(pubcookie_dir_rec));
	}
    va_start(args, message);

    pbc_vlog_activity(pp, logging_level, message, args );

    va_end(args);

	if (!p) {
		free(pp);
	}
}

char * AddToLog(char*LogBuff, const char *format, ...) {
	char *LogPos;

	va_list   args;

    va_start(args, format);

	LogPos = LogBuff + strlen(LogBuff);

    _vsnprintf(LogPos, LOGBUFFSIZE - (LogPos - LogBuff), format, args);
    LogBuff[LOGBUFFSIZE-1] = '\0';

    va_end(args);

    return (LogBuff);
}


