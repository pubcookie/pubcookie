// ========================================================================
// Copyright 2008 University of Washington
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
//  $Id: debug.h,v 1.15 2008/05/16 22:09:10 willey Exp $
//

#include <windows.h>

void syslog(int whichlog, const char *message, ...);
char * AddToLog(char*LogBuff, const char *format, ...);
void filter_log_activity ( pool *p, const char * source, int logging_level, const char * format, va_list args );

extern char Instance[64];
extern char *SystemRoot;

//Message Event IDs

// MessageId: ERR_ONE
//
// MessageText:
//
//  Generic Error
//
#define PBC_ERR_ID_GENERIC                      0x00000001L

//
// MessageId: ERR_TWO
//
// MessageText:
//
//  Debug: %1
//
#define PBC_ERR_ID_DEBUG                        0x00000002L

//
// MessageId: ERR_THREE
//
// MessageText:
//
//  %1
//
#define PBC_ERR_ID_SIMPLE                       0x00000003L

#define LOGBUFFSIZE 4096
