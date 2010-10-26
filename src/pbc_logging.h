/* ========================================================================
 * Copyright 2008 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ========================================================================
 */

/** @file pbc_logging.h
 * Header file for logging stuff
 *
 * $Id: pbc_logging.h,v 1.27 2008/05/16 22:09:10 willey Exp $
 */


#ifndef INCLUDED_PBC_LOGGING_H
#define INCLUDED_PBC_LOGGING_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#define PBC_LOG_ERROR 0         /* errors only */
#define PBC_LOG_AUDIT 1         /* activity (authns, redirects, etc.) */
#define PBC_LOG_DEBUG_LOW 2     /* some debugging */
#define PBC_LOG_DEBUG_VERBOSE 3 /* whole lotta debugging */
#define PBC_LOG_DEBUG_OUTPUT 5  /* adds logging of all html output */

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#endif /* HAVE_STDARG_H */

#ifdef NEED_LOG_AUTHPRIV
# define LOG_AUTHPRIV LOG_AUTH
#endif /* NEED_LOG_AUTHPRIV */

#ifdef NEED_LOG_MAKEPRI
# define LOG_MAKEPRI(fac, pri) fac|pri
#endif /* NEED_LOG_MAKEPRI */

#ifdef NEED_LOG_FAC
# define LOG_FAC(fac) fac
#endif /* NEED_LOG_FAC */

/* callbacks for the logging subsystem */
typedef void pbc_open_log (const char *ident, int option, int facility);
typedef void pbc_log_func (pool * p, int priority, const char *msg);
typedef void pbc_close_log ();
typedef int pbc_log_level (pool * p);

/**
 * Initializes the logging system.
 * @param pool Apache memory pool
 * @param ident the identification of this process
 * @param o optional function to replace openlog()
 * @param l optional function to replace syslog()
 * @param c optional function to replace closelog()
 */
void pbc_log_init (pool * p, const char *ident,
                   pbc_open_log * o, pbc_log_func * l, pbc_close_log * c,
                   pbc_log_level * v);
void pbc_log_init_syslog (pool * p, const char *ident);

/**
 * Log activity messages
 * @param pool Apache memory pool
 * @param logging_level the importance level of the message
 * @param message the message format to be logged
 * @param ... stuff to be logged.
 */
void pbc_log_activity (pool * p, int logging_level, const char *message,
                       ...);

/**
 * Log activity messages, takes a va_list.
 * @param pool Apache memory pool
 * @param logging_level the importance level of the message
 * @param message the message to be logged
 * @param arg a va_list to be logged.
 */
void pbc_vlog_activity (pool * p, int logging_level, const char *format,
                        va_list arg);

/**
 * Create well-formed messages to be logged
 * @param pool Apache memory pool
 * @param info the string that contains the actual message
 * @param user the user's id
 * @param app_id the app_id of the requesting application
 * @return a nicely-formatted string to be logged
 */
char *pbc_create_log_message (pool * p, char *info, char *user,
                              char *app_id);

/**
 * Closes the logging system.  Optional.
 */
void pbc_log_close ();

#endif /* INCLUDED_PBC_LOGGING_H */
