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

/** @file pbc_myconfig.h
 * header file for Runtime configuration
 *
 * $Id: pbc_myconfig.h,v 1.27 2008/05/16 22:09:10 willey Exp $
 */


#ifndef INCLUDED_PBC_MYCONF_H
#define INCLUDED_PBC_MYCONF_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifndef WIN32
/**
 * initialize the config subsystem
 * param pool Apache memory pool
 * param alt_config the location of an alternate configuration file
 * to read, instead of the default
 * param ident the identity of the calling program used
 * return 0 for success, non-zero for failure
 */
extern int libpbc_myconfig_init (pool * p, const char *alt_config,
                                 const char *ident);

/**
 * return a string variable identified by key
 * @param pool Apache memory pool
 * @param key the key to lookup
 * @param def the default value to return if the key isn't found
 * @return the value of the option or def if it isn't found.  the
 * string belongs to the config library---it should not be changed or
 * free().  */
extern const char *libpbc_myconfig_getstring (pool * p, const char *key,
                                              const char *def);

/**
 * return an int variable identified by key
 * @param pool Apache memory pool
 * @param key the key to lookup
 * @param def the default value to return if the key isn't found
 * @return the value of the option or def if it isn't found
 */
extern int libpbc_myconfig_getint (pool * p, const char *key, int def);

/**
 * return a switch variable (true/false, yes/no, 1/0) identified by key
 * @param pool Apache memory pool
 * @param key the key to lookup
 * @param def the default value to return if the key isn't found
 * @return the value (1 for true, 0 for false) of the option or def if
 * it isn't found 
 */
extern int libpbc_myconfig_getswitch (pool * p, const char *key, int def);

/**
 * find a space seperated list in the config list
 * @param pool Apache memory pool
 * @param key the string key
 * @return a NULL terminated array of NUL terminated strings.
 * the array must be free() when the caller is done */
extern char **libpbc_myconfig_getlist (pool * p, const char *key);

/**
 * int=dddS, dddM, dddH 
 */
extern int libpbc_myconfig_str2int (const char *val, int def);


#else //Win32 declarations.  Descriptions same as above.

extern int libpbc_myconfig_init (pool * p, LPCTSTR alt_config,
                                 LPCTSTR ident);
extern int libpbc_myconfig_getint (pool * p, LPCTSTR key, int def);
extern LPTSTR libpbc_myconfig_getstring (pool * p, LPCTSTR key,
                                         LPCTSTR def);
extern int libpbc_myconfig_getswitch (pool * p, LPCTSTR key, int def);
extern LPTSTR *libpbc_myconfig_getlist (pool * p, LPCTSTR key);

/**
 * Add a given subdirectory to the Windows System path. 
 * In: pool     Apache memory pool (not used)
 * In: subdir   Subdirectory to add
 * In: buff     pointer to preallocated memory to hold result
 * Returns:     pointer to preallocated memory (buff) */
extern LPTSTR AddSystemRoot (pool * p, LPCTSTR subdir);

# endif
#endif /* INCLUDED_PBC_MYCONF_H */
