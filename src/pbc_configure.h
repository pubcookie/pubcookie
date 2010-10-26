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

/*
  $Id: pbc_configure.h,v 2.14 2008/05/16 22:09:10 willey Exp $
 */

#ifndef INCLUDED_PBC_CONFIGURE_H
#define INCLUDED_PBC_CONFIGURE_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#endif /* HAVE_STDARG_H */

#include "pbc_myconfig.h"

/* callbacks for the configure subsystem */
typedef int config_initialize (pool * p, void *alt_config,
                               const char *ident);
typedef int config_getint (pool * p, const char *key, int def);
typedef char **config_getlist (pool * p, const char *key);
typedef const char *config_getstring (pool * p, const char *key,
                                      const char *def);

typedef int config_getswitch (pool * p, const char *key, int def);

/**
 *   backward compatibility interface
 *   please update code to use pbc_configure_init instead
 */
void libpbc_config_init (pool * p, const char *alt_config,
                         const char *ident);

/**
 * Initializes the configuration system.
 * @param pool Apache memory pool
 * @param ident the identification of this process
 * @param initialize function to call to set up the config subsystem
 * @param initarg generic argument to pass to the initializer
 * @param i function to get an integer
 * @param l function to get a list
 * @param s function to get a string
 * @param w function to get a switch
 */
void pbc_configure_init (pool * p, const char *ident,
                         config_initialize * initialize,
                         void *initarg,
                         config_getint * i,
                         config_getlist * l,
                         config_getstring * s, config_getswitch * w);

int libpbc_config_getint (pool * p, const char *key, int def);
char **libpbc_config_getlist (pool * p, const char *key);
const char *libpbc_config_getstring (pool * p, const char *key,
                                     const char *def);
int libpbc_config_getswitch (pool * p, const char *key, int def);

#endif /* INCLUDED_PBC_CONFIGURE_H */
