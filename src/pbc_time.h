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
  $Id: pbc_time.h,v 2.5 2008/05/16 22:09:10 willey Exp $
 */

#ifndef INCLUDED_PBC_TIME_H
#define INCLUDED_PBC_TIME_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

# ifdef HAVE_TIME_H
#  include <time.h>
# endif /* HAVE_TIME_H */

# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# endif /* HAVE_SYS_TIME_H */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef WIN32
	typedef int pbc_time_t; //on Windows int is always 32bit	
#else
	typedef int32_t pbc_time_t;
#endif

/**
 *
 * Gets a "time" the way that we want it.
 * @param tloc a place to put the time, also returned.
 * 
 */

pbc_time_t pbc_time( pbc_time_t *tloc );

#endif
