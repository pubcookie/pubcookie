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

/***************************************************************************
 * CAUTION!  This file (pbc_version.h) is automatically generated from
 * pbc_version.h.in.  Changes made directly in pbc_version.h will be overwritten
 * by configure when it is run again!
 *************************************************************************** */

#ifndef PUBCOOKIE_VERSION
#define PUBCOOKIE_VERSION

/* The cookie version - Needs to stick around a while
   we can call this the protocol version.  it's what goes into the 
   current cookie or post messages.  might use the PBC_VERSION_MAJOR
   someday but this works for now.
 */
#define PBC_VERSION "a5"

/*
 * Someday the cookie version will be the major version or something like that.
 */

/*
 * NOTE: These version strings are from configure.ac now.
 */

/***************************************************************************
 * CAUTION!  This file (pbc_version.h) is automatically generated from
 * pbc_version.h.in.  Changes made directly in pbc_version.h will be overwritten
 * by configure when it is run again!
 *************************************************************************** */

#define PBC_VERSION_MAJOR "3"
#define PBC_VERSION_MINOR "3"
#define PBC_VERSION_PATCH "5"

/***************************************************************************
 * CAUTION!  This file (pbc_version.h) is automatically generated from
 * pbc_version.h.in.  Changes made directly in pbc_version.h will be overwritten
 * by configure when it is run again!
 *************************************************************************** */

/* beta or final, so the code knows what it is, should it care. */
#define PBC_VERSION_RELEASE "final"

/***************************************************************************
 * CAUTION!  This file (pbc_version.h) is automatically generated from
 * pbc_version.h.in.  Changes made directly in pbc_version.h will be overwritten
 * by configure when it is run again!
 *************************************************************************** */

#define PBC_VERSION_STRING "3.3.5"

#endif /* !PUBCOOKIE_VERSION */
