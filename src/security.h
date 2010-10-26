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
  $Id: security.h,v 1.19 2008/05/16 22:09:10 willey Exp $
 */

#ifndef INCLUDED_SECURITY_H
#define INCLUDED_SECURITY_H

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/* crypt methods */

#define PBC_CRYPT_DES 'd'
#define PBC_CRYPT_AES 'a'
#define PBC_CRYPT_AES_D 'A'

#ifdef PBC_USE_DES_CRYPT
#define PBC_DEF_CRYPT PBC_CRYPT_DES /* old compat mode */
#else
#define PBC_DEF_CRYPT PBC_CRYPT_AES /* new and improved */
#endif



/**
 * the secuirty context structure 
 */
struct security_context_s;
typedef struct security_context_s security_context;

static void make_crypt_keyfile (pool * p, const char *peername, char *buf);

/**
 * initializes the security subsystem.
 * the configuration & logging subsystems are required prerequisites
 * @param pool pionter to an Apache memory pool
 * @param context a pointer to the context to be created inside pool
 * @returns non-zero on error
 */
int security_init (pool * p, security_context ** context);

/**
 * libpbc_mk_priv takes 'buf', 'len', and returns 'outbuf', 'outlen',
 * an encrypted string that can only be read by 'peer'.
 * @param pool pionter to an Apache memory pool
 * @param context the security context for the (virtual) host
 * @param peer the name of the peer this is destined for.  if NULL,
 * the message will be signed with private material that is only known
 * to this host. 
 * @param buf a pointer to the cleartext string
 * @param len the length of the data pointed to by buf
 * @param outbuf will be filled in with a malloc()ed buffer.  it must
 * later be free()ed.
 * @param outlen the length of outbuf.
 * @returns 0 on success, non-zero on failure.
 */
int libpbc_mk_priv (pool * p, const security_context * context,
                    const char *peer, const char use_granting,
                    const char *buf, const int len, char **outbuf,
                    int *outlen, char alg);

/**
 * libpbc_rd_priv decodes an encrypted string sent by 'peer'.  if
 * 'peer' is NULL, we assume that this host previously called libpbc_mk_priv
 * with NULL.
 * @param pool Apache memory pool
 * @param context the security context for the (virtual) host
 * @param peer the peer this message is destined to (the first parameter to
 * libpbc_mk_priv()).
 * @param buf a pointer to the encrypted message
 * @param len the length of the encrypted message
 * @param outbuf a malloc()ed pointer to the plaintext message
 * @param outlen the length of the plaintext message
 * @returns 0 on success, non-0 on failure (including if the message could 
 * not be decrypted or did not pass integrity checks)
 */
int libpbc_rd_priv (pool * p, const security_context * context,
                    const char *peer, const char use_granting,
                    const char *buf, const int len, char **outbuf,
                    int *outlen, char alg);

/**
 * libpbc_mk_safe allocates a signature and returns it to the
 * application. 'outbuf' does not contain the plaintext message; both
 * 'buf' and 'outbuf' must be sent to the other side.
 * @param pool pionter to an Apache memory pool
 * @param context the security context for the (virtual) host
 * @param peer the peer this message is being sent to; if NULL, this message
 * is destined to myself.
 * @param buf a pointer to the message to be sent
 * @param len  the length of the message
 * @param outbuf a malloc()ed pointer to the signature
 * @param outlen the length of the signature
 * @returns 0 success, non-0 on failure
 */
int libpbc_mk_safe (pool * p, const security_context * context,
                    const char *peer, const char use_granting,
                    const char *buf, const int len, char **outbuf,
                    int *outlen);

/**
 * verifies a message signed with libpbc_mk_safe()
 * @param pool pionter to an Apache memory pool
 * @param context the security context for the (virtual) host
 * @param peer the peer this message was sent to; the first parameter passed
 * to libpbc_mk_safe()
 * @param buf the plaintext message
 * @param len the length of the plaintext message
 * @param sigbuf the signature returned from libpbc_mk_safe()
 * @param siglen the length of the received signature
 * @returns 0 on success, non-0 on any failure
 */
int libpbc_rd_safe (pool * p, const security_context * context,
                    const char *peer, const char use_granting,
                    const char *buf, const int len, const char *sigbuf,
                    const int siglen);

/**
 * returns the public name of this service. this is what other systems
 * should use as peer to send data here with libpbc_mk_safe()
 * @param pool pionter to an Apache memory pool
 * @param context the security context for the (virtual) host
 * @returns a constant string, which should not be modified or free()ed
 */
const char *libpbc_get_cryptname (pool * p,
                                  const security_context * context);

#endif
