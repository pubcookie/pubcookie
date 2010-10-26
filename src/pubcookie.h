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
    $Id: pubcookie.h,v 1.31 2008/05/16 22:09:10 willey Exp $
 */

#ifndef PUBCOOKIE_MAIN
#define PUBCOOKIE_MAIN

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "pbc_time.h"

#ifdef OPENSSL_IN_DIR
# include <openssl/pem.h>
#else
# include <pem.h>
#endif /* OPENSSL_IN_DIR */

#include <security.h>

/* psuedo-arbitrary limit on the length of GET args supported */
#define PBC_MAX_GET_ARGS 1900

#define PBC_USER_LEN 42
#define PBC_VER_LEN 4
#define PBC_APPSRV_ID_LEN 40
#define PBC_APP_ID_LEN 128
#define PBC_TOT_COOKIE_DATA 228
#define PBC_DES_KEY_BUF 2048

#define PBC_1K 1024
#define PBC_2K 2048
#define PBC_4K 4096
#define PBC_20K 20480
#define PBC_SHORT_STRING 128
#define PBC_RAND_MALLOC_BYTES 8

#define PBC_X_STRING "XXXXXXXXXXXXX"
#define PBC_XS_IN_X_STRING 13
#define PBC_X_CHAR 'X'
#define PBC_NO_FORCE_REAUTH "NFR"
#define PBC_POST_NAME "relay.pubcookie3"

/* gotta start somewhere                                                      */
#define PBC_INIT_IVEC {0x4c,0x43,0x5f,0x98,0xbc,0xab,0xef,0xca}
#define PBC_INIT_IVEC_LEN 8
#define PBC_DES_INDEX_FOLDER 30

typedef struct
{
    unsigned char user[PBC_USER_LEN];
    unsigned char version[PBC_VER_LEN];
    unsigned char appsrvid[PBC_APPSRV_ID_LEN];
    unsigned char appid[PBC_APP_ID_LEN];
    unsigned char type;
    unsigned char creds;
    int pre_sess_token;
    pbc_time_t create_ts;
    pbc_time_t last_ts;
}
cookie_data_struct;

typedef union pbc_cookie_data_union
{
    cookie_data_struct broken;
    unsigned char string[PBC_TOT_COOKIE_DATA];
}
pbc_cookie_data;

typedef struct
{
    EVP_MD_CTX *ctx;
    EVP_PKEY *private_key;
    EVP_PKEY *public_key;
    char key_file[600];         /*for debugging routines to print */
}
md_context_plus;

typedef struct
{
    unsigned char key_a[PBC_DES_KEY_BUF];
}
crypt_stuff;

#endif /* !PUBCOOKIE_MAIN */
