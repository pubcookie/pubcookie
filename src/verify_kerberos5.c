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

    Modified further at Carnegie Mellon University
    Modified Kerberos code, modified at University of Washington
    Copyright 1995,1996,1997,1998 by the Massachusetts Institute of Technology.
       All Rights Reserved.

 */

/** @file verify_kerberos5.c
 * Kerberos 5 Verifier
 *
 * Verifies users against an Kerberos5 server (or servers.)
 *
 * $Id: verify_kerberos5.c,v 1.42 2008/05/16 22:09:10 willey Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

typedef void pool;

/* login cgi includes */
#include "index.cgi.h"
#include "verify.h"
#include "pbc_config.h"
#include "pbc_configure.h"
#include "pbc_myconfig.h"
#include "pbc_logging.h"
#include "snprintf.h"

#ifdef ENABLE_KRB5

/* LibC */
#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_ASSERT_H
# include <assert.h>
#endif /* HAVE_ASSERT_H */

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif /* HAVE_SYS_STAT_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */


/* krb5  */
#ifdef HAVE_COM_ERR_H
# include <com_err.h>
#endif /* HAVE_COM_ERR_H */

#ifdef HAVE_KRB5_H
# include <krb5.h>
#endif /* HAVE_KRB5_H */

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

#define KRB5_DEFAULT_OPTIONS 0

static char thishost[BUFSIZ];

static int save_tf (pool * p, const char *tfname,
                    struct credentials **credsp)
{
    FILE *f;
    struct stat sbuf;

    assert (tfname != NULL && credsp != NULL);

    *credsp = malloc (sizeof (struct credentials));
    if (!*credsp) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: malloc failed");
        return -1;
    }
    (*credsp)->str = NULL;

    f = fopen (tfname, "r");
    if (!f) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: can't open %s: %m", tfname);
        return -1;
    }

    if (fstat (fileno (f), &sbuf) < 0) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: fstat %s: %m", tfname);
        return -1;
    }

    (*credsp)->sz = sbuf.st_size;
    (*credsp)->str = malloc (sbuf.st_size * sizeof (char));
    if (!(*credsp)->str) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: malloc failed");
        goto cleanup;
    }

    if (fread ((*credsp)->str, sbuf.st_size, 1, f) != 1) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: short read %s: %m", tfname);
        goto cleanup;
    }

    fclose (f);
    return 0;

  cleanup:
    fclose (f);
    if ((*credsp)->str)
        free ((*credsp)->str);
    free (*credsp);

    return -1;
}

static int unsave_tf (pool * p, const char *tfname,
                      struct credentials *creds)
{
    FILE *f;

    assert (tfname != NULL && creds != NULL);

    f = fopen (tfname, "w");
    if (!f) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: can't open %s: %m", tfname);
        return -1;
    }

    if (fwrite (creds->str, creds->sz, 1, f) != 1) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: can't write %s: %m", tfname);
        fclose (f);
        unlink (tfname);
        return -1;
    }

    if (fclose (f) != 0) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: can't close %s: %m", tfname);
        unlink (tfname);
        return -1;
    }

    return 0;
}

static void creds_free (pool * p, struct credentials *creds)
{
    if (creds->str)
        free (creds->str);
    if (creds)
        free (creds);
}

static int cred_derive (pool * p, struct credentials *creds,
                        const char *app,
                        const char *target,
                        int initialize_cache,
                        krb5_context context,
                        krb5_ccache ccache, krb5_ccache ccache_target)
{
    char *realm = NULL;
    char *s, *t;
    krb5_creds request, *newcreds;
    int r = -1;
    krb5_error_code error;

    assert (creds != NULL);
    assert (app != NULL && target != NULL);

    memset (&request, 0, sizeof (request));

    s = strdup (target);
    if (!s) {
        return -1;
    }

    realm = strchr (s, '@');
    if (realm) {
        *realm++ = '\0';
        realm = strdup (realm); /* so we can free it later */
    } else {
        if (krb5_get_default_realm (context, &realm)) {
            realm = NULL;
        }
    }

    if (!realm) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: cred_derive %s: couldn't determine realm",
                          target);
        goto cleanup;
    }

    /* get the hostname out */
    t = strchr (s, '/');
    if (t)
        *t++ = '\0';

    /* who am i? */
    if (error = krb5_cc_get_principal (context, ccache, &(request.client))) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: cred_derive %s: who am i?",
                          target, error_message(error));
        goto cleanup;
    }

    /* build requested principal */
    if (error = krb5_build_principal (context, &request.server,
                              strlen (realm), realm, s, t, NULL)) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: cred_derive %s: couldn't build principal: %s",
                          target, error_message(error));
        goto cleanup;
    }

    /* fetch the request ticket */
    if (error = krb5_get_credentials (context, 0, ccache,
                                      &request, &newcreds)) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: cred_derive %s: krb5_get_credentials failed: %s",
                          target, error_message(error));
        goto cleanup;
    }

    if (initialize_cache == 0) {
        if (error = krb5_cc_initialize (context, ccache_target, request.client)) {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "verify_kerberos5: cred_derive %s: krb5_cc_initialize failed: %s",
                              target, error_message(error));
            goto cleanup;
        }
    }

    if (error = krb5_cc_store_cred (context, ccache_target, newcreds)) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: cred_derive %s: krb5_cc_store_cred failed: %s",
                          target, error_message(error));
        goto cleanup;
    }

    /* whew! done */
    r = 0;

  cleanup:
    if (s)
        free (s);
    if (request.client)
        krb5_free_principal (context, request.client);
    if (request.server)
        krb5_free_principal (context, request.server);

    return r;
}

static int creds_derive (pool * p, struct credentials *creds,
                         login_rec * l,
                         const char **target_array,
                         struct credentials **outcredsp)
{
    krb5_context context;
    char tfname[40];
    char tfname_target[50];
    krb5_ccache ccache;
    krb5_ccache ccache_target;
    int i = 0;
    int r = -1;

    assert (creds != NULL);
    assert (l->host != NULL && target_array != NULL);

    snprintf (tfname, sizeof (tfname), "/tmp/k5cc_%d_%s", getpid (),
              l->user);
    snprintf (tfname_target, sizeof (tfname_target), "%s_target", tfname);

    /* unpack 'creds' into a ticket file */
    if (unsave_tf (p, tfname, creds) < 0) {
        return -1;
    }

    /* examine the ticket file */
    if (krb5_init_context (&context)) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: creds_derive: krb5_init_context failed");
        goto cleanup;
    }

    if (krb5_cc_resolve (context, tfname, &ccache)) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: creds_derive: krb5_cc_resolve failed");
        goto cleanup;
    }


    if (krb5_cc_resolve (context, tfname_target, &ccache_target)) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: creds_derive: krb5_cc_resolve failed");
        goto cleanup;
    }


    for (i = 0; target_array[i] != NULL; i++) {
        if (cred_derive
            (p, creds, l->host, target_array[i], i, context, ccache,
             ccache_target) != 0) {
            goto cleanup;
        }
    }

    /* bundle up the new ticket */
    if (save_tf (p, tfname_target, outcredsp) < 0) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: save_tf failed");
        goto cleanup;
    }

    /* woo, success */
    r = 0;

  cleanup:
    krb5_cc_destroy (context, ccache);
    krb5_cc_destroy (context, ccache_target);
    krb5_free_context (context);

    return r;
}


/*
 * returns 0 success; non-0 on failure
 */
static int k5support_verify_tgt (pool * p, krb5_context context,
                                 krb5_ccache ccache,
                                 krb5_auth_context * auth_context,
                                 const char **errstr)
{
    krb5_principal server;
    krb5_data packet;
    krb5_keyblock *keyblock = NULL;
    krb5_error_code k5_retcode;
    int result = -1;
    char *sname =
        (char *) libpbc_config_getstring (p, "kerberos5_service_name",
                                          "host");

    krb5_keytab keytab;
    krb5_pointer keytabname;


    if (errstr) {
        *errstr = NULL;
    }

    if (krb5_sname_to_principal (context, NULL, sname,
                                 KRB5_NT_SRV_HST, &server)) {
        *errstr = "krb5_sname_to_principal() failed";
        return -1;
    }

    keytabname =
        (krb5_pointer) libpbc_config_getstring (p, "kerberos5_keytab",
                                                NULL);
    if (keytabname) {
        if ((k5_retcode = krb5_kt_resolve (context, keytabname, &keytab))) {
            *errstr = "unable to resolve keytab";
            goto fini;
        }
    } else {
        keytab = NULL;
    }

    if ((k5_retcode =
         krb5_kt_read_service_key (context, keytabname, server, 0, 0,
                                   &keyblock))) {
        *errstr = "unable to read service key";
        goto fini;
    }

    if (keyblock) {
        free (keyblock);
    }
#ifdef KRB5_HEIMDAL
    krb5_data_zero (&packet);
#else
    /* hopefully this will correctly zero out the packet */
    memset (&packet, 0, sizeof (packet));
#endif
    k5_retcode = krb5_mk_req (context, auth_context, 0, sname,
                              thishost, NULL, ccache, &packet);
    if (*auth_context) {
        krb5_auth_con_free (context, *auth_context);
        *auth_context = NULL;
    }

    if (k5_retcode) {
        *errstr = "krb5_mk_req failed";
        goto fini;
    }

    k5_retcode = krb5_rd_req (context, auth_context, &packet,
                              server, keytab, NULL, NULL);
    if (k5_retcode) {
        *errstr = "krb5_rd_req failed";
        goto fini;
    }

    /* all is good now */
    result = 0;
  fini:
    krb5_free_principal (context, server);

    if (k5_retcode)
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "k5support_verify_tgt: %s",
                          error_message (k5_retcode));

    return result;
}

/* returns 0 on success; non-zero on failure */
static int kerberos5_v (pool * p, const char *userid,
                        const char *passwd,
                        const char *service,
                        const char *user_realm,
                        struct credentials **credsp, const char **errstr)
{
    krb5_context context;
    krb5_auth_context auth_context = NULL;
    krb5_ccache ccache = NULL;
    krb5_principal auth_user;
    krb5_creds creds;
    krb5_get_init_creds_opt opts;
#ifdef KRB5_HEIMDAL
    krb5_addresses no_addrs;
#endif
    krb5_error_code k5_retcode;
    int result = -1;
    char tfname[40];
    char *realm = NULL;
    char *localpwd = NULL;

    if (credsp)
        *credsp = NULL;

    if (errstr) {
        *errstr = NULL;
    }

    if (!thishost[0] && gethostname (thishost, BUFSIZ) < 0) {
        *errstr = "gethostname failed";
        return -1;
    }
    thishost[BUFSIZ - 1] = '\0';

    if (!userid) {
        *errstr = "no userid to verify";
        return -1;
    }
    if (!passwd) {
        *errstr = "no password to verify";
        return -1;
    }

    if (krb5_init_context (&context)) {
        return -1;
    }

    /* add the other login servers to the acceptable IP addresses */

    if (!user_realm) {
        if (!krb5_get_default_realm (context, &realm)) {
            /* don't forget to free this if you care */
            user_realm = realm;
        } else {
            *errstr = "can't determine realm";
            krb5_free_context (context);
            return -1;
        }
    }

    if (krb5_build_principal (context, &auth_user, strlen (user_realm),
                              user_realm, userid, NULL)) {
        krb5_free_context (context);
        free (realm);
        return -1;
    }

    /* create a new CCACHE so we don't stomp on anything */
    snprintf (tfname, sizeof (tfname), "/tmp/k5cc_%d_%s@%s", getpid (),
              userid, user_realm);
    if (krb5_cc_resolve (context, tfname, &ccache)) {
        krb5_free_principal (context, auth_user);
        krb5_free_context (context);
        free (realm);
        return -1;
    }

    if (krb5_cc_initialize (context, ccache, auth_user)) {
        krb5_free_principal (context, auth_user);
        krb5_free_context (context);
        free (realm);
        return -1;
    }

    localpwd = strdup (passwd);

    if (localpwd == NULL)
        return 1;

    krb5_get_init_creds_opt_init (&opts);
#ifdef KRB5_HEIMDAL
    no_addrs.len = 0;
    no_addrs.val = NULL;
    krb5_get_init_creds_opt_set_address_list (&opts, &no_addrs);
#endif
    krb5_get_init_creds_opt_set_tkt_life (&opts,
            libpbc_config_getint (p, "default_l_expire", DEFAULT_LOGIN_EXPIRE) +
            libpbc_config_getint (p, "kerberos5_extralife", 0));

    if ((k5_retcode = krb5_get_init_creds_password (context, &creds,
                                                    auth_user, localpwd,
                                                    NULL, NULL, 0, NULL,
                                                    &opts))) {
        krb5_cc_destroy (context, ccache);
        krb5_free_principal (context, auth_user);
        krb5_free_context (context);
        free (realm);
        free (localpwd);
        *errstr = "can't get tgt";
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "kerberos5_v: can't get tgt: %s",
                          error_message (k5_retcode));
        return -1;
    }
    free (localpwd);

    /* at this point we should have a TGT. Let's make sure it is valid */
    if (krb5_cc_store_cred (context, ccache, &creds)) {
        krb5_free_principal (context, auth_user);
        krb5_cc_destroy (context, ccache);
        krb5_free_context (context);
        free (realm);
        *errstr = "can't verify tgt";
        return -1;
    }

    /* save the TGT if we were asked to */
    if (credsp && save_tf (p, tfname, credsp) < 0) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "verify_kerberos5: save_tf failed");
    }

    result =
        k5support_verify_tgt (p, context, ccache, &auth_context, errstr);

#if 0
    /* xxx this seems like the way it "should" be done instead of the
       save_tf() way */
    /* save the TGT */

    if (!result && credsp) {
        int r = 0;
        krb5_kdc_flags flags;
        krb5_principal server = 0;
        krb5_principal client = 0;
        krb5_data forw_creds;
        struct sockaddr_in sin;
        int sa_size;
        krb5_address addr;

        memset (&flags, 0, sizeof (flags));
        memset (&forw_creds, 0, sizeof (forw_creds));

        if (!auth_context) {
            /* initialize the auth_context */
            r = krb5_auth_con_init (context, &auth_context);
        }

        /* we're forwarding these credentials to ourselves; we'll 
           mark them as good for anyone */
        if (!r) {
            r = krb5_anyaddr (context, AF_INET, (struct sockaddr *) &sin,
                              &sa_size, 0);
        }

        if (!r) {
            r = krb5_sockaddr2address (context, (struct sockaddr *) &sin,
                                       &addr);
        }

        if (!r) {
            r = krb5_auth_con_setaddrs (context, auth_context,
                                        &addr, &addr);
        }

        /* get the opaque data to save for later */
        if (!r) {
            r = krb5_get_forwarded_creds (context, auth_context, ccache,
                                          flags.i, thishost, &creds,
                                          &forw_creds);
        }

        /* put it into a struct credentials */
        if (!r) {
            *credsp = malloc (sizeof (struct credentials));
            if (*credsp) {
                (*credsp)->sz = forw_creds.length;
                (*credsp)->str = forw_creds.data;
            } else {
                pbc_log_activity (p, PBC_LOG_ERROR,
                                  "verify_kerberos5: malloc() failed");
            }
        } else {
            /* krb error */
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "verify_kerberos5: error getting forwarded creds: %s",
                              error_message (r));
        }
    }
#endif

    /* destroy any tickets we had */
    if (auth_context) {
        krb5_auth_con_free (context, auth_context);
        auth_context = NULL;
    }
    krb5_free_cred_contents (context, &creds);
    krb5_free_principal (context, auth_user);
    krb5_cc_destroy (context, ccache);
    krb5_free_context (context);
    free (realm);

    if (result != 0 && credsp && *credsp) {
        /* destroy the credentials we saved */
        creds_free (p, *credsp);
    }

    return result;
}

verifier kerberos5_verifier = { "kerberos_v5", &kerberos5_v,
    &creds_free,
    &creds_derive
};

#else /* ENABLE_KRB5 */

verifier kerberos5_verifier = { "kerberos_v5", NULL, NULL, NULL };

#endif /* ENABLE_KRB5 */
