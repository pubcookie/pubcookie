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

/** @file index.cgi.c
 * U Wash SecurID verifier
 *
 *   the U Wash SecurID verifier verifies a username and PRN 
 *   against a U Wash SecurID.  sadly, U Wash SecurID is different
 *   than any other securid you're likely to run into
 *
 *  function: securid  
 *  args:     reason - points to a reason string
 *            user - the UWNetID
 *            card_id - the username for the card
 *            s_prn - the prn
 *            log - deprecieated, 
 *            type - SECURID_TYPE_NORM - normal
 *            doit - SECURID_DO_SID - yes, check prn
 *                   SECURID_ONLY_CRN - no, don't check prn, only report crn
 *
 *   returns:  SECURID_OK - ok
 *             SECURID_FAIL - fail
 *            SECURID_WANTNEXT - next prn
 *            SECURID_PROB - something went wrong
 *            SECURID_BAILOUT - bailed out before sid check, by request
 *  
 *  outputs:  even without log set non-zero there will be some output to
 *
 *   @return 0 on success, -1 if sid lookup fails, -3 next PRN,
 *          -2 on system error
 *
 * $Id: verify_uwsecurid.c,v 2.12 2008/05/16 22:09:10 willey Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#include "pbc_time.h"

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif /* HAVE_STDIO_H */

/* Pretending we're Apache */
typedef void pool;
pool *p = NULL;

#include "verify.h"

#ifdef ENABLE_UWSECURID         /* ENABLE_UWSECURID */

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif /* HAVE_CTYPE_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_SYS_PARAM_H
# include <sys/param.h>
#endif /* HAVE_SYS_PARAM_H */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif /* HAVE_SYS_RESOURCE_H */

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */

#ifdef HAVE_MANGO_MGOAPI2_H
# include <mango/mgoapi2.h>
# include <mango/sidapi.h>
# include <mango/messages.h>
# include <sys/stat.h>
#endif /* HAVE_MGOAPI_H */

#include "snprintf.h"

#ifdef HAVE_DMALLOC_H
# if (!defined(APACHE) && !defined(APACHE1_3))
#  include <dmalloc.h>
# endif /* ! APACHE */
#endif /* HAVE_DMALLOC_H */

#define SECURID_TRUE 1

#include "pbc_logging.h"

#define SECURID_DO_SID    1
#define SECURID_ONLY_CRN  0
#define SECURID_TYPE_NORM 0

#define SECURID_OK        0
#define SECURID_FAIL      1
#define SECURID_WANTNEXT  2
#define SECURID_PROB      3
#define SECURID_BAILOUT   4

#define BIGS 1024

void securid_cleanup (MgoHandle * shndl)
{
    MGOfreehandle (shndl);

}

int securid (char *reason,
             const char *user,
             const char *card_id,
             const char *s_prn, int log, int typ, int doit)
{
    int i, prn, ret;
    char tmp_res[BIGS];
    struct stat info;
    pbc_time_t date;
    char buff[BSIZ];
    int mode, opts, rets;
    MgoHandle *shndl;
    CrnList crn;

    MGOzero (&crn, sizeof (CrnList));
    strcpy (crn.principal, user);
    pbc_time (&date);
    shndl = NULL;
    rets = 0;
    snprintf (buff, BSIZ, "%s/%s", "weblogin", user);
    opts = MGO_OPT_CST;

    snprintf (tmp_res, BIGS,
              "user: %s card_id: %s s_prn: %s log: %d typ: %d doit: %d",
              (user ? user : "(NULL)"), (card_id ? card_id : "(NULL)"),
              (s_prn ? s_prn : "(NULL)"), log, typ, doit);
    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "Securid visit: %s",
                      tmp_res);

    /* move prn if we got one */
    if (s_prn == NULL) {
        reason = strdup ("No PRN");
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s", reason);
        securid_cleanup (shndl);
        return (SECURID_PROB);
    } else {
        prn = atoi (s_prn);
    }

    /*
     * Connect to Mango and query for CRN information
     */

    if ((rets = MGOinitialize (&shndl, SID_CONFIG)) == MGO_SUCCESS) {
        MGOsetoption (shndl, MGO_OPT_USER, (void *) buff);
    } else {
        if (rets == MGO_ENOENT) {
            MGOsetoption (shndl, MGO_OPT_HOST, (void *) SID_HOST);
            MGOsetoption (shndl, MGO_OPT_OPTIONS, (void *) &opts);
            MGOsetoption (shndl, MGO_OPT_USER, (void *) buff);
        } else {
            snprintf (tmp_res, BIGS, "SecurID initialize error: %s.",
                      MGOerrormsg (shndl, rets));
            reason = strdup (tmp_res);
            pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s", reason);
            securid_cleanup (shndl);
            return (SECURID_PROB);
        }
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                      "Securid: about to connect for %s", crn.principal);

    if ((rets = MGOconnect (shndl)) != MGO_SUCCESS) {
        snprintf (tmp_res, BIGS, "Securid connect error: %s.\n",
                  MGOerrormsg (shndl, rets));
        reason = strdup (tmp_res);
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s", reason);
        securid_cleanup (shndl);
        return (SECURID_PROB);
    }

    /* this is the bail-out option */
    if (doit == SECURID_ONLY_CRN) {
        snprintf (tmp_res, BIGS,
                  "no securid check was done for user: %s card_id: %s",
                  user, card_id);
        reason = strdup (tmp_res);
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s", reason);
        securid_cleanup (shndl);
        return (SECURID_BAILOUT);
    }

    if (card_id == NULL || strcmp (card_id, "") == 0)
        *crn.crn = ESV;
    else
        strcpy (crn.crn, card_id);

    mode = SID_VALIDATE;

    if ((rets =
         SIDcheckprn (shndl, (char *) user, crn.crn, prn,
                      mode)) != MGO_SUCCESS) {
        switch (shndl->srverrno) {
        case MGO_E_CRN:
            snprintf (tmp_res, BIGS,
                      "Failed SecurID check: id=%s, prn=%d.", user, prn);
            pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s", tmp_res);
            ret = SECURID_FAIL;
            break;
        case MGO_E_NPN:
            snprintf (tmp_res, BIGS,
                      "Asking for next prn: id=%s, prn=%d.", user, prn);
            pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s", tmp_res);
            ret = SECURID_WANTNEXT;
            break;
        default:
            snprintf (tmp_res, BIGS, "Unexpected error: %s.",
                      MGOerrormsg (shndl, rets));
            reason = strdup (tmp_res);
            pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s", reason);
            ret = SECURID_PROB;
            break;
        }
    } else {
        snprintf (tmp_res, BIGS, "OK SecurID check: id=%s", user);
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s", tmp_res);
        ret = SECURID_OK;
    }

    reason = strdup (tmp_res);
    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s", reason);
    securid_cleanup (shndl);
    return (ret);

}

static int uwsecurid_v (pool * p, const char *userid,
                        const char *sid,
                        const char *service,
                        const char *user_realm,
                        struct credentials **creds, const char **errstr)
{

    char *reason = NULL;        /* dunno about this */
    char *card_id;
    int result;
    char *ptr;
    char *prn = NULL;

    if (!sid)
        return (-1);

    /* if the securid field is in the form card_id=prn seperate it */
    ptr = card_id = (char *) sid;
    while (*ptr) {
        if (*ptr == '=') {
            *ptr = '\0';
            prn = ++ptr;
        }
        ptr++;
    }
    if (prn == NULL) {
        card_id = NULL;
        prn = (char *) sid;
    }

    /* what do we do with the card_id? */
    result = securid (reason,
                      userid,
                      card_id, prn, 1, SECURID_TYPE_NORM, SECURID_DO_SID);

    switch (result) {
    case SECURID_OK:
        return (0);
        break;
    case SECURID_FAIL:
        return (-1);
        break;
    case SECURID_WANTNEXT:
        return (-3);
        break;
    case SECURID_PROB:
        return (-2);
        break;
    case SECURID_BAILOUT:
        return (-2);
        break;
    default:
        return (-2);
        break;
    }

}

#ifdef TEST_UWSECURID

#include "pbc_config.h"
#include "pbc_logging.h"

static void mylog (pool * p, int logging_level, const char *msg)
{
    if (logging_level <= libpbc_config_getint (p, "logging_level", 0)) {
        fprintf (stderr, "%s\n", msg);
    }
}


int main (int argc, char **argv)
{
    char buf[1024];
    char name[9];
    char prn[7], junk[20], card_id[20];
    char *use_card_id;
    int i;
    char *reason;
    int check;

    libpbc_config_init (p, NULL, "uwsecurid");
    pbc_log_init (p, "uwsecurid_test", NULL, &mylog, NULL, NULL);

    if (strstr (*argv, "no_check"))
        check = SECURID_ONLY_CRN;
    else
        check = SECURID_DO_SID;

    printf ("want: name <userid> securid <sid>\n");
    printf ("or    name <userid> securid <sid> card_id <card_id>\n");

    while (fgets (buf, 1024, stdin)) {
        sscanf (buf, "%s", junk);
        if (!strcmp (junk, "exit"))
            break;
        if ((i =
             sscanf (buf, "name %s securid %s card_id %s", name, prn,
                     card_id)) == 0)
            i = sscanf (buf, "name %s securid %s", name, prn);

        printf ("\ti ->%d<- name ->%s<- prn ->%s<- card_id ->%s<-\n",
                i, name, prn, card_id);

        if (i = 2)
            use_card_id = name;
        else
            use_card_id = card_id;

        securid (reason, name, card_id, prn, 1, SECURID_TYPE_NORM, check)
            ? printf ("fail\n") : printf ("ok\n");

        *prn = '\0';
        *name = '\0';
        *card_id = '\0';
    }

    exit (0);

}

#endif /* #ifdef TEST_VERIFY */

#else /* ENABLE_UWSECURID */

static int uwsecurid_v (pool * p, const char *userid,
                        const char *passwd,
                        const char *service,
                        const char *user_realm,
                        struct credentials **creds, const char **errstr)
{
    if (creds)
        *creds = NULL;

    *errstr = "U Wash. SecurID verifier not implemented";
    return -1;
}

#endif /* ENABLE_UWSECURID */

verifier uwsecurid_verifier = { "uwsecurid", &uwsecurid_v, NULL, NULL };
