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

/** @file verify_fork.c

 *  Verifier that forks something and uses it to authenticate
 *
 * A verifier which launches another program which must read 4 string
 * arguments - userid, password, service and realm - from stdin. Each
 * string is terminated by a null character, \0. The called program
 * must then return a non-zero exit code if authentication fails. The
 * called program must exit with 0 status if all is OK.

 *
 * To use verify_fork:
 * a) In your config:  'basic_verifier: verify_fork'
 * b) The application to run is specified by a parameter called "verify_exe", 
 * for example:
 * verify_exe: /usr/local/pubcookie/readauth.py
 *
 * ...where readauth.py could be:
 *  #!/usr/bin/env python
 *  import sys
 *  import myauth
 *  user, pass, serv, realm=sys.stdin.read().split('\0')
 *  status=myauth.lookup(username, password, serv, realm)
 *  sys.exit(status)
 *  
 * From Tim Funk <funkman@joedog.org> 18-Sept-2003
 * Modified 4-April-2005: Fixed security issue - read user and
 * password from stdin rather passing as args. david.houlder@anu.edu.au
 *
 * $Id: verify_fork.c,v 1.12 2008/05/16 22:09:10 willey Exp $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif /*  */

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif /* HAVE_SYS_TYPES_H */

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif /* HAVE_SYS_WAIT_H */

#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif /* HAVE_ERRNO_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /*  */

/* Pretending we're Apache */
typedef void pool;

#include "verify.h"
#include "pbc_logging.h"
#include "pbc_configure.h"
int verify_fork_v (pool * p,
                   const char *userid, const char *passwd,
                   const char *service, const char *user_realm,
                   struct credentials **creds, const char **errstr)
{
    pid_t pid;
    int status, died;
    char *fork_exe;
    int stdin_pipe[2];

    if (errstr)
        *errstr = NULL;
    if (creds)
        *creds = NULL;
    pbc_log_activity (p, PBC_LOG_DEBUG_OUTPUT, "verify_fork: enter");
    fork_exe = (char *) libpbc_config_getstring (p, "verify_exe", "");
    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                      "verify_fork: verify_exe=%s", fork_exe);
    if (!userid) {
        *errstr = "no userid to verify";
        return -1;
    }
    if (!passwd) {
        *errstr = "no password to verify";
        return -1;
    }
    if (!service)
        service = "";
    if (!user_realm)
        user_realm = "";

    if (-1 == pipe (stdin_pipe)) {
        *errstr = "could not create pipe to child process";
        return -1;
    }
    pbc_log_activity (p, PBC_LOG_DEBUG_OUTPUT,
                      "verify_fork: about to fork");

    switch (pid = fork ()) {
    case -1:
        pbc_log_activity (p, PBC_LOG_ERROR, "verify_fork: Couldn't fork");
        *errstr = "Couldn't fork";
        exit (-1);
    case 0:
        pbc_log_activity (p, PBC_LOG_DEBUG_OUTPUT,
                          "verify_fork: about to execl");
        close (0);
        if (0 == dup (stdin_pipe[0]) &&
            0 == close (stdin_pipe[0]) && 0 == close (stdin_pipe[1])) {
            execl (fork_exe, fork_exe, NULL);

            /* Should not occur since execl doesn't return */
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "verify_fork: can't exec, errno=%d", errno);
        } else
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "verify_fork: can't set up pipe, errno=%d",
                              errno);
        exit (-1);
    default:
        pbc_log_activity (p, PBC_LOG_DEBUG_OUTPUT,
                          "verify_fork: about to wait");
        close (stdin_pipe[0]);
        /* write strlen()+1 to write the \0. O_NONBLOCK is clear so we
           get either a full write or -1 returned */
        if (-1 == write (stdin_pipe[1], userid, strlen (userid) + 1) ||
            -1 == write (stdin_pipe[1], passwd, strlen (passwd) + 1) ||
            -1 == write (stdin_pipe[1], service, strlen (service) + 1) ||
            -1 == write (stdin_pipe[1], user_realm,
                         strlen (user_realm) + 1))
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "verify_fork: Write to child failed, errno=%d",
                              errno);
        close (stdin_pipe[1]);
        if (-1 == waitpid (pid, &status, 0)) {
            pbc_log_activity (p, PBC_LOG_ERROR,
                              "verify_fork: Wait for child failed");
            *errstr = ("Wait for child failed");
            return -2;
        }
        pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                          "verify_fork: wait=%d", status);
        if (0 == status)
            return 0;
        pbc_log_activity (p, PBC_LOG_DEBUG_OUTPUT,
                          "verify_fork: setting error");
        *errstr = ("Non 0 child exit");
        return -1;
    }
}

verifier fork_verifier = {
    "verify_fork", &verify_fork_v, NULL, NULL
};
