/*

    User authentication using LDAP directory services.

    NOTE: Errors are collected in Web server's error log file.

 */

/*
    Version: index.cgi_ldap.c,v 1.0 2001/09/4 14:39:00 russ 
 */


/* LibC */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
/* ldap - using OpenLDAP SDK */
#include "ldap.h"

/* login cgi includes */
#include "index.cgi.h"

#define LF_SIZE 128

/*
 * Authenticate username using LDAP directory service.
 * Return: NULL if successful; else an error message.
 */
char *auth_ldap(const char *username, const char *passwd)
{

    char  *ret = NULL;
    int   got_error = 0;

    char  *ldap_server = "ldap1.its.hawaii.edu";
    int    ldap_port = LDAP_PORT; // the default 389
    char  *ldap_search_base = "ou=people, o=hawaii.edu";
    char  *ldap_uid_attribute = "uid";
    char  ldap_filter[LF_SIZE];
    char  *user_dn = NULL;

    LDAP *ld = NULL;
    LDAPMessage *results, *entry;
    int num_entries;

    if (username == NULL || passwd == NULL) {
	ret = strdup("username or password is null -- auth failed");
        return ret;
    }

    /* lookup DN for username using an anonymous bind */
    ld = ldap_init(ldap_server, ldap_port);
    if (ld == NULL) {
	ret = strdup("connection to ldap server failed -- auth failed");
        return ret;
    }

    got_error = ldap_simple_bind_s(ld, NULL, NULL);
    if (got_error != LDAP_SUCCESS) {
	ret = strdup("anonymous bind failed -- auth failed");
        return ret;
    }

    snprintf(ldap_filter, LF_SIZE - 1, "%s=%s", ldap_uid_attribute, username);
    ldap_filter[LF_SIZE - 1] = '\0';
    got_error = ldap_search_s(ld, ldap_search_base, LDAP_SCOPE_SUBTREE,
                              ldap_filter, NULL, 0, &results);
    if (got_error != LDAP_SUCCESS) {
	ret = strdup("user not found -- auth failed");
        return ret;
    }

    num_entries = ldap_count_entries(ld, results);
    if (num_entries != 1) {
        ldap_perror(ld, "ldap_count_entries");
        /* close ldap connection */
        ldap_msgfree(results);
        ldap_unbind(ld);
	ret = strdup("too many or no entries found -- auth failed");
        return ret;
    }
    else {
        entry = ldap_first_entry(ld, results);
        if (entry == NULL) {
            ldap_perror(ld, "ldap_first_entry");
            /* close ldap connection */
            ldap_msgfree(results);
            ldap_unbind(ld);
            ret = strdup("error getting ldap entry -- auth failed");
            return ret;
        }
        /* get dn */
        user_dn = ldap_get_dn(ld, entry);
        if (user_dn == NULL || passwd == NULL) {
            ldap_perror(ld, "ldap_get_dn");
            /* close ldap connection */
            ldap_msgfree(results);
            ldap_unbind(ld);
            ret = strdup("too many or no entries found -- auth failed");
            return ret;
        }
    }

    /* now bind as the user's DN using the supplied password */
    got_error = ldap_simple_bind_s(ld, user_dn, passwd);
    if (got_error != LDAP_SUCCESS) {
        ldap_perror(ld, "ldap_simple_bind");
        /* close ldap connection */
        free(user_dn);
        ldap_msgfree(results);
        ldap_unbind(ld);
	ret = strdup("couldn't bind as user -- auth failed");
        return ret;
    }

    /* check that the user's bind is good */
    got_error = ldap_search_s(ld, user_dn, LDAP_SCOPE_ONELEVEL,
                              "(objectclass=*)", NULL, 0, &results);
    if (got_error) {
        ldap_perror(ld, "ldap_search_s");
	ret = strdup("couldn't search user's entry -- auth failed");
    }

    /* close ldap connection */
    free(user_dn);
    ldap_msgfree(results);
    ldap_unbind(ld);
    return(ret);
}

