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

/** @file ntmpl.c
 * Template library
 *
 * $Id: ntmpl.c,v 1.29 2008/05/16 22:09:10 willey Exp $
 */

#ifdef WITH_FCGI
#include "fcgi_stdio.h"
#endif

#ifdef HAVE_CONFIG_H
# include "config.h"
# include "pbc_path.h"
#endif

#include "pbc_time.h"

typedef void pool;

#ifdef HAVE_STRINGS_H
# include <strings.h>
#endif /* HAVE_STRINGS_H */

#ifdef HAVE_STRING_H
# include <string.h>
#endif /* HAVE_STRING_H */

#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif

#ifdef HAVE_STDIO_H
# include <stdio.h>
#endif

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#endif

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pbc_logging.h"
#include "pbc_config.h"
#include "pubcookie.h"

/* hmm, bad place for this prototype. */
extern FILE *htmlout;
extern FILE *mirror;

/*
 * return the length of the passed file in bytes or 0 if we cant tell
 * resets the file postion to the start
 */
static long file_size (pool * p, FILE * afile)
{
    long len;
    if (fseek (afile, 0, SEEK_END) != 0)
        return 0;
    len = ftell (afile);
    if (fseek (afile, 0, SEEK_SET) != 0)
        return 0;
    return len;
}


/*
 * return a template html file
 */
static char *get_file_template (pool * p, const char *fpath,
                                const char *fname, int sub_len,
                                long *outlen)
{
    char *templatefile;
    char *template = NULL;
    long readlen;
    FILE *tmpl_file;

    /* +2 for the "/" between and the trailing null */
    *outlen = strlen (fpath) + strlen (fname) + 2;
    templatefile = (char *) malloc (*outlen * sizeof (char));
    if (templatefile == NULL) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "unable to malloc %d bytes for template filename %s",
                          *outlen, fname);
        goto done;
    }
    if (snprintf (templatefile, *outlen, "%s%s%s", fpath,
                  fpath[strlen (fpath) - 1] == '/' ? "" : "/",
                  fname) > *outlen) {
        pbc_log_activity (p, PBC_LOG_ERROR, "template filename overflow");
        goto done;
    }


    tmpl_file = (FILE *) pbc_fopen (p, templatefile, "r");
    if (tmpl_file == NULL) {
        pbc_log_activity (p, PBC_LOG_ERROR, "cant open template file %s",
                          templatefile);
        template = NULL;
        goto done;
        return NULL;
    }

    *outlen = file_size (p, tmpl_file);
    if (*outlen == 0) {
        goto done;
    }

    /* add in the length of the substitution text if there is such */
    template = (char *) malloc (((*outlen + 1) + sub_len) * sizeof (char));
    if (template == NULL) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "unable to malloc %d bytes for template file %s",
                          *outlen + 1, fname);
        goto done;
    }

    *template = 0;
    readlen = fread (template, 1, *outlen, tmpl_file);
    if (readlen != *outlen) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "read %d bytes when expecting %d for template file %s",
                          readlen, *outlen, fname);
        pbc_free (p, template);
        template = NULL;
        goto done;
    }

    template[*outlen++] = 0;

    pbc_fclose (p, tmpl_file);

  done:

    if (templatefile != NULL)
        pbc_free (p, templatefile);

    return template;

}

/**
 * ntmpl_print_html() takes a template and a list of items to fill in 
 * and prints to the HTML buffer the result of substitutions.
 * @param fname the name of the template to substitute for
 * @param ... a sequence of attr, substitution parameters for the
 * substitutions.  the attributes are searched for in the template
 * with "%<attr>%"; the entire string is then replaced with the next
 * parameter.  the caller must pass a NULL after all attributes
 */
void ntmpl_print_html (pool * p, const char *fpath, const char *fname, ...)
{
    const char *attr;
    const char *subst;
    va_list ap;
    long len;
    char *template = get_file_template (p, fpath, fname, 0, &len);
    char *t;
    char *percent;
    char candidate[256];
    int i;
    const char func[] = "ntmpl_print_html";

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: hello", func);

    memset (candidate, 0, 256);

    t = template;
    /* look for the next possible substitution */
    while (t != NULL && (percent = strchr (t, '%')) != NULL) {
        fwrite (t, percent - t, 1, htmlout);
        if (mirror != NULL)
            fwrite (t, percent - t, 1, mirror);

        /* look to see if this is a legitimate candidate for substitution */
        for (i = 1; percent[i] && (i < sizeof (candidate) - 1); i++) {
            if (percent[i] == '%')
                break;
            candidate[i - 1] = percent[i];
        }
        /* terminate candidate */
        candidate[i - 1] = '\0';

        attr = NULL;
        subst = NULL;
        if (percent[i] == '%') {
            /* ok, found a trailing %, so 'candidate' contains a possible
               substitution. look for it in the params */
            va_start (ap, fname);
            while ((attr = va_arg (ap, const char *)) != NULL)
            {
                subst = va_arg (ap, const char *);

                if (!strcmp (attr, candidate)) {
                    /* bingo, matched! */
                    break;
                }
            }
        }

        if (attr != NULL && subst != NULL) {
            /* we found a match; print that out instead */
            fputs (subst, htmlout);
            if (mirror != NULL)
                fputs (subst, mirror);
            /* move to the trailing % */
            percent = strchr (percent + 1, '%');
        } else {
            /* false alarm, not a substitution */
            fputc ('%', htmlout);
            if (mirror != NULL)
                fputc ('%', mirror);
        }
        /* skip after the % */
        t = percent + 1;
    }

    /* print out everything from the last % on */
    if (t != NULL)
        fputs (t, htmlout);
    if (t != NULL && mirror != NULL)
        fputs (t, mirror);

    pbc_free (p, template);

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: goodbye", func);

}

/* returns PBC_OK if template exists, PBC_FAIL if template doesn't exist      */
int ntmpl_tmpl_exist (pool * p, const char *fpath, const char *fname)
{
    struct stat buf;
    int len, ret;
    char *templatefile = NULL;

    /* +2 for the "/" between and the trailing null */
    len = strlen (fpath) + strlen (fname) + 2;
    templatefile = (char *) malloc (len * sizeof (char));
    if (templatefile == NULL) {
        pbc_log_activity (p, PBC_LOG_ERROR,
                          "unable to malloc %d bytes for template filename %s",
                          len, fname);
        return (PBC_FAIL);
    }
    if (snprintf (templatefile, len, "%s%s%s", fpath,
                  fpath[strlen (fpath) - 1] == '/' ? "" : "/",
                  fname) == -1) {
        pbc_log_activity (p, PBC_LOG_ERROR, "template filename overflow");
        return (PBC_FAIL);
    }

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE,
                      "ntmpl_tmpl_exist: looking for: %s", templatefile);

    if (stat (templatefile, &buf) == 0)
        ret = PBC_OK;
    else
        ret = PBC_FAIL;

    return (ret);

}

/* in the absense of a better template library create html from sub-templates
   this is code that that defected from flavour_basic.c                       */
/* returns NULL if it can't return the correct string */
char *ntmpl_sub_template (pool * p, const char *fpath, const char *fname,
                          ...)
{
    char *field_html = NULL;    /* net result */
    char *buf;
    long len;
    va_list ap, ap2;
    char *t;
    char *percent;
    int i;
    char candidate[256];
    const char *attr;
    const char *subst;
    char func[] = "ntmpl_sub_template";
    int subst_len = 0;

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: hello", func);

    memset (candidate, 0, 256);

    /* get lengths of substitution text */
    va_start (ap2, fname);
    while (va_arg (ap2, const char *) != NULL)
    {
        subst_len += strlen (va_arg (ap2, const char *));
    }
    va_end (ap2);

    /* pull file into a string */
    field_html = get_file_template (p, fpath, fname, subst_len, &len);

    buf = (char *) malloc (len * sizeof (char));
    if (buf == NULL) {
        pbc_log_activity (p, PBC_LOG_ERROR, "unable to malloc buffer");
        goto done;
    }

    /* keep track of length to make doubly sure we don't overflow */
    if (field_html != NULL)
        len -= strlen (field_html);

    t = field_html;
    /* look for the next possible substitution */
    while (field_html != NULL && (percent = strchr (t, '%')) != NULL) {

        /* look to see if this is a legitimate candidate for substitution */
        for (i = 1; percent[i] && (i < sizeof (candidate) - 1); i++) {
            if (percent[i] == '%')
                break;
            candidate[i - 1] = percent[i];
        }
        /* terminate candidate */
        candidate[i - 1] = '\0';

        attr = NULL;
        subst = NULL;
        if (percent[i] == '%') {
            /* ok, found a trailing %, so 'candidate' contains a possible
               substitution. look for it in the params */
            va_start (ap, fname);
            while ((attr = va_arg (ap, const char *)) != NULL)
            {
                subst = va_arg (ap, const char *);

                if (!strcmp (attr, candidate)) {
                    /* bingo, matched! */
                    break;
                }
            }
        }

        if (attr != NULL && subst != NULL) {

            if (len - strlen (subst) < 0) {
                pbc_log_activity (p, PBC_LOG_ERROR,
                                  "%s: not enough room in buffer for substitutions",
                                  func);
                goto done;
            }

            /* save what comes after */
            strcpy (buf, percent + i + 1);

            /* piece them back together */
            strcpy (percent, subst);
            strcpy (percent + (int) strlen (subst), buf);

            /* move to the trailing % */
            percent = percent + (int) strlen (subst) - 1;

            len -= strlen (subst);

        }
        /* skip after the % */
        t = percent + 1;
    }

  done:
    if (buf != NULL)
        pbc_free (p, buf);

    pbc_log_activity (p, PBC_LOG_DEBUG_VERBOSE, "%s: goodbye: %s",
                      func, field_html == NULL ? "" : field_html);

    return field_html;

}

#ifdef TEST_NTMPL

#include <stdio.h>

/* the test will substitute 
 *   '%name%' with 'Harry Bovik'
 *   '%userid%' with 'bovik'
 *   '%none%' with NULL
 */
/* pairs of tests/results */
char *test[] = {
    "hello", "hello",
    "hello % hello", "hello % hello",
    "hello %foo% hello", "hello %foo% hello",
    "hello %name% how are you?", "hello Harry Bovik how are you?",
    "hello %name% you are %userid%?", "hello Harry Bovik you are bovik?",
    "%name% aaa", "Harry Bovik aaa",
    "aaa %name%", "aaa Harry Bovik",
    "hello %name hello", "hello %name hello",
    "hello name% hello", "hello name% hello",
    "%foo%name%foo%", "%fooHarry Bovikfoo%",
    "a %none% c", "a %none% c",
    "%name%name%", "Harry Bovikname%",
    "%%name%name%", "%Harry Bovikname%",
    "%none%name%name%", "%noneHarry Bovikname%",
    NULL, NULL,
};

/* needed so we can look at the output */
FILE *htmlout;

int main (int argc, char *argv[])
{
    int i;
    char *x, *y;
    char outbuf[1024];
    FILE *f;
    int err = 0;
    int verbose;
    void *p;

    if (argc > 1 && !strcmp (argv[1], "-v")) {
        verbose++;
    }

    for (i = 0; test[i] != NULL; i += 2) {
        x = test[i];
        y = test[i + 1];

        /* initialize htmlout */
        htmlout = tmpfile ();

        /* write x to a file */
        f = fopen ("/tmp/tmpl_test", "w");
        if (f == NULL) {
            perror ("fopen");
            exit (1);
        }
        fputs (x, f);
        fclose (f);

        /* do the substitution */
        ntmpl_print_html (p, "/tmp", "tmpl_test",
                          "name", "Harry Bovik",
                          "none", NULL, "userid", "bovik", NULL);

        /* read from htmlout */
        rewind (htmlout);
        fgets (outbuf, sizeof (outbuf), htmlout);

        /* compare to y */
        if (strcmp (outbuf, y)) {
            printf ("ERROR\n"
                    "   template '%s'\n"
                    "   wanted   '%s'\n"
                    "   got      '%s'\n", x, y, outbuf);
            err++;
        } else if (verbose) {
            printf ("PASSED '%s'\n", x);
        }

        /* discard htmlout */
        fclose (htmlout);
    }

    if (err || verbose) {
        printf ("%d error%s\n", err, err != 1 ? "s" : "");
    }

    exit (err);
}

#endif
