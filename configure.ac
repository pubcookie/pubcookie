# Process this file with autoconf to produce a configure script.

AC_REVISION($Revision: 1.121 $)

dnl Unfortunately, this must come before the seperate version splits, which are
dnl definted below.  Please set them first, and then set the second argument of
dnl this to:
dnl PBC_VERSION_MAJOR.PBC_VERSION_MINOR.PBC_VERSION_PATCH PBC_VERSION_TYPE
dnl Omit PBC_VERSION_TYPE if the TYPE is "final"
dnl I apologize that this isn't done automatically
AC_INIT(Pubcookie, [3.3.5], pubcookie-dev@u.washington.edu)

AC_CONFIG_SRCDIR([src/libpubcookie.c])
AC_CONFIG_HEADER([src/config.h])
AC_LANG(C)

dnl The version number, to be assembled
dnl If any of these change, reset PBC_WIN_BUILD_NUMBER
PBC_VERSION_MAJOR=3
PBC_VERSION_MINOR=3
PBC_VERSION_PATCH=5

dnl The version "type".
dnl If this is "final", it is not included in the version string.
dnl Otherwise it is.  For the National Edition, this will be "pre-beta" or
dnl "beta".  For campus editions, this will be unique for the campus, we
dnl imagine.
dnl When this changes, don't forget to increment PBC_WIN_BUILD_NUMBER
PBC_VERSION_TYPE=final

dnl The Windows "Build Number" ..  Unfortunately the Windows build process can't
dnl use the text version (betaX, pre-betaX), so this is just incremented every
dnl time the PBC_VERSION_TYPE changes, and reset to 0 when any part of the
dnl version number proper (MAJOR, MINOR, PATCH) changes.
PBC_WIN_BUILD_NUMBER=0

AC_SUBST(PBC_VERSION_MAJOR, "$PBC_VERSION_MAJOR")
AC_SUBST(PBC_VERSION_MINOR, "$PBC_VERSION_MINOR")
AC_SUBST(PBC_VERSION_PATCH, "$PBC_VERSION_PATCH")
AC_SUBST(PBC_VERSION_TYPE, "$PBC_VERSION_TYPE") 
AC_SUBST(PBC_WIN_BUILD_NUMBER, "$PBC_WIN_BUILD_NUMBER") 

# Set default prefix to /usr/local/pubcookie
AC_PREFIX_DEFAULT(/usr/local/pubcookie)

AC_MSG_NOTICE([Configuring for $PACKAGE_STRING])

if test "x$enable_apache" = "x"; then
    enable_apache=yes
fi

# Before any tests, check to see if we are doing anything..

AC_MSG_CHECKING([if I should build the apache module])
AC_ARG_ENABLE(apache,
              AC_HELP_STRING([--enable-apache],
                             [Enable building the apache module (default: on)]),
              [ case "${enableval}" in
                yes)
                   AC_MSG_RESULT(yes)
                   AC_SUBST(apache_module, "apache_module")
                   AC_SUBST(install_apache, "install-apache")
                   ;;
                *)
                   AC_MSG_RESULT(no)
                   enable_apache=no
                   AC_SUBST(MAKE_APACHE, "@echo Skipping ")
                   AC_SUBST(IF_MOD, [#])
                   AC_SUBST(no_module, "no_module")
                   ;;
               esac ])


if test "x$enable_login" = "x"; then
    enable_login=no
fi

AC_MSG_CHECKING([if I should build the login cgi])
AC_ARG_ENABLE(login,
              AC_HELP_STRING([--enable-login],
                             [Enable building the login cgi (default: off)]),
              [ case "${enableval}" in
                yes)
                   AC_MSG_RESULT(yes)
                   enable_login=yes
                   AC_SUBST(login_server, "login_server")
                   AC_SUBST(install_login, "install-login")
                   ;;
                *)
                   AC_MSG_RESULT(no)
                   AC_SUBST(MAKE_LOGIN, "@echo Skipping ")
                   AC_SUBST(no_login, "no_login")
                   ;;
               esac ])

if test "$enable_login" = "no" && \
   test "$enable_apache" = "no"; then
    AC_MSG_ERROR([the login server or apache module must be enabled], 1)
fi

# Checks for programs.
AC_PROG_CC

AC_CANONICAL_HOST
AC_AIX

AIX_LDFLAGS=
need_slib_clean=
case $host in

    *aix*)
#      AIX needs additional loader help

      aix_system=yes
      AIX_LDFLAGS="-Wl,-bE:mod_pubcookie.exp -Wl,-bnoentry -Wl,-lcrypto"
      need_slib_clean="need_slib_clean"
    ;;

    *sun*)
# Check to see if this is the Sun Workshop compiler.

if test "$GCC" != "yes"; then

AC_MSG_CHECKING([for Sun Workshop Compiler])
AC_TRY_RUN( [ 
    #include <stdlib.h>

    #ifndef __SUNPRO_C
    # define __SUNPRO_C 0
    #endif

    int main() {
        exit( __SUNPRO_C == 0 );
    }
    ],
    [ AC_MSG_RESULT([yes])
    AC_DEFINE( SUN_WORKSHOP, 1,
    [Define to 1 if the Compiler is Sun Workshop] )
    SUN_WORKSHOP=1
    ],
    [ AC_MSG_RESULT([no])
    ]
)

fi
    ;;
esac

AC_SUBST(AIX_LDFLAGS, "$AIX_LDFLAGS")
AC_SUBST(need_slib_clean, "$need_slib_clean")

# Fix problems where we're using gcc without gnu ld
# (Code by Bradford L. Barrett at University of Florida)
if test "$GCC" = "yes"; then
    GCC_LIB=`gcc -print-libgcc-file-name`
    LIBS="$LIBS -lgcc";
    LDFLAGS="$LDFLAGS -L`dirname $GCC_LIB`"
fi

AC_PROG_CC_STDC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_AWK

# Utilities
AC_PATH_PROG(AR, ar, ar)
AC_PATH_PROG(RM, rm, rm)
AC_PATH_PROG(CP, cp, cp)
AC_PATH_PROG(SED, sed, sed)
AC_PATH_PROG(TAR, tar, tar)
AC_PATH_PROG(GZIP, gzip, gzip)
AC_PATH_PROG(MKDIR, mkdir, mkdir)
AC_PATH_PROG(MV, mv, mv)
AC_PATH_PROG(CHMOD, chmod, chmod)
AC_PATH_PROG(TEST, test, test)
AC_PATH_PROG(MAKE, make)
AC_PATH_PROG(GMAKE, gmake)
AC_PATH_PROG(PWD, pwd)
AC_PATH_PROG(LS, ls)
AC_PATH_PROG(RANLIB, ranlib)

gnu_make=no

if test "x$MAKE" != "x"; then
    AC_MSG_CHECKING( [if $MAKE is GNU make] )
    $MAKE --version > /dev/null 2>&1
    if test "$?" != "0"; then
        AC_MSG_RESULT([no])
        gnu_make=no
    else
        AC_MSG_RESULT([yes])
        gnu_make=yes
    fi
fi


# Are we building a module?  which type?  dso or static

if test "$enable_apache" = "yes"; then

# look for the static module build
apache_src=
AC_MSG_CHECKING(for apache src)
AC_ARG_WITH(apache-src,
[  --with-apache-src=DIR   Build static Apache module.  DIR is the path
                           to the top-level Apache source directory.],
[
   if test "$withval" = "yes"; then
      AC_MSG_ERROR(You need to specify a directory with --with-apache-src)
   fi
   if test -d $withval/modules && \
      test -f $withval/include/httpd.h; then  # apache2
         APACHE_VERSION=2
         apache_src=$withval
         apache_target=$withval/modules/pubcookie
         apache_src_ref=$PWD
#        I can't get it to work on apache2
         AC_MSG_ERROR(Cannot build static Apache 2 module)
   fi
   if test -d $withval/src/modules && \
      test -f $withval/src/include/httpd.h; then
         APACHE_VERSION=1_3
         apache_src=$withval
         apache_target=$withval/src/modules/pubcookie
         apache_src_ref=$PWD
   fi
   if test "x$apache_src" = "x"; then
         AC_MSG_ERROR(Cannot find the apache source)
   fi
   APXS=
   AC_SUBST(apache_module, "")
   AC_SUBST(install_apache, "")
   AC_MSG_RESULT($withval)

],[
    AC_MSG_RESULT(no)
])


AC_ARG_WITH(apxs,
    AC_HELP_STRING([--with-apxs=PATH],[/path/to/apxs]),
[ case "$withval" in
   no)
      OLDPATH=$PATH
      PATH="/usr/local/apache/bin:/usr/local/apache2/bin:/usr/www/bin:/usr/sbin:$PATH"
      AC_PATH_PROG(APXS, apxs)
      PATH=$OLDPATH
      ;;
    *)
      OLDPATH=$PATH
      if test -d "$withval"; then
          PATH="$withval:$PATH"
          AC_PATH_PROG(APXS, apxs)
      else 
          PATH=`dirname $withval`":$PATH"
          PROG=`basename $withval`
          AC_PATH_PROG(APXS, $PROG)
      fi
      PATH=$OLDPATH
      ;;
  esac ],[
 if test "x$apache_src" = "x"; then
     PATH="/usr/local/apache/bin:/usr/local/apache2/bin:/usr/www/bin:/usr/sbin:$PATH"
     AC_PATH_PROG(APXS, apxs)
 fi
])

if ! test "x$APXS" = "x"; then
  AC_MSG_CHECKING( [if $APXS works] )
  $APXS -q CFLAGS >/dev/null 2>&1
  if test "$?" != "0"; then
      AC_MSG_RESULT([no])
      AC_MSG_RESULT([Here is the output from $APXS:])
      $APXS -q CFLAGS
      AC_MSG_ERROR([Please correct this error and try again.])
  fi

  AC_MSG_RESULT([yes])
  AC_SUBST(APACHE_PREFIX, `$APXS -q PREFIX`)

 AC_MSG_CHECKING([Apache version])
 APACHE_VERSION=
 # maybe can just ask the server
 httpd="`$APXS -q SBINDIR`/`$APXS -q TARGET`"
 if test "x$httpd" != "x"; then
     v=`$httpd -v|$SED -n -e 's/.*Apache\/\.*//p'`
     case $v in
       1.3.*) APACHE_VERSION="1_3"
              ;;
       2.*)   APACHE_VERSION="2"
              ;;
     esac
 fi
 if test "x$APACHE_VERSION" = "x"; then
   OCFLAGS=$CFLAGS
   APXS_INC=`$APXS -q INCLUDEDIR`
   CFLAGS="$CFLAGS -I$APXS_INC"
   AC_TRY_RUN( [ 
     /* Look for 1.x version */
     #include <stdlib.h>
     #include <httpd.h>
 
     int main() {
        exit( ( APACHE_RELEASE > 10300000 &&
                APACHE_RELEASE < 10400000 ) != 1 );
     }
     ],
       [APACHE_VERSION="1_3"]
     [ 
     ]
   )
   if test "x$APACHE_VERSION" = "x"; then
     AC_TRY_RUN( [ 
       /* Look for 2.x version */
       #include <stdlib.h>
       #include <httpd.h>

       int main() {
          exit( *AP_SERVER_MAJORVERSION!='2');
       }
       ],
         [APACHE_VERSION="2"]
       [ 
         AC_MSG_ERROR([Apache version 1.3.x or 2.x is required!])
       ]
     )
   fi
   CFLAGS=$OCFLAGS
 fi
 AC_MSG_RESULT([$APACHE_VERSION])
 AC_SUBST(APACHE_VERSION, $APACHE_VERSION)


 apache_target=module
 apache_src_ref=".."

fi # if apxs


# if module was wanted make sure one will be built

if test "x$APXS" = "x" && \
   test "x$apache_src" = "x"; then
    AC_MSG_ERROR([either apxs or the apache source must be specified], 1)
fi

fi # if apache module


# Checks for libraries.
AC_CHECK_LIB(socket,socket)
AC_CHECK_LIB(nsl,gethostent)
AC_CHECK_LIB(dl,dlopen)

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h shadow.h stdlib.h \
                  string.h strings.h sys/param.h sys/socket.h sys/time.h \
                  unistd.h getopt.h ctype.h stdarg.h stdio.h varargs.h\
                  sys/utsname.h time.h pwd.h sys/types.h assert.h sys/stat.h \
                  sysexits.h mango/messages.h mango/mgoapi2.h mango/sidapi.h \
		  sys/resource.h fnmatch.h \
                  errno.h ])

AC_CHECK_HEADER([syslog.h], 
    AC_DEFINE(HAVE_SYSLOG_H, 1,
              [Define to 1 if you have the <syslog.h> header file.])
    AC_MSG_CHECKING([for LOG_AUTHPRIV in syslog.h])
    AC_TRY_LINK([
                 #include <stdio.h>
                 #include <syslog.h>
                ], [ printf( "%d", LOG_AUTHPRIV ); ],
                   [AC_MSG_RESULT(found) ],
                   [AC_MSG_RESULT(not found)
                    AC_DEFINE(NEED_LOG_AUTHPRIV, 1,
                              [Define to LOG_AUTH if your system doesn't define LOG_AUTHPRIV])])
    AC_MSG_CHECKING([for LOG_MAKEPRI in syslog.h])
    AC_TRY_LINK([
                 #include <stdio.h>
                 #include <syslog.h>
                ], [ printf( "%d", LOG_MAKEPRI(1,2) ); ],
                   [AC_MSG_RESULT(found) ],
                   [AC_MSG_RESULT(not found)
                    AC_DEFINE(NEED_LOG_MAKEPRI, 1,
                              [Define to 1 if your system doesn't define LOG_MAKEPRI])])
    AC_MSG_CHECKING([for LOG_FAC in syslog.h])
    AC_TRY_LINK([
                 #include <stdio.h>
                 #include <syslog.h>
                ], [ printf( "%d", LOG_FAC(1) ); ],
                   [AC_MSG_RESULT(found) ],
                   [AC_MSG_RESULT(not found)
                    AC_DEFINE(NEED_LOG_FAC, 1,
                              [Define to 1 if your system doesn't define LOG_FAC])])
    AC_MSG_CHECKING([for facilitynames in syslog.h])
    AC_TRY_LINK([
                 #include <stdio.h>
                 #define SYSLOG_NAMES 1
                 #include <syslog.h>
                ], 
                [ printf( "%p", facilitynames ); ],
                   [AC_MSG_RESULT(found) ],
                   [AC_MSG_RESULT(not found)
                    AC_DEFINE(NEED_SYSLOG_NAMES, 1,
                              [Define to 1 if your system doesn't have SYSLOG_NAMES])])
    )

AC_MSG_CHECKING([audit log facility])
AC_ARG_WITH(audit-log,
            AC_HELP_STRING([--with-audit-log=facility],
                           [syslog() facility of audit messages
                            (default: LOG_AUTHPRIV)]),
            AC_MSG_RESULT($withval)
            [AC_DEFINE_UNQUOTED(PBC_LOG_AUDIT_FACILITY, $withval,
                       [Define to the AUDIT syslog() facility])],
            AC_MSG_RESULT(LOG_AUTHPRIV)
            [AC_DEFINE(PBC_LOG_AUDIT_FACILITY, LOG_AUTHPRIV,
                       [Define to the AUDIT syslog() facility])],
                       )

AC_MSG_CHECKING([general log facility])
AC_ARG_WITH(general-log,
            AC_HELP_STRING([--with-general-log=facility],
                           [syslog() facility of general messages
                            (default: LOG_AUTHPRIV)]),
            AC_MSG_RESULT($withval)
            [AC_DEFINE_UNQUOTED(PBC_LOG_GENERAL_FACILITY, $withval,
                       [Define to the GENERAL syslog() facility])],
            AC_MSG_RESULT(LOG_AUTHPRIV)
            [AC_DEFINE(PBC_LOG_GENERAL_FACILITY, LOG_AUTHPRIV,
                       [Define to the GENERAL syslog() facility])],
                       )


# OpenSSL Fun

ssl_include_path=
ssl_lib_path=
ssl_openssl=openssl

AC_ARG_WITH(ssl,
    AC_HELP_STRING([--with-ssl=PATH], [Openssl lib/include root]),
[ case "$withval" in
   no)
     ;;
   *)
     ssl_include_path="-I$withval/include"
     ssl_lib_path="-L$withval/lib"
     ssl_openssl="$withval/bin/openssl"
     ;;
  esac ])

AC_ARG_WITH(ssl-dir,
    AC_HELP_STRING([--with-ssl-dir=PATH], [Openssl lib/include root (deprecated)]),
[ case "$withval" in
   no)
     ;;
   *)
     ssl_include_path="-I$withval/include"
     ssl_lib_path="-L$withval/lib"
     ssl_bin_path="$withval/bin/openssl"
     ;;
  esac ])

AC_ARG_WITH(ssl-inc-dir,
    AC_HELP_STRING([--with-ssl-inc-dir=PATH], [Openssl include path]),
[ case "$withval" in
   no)
     ;;
   *)
     ssl_include_path="-I$withval"
     ;;
  esac ])

AC_ARG_WITH(ssl-lib-dir,
    AC_HELP_STRING([--with-ssl-lib-dir=PATH], [Openssl lib path]),
[ case "$withval" in
   no)
     ;;
   *)
     ssl_lib_path="-L$withval"
     ;;
  esac ])

if test "x$ssl_include_path" = "x" -a -d "/usr/local/ssl/include"; then
    ssl_include_path="-I/usr/local/ssl/include"
fi

if test "x$ssl_include_path" = "x" -a -d "/usr/include/openssl"; then
    ssl_include_path="-I/usr/include/openssl"
fi

if test "x$ssl_lib_path" = "x" -a -d "/usr/local/ssl/lib"; then
    ssl_lib_path="-L/usr/local/ssl/lib"
fi

if test "x$ssl_include_path" != "x"; then
    CPPFLAGS="$CPPFLAGS $ssl_include_path"
fi

if test "x$ssl_lib_path" != "x"; then
    LDFLAGS="$LDFLAGS $ssl_lib_path"
fi

# Look for openssl krb5 includes

AC_MSG_CHECKING([for openssl krb5 includes])
vfi=
vfa=
for vf in `$ssl_openssl version -f`
do
    case $vf in
      -I*) vfi="$vfi $vf"
           ;;
    esac
    vfa="yes"
done
if test "x$vfi" != "x" ; then
    CPPFLAGS="$CPPFLAGS $vfi"
    AC_MSG_RESULT([$vfi])
else
    if test "x$vfa" != "x"; then
       AC_MSG_RESULT([none])
    else
       AC_MSG_WARN([could not run openssl to find includes])
    fi
fi


AC_CHECK_LIB(crypto,ERR_load_ASN1_strings,,
             AC_MSG_ERROR([libcrypto is required.]))
AC_CHECK_LIB(ssl,SSL_library_init,,
             AC_MSG_ERROR([libssl is required.]))
AC_CHECK_HEADERS([openssl/ssl.h])

if test "$ac_cv_header_openssl_ssl_h" = "yes"; then
     AC_CHECK_HEADERS([openssl/crypto.h openssl/x509.h openssl/pem.h openssl/err.h openssl/rand.h openssl/des.h], 
	[AC_DEFINE(OPENSSL_IN_DIR, 1, 
		 [Define to 1 if openssl is in include/openssl])],
		[AC_MSG_ERROR([can't find required SSL header files (may need --with-ssl-inc-dir)])])
else
     AC_CHECK_HEADERS([crypto.h x509.h pem.h err.h rand.h des.h], 
	[AC_DEFINE(OPENSSL_NOT_IN_DIR, 1, 
		 [Define to 1 if openssl is directly in include path.])],
		[AC_MSG_ERROR([can't find required SSL header files (may need --with-ssl-inc-dir)])])
fi

# default encryption

AC_ARG_ENABLE(default-des,
    AC_HELP_STRING([--enable-default-des],[Use DES encryption]),
[ case "${enableval}" in
   yes)
    AC_DEFINE(PBC_USE_DES_CRYPT, 1, [Define to 1 to revert to DES])
    ;;
  esac ])


# Login Server specific stuff.

OLDLIBS=$LIBS


if test "$enable_login" = yes; then

  OLDCPPFLAGS=$CPPFLAGS
  CPPFLAGS="$CPPFLAGS -I$srcdir/cgic"
  AC_CHECK_HEADERS([cgic.h])
  CPPFLAGS=$OLDCPPFLAGS
  AC_SUBST(CGIC_INC, "-I$srcdir/cgic")
  AC_SUBST(CGIC_LIB, "-L./cgic -lcgic")

AC_ARG_ENABLE(krb5,
    AC_HELP_STRING([--enable-krb5],[Enable Kerberos 5 Verifier]),
[ case "${enableval}" in
   yes)
    AC_DEFINE(ENABLE_KRB5, 1, [Define to 1 to support krb5 verifiers])
    ;;
  esac ])

if test "$enable_krb5" = "yes"; then

# Find the KRB5 Libraries!

# RetHat seems to put KRB5 in /usr/kerberos

if test -d "/usr/kerberos/include"; then
    CPPFLAGS="$CPPFLAGS -I/usr/kerberos/include"
fi

if test -d "/usr/kerberos/lib"; then
    LDFLAGS="$LDFLAGS -L/usr/kerberos/lib"
fi

AC_ARG_WITH(krb5-dir,
    AC_HELP_STRING([--with-krb5-dir=PATH], [KRB5 lib/include root]),
[ case "$withval" in
   no)
     ;;
   *)
     CPPFLAGS="$CPPFLAGS -I$withval/include"
     LDFLAGS="$LDFLAGS -L$withval/lib"
     ;;
  esac ])

AC_ARG_WITH(krb5-inc-dir,
    AC_HELP_STRING([--with-krb5-inc-dir=PATH], [KRB5 include path]),
[ case "$withval" in
   no)
     ;;
   *)
     CPPFLAGS="$CPPFLAGS -I$withval"
     ;;
  esac ])

AC_ARG_WITH(krb5-lib-dir,
    AC_HELP_STRING([--with-krb5-lib-dir=PATH], [KRB5 lib path]),
[ case "$withval" in
   no)
     ;;
   *)
     LDFLAGS="$LDFLAGS -L$withval"
     ;;
  esac ])

    AC_CHECK_HEADERS([com_err.h krb5.h])
    AC_CHECK_LIB(krb5, krb5_init_context)

# check to see if we're using Heimdal Kerberos
# thanks to Leif Johansson <leifj@it.su.se>
# and Love Hörnquist Åstrand <lha@it.su.se>
AC_CHECK_TYPE([krb5_addresses], 
  AC_DEFINE(KRB5_HEIMDAL, 1, [set to 1 if using Heimdal Kerberos]), 
  ,
  [#include <krb5.h>])

fi

AC_ARG_ENABLE(ldap,
    AC_HELP_STRING([--enable-ldap],[Enable LDAP Verifier]),
[ case "${enableval}" in
   yes)
    AC_DEFINE(ENABLE_LDAP, 1, [Define to 1 to support LDAP verifiers])
    ;;
  esac ])

# This is OpenLDAP Specific.  If I was cool, I would detect OpenLDAP vs the
# Netscape LDAP SDK, but I'm not that cool.
  
if test "$enable_ldap" = "yes"; then

# Find the LDAP Libraries!

AC_ARG_WITH(ldap-dir,
    AC_HELP_STRING([--with-ldap-dir=PATH], [LDAP lib/include root]),
[ case "$withval" in
   no)
     ;;
   *)
     CPPFLAGS="$CPPFLAGS -I$withval/include"
     LDFLAGS="$LDFLAGS -L$withval/lib"
     ;;
  esac ])

AC_ARG_WITH(ldap-inc-dir,
    AC_HELP_STRING([--with-ldap-inc-dir=PATH], [LDAP include path]),
[ case "$withval" in
   no)
     ;;
   *)
     CPPFLAGS="$CPPFLAGS -I$withval"
     ;;
  esac ])

AC_ARG_WITH(ldap-lib-dir,
    AC_HELP_STRING([--with-ldap-lib-dir=PATH], [LDAP lib path]),
[ case "$withval" in
   no)
     ;;
   *)
     LDFLAGS="$LDFLAGS -L$withval"
     ;;
  esac ])

    AC_CHECK_HEADERS([lber.h])
    AC_CHECK_HEADERS([ldap.h],,,[#include <lber.h>])

    AC_MSG_CHECKING([if LDAP API is OpenLDAP])
    AC_TRY_RUN( [ 
    #include <ldap.h>

    int main() {
        exit( strcmp(LDAP_VENDOR_NAME, "OpenLDAP") );
    }
                ],
                [ AC_MSG_RESULT([yes])
                  AC_DEFINE( LDAP_OPENLDAP, 1,
                             [Define to 1 if the LDAP library is OpenLDAP] )
                  LDAP_OPENLDAP=1
                ],
                [ AC_MSG_RESULT([no])
                  AC_MSG_WARN( "Warning: No OpenLDAP API found." ) 
                  LDAP_OPENLDAP=0
                ],
                AC_MSG_WARN( "Cross-Compiling not supported."  ) )

    if test "$LDAP_OPENLDAP" = "1"; then
        AC_CHECK_LIB(lber, ber_init)
        AC_CHECK_LIB(ldap, ldap_init)
    else

        AC_MSG_CHECKING([if LDAP API is Sun/Netscape/iPlanet])
        AC_TRY_RUN( [ 
        #include <lber.h>
        #include <ldap.h>

        int main() {

        if ( (strcmp(LDAP_VENDOR_NAME, "Sun Microsystems Inc.") == 0)
            && LDAP_VENDOR_VERSION >= 500 )
            exit(0);

            exit(2);
        }
                    ],
                    [ AC_MSG_RESULT([yes])
                    AC_MSG_WARN( "Warning: Non-OpenLDAP API found.  YMMV." ) 
                    AC_DEFINE( LDAP_SUN, 1,
                    [Define to 1 if the LDAP library is Sun/Netscape/iPlanet] )
                    LDAP_SUN=1
                    ],
                    [ AC_MSG_RESULT([no])
                    LDAP_SUN=0
                    ],
                    AC_MSG_WARN( "Cross-Compiling not supported."  ) )


        if test "$LDAP_SUN" = "1"; then
            AC_CHECK_HEADERS([ldap_ssl.h ldappr.h],,,
            [ #include <lber.h>
              #include <ldap.h>
            ])
            AC_CHECK_LIB(ldap50, ldap_init)
            AC_CHECK_LIB(ssl3, SSL_AuthCertificate)
            AC_CHECK_LIB(nss3, CERT_VerifyCert)
            AC_CHECK_LIB(prldap50, prldap_init)
            AC_CHECK_LIB(ssldap50, ldapssl_init)

            if test "x$with_cert_db_path" = "x"; then
                with_cert_db_path=no
            fi

            AC_MSG_CHECKING([for cert7.db and key3.db path])
            AC_ARG_WITH(cert-db-path,
                        AC_HELP_STRING([--with-cert-db-path=PATH],
                        [cert7 and key3 db path (from a Netscape installation)]),
            [ case "$withval" in
            no)
            AC_MSG_ERROR([with-cert-db-path must be specified with Sun SDK.], 1)
            ;;
            *)
            AC_SUBST(CERT_DB_PATH, "$withval")
            AC_MSG_RESULT($withval)
            ;;
        esac ])
    fi
fi

    # For now, Blow up if we aren't using OpenLDAP.

fi

AC_ARG_ENABLE(shadow,
    AC_HELP_STRING([--enable-shadow],[Enable Shadow Verifier ]),
[ case "${enableval}" in
   yes)
    AC_DEFINE(ENABLE_SHADOW, 1, [Define to 1 to support shadow verifiers])
    ;;
  esac ])

if test "$enable_shadow" = "yes"; then
    AC_CHECK_HEADERS([shadow.h crypt.h])
    AC_CHECK_LIB(crypt, crypt)
fi

AC_ARG_ENABLE(uwsecurid,
    AC_HELP_STRING([--enable-uwsecurid],[Enable U. Wash. SecurID Verifier ]),
[ case "${enableval}" in
   yes)
    AC_DEFINE(ENABLE_UWSECURID, 1, [Define to 1 to support U. Wash. SecurID verifiers])
    ;;
  esac ])

if test "$enable_uwsecurid" = "yes"; then

# Find the mango Libraries!

if test -d "/usr/local/include"; then
    CPPFLAGS="$CPPFLAGS -I/usr/local/include"
fi

if test -d "/usr/local/lib"; then
    LDFLAGS="$LDFLAGS -L/usr/local/lib"
fi

AC_ARG_WITH(mango-inc-dir,
    AC_HELP_STRING([--with-mango-inc-dir=PATH], [U WASH ONLY: Mango include path]),
[ case "$withval" in
   no)
     ;;
   *)
     CPPFLAGS="$CPPFLAGS -I$withval"
     ;;
  esac ])

AC_ARG_WITH(mango-lib-dir,
    AC_HELP_STRING([--with-mango-lib-dir=PATH], [U WASH ONLY: Mango lib path]),
[ case "$withval" in
   no)
     ;;
   *)
     LDFLAGS="$LDFLAGS -L$withval"
     ;;
  esac ])

    AC_CHECK_HEADERS([mango/mgoapi2.h mango/sidapi.h])
    LIBS="$LIBS -lmgoapi2 -lsidapi";
    AC_CHECK_LIB(mgoapi2, MGOinitialize)
fi

AC_ARG_ENABLE(dmalloc,
    AC_HELP_STRING([--enable-dmalloc],[Enable dmalloc debugging]),
[ case "${enableval}" in
   yes)
    AC_DEFINE(ENABLE_DMALLOC, 1, [Define to 1 to enable dmalloc debugging])
    ;;
  esac ])

if test "$enable_dmalloc" = "yes"; then
    AC_CHECK_HEADERS([dmalloc.h],,,[ ])
    AC_CHECK_LIB(dmalloc, dmalloc_shutdown)


    if test "x$SUN_WORKSHOP" != "x"; then
        # Sun Workshop Compiler is annoying!
        OLDCC=$CC
        CC="$CC -Xc"
        OLDCPPFLAGS=$CPPFLAGS
        CPPFLAGS="$CPPFLAGS -D__EXTENSIONS__"
        AC_TRY_COMPILE( [], [], [], [
            CC=$OLDCC
            CPPFLAGS=$CPPFLAGS
            ]
        )
    fi

fi

AC_ARG_WITH(fcgi,
    AC_HELP_STRING([--with-fcgi=PATH],[Build for fastcgi ]),
[ case "${withval}" in
   no)
    ;;
   *)
    CPPFLAGS="$CPPFLAGS -I$withval/include -DWITH_FCGI"
    LIBS="$LIBS -lfcgi"
    LDFLAGS="$LDFLAGS -L$withval/lib"
    ;;
  esac ])

if test "$enable_shadow" = "yes"; then
    AC_CHECK_HEADERS([shadow.h crypt.h])
    AC_CHECK_LIB(crypt, crypt)
fi

# See if we are to enable the unsafe relay
AC_ARG_ENABLE(unsafe-relay,
    AC_HELP_STRING([--enable-unsafe-relay],[Enable unsafe relay. (Compatibility)]),
[ case "${enableval}" in
   yes)
    CFLAGS="$CFLAGS -DALLOW_RELAY"
    ;;
  esac ])

fi # End of enabling the login server.


LOGINLIBS=$LIBS

LIBS=$OLDLIBS

AC_SUBST(LOGINLIBS, $LOGINLIBS)

# End of Login-server specific stuff, hopefully.



# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_FORK
# AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([bzero dup2 gethostbyname gethostname getspnam gettimeofday \
                memset socket strcasecmp strchr strdup strerror strncasecmp \
                strstr uname strlcpy strlcat bcopy])

AC_CHECK_FUNCS( [snprintf vsnprintf],, [
SNPRINTF_O="\$(builddir)/src/snprintf.o"
SNPRINTF_C="\$(srcdir)/src/snprintf.c"
] )

AC_SUBST( SNPRINTF_0, $SNPRINTF_O )
AC_SUBST( SNPRINTF_C, $SNPRINTF_C )

AM_MAINTAINER_MODE

AC_CONFIG_FILES([Makefile src/pbc_path.h src/pbc_version.h cgic/Makefile
                 src/Win32/PubCookieFilter.h src/Win32/PubCookieFilter.rc])
AC_CONFIG_FILES([stamp-h], [echo timestamp > stamp-h])



# setup module directory if we're building the module 
if test "$enable_apache" = "yes";  then

   echo "Copying apache module sources to $apache_target."

   if ! test -d $apache_target; then
      mkdir $apache_target
   fi
   if ! test -d $apache_target; then
      AC_MSG_ERROR([Could not create the module directory])
   fi

# get a list of components from the modules.mk file
pc=
for f in `$SED -n -e '
/\\\\$/{ 
  s/\\\\$//
  H
  d
} 
H
g
/^\nMOD_PUBCOOKIE/{
 s/\n//g
 s/.*=//
 p
}
s/.*//
h
' modules.mk `
do
#  echo "  $f"
  pc="$pc $f"
done
# get a list of includes from the src dir
# pch="config.h pbc_path.h"  # these built by configure
pch=
cd src
for f in `$LS *.h *.h.in | $SED 's/.in$//'`
do
#  echo "   $f"
  pch="$pch $f"
done
cd ..

# cleanup then setup module build directory
$RM -f $apache_target/.libs/*
$RM -f $apache_target/*.*
for f in $pc
do
# echo "  $f"
  ln -sf $apache_src_ref/src/${f}.c $apache_target
done
for f in $pch
do
# echo "  $f"
  ln -sf $apache_src_ref/src/$f $apache_target
done

obj=
for p in $pc
do
  obj="$obj $p.o"
done
src=

# copy the appropriate makefile

# apxs module
if test "x$APXS" != "x";  then

  touch $apache_target/.deps

  if test "$APACHE_VERSION" = "2"; then
     AC_SUBST(APACHE_INSTALLBUILDDIR, `$APXS -q exp_installbuilddir`)
     AC_SUBST(APACHE_MOD_EXT, "la")
     AC_SUBST(MOD_LIST, $MOD_LIST )
     cp Makefile.in.ap2 $apache_target/Makefile.in
     ln -sf $apache_src_ref/modules.mk $apache_target
  fi

  if test "$APACHE_VERSION" = "1_3"; then

    AC_SUBST(APACHE_MOD_EXT, "so")
    AC_SUBST( MOD_OBJ, $obj )
    AC_SUBST( MOD_HDR, $pch )
     
    cp Makefile.in.ap1 $apache_target/Makefile.in
    ln -sf $apache_src_ref/mod_pubcookie.exp $apache_target

  fi # apache 1.3

AC_CONFIG_FILES([$apache_target/Makefile])

fi # apxs module

# apache 1.3 static build
if test "x$apache_src" != "x"; then
cat > $apache_target/Makefile.tmpl.in << END
# Makefile.tmpl: generated by configure 
#
END
   cat Makefile.tmpl.in >> $apache_target/Makefile.tmpl.in
   AC_SUBST( MOD_OBJ, $obj )
   AC_SUBST( MOD_HDR, $pch )
   AC_CONFIG_FILES([$apache_target/Makefile.tmpl])

   cat > $apache_target/Makefile.libdir <<'END'
# dummy
END

fi # apache 1.3 static

fi # setup module directory

AC_OUTPUT

# finish with advisories

# gmake
if test "$gnu_make" = "no"; then
   echo ""
   echo "Note.  Your default make program is not GNU make."
   echo "       Your builds will be more efficient"
   echo "       if you can use gmake instead of make."
   echo ""
fi

# config of apache src
if test "x$apache_src" != "x"; then
   echo ""
   echo "Reminder: You must reconfigure apache with "
   echo "           --activate-module=src/modules/pubcookie/libpubcookie.a"
   echo ""
fi

