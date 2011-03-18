################################################################################
#
#   Copyright 1999, University of Washington.  All rights reserved.
#
#    ____        _                     _    _
#   |  _ \ _   _| |__   ___ ___   ___ | | _(_) ___
#   | |_) | | | | '_ \ / __/ _ \ / _ \| |/ / |/ _ \
#   |  __/| |_| | |_) | (_| (_) | (_) |   <| |  __/
#   |_|    \__,_|_.__/ \___\___/ \___/|_|\_\_|\___|
#
#
#   All comments and suggestions to pubcookie@cac.washington.edu
#   More info: http://www.washington.edu/pubcookie/
#   Written by the Pubcookie Team
#
#   This is the pubcookie general Makefile.  It is not for the Apache module
#   or the IIS filter.  See Makefile.tmpl or Makefile.apxs for Apache makefiles
#
################################################################################
#
#   $Id: Makefile.index.cgi,v 1.1 2001-12-14 00:38:58 willey Exp $
#

# your compiler here
CC=gcc
# choose your flags.
# some options are DEBUG
#CFLAGS=-O3 -Wall -I. -I/usr/local/ssl/include/openssl -I/usr/local/ssl/include -I/usr/local/include
CFLAGS=-O3 -Wall -I. -I/usr/include/openssl -I/usr/kerberos/include -I../cgic-1.07

# order is important here
# a blast from the past:
#LDFLAGS=-L/usr/local/ssl/lib/ -L./rsaref -lssl -lcrypto -lRSAglue -lrsaref -lkrb5 -lmgoapi -L/opt/nfast/gcc/lib -lnfstub -ldl
#LDFLAGS=-L/usr/local/ssl/lib/ -lssl -lcrypto -lkrb5 -lmgoapi -L/opt/nfast/gcc/lib -lnfstub -ldl
LDFLAGS=-lldap -llber -lssl -lcrypto -L/usr/kerberos/lib -lkrb5 -ldl

# hopefully you don't have to change anything below here
################################################################################

GEN_HEAD=pbc_config.h pubcookie.h libpubcookie.h pbc_version.h
ALLHEAD=${GEN_HEAD}
SRC=libpubcookie.c mod_pubcookie.c test_local_c_key.c base64.c dtest.c candv.c

BASENAME=pubcookie
#sed -e '/^#define PBC_VERSION/!d' -e '/^#define PBC_VERSION/s/^#define PBC_VERSION "\(a2\)".*$/\1/' pbc_version.h` \

VERSION=a5release5
DIR_NAME=$(BASENAME)-$(VERSION)
TARFILE=$(BASENAME)-$(VERSION).tar

MAKEFILE=Makefile.index.cgi
ALLSRC=pbc_create.c pbc_verify.c libpubcookie.c base64.c securid.c index.cgi_securid.c index.cgi_krb.c index.cgi_ldap.c
ALLHEAD=${GEN_HEAD}

TAR=tar
RM=rm
GZIP=gzip

default:	index.cgi

all:	index.cgi

index.cgi:	index.cgi.o  securid.o libpubcookie.o base64.o index.cgi_securid.o index.cgi_krb.o index.cgi_ldap.o
#		$(CC) ${CFLAGS} -o $@ index.cgi.o index.cgi_securid.o index.cgi_krb.o libpubcookie.o base64.o securid.o /usr/local/lib/libcgic.a /usr/local/mauth/authsrv-x86.o $(LDFLAGS)
		$(CC) ${CFLAGS} -o $@ index.cgi.o index.cgi_securid.o index.cgi_krb.o libpubcookie.o index.cgi_ldap.o base64.o securid.o ../cgic-1.07/libcgic.a  $(LDFLAGS)

uwnetid_stub:	uwnetid_stub.o  uwnetid_stub.o libpubcookie.o base64.o
		$(CC) ${CFLAGS} -o $@ uwnetid_stub.o libpubcookie.o base64.o $(LDFLAGS)

securid_stub:	securid_stub.o  securid.o libpubcookie.o base64.o
		$(CC) ${CFLAGS} -o $@ securid_stub.o libpubcookie.o base64.o securid.o $(LDFLAGS)

h2ph:
	co -l *.ph; \
	h2ph -d . *.h; \
	ci -mauto_update -u *.ph

base64.o: base64.c ${GEN_HEAD} ${MAKEFILE}
candv.o: candv.c ${GEN_HEAD} ${MAKEFILE}
dtest.o: dtest.c ${GEN_HEAD} ${MAKEFILE}
libpubcookie.o: libpubcookie.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}
make_crypted_bit.o: make_crypted_bit.c libpubcookie.h ${GEN_HEAD} ${MAKEFILE}
mkc_key_generic.o: mkc_key_generic.c ${GEN_HEAD} ${MAKEFILE}
mkc_key_local.o: mkc_key_local.c ${GEN_HEAD} ${MAKEFILE}
mod_pubcookie.o: mod_pubcookie.c libpubcookie.o ${MAKEFILE}
#index.cgi.o: index.cgi.c index.cgi.h libpubcookie.o ${MAKEFILE} /usr/local/lib/libcgic.a 
index.cgi.o: index.cgi.c index.cgi.h libpubcookie.o ${MAKEFILE} ../cgic-1.07/libcgic.a 
index.cgi_krb.o: index.cgi_krb.c index.cgi.h libpubcookie.o ${MAKEFILE}
index.cgi_securid.o: index.cgi_securid.c index.cgi.h libpubcookie.o ${MAKEFILE}
index.cgi_ldap.o: index.cgi_ldap.c index.cgi.h libpubcookie.o ${MAKEFILE}
securid.o: securid.c securid.h ${GEN_HEAD} ${MAKEFILE}

clean: 
	$(RM) -f index.cgi.o securid.o core index.cgi libpubcookie.o uwnetid_stub securid_stub base64.o  index.cgi_krb.o  index.cgi_securid.o index.cgi_ldap.o

# to purify candv (then run a.out)
#purify gcc ./candv.o libpubcookie.o base64.o -L./ssleay -lRSAglue -lcrypto ./rsaref/build/rsaref.a

# Added to make the other tools
mkc_key_local:	mkc_key_local.o libpubcookie.o base64.o
		$(CC) ${CFLAGS} -o $@ mkc_key_local.o libpubcookie.o base64.o ../cgic-1.07/libcgic.a  $(LDFLAGS)

mkc_key_generic:	mkc_key_local.o libpubcookie.o base64.o
		$(CC) ${CFLAGS} -o $@ mkc_key_generic.o libpubcookie.o base64.o ../cgic-1.07/libcgic.a  $(LDFLAGS)
