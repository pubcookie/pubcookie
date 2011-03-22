#!/bin/sh
#set -x
SPEC=pubcookie-vitki.spec
[ ! -r $SPEC ] && echo "$SPEC: cannot open" && exit
VER=`grep define $SPEC | grep pubver | head -1 | awk '{print $3}'`
SVNVER=`grep define $SPEC | grep svnid | head -1 | cut -d: -f2 | tr -cd 0-9`
TARBALL="../pubcookie-${VER}.r${SVNVER}.tar.gz"
echo version: $VER $SVNVER
tar -cz -f $TARBALL --exclude .svn --exclude 'nginx*.gz' --exclude `basename $0` *
echo $TARBALL
