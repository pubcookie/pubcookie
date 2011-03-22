#!/bin/sh
set -x
VER=3.3.5
SVNVER=`echo " $Revision$ " | tr -cd 0-9`
tar -cz -f ../pubcookie-${VER}.r${SVNVER}.tar.gz --exclude .svn --exclude 'nginx*.gz' --exclude `basename $0` *
