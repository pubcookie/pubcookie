cgidir=$(install_dir)
tpldir=$(install_dir)/templates
cgi_PROGRAMS=index.cgi
tpl_DATA=tologin.tpl toapp.tpl

DESTDIR=@prefix@
EXTRA_DIST= tologin.tpl toapp.tpl hello.tpl README

INCLUDES= -I@pubcookie_src@ -I@webtpl_dir@/include

index_cgi_LDADD=\
  @pubcookie_src@/pbc_configure.o \
  @pubcookie_src@/pbc_logging.o \
  @pubcookie_src@/pbc_myconfig.o \
  @pubcookie_src@/security_legacy.o \
  @pubcookie_src@/strlcpy.o \
  @pubcookie_src@/libpubcookie.o \
  @pubcookie_src@/base64.o \
  -L@webtpl_dir@/lib -lwebtpl -lssl -lcrypto

