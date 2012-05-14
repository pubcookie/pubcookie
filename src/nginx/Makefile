
PBC_VERSION = 3.3.5
NGX_VERSION = 1.2.0
MOD_VERSION = 0.6
VENDOR = vitki
VERSION = $(NGX_VERSION)-$(PBC_VERSION)-$(MOD_VERSION)-$(VENDOR)
TARBALL = nginx_http_pubcookie-$(VERSION).tar.gz
SOURCES = \
	ngx_http_pubcookie.h \
	ngx_http_pubcookie_library.c \
	ngx_http_pubcookie_module.c

dist: CHANGES README LICENSE config $(SOURCES)
	cd ../.. && SRCDIR=$$PWD && \
	cd .. && TARDIR=$$PWD && \
	cd $$SRCDIR && \
	tar -cpz -f $$TARDIR/$(TARBALL) --exclude .svn --exclude 'nginx*.gz' * && \
	echo $$TARDIR/$(TARBALL)

