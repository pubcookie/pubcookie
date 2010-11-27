
PBC_VERSION = 3.3.4a
NGX_VERSION = 0.8.52
MOD_VERSION = 0.1
VENDOR = vitki
VERSION = $(NGX_VERSION)-$(PBC_VERSION)-$(MOD_VERSION)-$(VENDOR)
TARBALL = nginx_http_pubcookie-$(VERSION).tar.gz
SOURCES = \
	ngx_http_pubcookie.h \
	ngx_http_pubcookie_library.c \
	ngx_http_pubcookie_module.c

dist: CHANGES README LICENSE config $(SOURCES)
	cd ../.. && f=`readlink -f ../$(TARBALL)` && tar czf $$f --exclude .svn * && echo $$f

