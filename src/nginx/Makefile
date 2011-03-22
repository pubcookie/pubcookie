
PBC_VERSION = 3.3.5
NGX_VERSION = 0.8.54
MOD_VERSION = 0.3
VENDOR = vitki
VERSION = $(NGX_VERSION)-$(PBC_VERSION)-$(MOD_VERSION)-$(VENDOR)
DIRNAME = nginx_http_pubcookie-$(VERSION)
SOURCES = \
	ngx_http_pubcookie.h \
	ngx_http_pubcookie_library.c \
	ngx_http_pubcookie_module.c

dist: CHANGES README LICENSE config $(SOURCES)
	cd ../.. && SRCDIR=$$PWD && \
	cd .. && TARDIR=$$PWD && \
	TMPDIR=/tmp/xx.$$$$ && rm -rf $$TMPDIR && mkdir -p $$TMPDIR/$(DIRNAME) && \
	cd $$SRCDIR && cp -rp * $$TMPDIR/$(DIRNAME) && \
	cd $$TMPDIR && rm -rf `find . -name .svn -o -name 'nginx_http_*.tar.gz'` && \
	tar -cpzf $$TARDIR/$(DIRNAME).tar.gz $(DIRNAME) && \
	cd $$SRCDIR && rm -rf $$TMPDIR && echo $$TARDIR/$(DIRNAME).tar.gz

