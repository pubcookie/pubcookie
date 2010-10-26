# Data for apache 2 module build
#
# These are usd by configure also

MOD_PUBCOOKIE=libpubcookie base64 strlcpy pbc_myconfig \
        security_legacy \
        pbc_logging capture_cmd_output pbc_configure \
        mod_pubcookie pbc_apacheconfig pbc_time

mod_pubcookie.la: ${MOD_PUBCOOKIE:=.slo}
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version ${MOD_PUBCOOKIE:=.lo}

DISTCLEAN_TARGETS = modules.mk

shared =  mod_pubcookie.la

