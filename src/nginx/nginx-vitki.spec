#
# Copyright (C) 2010-2012 VITKI
# RPM spec for custom Nginx with PubCookie
#

%define nginx_user      nginx
%define nginx_group     %{nginx_user}
%define nginx_home      %{_localstatedir}/lib/nginx
%define nginx_home_tmp  %{nginx_home}/tmp
%define nginx_logdir    %{_localstatedir}/log/nginx
%define nginx_confdir   %{_sysconfdir}/nginx
%define nginx_datadir   %{_datadir}/nginx
%define nginx_webroot   %{nginx_datadir}/html

#<VITKI>#
%define vitver  15
%define rhver   %((head -1 /etc/redhat-release 2>/dev/null || echo 0) | tr -cd 0-9 | cut -c1)
%define relver  vitki.%{vitver}%{?dist}%{!?dist:.el%{rhver}}
%define debug_package %{nil}
%define _without_debugging 1
%define _with_progress 1
%define _without_slowfs 1
%define _without_echo 1
%define _with_pubcookie 1
%define _without_pbc_trunk 1
%define _with_ipguard 1
%define _without_ipg_trunk 1
%define pubcookie_trunk_dir /root/pubcookie
%define ipguard_trunk_dir /root/ipguard
#</VITKI>#

Name:           nginx
Version:        1.2.0
Release:        %{relver}
Summary:        Robust, small and high performance http and reverse proxy server
Group:          System Environment/Daemons   

# BSD License (two clause)
# http://www.freebsd.org/copyright/freebsd-license.html
License:        BSD
URL:            http://nginx.net/ 
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:      pcre-devel,zlib-devel,openssl-devel,perl(ExtUtils::Embed)
Requires:           pcre,zlib,openssl
Requires:           perl(:MODULE_COMPAT_%(eval "`%{__perl} -V:version`"; echo $version))
# for /usr/sbin/useradd
Requires(pre):      shadow-utils
Requires(post):     chkconfig
# for /sbin/service
Requires(preun):    chkconfig, initscripts
Requires(postun):   initscripts

Source0:    http://sysoev.ru/nginx/nginx-%{version}.tar.gz
Source1:    %{name}.init
Source2:    %{name}.logrotate
Source3:    virtual.conf
Source4:    ssl.conf
Source5:    nginx-upstream-fair.tgz
Source6:    upstream-fair.conf
Source7:    %{name}.sysconfig
Source8:    %{name}.conf
Source100:  index.html
Source101:  poweredby.png
Source102:  nginx-logo.png
Source103:  50x.html
Source104:  404.html

#<VITKI>#
Source31:   masterzen-nginx-upload-progress-module-0.9.0-0.tar.gz
Source32:   ngx_slowfs_cache-1.5.tar.gz
Source33:   agentzh-echo-nginx-module-0.34.tar.gz
Source34:   nginx_http_pubcookie-1.2.0-3.3.5-0.6-vitki.tar.gz
Source35:   nginx_http_ipguard-1.2.0-0.7-vitki.tar.gz
Patch31:    nginx-dummy-try-files-1.0.11.patch
#</VITKI>#

# removes -Werror in upstream build scripts.  -Werror conflicts with
# -D_FORTIFY_SOURCE=2 causing warnings to turn into errors.
Patch0:     nginx-auto-cc-gcc.patch

#patch for http://www.kb.cert.org/vuls/id/120541
Patch1:     nginx-cve-2009-3555.patch


%description
Nginx [engine x] is an HTTP(S) server, HTTP(S) reverse proxy and IMAP/POP3
proxy server written by Igor Sysoev.

One third party module, nginx-upstream-fair, has been added.
Another added module: nginx-upload-progress

%prep
%setup -q

%patch0 -p0
#<VITKI/>#%patch1 -p0
tar xvzf %{SOURCE5}

#<VITKI>#
%patch31 -p0 -b .dummytryfiles
%{?_with_progress:  tar xvzf %{SOURCE31} }
%{?_with_slowfs:    tar xvzf %{SOURCE32} }
%{?_with_echo:      tar xvzf %{SOURCE33} }
%{?_with_pubcookie: mkdir nginx_pubcookie ; cd nginx_pubcookie ; tar xvzf %{SOURCE34} ; cd .. }
%{?_with_ipguard:   mkdir nginx_ipguard   ; cd nginx_ipguard   ; tar xvzf %{SOURCE35} ; cd .. }
#</VITKI>#

%build
# nginx does not utilize a standard configure script.  It has its own
# and the standard configure options cause the nginx configure script
# to error out.  This is is also the reason for the DESTDIR environment
# variable.  The configure script(s) have been patched (Patch1 and
# Patch2) in order to support installing into a build environment.
export DESTDIR=%{buildroot}
./configure \
    --user=%{nginx_user} \
    --group=%{nginx_group} \
    --prefix=%{nginx_datadir} \
    --sbin-path=%{_sbindir}/%{name} \
    --conf-path=%{nginx_confdir}/%{name}.conf \
    --error-log-path=%{nginx_logdir}/error.log \
    --http-log-path=%{nginx_logdir}/access.log \
    --http-client-body-temp-path=%{nginx_home_tmp}/client_body \
    --http-proxy-temp-path=%{nginx_home_tmp}/proxy \
    --http-fastcgi-temp-path=%{nginx_home_tmp}/fastcgi \
    --pid-path=%{_localstatedir}/run/%{name}.pid \
    --lock-path=%{_localstatedir}/lock/subsys/%{name} \
    --with-http_ssl_module \
    --with-http_realip_module \
    --with-http_addition_module \
    --with-http_sub_module \
    --with-http_dav_module \
    --with-http_flv_module \
    --with-http_gzip_static_module \
    --with-http_stub_status_module \
    --with-http_perl_module \
    --with-mail \
    --with-mail_ssl_module \
    --with-cc-opt="%{optflags} $(pcre-config --cflags)" \
    --add-module=%{_builddir}/nginx-%{version}/nginx-upstream-fair \
%{?VITKI:} \
    --with-ipv6 \
%{?_with_debugging: --with-debug } \
%{?_with_progress:  --add-module=%{_builddir}/nginx-%{version}/%(x=`basename %{SOURCE31}`; echo ${x%.tar.gz}) } \
%{?_with_slowfs:    --add-module=%{_builddir}/nginx-%{version}/%(x=`basename %{SOURCE32}`; echo ${x%.tar.gz}) } \
%{?_with_echo:      --add-module=%{_builddir}/nginx-%{version}/%(x=`basename %{SOURCE33}`; echo ${x%.tar.gz}) } \
%{?_with_pubcookie: --add-module=%{_builddir}/nginx-%{version}/nginx_pubcookie/src/nginx } \
%{?_with_pbc_trunk: --add-module=%{pubcookie_trunk_dir}/src/nginx } \
%{?_with_ipguard:   --add-module=%{_builddir}/nginx-%{version}/nginx_ipguard/nginx } \
%{?_with_ipg_trunk: --add-module=%{ipguard_trunk_dir}/nginx }
%{?!VITKI:}
make

# rename the readme for nginx-upstream-fair so it doesn't conflict with the main
# readme
mv nginx-upstream-fair/README nginx-upstream-fair/README.nginx-upstream-fair

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot} INSTALLDIRS=vendor
find %{buildroot} -type f -name .packlist -exec rm -f {} \;
find %{buildroot} -type f -name perllocal.pod -exec rm -f {} \;
find %{buildroot} -type f -empty -exec rm -f {} \;
find %{buildroot} -type f -exec chmod 0644 {} \;
find %{buildroot} -type f -name '*.so' -exec chmod 0755 {} \;
chmod 0755 %{buildroot}%{_sbindir}/nginx
%{__install} -p -D -m 0755 %{SOURCE1} %{buildroot}%{_initrddir}/%{name}
%{__install} -p -D -m 0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/logrotate.d/%{name}
%{__install} -p -D -m 0644 %{SOURCE7} %{buildroot}%{_sysconfdir}/sysconfig/%{name}
%{__install} -p -d -m 0755 %{buildroot}%{nginx_confdir}/conf.d
%{__install} -p -m 0644 %{SOURCE8} %{buildroot}%{nginx_confdir}
%{__install} -p -m 0644 %{SOURCE3} %{SOURCE4} %{SOURCE6} %{buildroot}%{nginx_confdir}/conf.d
%{__install} -p -d -m 0755 %{buildroot}%{nginx_home_tmp}
%{__install} -p -d -m 0755 %{buildroot}%{nginx_logdir}
%{__install} -p -d -m 0755 %{buildroot}%{nginx_webroot}
%{__install} -p -m 0644 %{SOURCE100} %{SOURCE101} %{SOURCE102} %{SOURCE103} %{SOURCE104} %{buildroot}%{nginx_webroot}

# convert to UTF-8 all files that give warnings.
for textfile in CHANGES
do
    mv $textfile $textfile.old
    iconv --from-code ISO8859-1 --to-code UTF-8 --output $textfile $textfile.old
    rm -f $textfile.old
done

%clean
rm -rf %{buildroot}

%pre
%{_sbindir}/useradd -c "Nginx user" -s /bin/false -r -d %{nginx_home} %{nginx_user} 2>/dev/null || :

%post
/sbin/chkconfig --add %{name}

%preun
if [ $1 = 0 ]; then
    /sbin/service %{name} stop >/dev/null 2>&1
    /sbin/chkconfig --del %{name}
fi

%postun
if [ $1 -ge 1 ]; then
    /sbin/service %{name} condrestart > /dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,-)
%doc LICENSE CHANGES README nginx-upstream-fair/README.nginx-upstream-fair
%{nginx_datadir}/
%{_sbindir}/%{name}
%{_mandir}/man3/%{name}.3pm.gz
%{_initrddir}/%{name}
%dir %{nginx_confdir}
%dir %{nginx_confdir}/conf.d
%dir %{nginx_logdir}
%config(noreplace) %{nginx_confdir}/conf.d/*.conf
%config(noreplace) %{nginx_confdir}/win-utf
%config(noreplace) %{nginx_confdir}/%{name}.conf.default
%config(noreplace) %{nginx_confdir}/mime.types.default
%config(noreplace) %{nginx_confdir}/fastcgi_params
%config(noreplace) %{nginx_confdir}/fastcgi_params.default
#<VITKI>#
%config(noreplace) %{nginx_confdir}/fastcgi.conf
%config(noreplace) %{nginx_confdir}/fastcgi.conf.default
%config(noreplace) %{nginx_confdir}/scgi_params
%config(noreplace) %{nginx_confdir}/scgi_params.default
%config(noreplace) %{nginx_confdir}/uwsgi_params
%config(noreplace) %{nginx_confdir}/uwsgi_params.default
#</VITKI>#
%config(noreplace) %{nginx_confdir}/koi-win
%config(noreplace) %{nginx_confdir}/koi-utf
%config(noreplace) %{nginx_confdir}/%{name}.conf
%config(noreplace) %{nginx_confdir}/mime.types
%config(noreplace) %{_sysconfdir}/logrotate.d/%{name}
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%dir %{perl_vendorarch}/auto/%{name}
%{perl_vendorarch}/%{name}.pm
%{perl_vendorarch}/auto/%{name}/%{name}.so
%attr(-,%{nginx_user},%{nginx_group}) %dir %{nginx_home}
%attr(-,%{nginx_user},%{nginx_group}) %dir %{nginx_home_tmp}


%changelog
* Tue May 15 2012 Vitki <vitki@vitki.net> - 1.2.0-15
- Update to Nginx 1.2.0
- Update to Upload module 0.9.0 (fixes incompatibility with latest nginx)
- Update to IPguard module 0.7 (fixes 64-bit build)
- Update to Pubcookie module 0.6 (fixes 64-bit build)

* Fri Dec 23 2011 Vitki <vitki@vitki.net> - 1.0.11-13
- Update to Nginx 1.0.11
- Enable IPv6

* Fri Nov  4 2011 Vitki <vitki@vitki.net> - 1.0.9-12
- Update to Nginx 1.0.9
- New Pubcookie v0.5 fixes "No granting cookie" with Chrome 12+

* Thu Jun  9 2011 Vitki <vitki@vitki.net> - 1.0.4-11
- Update to Nginx 1.0.4
- New Pubcookie v0.4 add support for $remote_user and fixes a few bugs

* Wed Mar 22 2011 Vitki <vitki@vitki.net> - 0.8.54-11
- New Pubcookie v0.3 fixes google chrome bug

* Sun Jan 16 2011 Vitki <vitki@vitki.net> - 0.8.52-10
- New Pubcookie v0.2 which returns status 200 or 301 instead of buggy 400

* Tue Dec  7 2010 Vitki <vitki@vitki.net> - 0.8.52-09
- Add support for IPguard authentication check

* Sat Nov 27 2010 Vitki <vitki@vitki.net> - 0.8.52-08
- Add support for Pubcookie 3.3.4a authentication, module v.0.1
- Location name of "-" in try_files avoids disk access and causes unconditional jump
- Feature macros for modules

* Tue Oct 26 2010 Vitki <vitki@vitki.net> - 0.8.52-07
- Update to Nginx 0.8.52
- Add the upload_progress module v.0.8.1
- Add the slow_cache module v.1.5
- Add the echo module v.0.34

* Sun Jun 20 2010 Jeremy Hinegardner <jeremy at hinegardner dot org> - 0.6.39-5
- fix bug #591543

* Mon Feb 15 2010 Jeremy Hinegardner <jeremy at hinegardner dot org> - 0.6.39-4
- change directory ownership of log dir to root:root

* Mon Feb 15 2010 Jeremy Hinegardner <jeremy at hinegardner dot org> - 0.6.39-3
- fix bug #554914 

* Fri Dec 04 2009 Jeremy Hinegardner <jeremy at hinegardner dot org> - 0.6.39-2
- fixes CVE-2009-3555

* Mon Sep 14 2009 Jeremy Hinegardner <jeremy at hinegardner dot org> - 0.6.39-1
- update to 0.6.39
- fixes CVE-2009-2629

* Sun Aug 02 2009 Jeremy Hinegardner <jeremy at hinegardner dot org> - 0.6.38-1
- update to 0.6.38

* Sat Apr 11 2009 Jeremy Hinegardner <jeremy at hinegardner dot org> 0.6.36-1
-  update to 0.6.36

* Thu Feb 19 2009 Jeremy Hinegardner <jeremy at hinegardner dot org> - 0.6.35-2
- rebuild

* Thu Feb 19 2009 Jeremy Hinegardner <jeremy at hinegardner dot org> - 0.6.35-1
- update to 0.6.35

* Tue Dec 30 2008 Jeremy Hinegardner <jeremy at hinegardner dot org> - 0.6.34-1
- update to 0.6.34
- Fix inclusion of /usr/share/nginx tree => no unowned directories [mschwendt]

* Sun Nov 23 2008 Jeremy Hinegardner <jeremy at hinegardner dot org> - 0.6.33-1
- update to 0.6.33

* Sun Jul 27 2008 Jeremy Hinegardner <jeremy at hinegardner dot org> - 0.6.32-1
- update to 0.6.32
- nginx now supports DESTDIR so removed the patches that enabled it

* Mon May 26 2008 Jeremy Hinegardner <jeremy at hinegardner dot org> - 0.6.31-3
- update init script
- remove 'default' listen parameter

* Tue May 13 2008 Jeremy Hinegardner <jeremy at hinegardner dot org> - 0.6.31-2
- added missing Source files

* Mon May 12 2008 Jeremy Hinegardner <jeremy at hinegardner dot org> - 0.6.31-1
- update to new upstream stable branch 0.6
- added 3rd party module nginx-upstream-fair
- add /etc/nginx/conf.d support [#443280]
- use /etc/sysconfig/nginx to determine nginx.conf [#442708]
- added default webpages
- add Requires for versioned perl (libperl.so) (via Tom "spot" Callaway)
- drop silly file Requires (via Tom "spot" Callaway)

* Sat Jan 19 2008 Jeremy Hinegardner <jeremy at hinegardner dot org> - 0.5.35-1
- update to 0.5.35

* Sun Dec 16 2007 Jeremy Hinegardner <jeremy at hinegardner dot org> - 0.5.34-1
- update to 0.5.34

* Mon Nov 12 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.33-2
- bump build number - source wasn't update

* Mon Nov 12 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.33-1
* update to 0.5.33

* Mon Sep 24 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.32-1
- updated to 0.5.32
- fixed rpmlint UTF-8 complaints.

* Sat Aug 18 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.31-3
- added --with-http_stub_status_module build option.
- added --with-http_sub_module build option.
- add in pcre-config --cflags

* Sat Aug 18 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.31-2
- remove BuildRequires: perl-devel

* Fri Aug 17 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.31-1
- Update to 0.5.31
- specify license is BSD

* Sat Aug 11 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.30-2
- Add BuildRequires: perl-devel - fixing rawhide build

* Mon Jul 30 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.30-1
- Update to 0.5.30

* Tue Jul 24 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.29-1
- Update to 0.5.29

* Wed Jul 18 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.28-1
- Update to 0.5.28

* Mon Jul 09 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.27-1
- Update to 0.5.27

* Mon Jun 18 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.26-1
- Update to 0.5.26

* Sat Apr 28 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.19-1
- Update to 0.5.19

* Mon Apr 02 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.17-1
- Update to 0.5.17

* Mon Mar 26 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.16-1
- Update to 0.5.16
- add ownership of /usr/share/nginx/html (#233950)

* Fri Mar 23 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.15-3
- fixed package review bugs (#235222) given by ruben@rubenkerkhof.com

* Thu Mar 22 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.15-2
- fixed package review bugs (#233522) given by kevin@tummy.com

* Thu Mar 22 2007 Jeremy Hinegardner <jeremy@hinegardner.org> - 0.5.15-1
- create patches to assist with building for Fedora
- initial packaging for Fedora

