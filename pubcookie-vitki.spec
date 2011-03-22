
%define pubver  3.3.5
%define svnid   $Revision$
%define vitver  03
%global topdir  /usr/pubcookie

%define svnver  r%(echo %{svnid} | tr -cd 0-9)
%global rhel    %((head -1 /etc/redhat-release 2>/dev/null || echo 0) | tr -cd 0-9 | cut -c1)
%define rdist   vitki.%{vitver}%{?dist}%{!?dist:.el%{rhel}}
%define debug_package %{nil}

Name:		pubcookie
Version:	%{pubver}.%{svnver}
Release:	%{rdist}
Summary:	Pubcookie is am open source single sign-on solution
Group:		System Environment/Daemons
License:	GNU General Public License
URL:		http://www.pubcookie.org/
Source0:	%{name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	openssl >= 0.9.8
Requires:	xinetd >= 2

BuildRequires:	httpd-devel >= 2.2
BuildRequires:	openssl-devel >= 0.9.8

%description
Pubcookie consists of a standalone login server and modules for
common web server platforms like Apache and Microsoft IIS.
Together, these components can turn existing authentication services
(like Kerberos, LDAP, or NIS) into a solution for single sign-on
authentication to websites throughout an institution.

%package apache
Summary:    Pubcookie module for Apache
Group:      System Environment/Daemons
Requires:   httpd >= 2.2
Requires:   pubcookie = %{version}-%{release}

%description apache
This package provides Pubcookie module for Apache.

%prep
%setup -c -q

%build
[ -d /usr/lib/httpd/build -a ! -h /etc/httpd/build ] && ln -s /usr/lib/httpd/build /etc/httpd/build
./configure --enable-apache --enable-login --disable-default-des \
            --disable-krb5 --disable-ldap --disable-shadow \
            --disable-uwsecurid --disable-unsafe-relay \
            --prefix=%{topdir}
make

%install
rm -rf $RPM_BUILD_ROOT

make DESTDIR=$RPM_BUILD_ROOT install

mkdir -p $RPM_BUILD_ROOT/etc/xinetd.d
cat <<EOF > $RPM_BUILD_ROOT/etc/xinetd.d/pubcookie-keyserver
service pubcookie-keyserver
{
	disable		= no
	type		= UNLISTED
	wait		= no
	socket_type	= stream
	protocol	= tcp
	port		= 2222
	user		= root
	group		= tty
	server		= /usr/pubcookie/keyserver
}
EOF

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,0755)
%dir %{topdir}
%config(noreplace) %{topdir}/config
%{topdir}/config.login.sample
%dir %{topdir}/keys
%dir %{topdir}/login
%{topdir}/login/index.cgi
%{topdir}/login/media
%{topdir}/keyclient
%{topdir}/keyserver
%{topdir}/starter.key
%dir %{topdir}/login_templates
%config(noreplace) %{topdir}/login_templates/*
%{topdir}/login_templates.default
%{_sysconfdir}/xinetd.d/pubcookie-keyserver

%files apache
%{_libdir}/httpd/modules/mod_pubcookie.so

%changelog
* Wed Mar 22 2011 Vitki <vitki@vitki.net> - 3.3.5-0.3
- Upgraded to Pubcookie 3.3.5
- Fixed: Post method fails with Google Chrome (issue 194)
- Fixed: Nested locations with pubcookie directives crash Nginx (issue 197)
- Fixed: FreeBSD build fails due to "readlink -f" (issue 193)
- Fixed: Logout does not work on Ubuntu (issue 195)
- Fixed: Build fails on FreeBSD due to undefined struct utsname (issue 201)
- Fixed: Directive pubcookie_post shall be disabled for main and server contexts (issue 196)
- Fixed: Directive pubcookie_add_request should be renamed to pubcookie_addl_request (issue 198)
- Fixed: Create ubuntu debs for pubcookie and nginx with pubcookie (issue 200)

* Tue Oct 26 2010 Vitki <vitki@vitki.net> - 3.3.4a
- Create RPM for CentOS 5.5

