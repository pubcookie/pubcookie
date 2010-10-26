
%define pubver  3.3.4a
%define svnver  r1379
%define vitkiv  01
%global rhel    %((head -1 /etc/redhat-release 2>/dev/null || echo 0) | tr -cd 0-9 | cut -c1)
%define rdist   99.vitki.%{vitkiv}%{?dist}%{!?dist:.el%{rhel}}
%global topdir  /usr/pubcookie     

Name:		pubcookie
Version:	%{pubver}.%{svnver}
Release:	%{rdist}
Summary:	Pubcookie is am open source single sign-on solution
Group:		System Environment/Daemons
License:	GNU General Public License
URL:		http://www.pubcookie.org/
Source0:	%{name}-%{version}.tar.gz
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires:	httpd >= 2.2
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
%config %{topdir}/config
%{topdir}/config.login.sample
%dir %{topdir}/keys
%dir %{topdir}/login
%{topdir}/login/index.cgi
%{topdir}/login/media
%{topdir}/keyclient
%{topdir}/keyserver
%{topdir}/starter.key
%dir %{topdir}/login_templates
%config %{topdir}/login_templates/*
%{topdir}/login_templates.default
%{_sysconfdir}/xinetd.d/pubcookie-keyserver
%{_libdir}/httpd/modules/mod_pubcookie.so

%changelog
* Tue Oct 26 2010 Vitki <vitki@vitki.net> - 3.3.4a
- Create RPM for CentOS 5.5

