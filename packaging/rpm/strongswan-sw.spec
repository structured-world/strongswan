# strongSwan SW fork spec file
# Based on Fedora strongswan.spec with modifications for SW Foundation

%global _hardened_build 1

Name:           strongswan-sw
Version:        %{upstream_version}.sw.%{sw_rev}
Release:        1%{?dist}
Summary:        strongSwan IPsec (SW fork)

License:        GPL-2.0-or-later
URL:            https://github.com/structured-world/strongswan
Source0:        strongswan-%{upstream_version}-sw.%{sw_rev}.tar.gz

BuildRequires:  autoconf
BuildRequires:  automake
BuildRequires:  libtool
BuildRequires:  make
BuildRequires:  gcc
BuildRequires:  systemd
BuildRequires:  systemd-devel
BuildRequires:  systemd-rpm-macros
BuildRequires:  gmp-devel
BuildRequires:  libcurl-devel
BuildRequires:  openldap-devel
BuildRequires:  openssl-devel
# Fedora 41+ moved deprecated OpenSSL ENGINE API to separate package
# Fedora 39/40 include ENGINE in main openssl-devel, so no conditional needed there
%if 0%{?fedora} >= 41
BuildRequires:  openssl-devel-engine
%endif
BuildRequires:  sqlite-devel
BuildRequires:  gettext-devel
BuildRequires:  pam-devel
BuildRequires:  libgcrypt-devel
BuildRequires:  iptables-devel
BuildRequires:  libcap-devel
BuildRequires:  libpq-devel
BuildRequires:  gperf
BuildRequires:  flex
BuildRequires:  bison

Requires:       gmp
Requires:       openssl-libs
Requires:       libcurl
Requires:       systemd-libs
Requires:       libcap
Requires:       pam
Requires:       openldap
Requires:       sqlite-libs
Requires:       libgcrypt

Provides:       strongswan = %{upstream_version}
Conflicts:      strongswan
# Obsoletes stock Fedora strongswan package (e.g., 6.0.4-1.fc42)
# Uses upstream_version intentionally - our .sw.N suffix makes our version higher
Obsoletes:      strongswan < %{upstream_version}

%description
strongSwan is a complete IPsec implementation for Linux.
This is the Structured World Foundation fork with:
- Socket permissions fix (umask 0660 for Unix sockets)
- PostgreSQL database plugin
- DHCP-INFORM responder plugin for Windows split-tunnel routes

Drop-in replacement for system strongswan package.

%package -n strongswan-pgsql
Summary:        PostgreSQL database plugin for strongSwan
Requires:       strongswan-sw = %{version}-%{release}
Requires:       libpq

%description -n strongswan-pgsql
PostgreSQL database backend for strongSwan SQL plugin.
Enables storing VPN user credentials and configuration in PostgreSQL.

%package -n strongswan-dhcp-inform
Summary:        DHCP INFORM responder plugin for strongSwan
Requires:       strongswan-sw = %{version}-%{release}
# dhcp-inform plugin stores/retrieves split-tunnel routes in PostgreSQL database
Requires:       strongswan-pgsql = %{version}-%{release}

%description -n strongswan-dhcp-inform
Responds to Windows DHCPINFORM requests with split-tunnel routes
from PostgreSQL database. Delivers routes via DHCP option 121/249.

%prep
%autosetup -n strongswan-%{upstream_version}-sw.%{sw_rev}

# Remove -Wno-format and -Wno-format-security from upstream configure.ac
# Fedora's hardened build requires -Wformat to be enabled when using -Werror=format-security
sed -i '/WARN_CFLAGS=.*-Wno-format/d' configure.ac

%build
autoreconf -fiv

%configure --disable-static \
    --prefix=/usr \
    --sysconfdir=/etc \
    --libdir=%{_libdir} \
    --libexecdir=%{_libdir} \
    --with-systemdsystemunitdir=%{_unitdir} \
    --enable-eap-identity \
    --enable-eap-mschapv2 \
    --enable-eap-radius \
    --enable-eap-tls \
    --enable-xauth-eap \
    --enable-vici \
    --enable-swanctl \
    --enable-sql \
    --enable-pgsql \
    --enable-sqlite \
    --enable-systemd \
    --enable-openssl \
    --enable-curl \
    --enable-ldap \
    --enable-gcrypt \
    --enable-farp \
    --enable-dhcp \
    --enable-dhcp-inform \
    --enable-attr-sql \
    --enable-forecast \
    --enable-pam \
    --with-capabilities=libcap

%make_build

%install
%make_install

# Remove .la files
find %{buildroot} -type f -name '*.la' -delete

# Create required directories
install -d -m 700 %{buildroot}%{_sysconfdir}/strongswan/ipsec.d
for i in aacerts acerts certs cacerts crls ocspcerts private reqs; do
    install -d -m 700 %{buildroot}%{_sysconfdir}/strongswan/ipsec.d/${i}
done

%files
%license COPYING
%doc README NEWS
# Configuration directories
%dir %{_sysconfdir}/strongswan
%dir %{_sysconfdir}/strongswan/ipsec.d
%dir %attr(700,root,root) %{_sysconfdir}/strongswan/ipsec.d/aacerts
%dir %attr(700,root,root) %{_sysconfdir}/strongswan/ipsec.d/acerts
%dir %attr(700,root,root) %{_sysconfdir}/strongswan/ipsec.d/certs
%dir %attr(700,root,root) %{_sysconfdir}/strongswan/ipsec.d/cacerts
%dir %attr(700,root,root) %{_sysconfdir}/strongswan/ipsec.d/crls
%dir %attr(700,root,root) %{_sysconfdir}/strongswan/ipsec.d/ocspcerts
%dir %attr(700,root,root) %{_sysconfdir}/strongswan/ipsec.d/private
%dir %attr(700,root,root) %{_sysconfdir}/strongswan/ipsec.d/reqs
%dir %{_sysconfdir}/swanctl
%dir %{_sysconfdir}/swanctl/bliss
%dir %{_sysconfdir}/swanctl/conf.d
%dir %{_sysconfdir}/swanctl/ecdsa
%dir %{_sysconfdir}/swanctl/pkcs8
%dir %{_sysconfdir}/swanctl/pkcs12
%dir %{_sysconfdir}/swanctl/private
%dir %{_sysconfdir}/swanctl/pubkey
%dir %{_sysconfdir}/swanctl/rsa
%dir %{_sysconfdir}/swanctl/x509
%dir %{_sysconfdir}/swanctl/x509aa
%dir %{_sysconfdir}/swanctl/x509ac
%dir %{_sysconfdir}/swanctl/x509ca
%dir %{_sysconfdir}/swanctl/x509crl
%dir %{_sysconfdir}/swanctl/x509ocsp
%config(noreplace) %{_sysconfdir}/strongswan.conf
%config(noreplace) %{_sysconfdir}/strongswan.d
%config(noreplace) %{_sysconfdir}/swanctl/swanctl.conf
# Binaries
%{_bindir}/pki
%{_sbindir}/swanctl
%{_sbindir}/charon-systemd
# Systemd service
%{_unitdir}/strongswan.service
# Libraries and plugins
%dir %{_libdir}/ipsec
%dir %{_libdir}/ipsec/plugins
%{_libdir}/ipsec/libcharon.so.0
%{_libdir}/ipsec/libcharon.so.0.0.0
%{_libdir}/ipsec/libstrongswan.so.0
%{_libdir}/ipsec/libstrongswan.so.0.0.0
%{_libdir}/ipsec/libvici.so.0
%{_libdir}/ipsec/libvici.so.0.0.0
%{_libdir}/ipsec/plugins/libstrongswan-*.so
%exclude %{_libdir}/ipsec/plugins/libstrongswan-pgsql.so
%exclude %{_libdir}/ipsec/plugins/libstrongswan-dhcp-inform.so
# Data files
%{_datadir}/strongswan
# Man pages
%{_mandir}/man1/pki*.1*
%{_mandir}/man5/strongswan.conf.5*
%{_mandir}/man5/swanctl.conf.5*
%{_mandir}/man8/swanctl.8*

%files -n strongswan-pgsql
%{_libdir}/ipsec/plugins/libstrongswan-pgsql.so

%files -n strongswan-dhcp-inform
%{_libdir}/ipsec/plugins/libstrongswan-dhcp-inform.so

%post
%systemd_post strongswan.service

%preun
%systemd_preun strongswan.service

%postun
%systemd_postun_with_restart strongswan.service

%changelog
# Use SOURCE_DATE_EPOCH for reproducible builds if set, otherwise current date
* %([ -n "$SOURCE_DATE_EPOCH" ] && date -d "@$SOURCE_DATE_EPOCH" "+%a %b %d %Y" || date "+%a %b %d %Y") SW Foundation <dev@sw.foundation> - %{version}-%{release}
- strongSwan SW fork release
