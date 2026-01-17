# strongSwan SW fork spec file
# Based on Fedora strongswan.spec with modifications for SW Foundation

%global _hardened_build 1
%global sw_suffix sw

Name:           strongswan-sw
Version:        %{upstream_version}.%{sw_suffix}.%{sw_rev}
Release:        1%{?dist}
Summary:        strongSwan IPsec (SW fork)

License:        GPL-2.0-or-later
URL:            https://github.com/structured-world/strongswan
Source0:        strongswan-%{upstream_version}-%{sw_suffix}.%{sw_rev}.tar.gz

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
Requires:       strongswan-pgsql = %{version}-%{release}

%description -n strongswan-dhcp-inform
Responds to Windows DHCPINFORM requests with split-tunnel routes
from PostgreSQL database. Delivers routes via DHCP option 121/249.

%prep
%autosetup -n strongswan-%{upstream_version}-%{sw_suffix}.%{sw_rev}

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
%dir %{_sysconfdir}/strongswan
%config(noreplace) %{_sysconfdir}/strongswan/*
%{_unitdir}/strongswan*.service
%{_sbindir}/*
%{_libdir}/ipsec
%exclude %{_libdir}/ipsec/plugins/libstrongswan-pgsql.so
%exclude %{_libdir}/ipsec/plugins/libstrongswan-dhcp-inform.so
%{_datadir}/strongswan
%{_mandir}/man?/*

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
* %(date "+%a %b %d %Y") SW Foundation <dev@sw.foundation> - %{version}-%{release}
- strongSwan SW fork release
