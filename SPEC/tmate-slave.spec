Name:		tmate-slave
Version:	1.8
Release:	2%{?dist}
Summary:	tmate slave server

#Group:		
License:	MIT
URL:		https://github.com/nviennot/tmate-slave
Source0:	%{name}-%{version}.tar.gz
Source1:	%{name}.service
Source2:	%{name}.sysconfig
Source3:	%{name}.logrotate
BuildRoot:	%{name}-%{version}-%{buildarch}
BuildArch:	x86_64

BuildRequires:	libevent-devel kernel-devel zlib-devel openssl-devel ncurses-devel cmake ruby

%description
tmate-slave is the server side part of tmate.io.

%prep
%setup -q


%build
./autogen.sh
%configure
make %{?_smp_mflags}


%install
rm -rf %{buildroot}
%make_install
mkdir -p %{buildroot}%{_sysconfdir}/sysconfig/
cp RPM/tmate-slave.sysconfig %{buildroot}%{_sysconfdir}/sysconfig/tmate-slave
mkdir -p %{buildroot}/usr/lib/systemd/system
cp RPM/tmate-slave.service %{buildroot}/usr/lib/systemd/system/
mkdir -p %{buildroot}%{_sysconfdir}/logrotate.d
cp RPM/tmate-slave.logrotate %{buildroot}%{_sysconfdir}/logrotate.d/tmate-slave
mkdir %{buildroot}%{_sysconfdir}/tmate-slave

%files
%defattr(-,root,root,-)
%doc examples create_keys.sh
%{_mandir}/man1/tmate.1.gz
%{_bindir}/tmate-slave
/usr/lib/systemd/system/tmate-slave.service
%config %{_sysconfdir}/sysconfig/tmate-slave
%config %{_sysconfdir}/logrotate.d/tmate-slave
%{_sysconfdir}/tmate-slave/

%post
# if there's a conf.sample file and the keys directory exists, then
# chances are that we're doing an upgrade, not a new install
CONF=/etc/tmate-slave/tmate.conf.sample
if [ -f "${CONF}" -a -d /etc/tmate-slave/keys ]; then
  exit 0;
fi
mkdir -p /etc/tmate-slave/keys
for type in dsa rsa ecdsa; do
  ssh-keygen -t ${type} -f /etc/tmate-slave/keys/ssh_host_${type}_key -N '' &>/dev/null
  FP=$(ssh-keygen -l -f /etc/tmate-slave/keys/ssh_host_${type}_key | awk '{print $2}')
  echo set -g tmate-server-${type}-fingerprint "${FP}" >> "${CONF}"
done
echo set -g tmate-server-host "${HOSTNAME}" >> "${CONF}"
echo set -g tmate-server-port 22000 >> "${CONF}"

%changelog
* Thu Apr 23 2015 Scott Merrill <skippy@skippy.net> - 1.8-2
- add logrotate, sysconfig, and systemd files
- add post script to ensure creation of keys and sample client config
* Wed Apr 15 2015 Scott Merrill <skippy@skippy.net> - 1.8-1
- initial RPM build
