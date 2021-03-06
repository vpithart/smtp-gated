%define user smtpgw
%define rpm_full 1.4.21

Summary: SMTP Transparent Proxy
Name: smtp-gated
Version: 1.4.21
Release: 1
Group: System Environment/Daemons
License: GNU GPL
Vendor: Bartlomiej Korupczynski <bartek@klolik.org>
Provides: smtp-proxy
Packager: Bartlomiej Korupczynski <bartek@klolik.org>
URL: https://vpithart.github.io/smtp-gated/
Source: %{name}-%{rpm_full}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-root
PreReq: /usr/bin/id /sbin/chkconfig
PreReq: %{_sbindir}/useradd %{_sbindir}/groupadd


%description
Transparent proxy for SMTP traffic.


%prep
#%setup -q
%setup -q -n %{name}-%{rpm_full}


%build
%configure
make RPM_OPT_FLAGS="$RPM_OPT_FLAGS"


%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
%makeinstall

install -d $RPM_BUILD_ROOT{/var/spool/%{name}/{msg,lock}}
install -d $RPM_BUILD_ROOT/var/run/%{name}
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d

install contrib/redhat.init $RPM_BUILD_ROOT/etc/rc.d/init.d/%{name}

src/%{name} -t | sed 's/^\([^#]\)/; &/' > $RPM_BUILD_ROOT%{_sysconfdir}/%{name}.conf

pushd $RPM_BUILD_ROOT

mkdir -p var/spool/%{name}/msg
mkdir -p var/spool/%{name}/lock
mkdir -p var/run/%{name}


%files
%defattr(0644,root,root,0755)
%doc AUTHORS ChangeLog COPYING INSTALL README
%doc contrib/fixed.conf contrib/nat.conf
%config(noreplace)	%{_sysconfdir}/%{name}.conf
%{_mandir}

%defattr(0755,root,root,0755)
%{_sbindir}/%{name}
/etc/rc.d/init.d/%{name}

%defattr(0750,smtpgw,smtpgw,0750)
/var/spool/%{name}
/var/run/%{name}


%pre
id %{user} >/dev/null 2>&1 && exit 0

groupadd -r -f %{user} || {
	echo "Group %{user} account could not be created" >&2
	exit 1
}

useradd -g %{user} -d /var/spool/%{name}/ -s /bin/false -c "SMTP Proxy" -M -n -r %{user} || {
	echo "User %{user} account could not be created" >&2
	exit 1
}


%post
chkconfig --add %{name}
/etc/rc.d/init.d/%{name} condrestart

%preun
if [ $1 == 0 ]; then
        /etc/rc.d/init.d/%{name} stop >/dev/null 2>&1
        chkconfig --del %{name}
fi

%postun


%changelog
* Fri Mar 04 2005 Bartlomiej Korupczynski <bartek@klolik.org>
- changed to spec.in template

* Thu Mar 03 2005 Bartlomiej Korupczynski <bartek@klolik.org>
- initial version
