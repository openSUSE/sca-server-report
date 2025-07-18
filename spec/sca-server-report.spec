#
# spec file for package sca-server-report
#
# Copyright (c) 2025 SUSE LLC
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://bugs.opensuse.org/
#


%define sca_common sca
%define sca_config sca
%define libbase /usr/lib/%{sca_common}
%define sca_python %{libbase}/python

Name:           sca-server-report
Version:        1.6.5
Release:        0
Summary:        Supportconfig Analysis Server Report
License:        GPL-2.0-only
URL:            https://github.com/g23guy/sca-server-report
Group:          System/Monitoring
Source:         %{name}-%{version}.tar.gz
Requires:       python3-base
Requires:       sca-patterns-base >= 1.6.2
Requires:       sca-patterns-template-gen2
BuildArch:      noarch

%description
A tool that primarily analyzes the local server, but can analyze other
supportconfigs that have been copied to the server. It uses the
Supportconfig Analysis patterns to perform the analysis.

See %{_docdir}/sca-patterns-base/COPYING.GPLv2

%prep
%setup -q

%build
gzip -9f man/*5
gzip -9f man/*8

%install
pwd;ls -la
install -d %{buildroot}%{_sysconfdir}/%{sca_config}
install -d %{buildroot}%{_mandir}/man5
install -d %{buildroot}%{_mandir}/man8
install -d %{buildroot}%{sca_python}
mkdir -p %{buildroot}%{_bindir}
install -m 755 bin/scatool %{buildroot}%{_bindir}
install -m 644 config/scatool.conf %{buildroot}%{_sysconfdir}/%{sca_config}
install -m 644 man/*.5.gz %{buildroot}%{_mandir}/man5
install -m 644 man/*.8.gz %{buildroot}%{_mandir}/man8

%files
%defattr(-,root,root)
%{_bindir}/scatool
%dir %{_sysconfdir}/%{sca_config}
%config %{_sysconfdir}/%{sca_config}/*
%doc %{_mandir}/man5/*
%doc %{_mandir}/man8/*

%changelog
