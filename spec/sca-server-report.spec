#
# spec file for package sca-server-report (Version 0.1)
#
# Copyright (C) 2013 SUSE LLC
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#
# Report bugs to:
# http://code.google.com/p/sca-server-report/issues/list
#

# norootforbuild
# neededforbuild  

Name:         sca-server-report
URL:          https://bitbucket.org/g23guy/sca-server-report
License:      GPLv2
Group:        System/Management
Autoreqprov:  on
Version:      0.1
Release:      1.131119.DEV.1
Source:       %{name}-%{version}.tar.gz
Summary:      Supportconfig Analysis Server Report
BuildRoot:    %{_tmppath}/%{name}-%{version}-build
Requires:     sca-patterns-base
BuildArch:    noarch
Requires:     python
Requires:     w3m

%description
A tool that primarily analyzes the local server, but can analyze other 
supportconfigs that have been copied to the server. It uses the 
Supportconfig Analysis patterns to perform the analysis.

Authors:
--------
    David Hamner <dhamner@novell.com>
    Jason Record <jrecord@suse.com>

%prep
%setup -q

%build
gzip -9f scatool.8

%install
pwd;ls -la
rm -rf $RPM_BUILD_ROOT
install -d $RPM_BUILD_ROOT/usr/sbin
install -d $RPM_BUILD_ROOT/usr/share/man/man8
install -m 544 scatool $RPM_BUILD_ROOT/usr/sbin
install -m 544 scatool.py $RPM_BUILD_ROOT/usr/sbin
install -m 644 scatool.8.gz $RPM_BUILD_ROOT/usr/share/man/man8

%files
%defattr(-,root,root)
/usr/sbin/scatool
/usr/sbin/scatool.py
%doc /usr/share/man/man8/*

%clean
rm -rf $RPM_BUILD_ROOT

%changelog
* Fri Nov 15 2013 dhamner@novell.com
- Fixed HTML ouput
- Analyze run from console will auto start w3m

* Fri Nov 08 2013 jrecord@suse.com
- initial package

