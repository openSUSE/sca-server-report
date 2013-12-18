OBSPACKAGE=sca-server-report
SVNDIRS=spec bin man
VERSION=$(shell awk '/Version:/ { print $$2 }' spec/${OBSPACKAGE}.spec)
RELEASE=$(shell awk '/Release:/ { print $$2 }' spec/${OBSPACKAGE}.spec)
SRCDIR=$(OBSPACKAGE)-$(VERSION)
SRCFILE=$(SRCDIR).tar
BUILDDIR=/usr/src/packages

default: build

install: dist
	@echo install: Installing source files into build directory
	@cp src/$(SRCFILE).gz $(BUILDDIR)/SOURCES
	@cp spec/$(OBSPACKAGE).spec $(BUILDDIR)/SPECS
	@rm -f $(BUILDDIR)/SPECS/$(OBSPACKAGE).changes
	@echo

uninstall:
	@echo uninstall: Uninstalling from build directory
	@rm -rf $(BUILDDIR)/SOURCES/$(SRCFILE).gz
	@rm -rf $(BUILDDIR)/SPECS/$(OBSPACKAGE).spec
	@rm -rf $(BUILDDIR)/BUILD/$(SRCDIR)
	@rm -f $(BUILDDIR)/SRPMS/$(OBSPACKAGE)-$(VERSION)-$(RELEASE).src.rpm
	@rm -f $(BUILDDIR)/RPMS/noarch/$(OBSPACKAGE)-$(VERSION)-$(RELEASE).noarch.rpm
	@echo

dist:
	@echo dist: Creating distribution source tarball
	@mkdir -p $(SRCDIR)
	@for i in $(SVNDIRS); do cp $$i/* $(SRCDIR); done
	@cp COPYING.GPLv2 $(SRCDIR)
	@tar cf $(SRCFILE) $(SRCDIR)/*
	@gzip -9f $(SRCFILE)
	@rm -rf $(SRCDIR)
	@mv -f $(SRCFILE).gz src
	@echo

clean: uninstall
	@echo clean: Cleaning up make files
	@rm -rf $(OBSPACKAGE)*
	@for i in $(SVNDIRS); do rm -f $$i/*~; done
	@rm -f *~
	@rm -f src/$(OBSPACKAGE)*
	@echo
	@ls -al ${LS_OPTIONS}
	@echo

build: clean install
	@echo build: Building RPM package
	@rpmbuild -ba $(BUILDDIR)/SPECS/$(OBSPACKAGE).spec
	@cp $(BUILDDIR)/SRPMS/$(OBSPACKAGE)-$(VERSION)-$(RELEASE).src.rpm .
	@cp $(BUILDDIR)/RPMS/noarch/$(OBSPACKAGE)-$(VERSION)-$(RELEASE).noarch.rpm .
	@echo
	@ls -al ${LS_OPTIONS}
	@echo

obsetup:
	@echo obsetup: Setup OBS Novell:NTS:SCA/$(OBSPACKAGE)
	@rm -rf Novell:NTS:SCA
	@osc co Novell:NTS:SCA/$(OBSPACKAGE)
	@rm -f Novell:NTS:SCA/$(OBSPACKAGE)/*
	@cp spec/$(OBSPACKAGE).spec Novell:NTS:SCA/$(OBSPACKAGE)
	@cp spec/$(OBSPACKAGE).changes Novell:NTS:SCA/$(OBSPACKAGE)
	@cp src/$(SRCFILE).gz Novell:NTS:SCA/$(OBSPACKAGE)
	@osc status Novell:NTS:SCA/$(OBSPACKAGE)

buildci: build
	@echo buildci: Checking in Files
	@echo
	@svn up
	@svn ci -m "Build SVN Check In: $(OBSPACKAGE)-$(VERSION)-$(RELEASE)"
	@ls -al ${LS_OPTIONS}
	@echo
	
commit: build
	@echo commit: Committing changes to OBS Novell:NTS:SCA/$(OBSPACKAGE)
	@osc up Novell:NTS:SCA/$(OBSPACKAGE)
	@osc del Novell:NTS:SCA/$(OBSPACKAGE)/*
	@osc ci -m "Removing old files before committing: $(OBSPACKAGE)-$(VERSION)-$(RELEASE)" Novell:NTS:SCA/$(OBSPACKAGE)
	@rm -f Novell:NTS:SCA/$(OBSPACKAGE)/*
	@cp spec/$(OBSPACKAGE).spec Novell:NTS:SCA/$(OBSPACKAGE)
	@cp spec/$(OBSPACKAGE).changes Novell:NTS:SCA/$(OBSPACKAGE)
	@cp src/$(SRCFILE).gz Novell:NTS:SCA/$(OBSPACKAGE)
	@osc add Novell:NTS:SCA/$(OBSPACKAGE)/*
	@osc up Novell:NTS:SCA/$(OBSPACKAGE)
	@osc ci -m "Committing to OBS: $(OBSPACKAGE)-$(VERSION)-$(RELEASE)" Novell:NTS:SCA/$(OBSPACKAGE)
	@svn up
	@svn ci -m "Committed to OBS: $(OBSPACKAGE)-$(VERSION)-$(RELEASE)"
	@echo

help:
	@clear
	@make -v
	@echo
	@echo Make options for package: $(OBSPACKAGE)
	@echo make {obsetup, install, uninstall, dist, clean, build[default], buildci, commit}
	@echo
