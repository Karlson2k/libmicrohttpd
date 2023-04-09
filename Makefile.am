# This Makefile.am is in the public domain
ACLOCAL_AMFLAGS = -I m4
SUBDIRS = contrib m4 src .

if BUILD_DOC
SUBDIRS += doc
endif


W32COMMON = w32/common/gen_dll_res.ps1 w32/common/microhttpd_dll_res_vc.rc.in w32/common/microhttpd_dll_res_vc.rc \
  w32/common/MHD_config.h w32/common/vs_dirs.props w32/common/common-build-settings.vcxproj \
  w32/common/libmicrohttpd-build-settings.vcxproj w32/common/libmicrohttpd-files.vcxproj w32/common/libmicrohttpd-filters.vcxproj \
  w32/common/hellobrowser-files.vcxproj w32/common/hellobrowser-filters.vcxproj \
  w32/common/apps-build-settings.vcxproj
W32VS2013 = w32/VS2013/libmicrohttpd.vcxproj w32/VS2013/libmicrohttpd.vcxproj.filters \
  w32/VS2013/hellobrowser.vcxproj w32/VS2013/hellobrowser.vcxproj.filters \
  w32/VS2013/simplepost.vcxproj w32/VS2013/largepost.vcxproj \
  w32/VS2013/libmicrohttpd.sln
W32VS2015 = w32/VS2015/libmicrohttpd.vcxproj w32/VS2015/libmicrohttpd.vcxproj.filters \
  w32/VS2015/hellobrowser.vcxproj w32/VS2015/hellobrowser.vcxproj.filters \
  w32/VS2015/simplepost.vcxproj w32/VS2015/largepost.vcxproj \
  w32/VS2015/libmicrohttpd.sln
W32VS2017 = w32/VS2017/libmicrohttpd.vcxproj w32/VS2017/libmicrohttpd.vcxproj.filters \
  w32/VS2017/hellobrowser.vcxproj w32/VS2017/hellobrowser.vcxproj.filters \
  w32/VS2017/simplepost.vcxproj w32/VS2017/largepost.vcxproj \
  w32/VS2017/libmicrohttpd.sln
W32VS2019 = w32/VS2019/libmicrohttpd.vcxproj w32/VS2019/libmicrohttpd.vcxproj.filters \
  w32/VS2019/hellobrowser.vcxproj w32/VS2019/hellobrowser.vcxproj.filters \
  w32/VS2019/simplepost.vcxproj w32/VS2019/largepost.vcxproj \
  w32/VS2019/libmicrohttpd.sln
W32VS2022 = w32/VS2022/libmicrohttpd.vcxproj w32/VS2022/libmicrohttpd.vcxproj.filters \
  w32/VS2022/hellobrowser.vcxproj w32/VS2022/hellobrowser.vcxproj.filters \
  w32/VS2022/simplepost.vcxproj w32/VS2022/largepost.vcxproj \
  w32/VS2022/libmicrohttpd.sln
W32VSAV = w32/VS-Any-Version/libmicrohttpd.vcxproj w32/VS-Any-Version/libmicrohttpd.vcxproj.filters \
  w32/VS-Any-Version/hellobrowser.vcxproj w32/VS-Any-Version/hellobrowser.vcxproj.filters \
  w32/VS-Any-Version/simplepost.vcxproj w32/VS-Any-Version/largepost.vcxproj \
  w32/VS-Any-Version/libmicrohttpd.sln

EXTRA_DIST = \
  libmicrohttpd.pc.in \
  $(W32COMMON) $(W32VS2013) $(W32VS2015) $(W32VS2017) \
  $(W32VS2019) $(W32VS2022) $(W32VSAV)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libmicrohttpd.pc

EXTRA_DIST += pre-dist-hook-dummy
MOSTLYCLEANFILES = pre-dist-hook-dummy
DISTCLEANFILES = 
MAINTAINERCLEANFILES = m4/c_backported.m4

pre-dist-hook-dummy: pre-dist-hook Makefile
	@echo "dummy" > $@

dist-hook: dist-po
	@chmod u+w '$(distdir)/pre-dist-hook-dummy' && \
	  rm -f '$(distdir)/pre-dist-hook-dummy'
	@rm -f pre-dist-hook-dummy
	@if test -w '$(distdir)/m4/c_backported.m4'; then \
	  echo "Use empty m4/c_backported.m4 for dist target"; \
	  touch -r '$(distdir)/m4/c_backported.m4' '$(distdir)/m4/c_backported.m4-tmst' && \
	    echo '# Not used for distribution' > '$(distdir)/m4/c_backported.m4' && \
	    touch -r '$(distdir)/m4/c_backported.m4-tmst' '$(distdir)/m4/c_backported.m4' && \
	    rm -f '$(distdir)/m4/c_backported.m4-tmst'; \
	else \
	  true; \
	fi

pre-dist-hook: pre-dist-hook-doc
	@echo "Preparing to make dist"

pre-dist-hook-doc:
	@echo "Preparing to make dist in doc"
	@if test -w '$(top_srcdir)/doc' ; then \
	  $(am__cd) doc && $(MAKE) $(AM_MAKEFLAGS) update-stamp; \
	else \
	  echo "Source tree is read-only, skipping force doc update"; \
	fi;

.PHONY: pre-dist-hook pre-dist-hook-doc

distclean-local: distclean-po

maintainer-clean-local: maintainer-clean-po

PO_ACLOCAL_M4 = $(top_srcdir)/po/aclocal.m4

PO_M4_FILES = $(top_srcdir)/po/m4/gettext.m4 $(top_srcdir)/po/m4/host-cpu-c-abi.m4 \
  $(top_srcdir)/po/m4/iconv.m4 $(top_srcdir)/po/m4/intlmacosx.m4 \
  $(top_srcdir)/po/m4/lib-ld.m4 $(top_srcdir)/po/m4/lib-link.m4 \
  $(top_srcdir)/po/m4/lib-prefix.m4 $(top_srcdir)/po/m4/nls.m4 \
  $(top_srcdir)/po/m4/po.m4 $(top_srcdir)/po/m4/progtest.m4

am__po_aclocal_m4_deps = $(PO_M4_FILES) $(top_srcdir)/po/configure.ac
am__po_configure_deps = $(am__po_aclocal_m4_deps) $(PO_ACLOCAL_M4)

$(PO_ACLOCAL_M4): $(am__po_aclocal_m4_deps)
	@echo "Building $@"
	$(am__cd) '$(top_srcdir)/po' && $(ACLOCAL) $(ACLOCAL_AMFLAGS)

# Do update po/configure.ac only if template files updated
$(top_srcdir)/po/configure.ac: $(top_srcdir)/po/po-configure.ac.in $(top_srcdir)/configure.ac
	@echo "Building $@"
	@$(am__cd) '$(top_builddir)' && $(MAKE) $(AM_MAKEFLAGS) po/po-configure.ac
	@rm -f '$@' && cp -f po/po-configure.ac '$@'

$(top_srcdir)/po-configure: $(top_srcdir)/po/configure.ac $(PO_ACLOCAL_M4)
	@echo "Building $@"
	@$(am__cd) '$(top_srcdir)/po' && $(AUTOCONF)
	@mv -f '$(top_srcdir)/po/configure' '$@'

po-config.status: $(top_srcdir)/po-configure
	@if test -f config.log; then \
	  mv -f config.log config.main.log; \
	else \
	  true; \
	fi
	@SHELL@ '$(top_srcdir)/po-configure' $(ac_configure_args) --silent --no-create --no-recursion --disable-option-checking
	@mv -f config.log po-config.log
	@if test -f config.main.log; then \
	  mv -f config.main.log config.log; \
	else \
	  true; \
	fi

po/Makefile: $(top_srcdir)/po/Makefile.in.in $(top_srcdir)/po/Makevars $(top_builddir)/po-config.status $(top_srcdir)/po/POTFILES.in
	@$(am__cd) $(top_builddir) \
	  && @SHELL@ ./po-config.status po/Makefile.in po-directories

dist-po: po/Makefile
	@dir1="po"; dir2="$(distdir)/po"; \
	$(am__relativize); \
	rel_distsubdir=$$reldir; \
	echo "cd po && $(MAKE) $(AM_MAKEFLAGS) distdir='$$rel_distsubdir' distdir" && \
	$(am__cd) po && $(MAKE) $(AM_MAKEFLAGS) distdir="$$rel_distsubdir" distdir

$(top_srcdir)/po/POTFILES.in: $(top_srcdir)/src/microhttpd/Makefile.am
	@echo "cd src/microhttpd && $(MAKE) $(AM_MAKEFLAGS) update-po-POTFILES.in" && \
	$(am__cd) src/microhttpd && $(MAKE) $(AM_MAKEFLAGS) update-po-POTFILES.in

EXTRA_DIST += $(am__po_configure_deps) $(top_srcdir)/po/po-configure.ac.in $(top_srcdir)/po-configure
DISTCLEANFILES += config.main.log po-config.log

distclean-po:
	@if test -f po/Makefile; then \
	  $(am__cd) po && $(MAKE) $(AM_MAKEFLAGS) distclean; \
	else \
	  true; \
	fi
	-rm -f po-config.status po/Makefile
	-rm -f po/POTFILES po/remove-potcdate.sed po/Makefile.in

maintainer-clean-po:
	@if test -f po/Makefile; then \
	  $(am__cd) po && $(MAKE) $(AM_MAKEFLAGS) maintainer-clean; \
	else \
	  true; \
	fi
	-rm -f po/$(PACKAGE_TARNAME).pot po/stamp-po
	-rm -rf $(top_srcdir)/po/autom4te.cache

.PHONY: distclean-po maintainer-clean-po
