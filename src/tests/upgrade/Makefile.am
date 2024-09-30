# This Makefile.am is in the public domain
AM_CPPFLAGS = \
  -I$(top_srcdir)/src/include \
  -I$(top_srcdir)/src/incl_priv \
  -I$(top_srcdir)/src/mhd2 \
  -DMHD_CPU_COUNT=$(CPU_COUNT) \
  $(CPPFLAGS_ac) $(MHD_TLS_LIB_CPPFLAGS) 

AM_CFLAGS = $(CFLAGS_ac)

AM_LDFLAGS = $(LDFLAGS_ac) $(MHD_TLS_LIB_LDFLAGS)

AM_TESTS_ENVIRONMENT = $(TESTS_ENVIRONMENT_ac)

if USE_COVERAGE
  AM_CFLAGS += -fprofile-arcs -ftest-coverage
endif

LDADD = $(top_builddir)/src/mhd2/libmicrohttpd2.la

$(top_builddir)/src/mhd2/libmicrohttpd2.la: $(top_builddir)/src/mhd2/Makefile
	@echo ' cd $(top_builddir)/src/mhd2 && $(MAKE) $(AM_MAKEFLAGS) libmicrohttpd2.la'; \
	$(am__cd) $(top_builddir)/src/mhd2 && $(MAKE) $(AM_MAKEFLAGS) libmicrohttpd2.la

noinst_HEADERS = \
  test_helpers.h

check_PROGRAMS = \
  test_upgrade \
  test_upgrade_large \
  test_upgrade_vlarge \
  $(EMPTY_ITEM)

test_upgrade_SOURCES = test_upgrade.c

test_upgrade_large_SOURCES = $(test_upgrade_SOURCES)

test_upgrade_vlarge_SOURCES = $(test_upgrade_SOURCES)

TESTS = $(check_PROGRAMS)
