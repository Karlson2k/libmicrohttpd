# This Makefile.am is in the public domain
SUBDIRS  = .

AM_CPPFLAGS = \
  -I$(top_srcdir)/src/include \
  $(CPPFLAGS_ac)

AM_CFLAGS = $(CFLAGS_ac)

AM_LDFLAGS = $(LDFLAGS_ac)

MHD_CPU_COUNT_DEF = -DMHD_CPU_COUNT=$(CPU_COUNT)

AM_TESTS_ENVIRONMENT = $(TESTS_ENVIRONMENT_ac)

LDADD = $(top_builddir)/src/mhd2/libmicrohttpd2.la

if USE_COVERAGE
  AM_CFLAGS += --coverage
endif

$(top_builddir)/src/mhd2/libmicrohttpd2.la: $(top_builddir)/src/mhd2/Makefile
	@echo ' cd $(top_builddir)/src/mhd2 && $(MAKE) $(AM_MAKEFLAGS) libmicrohttpd2.la'; \
	$(am__cd) $(top_builddir)/src/mhd2 && $(MAKE) $(AM_MAKEFLAGS) libmicrohttpd2.la


# example programs
noinst_PROGRAMS = \
  minimal_example2

minimal_example2_SOURCES = \
  minimal_example2.c
