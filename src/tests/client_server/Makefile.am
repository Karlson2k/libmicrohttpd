# This Makefile.am is in the public domain
EMPTY_ITEM =

AM_CPPFLAGS = \
  -I$(top_srcdir)/src/include \
  -I$(top_srcdir)/src/mhd2 \
  -DMHD_CPU_COUNT=$(CPU_COUNT) \
  $(CPPFLAGS_ac)

AM_CFLAGS = $(CFLAGS_ac)

AM_LDFLAGS = $(LDFLAGS_ac)

AM_TESTS_ENVIRONMENT = $(TESTS_ENVIRONMENT_ac)

if USE_COVERAGE
  AM_CFLAGS += -fprofile-arcs -ftest-coverage
endif

LDADD = $(top_builddir)/src/mhd2/libmicrohttpd2.la
LIBADD = $(top_builddir)/src/mhd2/libmicrohttpd2.la

$(top_builddir)/src/mhd2/libmicrohttpd2.la: $(top_builddir)/src/mhd2/Makefile
	@echo ' cd $(top_builddir)/src/mhd2 && $(MAKE) $(AM_MAKEFLAGS) libmicrohttpd2.la'; \
	$(am__cd) $(top_builddir)/src/mhd2 && $(MAKE) $(AM_MAKEFLAGS) libmicrohttpd2.la

check_PROGRAMS = \
  test_client_server

TESTS = $(check_PROGRAMS)


noinst_LTLIBRARIES = \
  libmhdt.la

libmhdt_la_SOURCES = \
  libtest.c libtest.h \
  libtest_convenience.c \
  libtest_convenience_client_request.c \
  libtest_convenience_server_reply.c
libmhdt_la_LIBADD = \
  -lpthread \
  -lcurl \
  $(LIBADD)

test_client_server_SOURCES = \
  test_client_server.c
test_client_server_LDADD = \
  libmhdt.la 
