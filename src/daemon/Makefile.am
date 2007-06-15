SUBDIRS  = .

INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libmicrohttpd.la

libmicrohttpd_la_LDFLAGS = \
  -export-dynamic -version-info 0:0:0 
# libmicrohttpd_la_LIBADD = \
#  -lm
libmicrohttpd_la_SOURCES = \
  daemon.c  \
  internal.c internal.h \
  plibc.h \
  response.c response.h \
  session.c session.h


# example programs

noinst_PROGRAMS = minimal_example

minimal_example_SOURCES = \
 minimal_example.c 
minimal_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 


# No curl, no testcases
if HAVE_CURL

check_PROGRAMS = \
  daemontest \
  daemontest1

TESTS = $(check_PROGRAMS)

daemontest_SOURCES = \
  daemontest.c
daemontest_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la 

daemontest1_SOURCES = \
  daemontest1.c
daemontest1_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

endif