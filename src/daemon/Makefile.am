SUBDIRS  = .

INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libmicrohttpd.la

libmicrohttpd_la_LDFLAGS = \
  -export-dynamic -version-info 0:0:0 
# libmicrohttpd_la_LIBADD = \
#  -lm
libmicrohttpd_la_SOURCES = \
  daemon.c 

# No curl, not testcases
if HAVE_CURL

check_PROGRAMS = \
  testdaemon

test_daemon_SOURCES = \
  testdaemon.c
test_daemon_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

endif