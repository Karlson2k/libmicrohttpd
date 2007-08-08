SUBDIRS  = .

INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = \
  libmicrohttpd.la

libmicrohttpd_la_LDFLAGS = \
  -export-dynamic -version-info 0:0:0 
libmicrohttpd_la_SOURCES = \
  connection.c connection.h \
  daemon.c  \
  internal.c internal.h \
  memorypool.c memorypool.h \
  plibc.h \
  response.c response.h 

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
  daemontest_get \
  daemontest_post \
  daemontest_put \
  daemontest_post11 \
  daemontest_put11

TESTS = $(check_PROGRAMS)

daemontest_SOURCES = \
  daemontest.c
daemontest_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la 

daemontest_get_SOURCES = \
  daemontest_get.c
daemontest_get_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

daemontest_post_SOURCES = \
  daemontest_post.c
daemontest_post_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

daemontest_put_SOURCES = \
  daemontest_put.c
daemontest_put_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

daemontest_post11_SOURCES = \
  daemontest_post.c
daemontest_post11_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 


daemontest_put11_SOURCES = \
  daemontest_put.c
daemontest_put11_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

endif