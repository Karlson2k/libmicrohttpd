SUBDIRS  = .

INCLUDES = -I$(top_srcdir)/src/include

if HAVE_GNU_LD
 retaincommand=-Wl,--retain-symbols-file -Wl,$(srcdir)/SYMBOLS
endif

EXTRA_DIST = SYMBOLS

lib_LTLIBRARIES = \
  libmicrohttpd.la

libmicrohttpd_la_LDFLAGS = \
  -export-dynamic -version-info 3:1:0 $(retaincommand)
libmicrohttpd_la_SOURCES = \
  connection.c connection.h \
  reason_phrase.c reason_phrase.h \
  daemon.c  \
  internal.c internal.h \
  memorypool.c memorypool.h \
  plibc.h \
  postprocessor.c \
  response.c response.h 

# example programs

noinst_PROGRAMS = minimal_example fileserver_example

minimal_example_SOURCES = \
 minimal_example.c 
minimal_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

fileserver_example_SOURCES = \
 fileserver_example.c 
fileserver_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 


# No curl, no testcases
if HAVE_CURL

check_PROGRAMS = \
  postprocessor_test \
  daemontest \
  daemontest_get \
  daemontest_post \
  daemontest_postform \
  daemontest_post_loop \
  daemontest_put \
  daemontest_large_put \
  daemontest_get11 \
  daemontest_post11 \
  daemontest_postform11 \
  daemontest_post_loop11 \
  daemontest_put11 \
  daemontest_large_put11 \
  daemontest_long_header \
  daemontest_get_chunked \
  daemontest_put_chunked 

TESTS = $(check_PROGRAMS)

daemontest_SOURCES = \
  daemontest.c
daemontest_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la 

postprocessor_test_SOURCES = \
  postprocessor_test.c
postprocessor_test_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la 

daemontest_get_SOURCES = \
  daemontest_get.c
daemontest_get_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

daemontest_get_chunked_SOURCES = \
  daemontest_get_chunked.c
daemontest_get_chunked_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

daemontest_post_SOURCES = \
  daemontest_post.c
daemontest_post_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

daemontest_postform_SOURCES = \
  daemontest_postform.c
daemontest_postform_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

daemontest_post_loop_SOURCES = \
  daemontest_post_loop.c
daemontest_post_loop_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

daemontest_put_SOURCES = \
  daemontest_put.c
daemontest_put_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

daemontest_put_chunked_SOURCES = \
  daemontest_put_chunked.c
daemontest_put_chunked_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

daemontest_get11_SOURCES = \
  daemontest_get.c
daemontest_get11_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

daemontest_post11_SOURCES = \
  daemontest_post.c
daemontest_post11_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

daemontest_postform11_SOURCES = \
  daemontest_postform.c
daemontest_postform11_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

daemontest_post_loop11_SOURCES = \
  daemontest_post_loop.c
daemontest_post_loop11_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

daemontest_put11_SOURCES = \
  daemontest_put.c
daemontest_put11_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 


daemontest_large_put_SOURCES = \
  daemontest_large_put.c
daemontest_large_put_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

daemontest_large_put11_SOURCES = \
  daemontest_large_put.c
daemontest_large_put11_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

daemontest_long_header_SOURCES = \
  daemontest_long_header.c
daemontest_long_header_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@ 

endif
