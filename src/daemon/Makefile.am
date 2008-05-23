SUBDIRS  = .

INCLUDES = -I$(top_srcdir)/src/include

if HAVE_GNU_LD
 retaincommand=-Wl,--retain-symbols-file -Wl,$(srcdir)/SYMBOLS
endif

EXTRA_DIST = SYMBOLS

lib_LTLIBRARIES = \
  libmicrohttpd.la

libmicrohttpd_la_LDFLAGS = \
  -export-dynamic -version-info 4:2:0 $(retaincommand)
libmicrohttpd_la_SOURCES = \
  connection.c connection.h \
  reason_phrase.c reason_phrase.h \
  daemon.c  \
  internal.c internal.h \
  memorypool.c memorypool.h \
  plibc.h \
  postprocessor.c \
  response.c response.h 

check_PROGRAMS = \
  postprocessor_test \
  postprocessor_large_test \
  daemon_test 

TESTS = $(check_PROGRAMS)

daemon_test_SOURCES = \
  daemon_test.c
daemon_test_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la 

postprocessor_test_SOURCES = \
  postprocessor_test.c
postprocessor_test_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la 


postprocessor_large_test_SOURCES = \
  postprocessor_large_test.c
postprocessor_large_test_LDADD = \
  $(top_builddir)/src/daemon/libmicrohttpd.la 
