AM_CPPFLAGS = -I$(top_srcdir)/src/include \
-I$(top_srcdir)/src/daemon \
-I$(top_srcdir)/src/daemon/https/lgl \
-I$(top_srcdir)/src/daemon/https/x509 \
-I$(top_srcdir)/src/daemon/https/openpgp \
-I$(top_srcdir)/src/daemon/https/opencdk \
-I$(top_srcdir)/src/daemon/https/tls \
-I$(top_srcdir)/src/daemon/https/includes \
-I$(top_srcdir)/src/daemon/https/cfg \
-I$(GCRYPT_CPPFLAGS)

if HAVE_GNU_LD
 retaincommand=-Wl,--retain-symbols-file -Wl,$(srcdir)/SYMBOLS
endif

EXTRA_DIST = SYMBOLS

lib_LTLIBRARIES = \
  libmicrohttpd.la

SUBDIRS =
libmicrohttpd_la_LIBADD = 

if ENABLE_HTTPS
SUBDIRS += https .
libmicrohttpd_la_LIBADD += https/libhttps.la 
endif

libmicrohttpd_la_SOURCES = \
connection.c connection.h \
reason_phrase.c reason_phrase.h \
daemon.c  \
internal.c internal.h \
memorypool.c memorypool.h \
plibc.h \
postprocessor.c \
response.c response.h
libmicrohttpd_la_LDFLAGS = \
  -export-dynamic -version-info 4:3:0 $(retaincommand)
 
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
