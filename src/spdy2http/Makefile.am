SUBDIRS  = .

AM_CFLAGS = -DDATA_DIR=\"$(top_srcdir)/src/datadir/\"

if USE_COVERAGE
  AM_CFLAGS += -fprofile-arcs -ftest-coverage
endif

if USE_PRIVATE_PLIBC_H
 PLIBC_INCLUDE = -I$(top_srcdir)/src/include/plibc
endif

AM_CPPFLAGS = \
  $(PLIBC_INCLUDE) \
 -I$(top_srcdir) \
 -I$(top_srcdir)/src/include \
 -I$(top_srcdir)/src/applicationlayer \
$(LIBCURL_CPPFLAGS)

if !HAVE_W32
PERF_GET_CONCURRENT=perf_get_concurrent
endif

bin_PROGRAMS = \
 microspdy2http

microspdy2http_SOURCES = \
 proxy.c 
microspdy2http_LDADD = \
  $(top_builddir)/src/microspdy/libmicrospdy.la \
 -lssl \
 -lcrypto \
 -lz \
 -ldl \
 -lcurl
