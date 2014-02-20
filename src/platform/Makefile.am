AM_CPPFLAGS = \
  -I$(top_srcdir)/src/include

AM_CFLAGS = $(HIDDEN_VISIBILITY_CFLAGS) \
  @LIBGCRYPT_CFLAGS@

if USE_COVERAGE
  AM_CFLAGS += --coverage
endif

if HAVE_W32
noinst_LTLIBRARIES = \
  libmicrohttpd_w32.la
libmicrohttpd_w32_la_CPPFLAGS = \
  $(AM_CPPFLAGS) \
  -DBUILDING_MHD_LIB=1
libmicrohttpd_w32_la_SOURCES = \
  w32functions.c
endif

