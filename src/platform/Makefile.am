AM_CPPFLAGS = \
  -I$(top_srcdir)/src/include \
  -I$(top_srcdir)/src/microhttpd

AM_CFLAGS = $(HIDDEN_VISIBILITY_CFLAGS) \
  @LIBGCRYPT_CFLAGS@

if USE_COVERAGE
  AM_CFLAGS += --coverage
endif

if HAVE_W32
lib_LIBRARIES = \
  libmicrohttpd_w32.a
libmicrohttpd_w32_a_CPPFLAGS = \
  $(AM_CPPFLAGS) \
  -DBUILDING_MHD_LIB=1
libmicrohttpd_w32_a_SOURCES = \
  w32functions.c
endif

