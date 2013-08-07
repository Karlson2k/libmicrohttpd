if USE_PRIVATE_PLIBC_H
 PLIBC_INCLUDE = -I$(top_srcdir)/src/include/plibc
endif

AM_CPPFLAGS = \
  $(PLIBC_INCLUDE) \
  -I$(top_srcdir)/src/include \
  -I$(top_srcdir)/src/microspdy


EXTRA_DIST = EXPORT.sym


lib_LTLIBRARIES = \
  libmicrospdy.la

libmicrospdy_la_SOURCES = \
  io.h io.c \
  io_openssl.h io_openssl.c \
  io_raw.h io_raw.c \
  structures.h structures.c \
  internal.h internal.c \
  daemon.h daemon.c \
  stream.h stream.c \
  compression.h compression.c \
  session.h session.c \
  applicationlayer.c applicationlayer.h \
  alstructures.c alstructures.h 


libmicrospdy_la_LDFLAGS = \
  $(SPDY_LIB_LDFLAGS) 

libmicrospdy_la_CFLAGS = -Wextra \
  $(SPDY_LIB_CFLAGS)


if USE_COVERAGE
  AM_CFLAGS = --coverage
endif
