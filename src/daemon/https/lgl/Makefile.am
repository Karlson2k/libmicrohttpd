AM_CPPFLAGS = \
  -I$(top_srcdir)/src/include 

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

noinst_LTLIBRARIES = liblgl.la

liblgl_la_LDFLAGS = -lgcrypt
liblgl_la_SOURCES = \
  gc-libgcrypt.c \
  gc.h 

