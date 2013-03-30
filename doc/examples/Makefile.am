SUBDIRS  = .

if USE_PRIVATE_PLIBC_H
 PLIBC_INCLUDE = -I$(top_srcdir)/src/include/plibc
endif

AM_CPPFLAGS = \
  $(PLIBC_INCLUDE) \
  -I$(top_srcdir)/src/include \
  @LIBGCRYPT_CFLAGS@

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

# example programs
noinst_PROGRAMS = \
  basicauthentication \
  hellobrowser \
  logging \
  responseheaders 

if ENABLE_HTTPS
noinst_PROGRAMS += \
  tlsauthentication
endif
if HAVE_POSTPROCESSOR
noinst_PROGRAMS += simplepost largepost sessions 
endif

if HAVE_W32
IBERTY=-liberty
endif

basicauthentication_SOURCES = \
 basicauthentication.c 
basicauthentication_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

hellobrowser_SOURCES = \
 hellobrowser.c 
hellobrowser_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

logging_SOURCES = \
 logging.c 
logging_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la \
 $(IBERTY)

responseheaders_SOURCES = \
 responseheaders.c 
responseheaders_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

sessions_SOURCES = \
 sessions.c 
sessions_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

tlsauthentication_SOURCES = \
 tlsauthentication.c 
tlsauthentication_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

simplepost_SOURCES = \
 simplepost.c 
simplepost_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

largepost_SOURCES = \
 largepost.c 
largepost_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

