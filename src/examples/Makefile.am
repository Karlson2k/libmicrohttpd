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
authorization_example \
minimal_example \
minimal_example_comet \
querystring_example \
fileserver_example \
fileserver_example_dirs \
fileserver_example_external_select \
refuse_post_example

if ENABLE_HTTPS
noinst_PROGRAMS += https_fileserver_example 
endif

if ENABLE_DAUTH
noinst_PROGRAMS += digest_auth_example 
endif

minimal_example_SOURCES = \
 minimal_example.c 
minimal_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

minimal_example_comet_SOURCES = \
 minimal_example_comet.c 
minimal_example_comet_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

authorization_example_SOURCES = \
 authorization_example.c 
authorization_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

digest_auth_example_SOURCES = \
 digest_auth_example.c 
digest_auth_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

refuse_post_example_SOURCES = \
 refuse_post_example.c 
refuse_post_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

querystring_example_SOURCES = \
 querystring_example.c 
querystring_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

fileserver_example_SOURCES = \
 fileserver_example.c 
fileserver_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

fileserver_example_dirs_SOURCES = \
 fileserver_example_dirs.c 
fileserver_example_dirs_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

fileserver_example_external_select_SOURCES = \
 fileserver_example_external_select.c 
fileserver_example_external_select_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

https_fileserver_example_SOURCES = \
https_fileserver_example.c
https_fileserver_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la
