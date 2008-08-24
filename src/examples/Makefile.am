SUBDIRS  = .

AM_CPPFLAGS = \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src/daemon/https

# example programs
noinst_PROGRAMS = \
authorization_example \
minimal_example \
querystring_example \
fileserver_example \
fileserver_example_external_select \
refuse_post_example

if ENABLE_HTTPS
noinst_PROGRAMS += https_server_example 
endif

minimal_example_SOURCES = \
 minimal_example.c 
minimal_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

authorization_example_SOURCES = \
 authorization_example.c 
authorization_example_LDADD = \
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

fileserver_example_external_select_SOURCES = \
 fileserver_example_external_select.c 
fileserver_example_external_select_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

https_server_example_SOURCES = \
https_server_example.c
https_server_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la
