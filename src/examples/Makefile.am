SUBDIRS  = .

AM_CPPFLAGS = -I$(top_srcdir)/src/include 

# example programs

noinst_PROGRAMS = \
https_server_example \
https_echo_server_example \
https_echo_client_example \
minimal_example \
querystring_example \
fileserver_example \
fileserver_example_external_select

minimal_example_SOURCES = \
 minimal_example.c 
minimal_example_LDADD = \
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

https_server_example_CPPFLAGS = \
 $(GNUTLS_CPPFLAGS) \
 -I$(top_srcdir)/src/daemon \
 -I$(top_srcdir)/src/include 
https_server_example_SOURCES = \
 https_server_example.c
https_server_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la
https_server_example_LDFLAGS = \
 -L$(GNUTLS_LIB_PATH) \
 -lgnutls

https_echo_server_example_CPPFLAGS = \
 $(GNUTLS_CPPFLAGS) \
 -I$(top_srcdir)/src/daemon \
 -I$(top_srcdir)/src/include 
https_echo_server_example_SOURCES = \
 https_echo_server_example.c
https_echo_server_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la
https_echo_server_example_LDFLAGS = \
 -L$(GNUTLS_LIB_PATH) \
 -lgnutls
 
https_echo_client_example_CPPFLAGS = \
 $(GNUTLS_CPPFLAGS) \
 -I$(top_srcdir)/src/daemon \
 -I$(top_srcdir)/src/include 
https_echo_client_example_SOURCES = \
 https_echo_client_example.c
https_echo_client_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la
https_echo_client_example_LDFLAGS = \
 -L$(GNUTLS_LIB_PATH) \
 -lgnutls


