SUBDIRS  = .

INCLUDES = -I$(top_srcdir)/src/include

# example programs

noinst_PROGRAMS = minimal_example fileserver_example

minimal_example_SOURCES = \
 minimal_example.c 
minimal_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

fileserver_example_SOURCES = \
 fileserver_example.c 
fileserver_example_LDADD = \
 $(top_builddir)/src/daemon/libmicrohttpd.la 

