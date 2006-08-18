SUBDIRS = .

INCLUDES = -I$(top_srcdir)/include

lib_LTLIBRARIES = libwebserver_gnunet.la

AM_CFLAGS = \
  -D_SERVER_VERSION="\"0.6.3-GNUnet\"" 

libwebserver_gnunet_la_SOURCES = \
 clientinfo.c \
 server.c \
 client.c \
 gethandler.c \
 memory.c \
 utils.c \
 fnmatch.c

libwebserver_gnunet_la_LDFLAGS = \
 -version-info 0:0:0

