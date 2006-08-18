SUBDIRS = .

INCLUDES = -I$(top_srcdir)/src/include

lib_LTLIBRARIES = libwebserver_gnunet.la

AM_CFLAGS = \
  -D_SERVER_VERSION="\"0.6.3-GNUnet\""

libwebserver_gnunet_la_SOURCES = \
 clientinfo.c \
 server.c \
 client.c \
 gethandler.c \
 socket.c \
 memory.c \
 outstream.c \
 weblog.c \
 utils.c \
 fnmatch.c \
 outgif.c \
 error.c

libwebserver_gnunet_la_LDFLAGS = \
 -version-info 0:0:0

