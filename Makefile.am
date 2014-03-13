ACLOCAL_AMFLAGS = -I m4
SUBDIRS = contrib src m4 .
EXTRA_DIST = acinclude.m4 libmicrohttpd.pc.in libmicrospdy.pc.in

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libmicrohttpd.pc libmicrospdy.pc

if BUILD_DOC
SUBDIRS += doc
endif
