
AM_CPPFLAGS = -I./includes \
-I$(top_srcdir)/src/daemon/https/lgl \
-I$(top_srcdir)/src/daemon/https/tls \
-I$(top_srcdir)/src/daemon/https/includes 

noinst_LTLIBRARIES = libasn1.la

libasn1_la_SOURCES = \
libtasn1.h \
mem.h \
gstr.h \
errors.h \
int.h \
parser_aux.h structure.h element.h decoding.c gstr.c errors.c	\
parser_aux.c structure.c element.c coding.c
