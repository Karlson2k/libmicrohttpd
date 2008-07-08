AM_CPPFLAGS = \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/lib \
-I$(top_srcdir)/lgl \
-I$(GCRYPT_CPPFLAGS)

noinst_LTLIBRARIES = libopencdk.la

libopencdk_la_LDFLAGS = -lgcrypt

libopencdk_la_SOURCES = armor.c filters.h main.c seskey.c types.h	\
	cipher.c kbnode.c main.h packet.h dummy.c sig-check.c verify.c	\
	compress.c keydb.c misc.c pubkey.c stream.c write-packet.c	\
	context.h literal.c new-packet.c read-packet.c stream.h opencdk.h
