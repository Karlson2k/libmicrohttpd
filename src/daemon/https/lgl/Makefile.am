SUBDIRS = . 

AM_CPPFLAGS = -std=c99 \
-I$(top_srcdir)/src/include \
-I$(GCRYPT_CPPFLAGS)

# gc-gnulib.c

noinst_LTLIBRARIES = liblgl.la

liblgl_la_LDFLAGS = -lgcrypt
# liblgl_la_LIBADD = ./gc-libgcrypt.lo

liblgl_la_SOURCES = \
sha1.c sha1.h \
gc-libgcrypt.c \
rijndael-api-fst.c rijndael-api-fst.h \
gc-pbkdf2-sha1.c gc.h \
rijndael-alg-fst.c rijndael-alg-fst.h \
hmac-md5.c hmac.h \
hmac-sha1.c \
memxor.c memxor.h\
strverscmp.c strverscmp.h \
md5.c md5.h \
des.c des.h

