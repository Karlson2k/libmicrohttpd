SUBDIRS = . 

AM_CPPFLAGS = -std=c99 \
-I$(top_srcdir)/src/include \
-I$(GCRYPT_CPPFLAGS)

# gc-gnulib.c

noinst_LTLIBRARIES = liblgl.la

liblgl_la_LDFLAGS = -lgcrypt
# liblgl_la_LIBADD = ./gc-libgcrypt.lo

liblgl_la_SOURCES = \
sha1.c \
gc-libgcrypt.c \
time_r.c \
rijndael-api-fst.c \
gc-pbkdf2-sha1.c \
read-file.c \
rijndael-alg-fst.c \
hmac-md5.c \
hmac-sha1.c \
realloc.c \
memxor.c \
memmem.c \
strverscmp.c \
md5.c \
des.c 

