SUBDIRS = . 

AM_CPPFLAGS = -std=c99 \
-I$(GCRYPT_CPPFLAGS)

# gc-gnulib.c

noinst_LTLIBRARIES = liblgl.la

liblgl_la_LDFLAGS = -lgcrypt
# liblgl_la_LIBADD = ./gc-libgcrypt.lo

liblgl_la_SOURCES = \
asnprintf.c \
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
memmem.c \
memmove.c \
memxor.c \
printf-args.c \
strverscmp.c \
snprintf.c \
asprintf.c \
vasprintf.c \
vasnprintf.c \
md5.c \
printf-parse.c \
des.c 
  