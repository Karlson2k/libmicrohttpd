SUBDIRS = minitasn1 opencdk openpgp lgl x509 tls . 

AM_CPPFLAGS = -I./includes \
-I$(top_srcdir)/src/daemon/https/lgl \
-I$(top_srcdir)/src/daemon/https/x509 \
-I$(top_srcdir)/src/daemon/https/openpgp \
-I$(top_srcdir)/src/daemon/https/opencdk \
-I$(top_srcdir)/src/daemon/https/tls \
-I$(top_srcdir)/src/daemon/https/includes \
-I$(top_srcdir)/src/daemon/https/cfg 

noinst_LTLIBRARIES = libhttps.la

libhttps_la_SOURCES = \
https_common.c \
errcodes.c 

libhttps_la_LIBADD = \
opencdk/libopencdk.la \
openpgp/libopenpgp.la \
x509/libx509.la \
lgl/liblgl.la \
tls/libtls.la \
minitasn1/libasn1.la
   
#noinst_PROGRAMS = errcodes
#errcodes_SOURCES = errcodes.c
#errcodes_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS) $(LIBTASN1_LIBS)

# gnutls_serv_SOURCES = serv.gaa serv-gaa.h serv-gaa.c list.h serv.c common.h common.c select.c
# srptool_SOURCES = crypt.gaa crypt-gaa.h crypt-gaa.c crypt.c
# gnutls_cli_debug_SOURCES = tls_test.gaa tls_test-gaa.h tls_test-gaa.c	\
#	tls_test.c tests.h tests.c common.h common.c
# certtool_SOURCES = certtool.gaa certtool-gaa.h certtool-cfg.h \
# certtool-gaa.c certtool.c prime.c certtool-cfg.c
