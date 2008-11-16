SUBDIRS = .

if USE_COVERAGE
  AM_CFLAGS = -fprofile-arcs -ftest-coverage
endif

AM_CPPFLAGS = \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src/daemon/https \
-I$(top_srcdir)/src/daemon/https/minitasn1 \
-I$(top_srcdir)/src/daemon/https/lgl \
-I$(top_srcdir)/src/daemon/https/x509 \
-I$(top_srcdir)/src/daemon/https/tls

noinst_LTLIBRARIES = libx509.la

libx509_la_LDFLAGS = -lgcrypt 

libx509_la_SOURCES = \
common.c common.h \
crl.c \
dn.c dn.h \
extensions.c extensions.h \
mpi.c mpi.h \
pkcs12_encr.c pkcs12.h \
pkcs7.c pkcs7.h \
x509_privkey.c privkey.h \
privkey_pkcs8.c \
rfc2818_hostname.c rfc2818.h \
sign.c sign.h \
x509_verify.c verify.h \
x509.c x509.h

