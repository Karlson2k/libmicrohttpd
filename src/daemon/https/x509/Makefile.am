
AM_CPPFLAGS = \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src/daemon/https \
-I$(top_srcdir)/src/daemon/https/minitasn1 \
-I$(top_srcdir)/src/daemon/https/lgl \
-I$(top_srcdir)/src/daemon/https/x509 \
-I$(top_srcdir)/src/daemon/https/tls

noinst_LTLIBRARIES = libx509.la

libx509_la_LDFLAGS = -lgcrypt 
# -l $(top_srcdir)/src/daemon/https/lgl/liblgl.la

libx509_la_SOURCES = \
common.c \
crq.c \
crl.c \
dn.c \
dsa.c \
extensions.c \
mpi.c \
pkcs12_bag.c \
pkcs12.c \
pkcs12_encr.c \
pkcs7.c \
x509_privkey.c \
privkey_pkcs8.c \
rfc2818_hostname.c \
sign.c \
x509_verify.c \
x509.c 



