SUBDIRS = .

AM_CPPFLAGS = \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src/daemon/https/includes \
-I$(top_srcdir)/src/daemon/https/lgl \
-I$(top_srcdir)/src/daemon/https/x509 \
-I$(top_srcdir)/src/daemon/https/tls \
-I$(top_srcdir)/src/daemon/https/openpgp \
-I$(top_srcdir)/src/daemon/https/opencdk \
-I$(top_srcdir)/src/daemon/https/minitasn1

noinst_LTLIBRARIES = libopenpgp.la

# libopenpgp_la_LDFLAGS = -l$(top_srcdir)/src/daemon/https/libextra/.lib/libextra.la

libopenpgp_la_SOURCES = \
pgp_privkey.c \
compat.c \
pgp_verify.c \
extras.c \
pgp.c

# x libextra source list
libopenpgp_la_SOURCES += \
gnutls_openpgp.c \
gnutls_ia.c \
gnutls_extra.c
