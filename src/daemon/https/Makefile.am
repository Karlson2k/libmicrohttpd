# placing '.' at the end of SUBDIRS having OPENPGP enabled mixes up build order !
SUBDIRS = minitasn1 lgl x509 tls 

if ENABLE_OPENPGP
SUBDIRS += opencdk openpgp
endif

#noinst_PROGRAMS = errcodes
#errcodes_SOURCES = errcodes.c
#errcodes_LDADD = ../lib/libgnutls.la $(LIBGCRYPT_LIBS) $(LIBTASN1_LIBS)

# gnutls_serv_SOURCES = serv.gaa serv-gaa.h serv-gaa.c list.h serv.c common.h common.c select.c
# srptool_SOURCES = crypt.gaa crypt-gaa.h crypt-gaa.c crypt.c
# gnutls_cli_debug_SOURCES = tls_test.gaa tls_test-gaa.h tls_test-gaa.c	\
#	tls_test.c tests.h tests.c common.h common.c
# certtool_SOURCES = certtool.gaa certtool-gaa.h certtool-cfg.h \
# certtool-gaa.c certtool.c prime.c certtool-cfg.c

EXTRA_DIST = gnutls.h
