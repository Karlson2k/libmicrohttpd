SUBDIRS = .

AM_CPPFLAGS = \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src/daemon/ \
-I$(top_srcdir)/src/daemon/https \
-I$(top_srcdir)/src/daemon/https/tls \
-I$(top_srcdir)/src/daemon/https/lgl \
-I$(top_srcdir)/src/daemon/https/x509 \
-I$(top_srcdir)/src/daemon/https/openpgp \
-I$(top_srcdir)/src/daemon/https/opencdk \
-I$(GCRYPT_CPPFLAGS)

noinst_LTLIBRARIES = libtls.la

libtls_la_LDFLAGS = \
 -L$(GCRYPT_LIB_PATH)
 
libtls_la_SOURCES = \
auth_anon.c \
auth_cert.c \
auth_dh_common.c \
auth_dhe.c \
auth_rsa.c \
auth_rsa_export.c \
debug.c \
ext_cert_type.c \
ext_inner_application.c \
ext_max_record.c \
ext_oprfi.c \
ext_server_name.c \
gnutls_alert.c \
gnutls_algorithms.c \
gnutls_anon_cred.c \
gnutls_asn1_tab.c \
gnutls_auth.c \
gnutls_buffers.c \
gnutls_cert.c \
gnutls_cipher.c \
gnutls_cipher_int.c \
gnutls_compress.c \
gnutls_compress_int.c \
gnutls_constate.c \
gnutls_datum.c \
gnutls_db.c \
gnutls_dh.c \
gnutls_dh_primes.c \
gnutls_errors.c \
gnutls_extensions.c \
gnutls_extra_hooks.c \
gnutls_global.c \
gnutls_handshake.c \
gnutls_hash_int.c \
gnutls_kx.c \
gnutls_mem.c \
gnutls_mpi.c \
gnutls_num.c \
gnutls_pk.c \
gnutls_priority.c \
gnutls_record.c \
gnutls_rsa_export.c \
gnutls_session.c \
gnutls_session_pack.c \
gnutls_sig.c \
gnutls_state.c \
gnutls_str.c \
gnutls_supplemental.c \
gnutls_ui.c \
gnutls_x509.c \
pkix_asn1_tab.c \
x509_b64.c


