SUBDIRS = .

if USE_COVERAGE
  AM_CFLAGS = --coverage
endif

if USE_PRIVATE_PLIBC_H
 PLIBC_INCLUDE = -I$(top_srcdir)/src/include/plibc
endif

AM_CPPFLAGS = \
  $(PLIBC_INCLUDE) \
  -I$(top_srcdir)/src/include \
  -I$(top_srcdir)/src/microhttpd \
  $(LIBCURL_CPPFLAGS)

check_PROGRAMS = \
  test_tls_options \
  test_tls_authentication \
  test_https_multi_daemon \
  test_https_get \
  test_https_sni \
  test_https_get_select \
  test_https_get_parallel \
  test_https_get_parallel_threads \
  test_https_session_info \
  test_https_time_out \
  test_empty_response

EXTRA_DIST = cert.pem key.pem tls_test_keys.h tls_test_common.h

TESTS = \
  test_tls_options \
  test_https_multi_daemon \
  test_https_get \
  test_https_sni \
  test_https_get_select \
  test_https_get_parallel \
  test_https_get_parallel_threads \
  test_https_session_info \
  test_https_time_out \
  test_tls_authentication \
  test_empty_response


test_https_time_out_SOURCES = \
  test_https_time_out.c \
  tls_test_common.c
test_https_time_out_LDADD  = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/microhttpd/libmicrohttpd.la \
  @LIBCURL@ -lgnutls @LIBGCRYPT_LIBS@

test_tls_options_SOURCES = \
  test_tls_options.c \
  tls_test_common.c
test_tls_options_LDADD = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/microhttpd/libmicrohttpd.la \
  @LIBCURL@ -lgnutls @LIBGCRYPT_LIBS@

test_https_get_parallel_SOURCES = \
  test_https_get_parallel.c \
  tls_test_common.c
test_https_get_parallel_LDADD = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/microhttpd/libmicrohttpd.la \
  @LIBCURL@ -lgnutls @LIBGCRYPT_LIBS@

test_empty_response_SOURCES = \
  test_empty_response.c \
  tls_test_common.c
test_empty_response_LDADD = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/microhttpd/libmicrohttpd.la \
  @LIBCURL@ -lgnutls @LIBGCRYPT_LIBS@

test_https_get_parallel_threads_SOURCES = \
  test_https_get_parallel_threads.c \
  tls_test_common.c
test_https_get_parallel_threads_LDADD = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/microhttpd/libmicrohttpd.la \
  @LIBCURL@ -lgnutls @LIBGCRYPT_LIBS@

test_tls_authentication_SOURCES = \
  test_tls_authentication.c \
  tls_test_common.c
test_tls_authentication_LDADD  = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/microhttpd/libmicrohttpd.la \
  @LIBCURL@ -lgnutls @LIBGCRYPT_LIBS@

test_https_session_info_SOURCES = \
  test_https_session_info.c \
  tls_test_common.c
test_https_session_info_LDADD  = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/microhttpd/libmicrohttpd.la \
  @LIBCURL@ -lgnutls @LIBGCRYPT_LIBS@

test_https_multi_daemon_SOURCES = \
  test_https_multi_daemon.c \
  tls_test_common.c
test_https_multi_daemon_LDADD  = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/microhttpd/libmicrohttpd.la \
  @LIBCURL@ -lgnutls @LIBGCRYPT_LIBS@

test_https_get_SOURCES = \
  test_https_get.c \
  tls_test_common.c
test_https_get_LDADD  = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/microhttpd/libmicrohttpd.la \
  @LIBCURL@ -lgnutls @LIBGCRYPT_LIBS@

test_https_sni_SOURCES = \
  test_https_sni.c \
  tls_test_common.c
test_https_sni_LDADD  = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/microhttpd/libmicrohttpd.la \
  @LIBCURL@ -lgnutls @LIBGCRYPT_LIBS@

test_https_get_select_SOURCES = \
  test_https_get_select.c \
  tls_test_common.c
test_https_get_select_LDADD  = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/microhttpd/libmicrohttpd.la \
  @LIBCURL@ -lgnutls @LIBGCRYPT_LIBS@

