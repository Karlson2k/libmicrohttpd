SUBDIRS = .

AM_CPPFLAGS = \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src/daemon/https \
-I$(top_srcdir)/src/daemon/https/tls \
-I$(top_srcdir)/src/daemon/https/lgl \
-I$(top_srcdir)/src/daemon/https/x509 \
-I$(top_srcdir)/src/daemon \
$(LIBCURL_CPPFLAGS)

check_PROGRAMS = \
tls_session_time_out_test \
tls_cipher_change_test \
mhds_get_test \
tls_alert_test \
tls_authentication_test \
mhds_multi_daemon_test \
mhds_session_info_test 
   
TESTS = $(check_PROGRAMS)

tls_session_time_out_test_SOURCES = \
  tls_session_time_out_test.c
tls_session_time_out_test_LDADD  = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/daemon/libmicrohttpd.la

tls_cipher_change_test_SOURCES = \
  tls_cipher_change_test.c
tls_cipher_change_test_LDADD  = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/daemon/libmicrohttpd.la

tls_alert_test_SOURCES = \
  tls_alert_test.c
tls_alert_test_LDADD  = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/daemon/libmicrohttpd.la

tls_authentication_test_SOURCES = \
  tls_authentication_test.c
tls_authentication_test_LDADD  = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@

mhds_get_test_SOURCES = \
  mhds_get_test.c
mhds_get_test_LDADD = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@
  
mhds_session_info_test_SOURCES = \
  mhds_session_info_test.c
mhds_session_info_test_LDADD  = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@
  
mhds_multi_daemon_test_SOURCES = \
  mhds_multi_daemon_test.c
mhds_multi_daemon_test_LDADD  = \
  $(top_builddir)/src/testcurl/libcurl_version_check.a \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@  
