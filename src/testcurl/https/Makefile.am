SUBDIRS = .

AM_CPPFLAGS = \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src/daemon/https/includes \
-I$(top_srcdir)/src/daemon


check_PROGRAMS = \
   tls_authentication_test \
   mhds_get_test \
   mhds_session_info_test \
   mhds_multi_daemon_test 

TESTS = $(check_PROGRAMS)

tls_authentication_test_SOURCES = \
  tls_authentication_test.c
tls_authentication_test_LDADD  = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@

mhds_get_test_SOURCES = \
  mhds_get_test.c
mhds_get_test_LDADD  = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@
  
mhds_session_info_test_SOURCES = \
  mhds_session_info_test.c
mhds_session_info_test_LDADD  = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@
  
mhds_multi_daemon_test_SOURCES = \
  mhds_multi_daemon_test.c
mhds_multi_daemon_test_LDADD  = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@  
