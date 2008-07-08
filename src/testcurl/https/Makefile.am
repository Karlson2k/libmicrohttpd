SUBDIRS = .

AM_CPPFLAGS = \
-I$(top_srcdir)/src/include \
-I$(top_srcdir)/src/daemon/https/includes \
-I$(top_srcdir)/src/daemon


check_PROGRAMS = \
  mhds_get_test \
  mhds_session_info_test

TESTS = $(check_PROGRAMS)

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
