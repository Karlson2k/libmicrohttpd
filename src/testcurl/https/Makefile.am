SUBDIRS = .

AM_CPPFLAGS = -ggdb \
-I$(top_srcdir)/src/daemon/https/includes \
-I$(top_srcdir)/src/daemon \
-I$(top_srcdir)/src/include

check_PROGRAMS = \
  daemon_https_test_get \
  mhds_test_session_info

TESTS = $(check_PROGRAMS)

daemon_https_test_get_SOURCES = \
  daemon_https_test_get.c
daemon_https_test_get_LDADD  = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@
  
mhds_test_session_info_SOURCES = \
  mhds_test_session_info.c
mhds_test_session_info_LDADD  = \
  $(top_builddir)/src/daemon/libmicrohttpd.la \
  @LIBCURL@
