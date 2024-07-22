# This Makefile.am is in the public domain
EMPTY_ITEM =

AM_CPPFLAGS = \
  -I$(top_srcdir)/src/include \
  -I$(top_srcdir)/src/mhd2 \
  -DMHD_CPU_COUNT=$(CPU_COUNT) \
  $(CPPFLAGS_ac)

AM_CFLAGS = $(CFLAGS_ac)

AM_LDFLAGS = $(LDFLAGS_ac)

AM_TESTS_ENVIRONMENT = $(TESTS_ENVIRONMENT_ac)

if USE_COVERAGE
  AM_CFLAGS += -fprofile-arcs -ftest-coverage
endif

LDADD = $(top_builddir)/src/mhd2/libmicrohttpd2.la

$(top_builddir)/src/mhd2/libmicrohttpd2.la: $(top_builddir)/src/mhd2/Makefile
	@echo ' cd $(top_builddir)/src/mhd2 && $(MAKE) $(AM_MAKEFLAGS) libmicrohttpd2.la'; \
	$(am__cd) $(top_builddir)/src/mhd2 && $(MAKE) $(AM_MAKEFLAGS) libmicrohttpd2.la

check_PROGRAMS = \
  test_create_destroy \
  test_create_start_destroy \
  test_create_destroy_ipv4 \
  test_create_start_destroy_ipv4 \
  test_create_destroy_ipv6 \
  test_create_start_destroy_ipv6_ipv4 \
  test_create_destroy_ipbest \
  test_create_start_destroy_ipbest \
  $(EMPTY_ITEM)

if MHD_USE_SELECT
check_PROGRAMS += \
  test_create_destroy_select \
  test_create_start_destroy_select \
  test_create_destroy_select_ipv4 \
  test_create_start_destroy_select_ipv4 \
  $(EMPTY_ITEM)
endif

if MHD_USE_POLL
check_PROGRAMS += \
  test_create_destroy_poll \
  test_create_start_destroy_poll \
  test_create_destroy_poll_ipv4 \
  test_create_start_destroy_poll_ipv4 \
  $(EMPTY_ITEM)
endif

if MHD_USE_EPOLL
check_PROGRAMS += \
  test_create_destroy_epoll \
  test_create_start_destroy_epoll \
  test_create_destroy_epoll_ipv4 \
  test_create_start_destroy_epoll_ipv4 \
  $(EMPTY_ITEM)
endif

if MHD_USE_THREADS
check_PROGRAMS += \
  test_create_destroy_int_thread \
  test_create_start_destroy_int_thread \
  test_create_start_destroy_int_thread_ipv4 \
  test_create_destroy_thread_per_conn \
  test_create_start_destroy_thread_per_conn \
  test_create_start_destroy_thread_per_conn_ipv4 \
  test_create_destroy_thread_pool \
  test_create_start_destroy_thread_pool \
  test_create_start_destroy_thread_pool_ipv4 \
  $(EMPTY_ITEM)

if MHD_USE_SELECT
check_PROGRAMS += \
  test_create_start_destroy_select_int_thread_ipv4 \
  test_create_start_destroy_select_thread_per_conn_ipv4 \
  $(EMPTY_ITEM)
endif

if MHD_USE_POLL
check_PROGRAMS += \
  test_create_start_destroy_poll_int_thread_ipv4 \
  test_create_start_destroy_poll_thread_per_conn_ipv4 \
  $(EMPTY_ITEM)
endif

if MHD_USE_EPOLL
check_PROGRAMS += \
  test_create_start_destroy_epoll_int_thread_ipv4 \
  test_create_start_destroy_epoll_thread_pool_ipv4 \
  $(EMPTY_ITEM)
endif

endif

if USE_IPV6_TESTING
check_PROGRAMS += \
  test_create_start_destroy_ipv6
endif

TESTS = $(check_PROGRAMS)

# The universal sources used in all tests
basic_test_sources = test_basic_checks.c

test_create_destroy_SOURCES = $(basic_test_sources)

test_create_start_destroy_SOURCES = $(basic_test_sources)

test_create_destroy_ipv4_SOURCES = $(basic_test_sources)

test_create_start_destroy_ipv4_SOURCES = $(basic_test_sources)

test_create_destroy_ipv6_SOURCES = $(basic_test_sources)

test_create_start_destroy_ipv6_SOURCES = $(basic_test_sources)

test_create_start_destroy_ipv6_ipv4_SOURCES = $(basic_test_sources)

test_create_destroy_ipbest_SOURCES = $(basic_test_sources)

test_create_start_destroy_ipbest_SOURCES = $(basic_test_sources)

test_create_destroy_select_SOURCES = $(basic_test_sources)

test_create_start_destroy_select_SOURCES = $(basic_test_sources)

test_create_destroy_select_ipv4_SOURCES = $(basic_test_sources)

test_create_start_destroy_select_ipv4_SOURCES = $(basic_test_sources)

test_create_destroy_poll_SOURCES = $(basic_test_sources)

test_create_start_destroy_poll_SOURCES = $(basic_test_sources)

test_create_destroy_poll_ipv4_SOURCES = $(basic_test_sources)

test_create_start_destroy_poll_ipv4_SOURCES = $(basic_test_sources)

test_create_destroy_epoll_SOURCES = $(basic_test_sources)

test_create_start_destroy_epoll_SOURCES = $(basic_test_sources)

test_create_destroy_epoll_ipv4_SOURCES = $(basic_test_sources)

test_create_start_destroy_epoll_ipv4_SOURCES = $(basic_test_sources)

test_create_destroy_int_thread_SOURCES = $(basic_test_sources)

test_create_start_destroy_int_thread_SOURCES = $(basic_test_sources)

test_create_start_destroy_int_thread_ipv4_SOURCES = $(basic_test_sources)

test_create_destroy_thread_per_conn_SOURCES = $(basic_test_sources)

test_create_start_destroy_thread_per_conn_SOURCES = $(basic_test_sources)

test_create_start_destroy_thread_per_conn_ipv4_SOURCES = $(basic_test_sources)

test_create_destroy_thread_pool_SOURCES = $(basic_test_sources)

test_create_start_destroy_thread_pool_SOURCES = $(basic_test_sources)

test_create_start_destroy_thread_pool_ipv4_SOURCES = $(basic_test_sources)

test_create_start_destroy_select_int_thread_ipv4_SOURCES = $(basic_test_sources)

test_create_start_destroy_select_thread_per_conn_ipv4_SOURCES = $(basic_test_sources)

test_create_start_destroy_poll_int_thread_ipv4_SOURCES = $(basic_test_sources)

test_create_start_destroy_poll_thread_per_conn_ipv4_SOURCES = $(basic_test_sources)

test_create_start_destroy_epoll_int_thread_ipv4_SOURCES = $(basic_test_sources)

test_create_start_destroy_epoll_thread_pool_ipv4_SOURCES = $(basic_test_sources)
