# This Makefile.am is in the public domain

AM_CPPFLAGS = \
  -I$(srcdir)/../incl_priv \
  -I$(srcdir)/../include \
  $(CPPFLAGS_ac)

AM_CFLAGS = $(CFLAGS_ac)

if USE_COVERAGE
  AM_CFLAGS += --coverage
endif

AM_LDFLAGS = $(LDFLAGS_ac)

AM_TESTS_ENVIRONMENT = $(TESTS_ENVIRONMENT_ac)

lib_LTLIBRARIES = \
  libmicrohttpd2.la

noinst_DATA =
MOSTLYCLEANFILES =

libmicrohttpd2_la_SOURCES = \
  $(CONFIG_HEADER) \
  autoinit_funcs.h \
  sys_null_macro.h          sys_base_types.h          sys_bool_type.h \
  sys_sockets_types.h       sys_sockets_headers.h     sys_ip_headers.h \
  sys_errno.h               sys_malloc.h \
  sys_poll.h \
  sys_sendfile.h \
  compat_calloc.h \
  mhd_assert.h \
  mhd_tristate.h \
  mhd_socket_types.h        mhd_sockets_macros.h \
  mhd_sockets_funcs.c       mhd_sockets_funcs.h \
  mhd_iovec.h \
  mhd_panic.c               mhd_panic.h \
  mhd_lib_init.c            mhd_lib_init_impl.h       mhd_lib_init.h \
  mhd_dlinked_list.h \
  mhd_locks.h \
  mhd_itc.c                 mhd_itc.h                 mhd_itc_types.h \
  mhd_threads.c             mhd_threads.h             sys_thread_entry_type.h \
  mhd_mono_clock.c          mhd_mono_clock.h \
  mhd_mempool.c             mhd_mempool.h \
  mhd_daemon.h              daemon_funcs.c            daemon_funcs.h \
  mhd_public_api.h \
  events_process.c          events_process.h \
  daemon_logger.c           daemon_logger.h \
  daemon_logger_default.c   daemon_logger_default.h \
  daemon_options.h          daemon_set_options.c \
  daemon_create.c \
  daemon_start.c \
  daemon_add_conn.c         daemon_add_conn.h \
  mhd_connection.h          mhd_request.h             mhd_reply.h \
  response_from.c           response_from.h


if ! HAVE_SYS_CALLOC
libmicrohttpd2_la_SOURCES += \
  compat_calloc.c
endif


libmicrohttpd2_la_CPPFLAGS = \
  $(AM_CPPFLAGS) $(MHD_LIB_CPPFLAGS) $(MHD_TLS_LIB_CPPFLAGS) \
  -DBUILDING_MHD_LIB=1
libmicrohttpd2_la_CFLAGS = \
  $(AM_CFLAGS) $(MHD_LIB_CFLAGS) $(MHD_TLS_LIB_CFLAGS)
libmicrohttpd2_la_LDFLAGS = \
  $(AM_LDFLAGS) $(MHD_LIB_LDFLAGS) $(MHD_TLS_LIB_LDFLAGS) \
  $(W32_MHD_LIB_LDFLAGS) \
  -export-dynamic -no-undefined \
  -version-info @LIB_VERSION_CURRENT@:@LIB_VERSION_REVISION@:@LIB_VERSION_AGE@
libmicrohttpd2_la_LIBADD = \
  $(MHD_LIBDEPS) $(MHD_TLS_LIBDEPS)


AM_V_RC = $(am__v_RC_@AM_V@)
am__v_RC_ = $(am__v_RC_@AM_DEFAULT_V@)
am__v_RC_0 = @echo "  RC      " $@;
am__v_RC_1 = 

# General rule is not required, but keep it just in case
# Note: windres does not understand '-isystem' flag, so all
# possible '-isystem' flags are replaced by simple '-I' flags.
.rc.lo:
	$(AM_V_RC) RC_ALL_CPPFLAGS=`echo ' $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) ' | $(SED) -e 's/ -isystem / -I/g'`; \
          $(LIBTOOL) $(AM_V_lt) --tag=RC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(RC) $(RCFLAGS) $(DEFS) $${RC_ALL_CPPFLAGS} $< -o $@

# Note: windres does not understand '-isystem' flag, so all
# possible '-isystem' flags are replaced by simple '-I' flags.
libmicrohttpd2_la-w32_lib_res.lo: $(builddir)/w32_lib_res.rc
	$(AM_V_RC) RC_ALL_CPPFLAGS=`echo ' $(DEFAULT_INCLUDES) $(INCLUDES) $(libmicrohttpd_la_CPPFLAGS) $(CPPFLAGS) ' | $(SED) -e 's/ -isystem / -I/g'`; \
          $(LIBTOOL) $(AM_V_lt) --tag=RC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(RC) $(RCFLAGS) $(DEFS) $${RC_ALL_CPPFLAGS} $(builddir)/w32_lib_res.rc -o $@

if HAVE_W32
MHD_DLL_RES_LO = libmicrohttpd2_la-w32_lib_res.lo
else
MHD_DLL_RES_LO = 
endif

EXTRA_libmicrohttpd2_la_DEPENDENCIES = $(MHD_DLL_RES_LO)
libmicrohttpd2_la_LIBADD += $(MHD_DLL_RES_LO)

#TESTS = $(check_PROGRAMS)

update-po-POTFILES.in: $(top_srcdir)/po/POTFILES.in

$(top_srcdir)/po/POTFILES.in: $(srcdir)/Makefile.am
	@echo "Creating $@"
	@echo  src/include/microhttpd2.h > "$@" && \
	for src in $(am__libmicrohttpd2_la_SOURCES_DIST) ; do \
	  echo "$(subdir)/$$src" >> "$@" ; \
	done

.PHONY: update-po-POTFILES.in


$(CONFIG_HEADER): $(builddir)/../incl_priv/mhd_config.h.in $(top_srcdir)/configure $(top_builddir)/config.status
	@echo "cd $(srcdir)/../incl_priv && $(MAKE) $(AM_MAKEFLAGS) mhd_config.h" && \
	  $(am__cd) $(srcdir)/../incl_priv && $(MAKE) $(AM_MAKEFLAGS) mhd_config.h

$(builddir)/../incl_priv/mhd_config.h.in: $(top_srcdir)/configure.ac
	@echo "cd $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh" && \
	  $(am__cd) $(top_builddir) && $(MAKE) $(AM_MAKEFLAGS) am--refresh
