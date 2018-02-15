# This Makefile.am is in the public domain
AM_CPPFLAGS = \
  -I$(top_srcdir)/src/include \
  -I$(top_srcdir)/src/lib

AM_CFLAGS = $(HIDDEN_VISIBILITY_CFLAGS)

lib_LTLIBRARIES = \
  libmicrohttpd.la

noinst_DATA =
MOSTLYCLEANFILES =

if W32_SHARED_LIB_EXP
W32_MHD_LIB_LDFLAGS = -Wl,--output-def,$(lt_cv_objdir)/libmicrohttpd.def -XCClinker -static-libgcc
noinst_DATA += $(lt_cv_objdir)/libmicrohttpd.lib $(lt_cv_objdir)/libmicrohttpd.def $(lt_cv_objdir)/libmicrohttpd.exp
MOSTLYCLEANFILES += $(lt_cv_objdir)/libmicrohttpd.lib $(lt_cv_objdir)/libmicrohttpd.def $(lt_cv_objdir)/libmicrohttpd.exp

$(lt_cv_objdir)/libmicrohttpd.def: libmicrohttpd.la

$(lt_cv_objdir)/libmicrohttpd.exp: $(lt_cv_objdir)/libmicrohttpd.lib

$(lt_cv_objdir)/libmicrohttpd.lib: $(lt_cv_objdir)/libmicrohttpd.def libmicrohttpd.la $(libmicrohttpd_la_OBJECTS)
if USE_MS_LIB_TOOL
	@echo Creating $@ and libmicrohttpd.exp by $(MS_LIB_TOOL)... && \
	dll_name=`$(EGREP) -o dlname=\'.+\' libmicrohttpd.la` && \
	dll_name=$${dll_name#*\'} && dll_name=$${dll_name%\'} && test -n "$$dll_name" && \
	echo Creating $$dll_name by $(MS_LIB_TOOL).. && cd "$(lt_cv_objdir)" && \
	$(MS_LIB_TOOL) -def:libmicrohttpd.def -name:$$dll_name -out:libmicrohttpd.lib $(libmicrohttpd_la_OBJECTS:.lo=.o) && cd ..
else
	@echo Creating $@ and libmicrohttpd.exp by $(DLLTOOL)... && \
	dll_name=`$(EGREP) -o dlname=\'.+\' libmicrohttpd.la` && \
	dll_name=$${dll_name#*\'} && dll_name=$${dll_name%\'} && test -n "$$dll_name" && \
	echo Creating $$dll_name by $(DLLTOOL).. && cd "$(lt_cv_objdir)" && \
	$(DLLTOOL) -d ./libmicrohttpd.def -D $$dll_name -l libmicrohttpd.lib $(libmicrohttpd_la_OBJECTS:.lo=.o) -e ./libmicrohttpd.exp && cd .. &&\
	echo Created libmicrohttpd.exp and libmicrohttpd.lib.
endif
else
  W32_MHD_LIB_LDFLAGS =
endif

if W32_STATIC_LIB
noinst_DATA += $(lt_cv_objdir)/libmicrohttpd-static.lib
MOSTLYCLEANFILES += $(lt_cv_objdir)/libmicrohttpd-static.lib

$(lt_cv_objdir)/libmicrohttpd-static.lib: libmicrohttpd.la $(libmicrohttpd_la_OBJECTS)
if USE_MS_LIB_TOOL
	$(MS_LIB_TOOL) -out:$@ $(libmicrohttpd_la_OBJECTS:.lo=.o)
else
	cp $(lt_cv_objdir)/libmicrohttpd.a $@
endif
endif


libmicrohttpd_la_SOURCES = \
  action_continue.c \
  action_from_response.c \
  action_parse_post.c \
  action_process_upload.c \
  action_suspend.c \
  connection_add.c connection_add.h \
  connection_info.c \
  connection_options.c \
  daemon_create.c \
  daemon_destroy.c \
  daemon_epoll.c daemon_epoll.h \
  daemon_get_timeout.c \
  daemon_info.c \
  daemon_ip_limit.c daemon_ip_limit.h \
  daemon_options.c \
  daemon_poll.c daemon_poll.h \
  daemon_run.c \
  daemon_select.c daemon_select.h \
  daemon_start.c \
  daemon_quiesce.c \
  init.c init.h \
  internal.c internal.h \
  memorypool.c memorypool.h \
  mhd_assert.h \
  mhd_byteorder.h \
  mhd_compat.c mhd_compat.h \
  mhd_itc.c mhd_itc.h mhd_itc_types.h \
  mhd_limits.h \
  mhd_locks.h \
  mhd_mono_clock.c mhd_mono_clock.h \
  mhd_str.c mhd_str.h \
  mhd_sockets.c mhd_sockets.h \
  mhd_threads.c mhd_threads.h \
  response.c \
  response_for_upgrade.c \
  response_from_buffer.c \
  response_from_callback.c \
  response_from_fd.c \
  response_options.c \
  reason_phrase.c \
  request.c \
  request_info.c \
  request_resume.c \
  sysfdsetsize.c sysfdsetsize.h \
  panic.c \
  version.c 



libmicrohttpd_la_CPPFLAGS = \
  $(AM_CPPFLAGS) $(MHD_LIB_CPPFLAGS) \
  -DBUILDING_MHD_LIB=1
libmicrohttpd_la_CFLAGS = \
  $(AM_CFLAGS) $(MHD_LIB_CFLAGS)
libmicrohttpd_la_LDFLAGS = \
  $(MHD_LIB_LDFLAGS) \
  $(W32_MHD_LIB_LDFLAGS) \
  -version-info 666:0:0 # FIXME: fix once closer to release...
libmicrohttpd_la_LIBADD = \
  $(MHD_LIBDEPS) # FIXME: should separate out GNUTLS_LIBS/GCRYPT here!

if HAVE_W32
MHD_DLL_RES_SRC = microhttpd_dll_res.rc
MHD_DLL_RES_LO = libmicrohttpd_la-$(MHD_DLL_RES_SRC:.rc=.lo)

EXTRA_libmicrohttpd_la_DEPENDENCIES = $(MHD_DLL_RES_LO)
libmicrohttpd_la_LIBADD += $(MHD_DLL_RES_LO)

# General rule is not required, but keep it just in case
.rc.lo:
	$(LIBTOOL) $(AM_V_lt) --tag=RC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(RC) $(RCFLAGS) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) $< -o $@

# To add dll resource only to .dll file and exclude it form static
# lib, a little trick was used. Allow libtool to create file.lo,
# file.o and .libs/file.lo, .libs/file.o files, then overwrite file.o
# by empty object generated from empty c-file. Later libtool will
# use .libs/file.o for shared lib and empty file.o for static lib.
# This implementation is based on trick found in liblzma.
# Note: windres does not understand '-isystem' flag, so all
# possible '-isystem' flags are replaced by simple '-I' flags.
$(MHD_DLL_RES_LO): $(MHD_DLL_RES_SRC)
	RC_CPP_FLAGS=" $(DEFAULT_INCLUDES) $(INCLUDES) $(libmicrohttpd_la_CPPFLAGS) $(CPPFLAGS) " && \
	$(LIBTOOL) $(AM_V_lt) --tag=RC $(AM_LIBTOOLFLAGS) $(LIBTOOLFLAGS) --mode=compile $(RC) $(RCFLAGS) $(DEFS) $${RC_CPP_FLAGS// -isystem / -I } $< -o $@ && \
	echo > $@-empty.c && $(CC) $(AM_CFLAGS) $(CFLAGS) -c $@-empty.c -o $(@:.lo=.o) && rm -f $@-empty.c
endif

if USE_COVERAGE
  AM_CFLAGS += --coverage
endif

if !MHD_HAVE_TSEARCH
libmicrohttpd_la_SOURCES += \
  tsearch.c tsearch.h
endif

# TBD!
if HAVE_POSTPROCESSOR
#libmicrohttpd_la_SOURCES += \
#  postprocessor.c
endif

# TBD!
if ENABLE_DAUTH
#libmicrohttpd_la_SOURCES += \
#  digestauth.c \
#  md5.c md5.h
endif

# TBD!
if ENABLE_BAUTH
#libmicrohttpd_la_SOURCES += \
#  basicauth.c \
#  base64.c base64.h
endif





