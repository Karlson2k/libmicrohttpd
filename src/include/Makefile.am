# This Makefile.am is in the public domain
SUBDIRS = .

MHD2DIR = $(srcdir)/../mhd2

DAEMON_GEN_FILES = \
  $(srcdir)/microhttpd2_inline_daemon_documentation.h.in \
  $(srcdir)/microhttpd2_generated_daemon_options.h \
  $(MHD2DIR)/daemon_options.h \
  $(MHD2DIR)/daemon_set_options.c

RESPONSE_GEN_FILES = \
  $(srcdir)/microhttpd2_inline_response_documentation.h.in \
  $(srcdir)/microhttpd2_generated_response_options.h \
  $(MHD2DIR)/response_options.h \
  $(MHD2DIR)/response_set_options.c

update-daemon-gen-files: $(DAEMON_GEN_FILES)

$(DAEMON_GEN_FILES): d_options.rec options-generator.c
	for f in $(DAEMON_GEN_FILES); do if test -f $$f; then chmod +w $$f; else :; fi; done
	$(MAKE) $(AM_MAKEFLAGS) options-generator
	./options-generator daemon > $(srcdir)/microhttpd2_generated_daemon_options.h
	chmod -w $(DAEMON_GEN_FILES)

update-response-gen-files: $(RESPONSE_GEN_FILES)

$(RESPONSE_GEN_FILES): r_options.rec options-generator.c
	for f in $(RESPONSE_GEN_FILES); do if test -f $$f; then chmod +w $$f; else :; fi; done
	$(MAKE) $(AM_MAKEFLAGS) options-generator
	./options-generator response > $(srcdir)/microhttpd2_generated_response_options.h
	chmod -w $(RESPONSE_GEN_FILES)

microhttpd2.h: microhttpd2_preamble.h.in microhttpd2_inline_daemon_documentation.h.in microhttpd2_inline_response_documentation.h.in microhttpd2_main.h.in microhttpd2_postamble.h.in
	rm -f $@
	cat $^ >$@
	chmod -w $@

noinst_PROGRAMS = \
  options-generator

options_generator_SOURCES = \
  options-generator.c

mhd2includedir = $(includedir)/mhd2

include_HEADERS = \
  microhttpd.h
mhd2include_HEADERS = \
  microhttpd2.h \
  microhttpd2_generated_daemon_options.h \
  microhttpd2_generated_response_options.h \
  microhttpd2_portability.h

noinst_HEADERS = \
  microhttpd_tls.h \
  microhttpd_ws.h

if HAVE_EXPERIMENTAL
include_HEADERS += microhttpd_ws.h
endif

EXTRA_DIST = \
  platform.h \
  autoinit_funcs.h \
  mhd_options.h \
  d_options.tmpl \
  d_options.rec \
  microhttpd2_generated_daemon_options.h \
  microhttpd2_generated_response_options.h \
  microhttpd2_portability.h \
  microhttpd2.h

.NOTPARALLEL:

.PHONY: update-daemon-gen-files update-response-gen-files
