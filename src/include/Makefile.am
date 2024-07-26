# This Makefile.am is in the public domain
SUBDIRS = .

microhttpd2_inline_daemon_documentation.h.in microhttpd2_generated_daemon_options.h: d_options.rec options-generator
	rm -f microhttpd2_inline_daemon_documentation.h.in microhttpd2_generated_daemon_options.h
	./options-generator daemon > microhttpd2_generated_daemon_options.h
	chmod -w $@
microhttpd2_inline_response_documentation.h.in microhttpd2_generated_response_options.h: r_options.rec options-generator
	rm -f microhttpd2_inline_response_documentation.h.in microhttpd2_generated_response_options.h
	./options-generator response > microhttpd2_generated_response_options.h
	chmod -w $@

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
