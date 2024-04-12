# This Makefile.am is in the public domain
SUBDIRS = .

d_options.json: options.tmpl d_options.rec
	recfmt -f options.tmpl < d_options.rec | sed -e "s/,*]/]/g" -e "s/\(,\"\"\)*]/]/" -e "s/\[\"\"\]/\[\]/" -e '0,/./i{' -e '$$a"end":""}' -e 's/\"\"/null/' | gawk -v RS='"' 'NR % 2 == 0 { gsub(/\n/, "\\n") } { printf("%s%s", $$0, RT) }' | jq 'del(..|nulls)' > d_options.json

r_options.json: options.tmpl r_options.rec
	recfmt -f options.tmpl < r_options.rec | sed -e "s/,*]/]/g" -e "s/\(,\"\"\)*]/]/" -e "s/\[\"\"\]/\[\]/" -e '0,/./i{' -e '$$a"end":""}' -e 's/\"\"/null/' | gawk -v RS='"' 'NR % 2 == 0 { gsub(/\n/, "\\n") } { printf("%s%s", $$0, RT) }' | jq 'del(..|nulls)' > r_options.json

microhttpd2_inline_daemon_documentation.h.in microhttpd2_generated_daemon_options.h: d_options.json options-generator
	rm -f microhttpd2_inline_daemon_documentation.h.in microhttpd2_generated_daemon_options.h
	./options-generator daemon > microhttpd2_generated_daemon_options.h
	chmod -w $@
microhttpd2_inline_response_documentation.h.in microhttpd2_generated_response_options.h: r_options.json options-generator
	rm -f microhttpd2_inline_response_documentation.h.in microhttpd2_generated_response_options.h
	./options-generator response > microhttpd2_generated_response_options.h
	chmod -w $@

microhttpd2.h: microhttpd2_preamble.h.in microhttpd2_inline_daemon_documentation.h.in microhttpd2_inline_response_documentation.h.in microhttpd2_main.h.in microhttpd2_postamble.h.in
	rm -f $@
	cat $^ >$@
	chmod -w $@

# TODO: make conditional on 'libjansson' being available!
noinst_PROGRAMS = \
  options-generator

options_generator_SOURCES = \
 options-generator.c
options_generator_LDADD = \
  -ljansson

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
