# This Makefile.am is in the public domain

if BUILD_EXAMPLES
examplesdirs = examples examples2
else
examplesdirs = 
endif

SUBDIRS = incl_priv include mhd2 $(examplesdirs) tests .

if RUN_LIBCURL_TESTS
#SUBDIRS += testcurl
if RUN_ZZUF_TESTS
#SUBDIRS += testzzuf
endif
endif

# Finally (last!) also build experimental lib...
if HAVE_EXPERIMENTAL
SUBDIRS += microhttpd_ws
endif

if BUILD_TOOLS
#SUBDIRS += tools
endif

EXTRA_DIST = \
 datadir/cert-and-key.pem \
 datadir/cert-and-key-for-wireshark.pem

.NOTPARALLEL:
