if HAVE_CURL
curltests = testcurl
if HAVE_ZZUF
if HAVE_SOCAT
zzuftests = testzzuf
endif
endif
endif
if ENABLE_SPDY
# fixme: should test for spdylay before building testspdy!
microspdy = microspdy testspdy
endif

SUBDIRS = include microhttpd $(microspdy) examples $(curltests) $(zzuftests) . 

EXTRA_DIST = \
 datadir/cert-and-key.pem \
 datadir/cert-and-key-for-wireshark.pem
