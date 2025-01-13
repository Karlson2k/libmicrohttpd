# This Makefile.am is in the public domain

SUBDIRS = basic

if MHD_SUPPORT_UPGRADE
SUBDIRS += upgrade
endif

if RUN_LIBCURL_TESTS
SUBDIRS += client_server
endif

.NOTPARALLEL:
