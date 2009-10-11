This directory contains a MHD_config.h that allows compilation on Symbian OS 9
with OpenC 1.6 (possibly earlier and later versions too) and plibc. It also
contains a Scons-for-Symbian (http://code.google.com/p/scons-for-symbian/)
SConstruct file that compiler the code into a static library, as an example
of how to use this. It assumes that plibc is checked out into <libmicrohttpd
directory>/../plibc.

Since Symbian lacks POSIX signals you need to run this in 'external select
loop' mode.
