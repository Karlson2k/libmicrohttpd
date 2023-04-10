#!/bin/bash

#
# This file creates dist tarball.
# Optional autotools patches are applied for better toolchains
# compatibility.
#
# Based on Debian SID baseline files as of April 2023.
#

if ! grep -Eq -e '^PRETTY_NAME="Debian GNU/Linux 12 \(bookworm\)"$' /etc/os-release
then
  echo "Only Debian 'bookworm' is supported by this script." >&2
  exit 1
fi

if ! autoconf --version | head -1 | grep -Eq -e ' 2\.71$' -
then
  echo "The only supported autoconf version is 2.71." >&2
  exit 1
fi


tooldir=$(dirname $BASH_SOURCE) || exit 2
test -n "$tooldir" || exit 2
cd "$tooldir" || exit 2
tooldir="$PWD" || exit 2
cd "${tooldir}/.." || exit 2
rootsrcdir="$PWD" || exit 2

# Cleanup sources
echo ''
echo '*** Performing initial cleanup...'
echo ''
if [[ ! -f 'Makefile' ]] || ! make maintainer-clean
then
  # Makefile needed for initial cleanup
  if [[ ! -f 'Makefile.in' ]] || [[ ! -f 'configure' ]] || ! ./configure || ! make maintainer-clean
  then
    rm -f po/Makefile || exit 3
    # Build 'configure' to build Makefile for initial cleanup
    autoreconf -fvi || exit 3
    ./configure || exit 3
    make maintainer-clean || exit 3
  fi
fi
echo ''
echo '** Initial cleanup completed.'
echo ''

# Copy latest autotools files
echo ''
echo '*** Copying autotools files...'
echo ''
autoreconf -fvi || exit 4
echo ''
echo '*** Performing intermediate cleanup...'
echo ''
./configure || exit 4
make distclean || exit 4
rm -f ./configure ./aclocal.m4 || exit 4
rm -rf ./autom4te.cache || exit 4
echo ''
echo '** Intermediate cleanup completed.'
echo ''

# Patching local autotools files
echo ''
echo '*** Performing patching of local autotools files...'
echo ''
"$tooldir/fixes-libtool/apply-all.sh" || exit 5
"$tooldir/fixes-autoconf/apply-all.sh" || exit 5
echo ''
echo '** Local autotools files patched.'
echo ''

# Build the configure and the related files with patches
echo ''
echo '*** Building patched configure and related files...'
echo ''
autoreconf -v || exit 6
echo ''
echo '** Patched build system ready.'
echo ''

# Build the configure and the related files with patches
echo ''
echo '*** Building dist tarball...'
echo ''
./configure || exit 7
make dist || exit 7
echo ''
echo '** Dist tarball ready.'
echo ''

exit 0
