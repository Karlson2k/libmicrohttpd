# This file is part of libmicrohttpd.
# (C) 2006, 2007 Christian Grothoff (and other contributing authors)
#
# libmicrohttpd is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 2, or (at your
# option) any later version.
#
# libmicrohttpd is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with libmicrohttpd; see the file COPYING.  If not, write to the
# Free Software Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA 02111-1307, USA.
#
#
# Process this file with autoconf to produce a configure script.
#
#
AC_PREREQ(2.57)
AC_INIT([libmicrohttpd], [0.2.1],[libmicrohttpd@gnunet.org])
AM_INIT_AUTOMAKE([libmicrohttpd], [0.2.1])
AM_CONFIG_HEADER([config.h])

AH_TOP([#define _GNU_SOURCE  1])

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_CANONICAL_HOST
AC_PROG_LIBTOOL

# set GCC options
# use '-fno-strict-aliasing', but only if the compiler can take it
if gcc -fno-strict-aliasing -S -o /dev/null -xc /dev/null >/dev/null 2>&1; 
then
 CFLAGS="-fno-strict-aliasing $CFLAGS"
fi

# Check system type
case "$host_os" in
*darwin* | *rhapsody* | *macosx*)
     AC_DEFINE_UNQUOTED(OSX,1,[This is an OS X system])
     CFLAGS="-no-cpp-precomp $CFLAGS"
     LDFLAGS="-flat_namespace -undefined suppress $LDFLAGS"
     AM_CONDITIONAL(HAVE_GNU_LD, false)    
     ;;
linux*)
     AC_DEFINE_UNQUOTED(LINUX,1,[This is a Linux system])
     AM_CONDITIONAL(HAVE_GNU_LD, true)    
     ;;
freebsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(FREEBSD,1,[This is a FreeBSD system])
     AM_CONDITIONAL(HAVE_GNU_LD, true)    
     CFLAGS="-D_THREAD_SAFE $CFLAGS"
     ;;
openbsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(OPENBSD,1,[This is an OpenBSD system])
     AM_CONDITIONAL(HAVE_GNU_LD, true)    
     ;;
netbsd*)
     AC_DEFINE_UNQUOTED(SOMEBSD,1,[This is a BSD system])
     AC_DEFINE_UNQUOTED(NETBSD,1,[This is a NetBSD system])
     AM_CONDITIONAL(HAVE_GNU_LD, true)    
     ;;
*solaris*)
     AC_DEFINE_UNQUOTED(SOLARIS,1,[This is a Solaris system])
     AC_DEFINE_UNQUOTED(_REENTRANT,1,[Need with solaris or errno doesnt work])
     AM_CONDITIONAL(HAVE_GNU_LD, false)    
     ;;
*arm-linux*)
     AC_DEFINE_UNQUOTED(LINUX,1,[This is a Linux system])
     CFLAGS="-D_REENTRANT -fPIC -pipe $CFLAGS"
     AM_CONDITIONAL(HAVE_GNU_LD, true)    
     ;;
*cygwin*)
     AC_DEFINE_UNQUOTED(CYGWIN,1,[This is a Cygwin system])
     AC_DEFINE_UNQUOTED(WINDOWS,1,[This is a Windows system])
     AM_CONDITIONAL(HAVE_GNU_LD, false)    
     LDFLAGS="$LDFLAGS -no-undefined"
     ;;
*mingw*)
     AC_DEFINE_UNQUOTED(MINGW,1,[This is a MinGW system])
     AC_DEFINE_UNQUOTED(WINDOWS,1,[This is a Windows system])
     LDFLAGS="$LDFLAGS -no-undefined -Wl,--export-all-symbols -lws2_32 -lplibc"
     AM_CONDITIONAL(HAVE_GNU_LD, true)    
     ;;
*)
     AC_MSG_RESULT(Unrecognised OS $host_os)
     AC_DEFINE_UNQUOTED(OTHEROS,1,[Some strange OS])
     AM_CONDITIONAL(HAVE_GNU_LD, false)    
;;
esac

CHECK_PTHREAD
LIBS="$PTHREAD_LIBS $LIBS"
AC_SUBST(PTHREAD_LIBS)
AC_SUBST(PTHREAD_LDFLAGS)
AC_SUBST(PTHREAD_CPPFLAGS)

# Check for headers that are ALWAYS required
AC_CHECK_HEADERS([fcntl.h math.h errno.h limits.h stdio.h locale.h sys/stat.h sys/types.h pthread.h],,AC_MSG_ERROR([Compiling libmicrohttpd requires standard UNIX headers files]))


# libcurl (required for testing)
SAVE_LIBS=$LIBS
LIBCURL_CHECK_CONFIG(,,curl=1,curl=0)
AM_CONDITIONAL(HAVE_CURL, test x$curl = x1)
LIBS=$SAVE_LIBS


# large file support (> 4 GB)
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO


# optional: have error messages?
AC_MSG_CHECKING(--enable-messages argument)
AC_ARG_ENABLE(messages,
   [  --enable-messages 	Enable MHD error messages],
   [enable_messages=$enableval],
   [enable_messages="no"])
AC_MSG_RESULT($enable_messages)
if test "$enable_messages" = "yes"
then
 AC_DEFINE([HAVE_MESSAGES],[1],[Include error messages])
fi


AC_SUBST(CPPFLAGS)
AC_SUBST(LIBS)
AC_SUBST(LDFLAGS)
AC_SUBST(EXT_LIB_PATH)
AC_SUBST(EXT_LIBS)

AC_CONFIG_FILES([ 
Makefile
doc/Makefile
m4/Makefile
src/Makefile
src/include/Makefile
src/daemon/Makefile])
AC_OUTPUT

if test "$curl" != 1
then
 AC_MSG_NOTICE([WARNING: libcurl not found, testcases cannot be built.])
fi
