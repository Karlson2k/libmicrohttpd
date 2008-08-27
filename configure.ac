# This file is part of libmicrohttpd.
# (C) 2006, 2007, 2008 Christian Grothoff (and other contributing authors)
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
AC_INIT([libmicrohttpd], [0.3.1],[libmicrohttpd@gnunet.org])
AM_INIT_AUTOMAKE([libmicrohttpd], [0.3.1])
AM_CONFIG_HEADER([MHD_config.h])

AH_TOP([#define _GNU_SOURCE  1])

# Checks for programs.
AC_PROG_AWK


AM_PROG_CC_C_O


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

# Check for optional headers
AC_CHECK_HEADERS([sys/select.h sys/types.h sys/time.h sys/msg.h netdb.h netinet/in.h time.h sys/socket.h sys/mman.h arpa/inet.h])

# libcurl (required for testing)
SAVE_LIBS=$LIBS
LIBCURL_CHECK_CONFIG(,,curl=1,curl=0)
AM_CONDITIONAL(HAVE_CURL, test x$curl = x1)
LIBS=$SAVE_LIBS

# Lib cURL & cURL - OpenSSL versions
MHD_REQ_CURL_VERSION=7.16.4
MHD_REQ_CURL_OPENSSL_VERSION=0.9.8
MHD_REQ_CURL_GNUTLS_VERSION=2.2.3
AC_DEFINE_UNQUOTED([MHD_REQ_CURL_VERSION], "$MHD_REQ_CURL_VERSION", [required cURL version to run tests])
AC_DEFINE_UNQUOTED([MHD_REQ_CURL_OPENSSL_VERSION], "$MHD_REQ_CURL_OPENSSL_VERSION", [required cURL SSL version to run tests])
AC_DEFINE_UNQUOTED([MHD_REQ_CURL_GNUTLS_VERSION], "$MHD_REQ_CURL_GNUTLS_VERSION", [gnuTLS lib version - used in conjunction with cURL])

# large file support (> 4 GB)
AC_SYS_LARGEFILE
AC_FUNC_FSEEKO

# optional: have error messages ?
AC_MSG_CHECKING(--enable-messages argument)
AC_ARG_ENABLE(messages,
   [AS_HELP_STRING([--enable-messages],
               [Enable MHD error messages])],
   [enable_messages=$enableval],
   [enable_messages="no"])
AC_MSG_RESULT($enable_messages)
if test "$enable_messages" = "yes"
then
 AC_DEFINE([HAVE_MESSAGES],[1],[Include error messages])
fi

# optional: compile TLS client side code [only for test running] ?
AC_MSG_CHECKING(--enable-client-side argument)
AC_ARG_ENABLE(client-side,
   [AS_HELP_STRING([--enable-client-side],
               [Compile client side code])],
   [enable_client_side=$enableval],
   [enable_client_side="no"])
AC_MSG_RESULT($enable_client_side)
if test "$enable_client_side" = "no"
then
 AC_DEFINE([MHD_DEBUG_TLS],[0],[Compile client side code. This will enable running some test cases.])
 MSG_CLIENT_SIDE="disabled. running some test cases won't be possible"
else
 AC_DEFINE([MHD_DEBUG_TLS],[1],[Compile client side code. This will enable running some test cases.])
 MSG_CLIENT_SIDE="enabled" 
fi
AM_CONDITIONAL(MHD_DEBUG_TLS, test "$enable_client_side" != "no")

# optional: have zzuf, socat?
AC_CHECK_PROG([HAVE_ZZUF],[zzuf], 1, 0)
AC_CHECK_PROG([HAVE_SOCAT],[socat], 1, 0)

AM_CONDITIONAL(HAVE_ZZUF, test 0 != $HAVE_ZZUF)
AM_CONDITIONAL(HAVE_SOCAT, test 0 != $HAVE_SOCAT)

# optional: HTTPS support. Included by default
AC_MSG_CHECKING(--enable-HTTPS argument)
AC_ARG_ENABLE([HTTPS],
   [AS_HELP_STRING([--enable-HTTPS],
               [enable HTTPS support (default is yes)])],
   [enable_HTTPS=$enableval],
   [enable_HTTPS="yes"])
AC_MSG_RESULT($enable_HTTPS)
if test "$enable_HTTPS" = "yes"
then
 AC_DEFINE([HTTPS_SUPPORT],[1],[include HTTPS support])
else
 AC_DEFINE([HTTPS_SUPPORT],[0],[disable HTTPS support])
fi
AM_CONDITIONAL(ENABLE_HTTPS, test "$enable_HTTPS" = "yes")

# optional: TLS support. Included by default
AC_MSG_CHECKING(--enable-TLS argument)
AC_ARG_ENABLE([TLS],
   [AS_HELP_STRING([--enable-TLS],
               [enable TLS support (default is yes)])],
   [enable_TLS=$enableval],
   [enable_TLS="yes"])
AC_MSG_RESULT($enable_TLS)


# optional: SSLv3 support. Exclude by default
AC_MSG_CHECKING(--enable-SSL argument)
AC_ARG_ENABLE([SSL],
   [AS_HELP_STRING([--enable-SSL],
               [enable SSLv3 support (default is no)])],
   [enable_SSL=$enableval],
   [enable_SSL="no"])
AC_MSG_RESULT($enable_SSL)


# optional: x509 certificate support. Include by default
AC_MSG_CHECKING(--enable-x509 argument)
AC_ARG_ENABLE([x509],
   [AS_HELP_STRING([--enable-x509],
               [enable x509 support (default is yes)])],
   [enable_x509=$enableval],
   [enable_x509="yes"])
AC_MSG_RESULT($enable_x509)


# Libgcrypt linkage : required for HTTPS support 
AC_CHECK_HEADERS(gcrypt.h,gcrypt=true,gcrypt=false)
AC_ARG_WITH(libgcrypt,
  [AS_HELP_STRING([--with-libgcrypt=PFX],
               [Base of libgcrypt installation])],
  [AC_MSG_RESULT("$with_libgcrypt")
   case $with_libgcrypt in
   no)
     gcrypt=false
     ;;
   yes)
     ;;
   *)
    LDFLAGS="-L$with_libgcrypt/lib $LDFLAGS"
    CPPFLAGS="-I$with_libgcrypt/include $CPPFLAGS"
    AC_CHECK_HEADERS(gcrypt.h,
     # check for 'gcry_prime_generate' in gcrypt.la
     AC_CHECK_LIB(gcrypt,gcry_prime_generate,
       GCRYPT_LIB_PATH="$with_libgcrypt/lib"
       GCRYPT_LDFLAGS="-L$with_libgcrypt/lib"
       GCRYPT_CPPFLAGS="-I$with_libgcrypt/include"
       gcrypt=true,
       gcrypt=false))
    LDFLAGS=$SAVE_LDFLAGS
    CPPFLAGS=$SAVE_CPPFLAGS
    ;;
   esac
  ],
  [AC_MSG_RESULT([--with_libgcrypt not specified])])

# define the minimal version of libgcrypt required   
MHD_GCRYPT_VERSION=1:1.2.4
AC_DEFINE_UNQUOTED([MHD_GCRYPT_VERSION], "$MHD_GCRYPT_VERSION", [gcrypt lib version])
  
AC_SUBST(GCRYPT_LIB_PATH)
AC_SUBST(GCRYPT_LDFLAGS)
AC_SUBST(GCRYPT_CPPFLAGS)

# Symbols required by GNU_TLS 
AC_DEFINE([ENABLE_MINITASN1],[1],[Include minitasn1 support])
AC_DEFINE([GNULIB_GC_HMAC_SHA1],[1],[GNULIB_GC_HMAC_SHA1])
AC_DEFINE([GNULIB_GC_RANDOM],[1],[GNULIB_GC_RANDOM])
AC_DEFINE([ENABLE_ANON],[1],[Enable anonymous authentication])
AC_DEFINE([ENABLE_PKI],[1],[Include PKI support])
AC_DEFINE([ENABLE_INCLUDED_OPENCDK],[1],[Include ENABLE_INCLUDED_OPENCDK support])
# gnutls debug support
AC_DEFINE([DEBUG],[1],[Include gnutls debug message support])
AC_DEFINE([C99_MACROS],[1],[Include gnutls debug message support])

AC_DEFINE([ENABLE_OPENSSL],[0],[Include ENABLE_OPENSSL support])
AC_DEFINE([HAVE_LD_OUTPUT_DEF],[0],[Include HAVE_LD_OUTPUT_DEF support])
AC_DEFINE([HAVE_LD_VERSION_SCRIPT],[0],[Include HAVE_LD_VERSION_SCRIPT support])


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
src/daemon/Makefile
src/daemon/https/Makefile
src/daemon/https/tls/Makefile
src/daemon/https/x509/Makefile
src/daemon/https/lgl/Makefile
src/daemon/https/minitasn1/Makefile
src/examples/Makefile
src/testcurl/Makefile
src/testcurl/https/Makefile
src/testzzuf/Makefile])
AC_OUTPUT

AM_CONDITIONAL(ENABLE_MINITASN1,  [test -n " " ] )
AM_CONDITIONAL(ENABLE_OPENSSL,  [test -n "" ] )
AM_CONDITIONAL(HAVE_LD_OUTPUT_DEF,  [test -n "" ] )
AM_CONDITIONAL(HAVE_LD_VERSION_SCRIPT,  [test -n "" ] )
AM_CONDITIONAL(ENABLE_INCLUDED_OPENCDK,  [test -n "" ] )

# Finally: summary
if test "$curl" != 1 ; then
 MSG_CURL="libcurl not found, building test won't be possible"
else
 MSG_CURL="${_libcurl_with}/lib"
fi
if test "$gcrypt" != true
then
 MSG_GCRYPT="libgcrypt not found, HTTPS supprot cannot be built"
else
 MSG_GCRYPT="${with_libgcrypt}/lib"
fi

AC_MSG_NOTICE([Configured to build curl/libcurl:
  Configuration Summery:
  
  os:                ${host_os}
  target dir:        ${prefix}
  messages:          ${enable_messages}
  HTTPS support:     ${enable_HTTPS}	
  TLS support:       ${enable_TLS}
  SSLv3 support:     ${enable_SSL}
  x509 support:      ${enable_x509}
  libgcrypt:         ${MSG_GCRYPT}
  
  # Testing
  libcurl:           ${MSG_CURL}
  client code dep.:  ${MSG_CLIENT_SIDE}    		
])

