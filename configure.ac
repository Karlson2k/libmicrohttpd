dnl Process this file with autoconf to produce a configure script.
AC_INIT([libwebserver],[0.5.3-GNUnet],[bug-gnunet@gnu.org])
AM_INIT_AUTOMAKE([libwebserver], [0.5.3-GNUnet])
AC_CONFIG_HEADER([config.h])

AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h netinet/in.h stddef.h stdlib.h string.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_MEMCMP
AC_TYPE_SIGNAL
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([inet_ntoa memset select socket strchr strerror strncasecmp strstr strtol])

AC_SUBST(INCLUDE)
AC_SUBST(LIBDIR)
AC_SUBST(LIBS)

AC_CONFIG_FILES([Makefile 
src/Makefile
include/Makefile
])
AC_OUTPUT
