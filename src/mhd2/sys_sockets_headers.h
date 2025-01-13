/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Evgeny Grin (Karlson2k)

  GNU libmicrohttpd is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  GNU libmicrohttpd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

*/

/**
 * @file src/mhd2/sys_sockets_headers.h
 * @brief  The header for system headers for the sockets and some basic macros
 * @author Karlson2k (Evgeny Grin)
 *
 * The macros are limited to simple local constants definitions
 */

#ifndef MHD_SYS_SOCKETS_HEADERS_H
#define MHD_SYS_SOCKETS_HEADERS_H 1

#include "mhd_sys_options.h"

#include "mhd_socket_type.h"

#ifdef MHD_SOCKETS_KIND_POSIX
#  include "sys_base_types.h" /* required on old platforms */
#  ifdef HAVE_SYS_SOCKET_H
#    include <sys/socket.h>
#  endif
#  ifdef HAVE_SOCKLIB_H
#    include <sockLib.h>
#  endif /* HAVE_SOCKLIB_H */
#elif defined(MHD_SOCKETS_KIND_WINSOCK)
#  include <winsock2.h>
#endif
#ifdef HAVE_SYS_UN_H
#  include <sys/un.h>
#endif

#if defined(SOCK_NONBLOCK) && ! defined(HAVE_DCLR_SOCK_NONBLOCK)
/* Mis-detected by configure */
#  define HAVE_DCLR_SOCK_NONBLOCK 1
#endif

#if defined(SOCK_CLOEXEC) && ! defined(HAVE_DCLR_SOCK_CLOEXEC)
/* Mis-detected by configure */
#  define HAVE_DCLR_SOCK_CLOEXEC 1
#endif

#if defined(SOCK_NOSIGPIPE) && ! defined(HAVE_DCLR_SOCK_NOSIGPIPE)
/* Mis-detected by configure */
#  define HAVE_DCLR_SOCK_NOSIGPIPE 1
#endif

#if defined(MSG_NOSIGNAL) && ! defined(HAVE_DCLR_MSG_NOSIGNAL)
/* Mis-detected by configure */
#  define HAVE_DCLR_MSG_NOSIGNAL 1
#endif

#if defined(MSG_MORE) && ! defined(HAVE_DCLR_MSG_MORE)
/* Mis-detected by configure */
#  define HAVE_DCLR_MSG_MORE 1
#endif

#if defined(SOL_SOCKET) && ! defined(HAVE_DCLR_SOL_SOCKET)
/* Mis-detected by configure */
#  define HAVE_DCLR_SOL_SOCKET 1
#endif

#if defined(SO_REUSEADDR) && ! defined(HAVE_DCLR_SO_REUSEADDR)
/* Mis-detected by configure */
#  define HAVE_DCLR_SO_REUSEADDR 1
#endif

#if defined(SO_REUSEPORT) && ! defined(HAVE_DCLR_SO_REUSEPORT)
/* Mis-detected by configure */
#  define HAVE_DCLR_SO_REUSEPORT 1
#endif

#if defined(SO_LINGER) && ! defined(HAVE_DCLR_SO_LINGER)
/* Mis-detected by configure */
#  define HAVE_DCLR_SO_LINGER 1
#endif

#if defined(SO_NOSIGPIPE) && ! defined(HAVE_DCLR_SO_NOSIGPIPE)
/* Mis-detected by configure */
#  define HAVE_DCLR_SO_NOSIGPIPE 1
#endif

#if defined(HAVE_DCLR_SOCK_NONBLOCK) && ! defined(MHD_SOCKETS_KIND_WINSOCK)
#  define mhd_SOCK_NONBLOCK SOCK_NONBLOCK
#else
#  define mhd_SOCK_NONBLOCK (0)
#endif

#if defined(HAVE_DCLR_SOCK_CLOEXEC) && ! defined(MHD_SOCKETS_KIND_WINSOCK)
#  define mhd_SOCK_CLOEXEC SOCK_CLOEXEC
#else
#  define mhd_SOCK_CLOEXEC (0)
#endif

#if defined(HAVE_DCLR_SOCK_NOSIGPIPE) && ! defined(MHD_SOCKETS_KIND_WINSOCK)
#  define mhd_SOCK_NOSIGPIPE SOCK_NOSIGPIPE
#else
#  define mhd_SOCK_NOSIGPIPE (0)
#endif

#if defined(HAVE_DCLR_MSG_NOSIGNAL) && ! defined(MHD_SOCKETS_KIND_WINSOCK)
#  define mhd_MSG_NOSIGNAL MSG_NOSIGNAL
#else
#  define mhd_MSG_NOSIGNAL (0)
#endif

#ifdef HAVE_DCLR_MSG_MORE
#  ifdef __linux__
/* MSG_MORE signal kernel to buffer outbond data and works like
 * TCP_CORK per call without actually setting TCP_CORK value.
 * It's known to work on Linux. Add more OSes if they are compatible. */
/**
 * Indicate MSG_MORE is usable for buffered send().
 */
#    define mhd_USE_MSG_MORE 1
#  endif /* __linux__ */
#endif /* MSG_MORE */

#ifdef mhd_USE_MSG_MORE
#  define mhd_MSG_MORE MSG_MORE
#else
#  define mhd_MSG_MORE (0)
#endif


/**
 * mhd_SCKT_OPT_BOOL is the type for bool parameters
 * for setsockopt()/getsockopt() functions
 */
#if defined(MHD_SOCKETS_KIND_POSIX)
#  define mhd_SCKT_OPT_BOOL int
#elif defined(MHD_SOCKETS_KIND_WINSOCK)
#  define mhd_SCKT_OPT_BOOL BOOL
#endif /* MHD_SOCKETS_KIND_WINSOCK */

/**
 * mhd_SCKT_SEND_SIZE is type used to specify size for send() and recv()
 * functions
 */
#if defined(MHD_SOCKETS_KIND_POSIX)
typedef size_t mhd_SCKT_SEND_SIZE;
#elif defined(MHD_SOCKETS_KIND_WINSOCK)
typedef int mhd_SCKT_SEND_SIZE;
#endif

/**
 * MHD_SCKT_SEND_MAX_SIZE_ is maximum send()/recv() size value.
 */
#if defined(MHD_SOCKETS_KIND_POSIX)
#  define MHD_SCKT_SEND_MAX_SIZE_ SSIZE_MAX
#elif defined(MHD_SOCKETS_KIND_WINSOCK)
#  define MHD_SCKT_SEND_MAX_SIZE_ (0x7FFFFFFF) /* INT_MAX */
#endif


#if defined(AF_UNIX) || defined(HAVE_DCLR_AF_UNIX)
#  define MHD_AF_UNIX AF_UNIX
#elif defined(AF_LOCAL) || defined(HAVE_DCLR_AF_LOCAL)
#  define MHD_AF_UNIX AF_LOCAL
#endif /* AF_UNIX */


#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || \
  defined(__OpenBSD__) || defined(__NetBSD__) || \
  defined(MHD_SOCKETS_KIND_WINSOCK) || defined(__MACH__) || defined(__sun) || \
  defined(SOMEBSD)
/* Most of the OSes inherit nonblocking setting from the listen socket */
#  define MHD_ACCEPTED_INHERITS_NONBLOCK 1
#elif defined(__gnu_linux__) || defined(__linux__)
#  define MHD_ACCEPTED_DOES_NOT_INHERIT_NONBLOCK 1
#endif


#if defined(HAVE_DCLR_SOL_SOCKET) && defined(HAVE_DCLR_SO_NOSIGPIPE)
/**
 * Helper for mhd_socket_nosignal()
 */
#  ifdef HAVE_COMPOUND_LITERALS_LVALUES
#    define mhd_socket_nosig_helper_int_one ((mhd_SCKT_OPT_BOOL){1})
#  else
/**
 * Internal static const helper for mhd_socket_nosignal()
 */
static const mhd_SCKT_OPT_BOOL mhd_socket_nosig_helper_int_one = 1;
#  endif

/**
 * Change socket options to no signal on remote disconnect / broken connection.
 *
 * @param sock socket to manipulate
 * @return non-zero if succeeded, zero otherwise
 */
#  define mhd_socket_nosignal(sock) \
        (! setsockopt ((sock),SOL_SOCKET,SO_NOSIGPIPE, \
                       &mhd_socket_nosig_helper_int_one, \
                       sizeof(mhd_SCKT_OPT_BOOL)))
#endif /* SOL_SOCKET && SO_NOSIGPIPE */


#if defined(mhd_socket_nosignal) || defined(HAVE_DCLR_MSG_NOSIGNAL)
/**
 * Indicate that SIGPIPE can be suppressed by MHD for normal send() by flags
 * or socket options.
 * If this macro is undefined, MHD cannot suppress SIGPIPE for socket functions
 * so application need to handle SIGPIPE.
 */
#  define mhd_SEND_SPIPE_SUPPRESS_POSSIBLE   1
#endif /* mhd_socket_nosignal || HAVE_DCLR_MSG_NOSIGNAL */


#endif /* ! MHD_SYS_SOCKETS_HEADERS_H */
