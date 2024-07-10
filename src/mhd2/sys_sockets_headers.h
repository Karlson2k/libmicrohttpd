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

#ifdef MHD_POSIX_SOCKETS
#  include "sys_base_types.h" /* required on old platforms */
#  ifdef HAVE_SYS_SOCKET_H
#    include <sys/socket.h>
#  endif
#  ifdef HAVE_SOCKLIB_H
#    include <sockLib.h>
#  endif /* HAVE_SOCKLIB_H */
#elif defined(MHD_WINSOCK_SOCKETS)
#  include <winsock2.h>
#endif
#ifdef HAVE_SYS_UN_H
#  include <sys/un.h>
#endif

#if defined(HAVE_SOCK_NONBLOCK) && ! defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SOCK_NONBLOCK SOCK_NONBLOCK
#else
#  define mhd_SOCK_NONBLOCK (0)
#endif

#if defined(SOCK_CLOEXEC) && ! defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SOCK_CLOEXEC SOCK_CLOEXEC
#else
#  define mhd_SOCK_CLOEXEC (0)
#endif

#if defined(SOCK_NOSIGPIPE) && ! defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SOCK_NOSIGPIPE SOCK_NOSIGPIPE
#else
#  define mhd_SOCK_NOSIGPIPE (0)
#endif

#if defined(MSG_NOSIGNAL) && ! defined(MHD_WINSOCK_SOCKETS)
#  define mhd_MSG_NOSIGNAL MSG_NOSIGNAL
#else
#  define mhd_MSG_NOSIGNAL (0)
#endif

#ifdef MSG_MORE
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
#if defined(MHD_POSIX_SOCKETS)
#  define mhd_SCKT_OPT_BOOL int
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_OPT_BOOL BOOL
#endif /* MHD_WINSOCK_SOCKETS */

/**
 * mhd_SCKT_SEND_SIZE is type used to specify size for send() and recv()
 * functions
 */
#if defined(MHD_POSIX_SOCKETS)
typedef size_t mhd_SCKT_SEND_SIZE;
#elif defined(MHD_WINSOCK_SOCKETS)
typedef int mhd_SCKT_SEND_SIZE;
#endif

/**
 * MHD_SCKT_SEND_MAX_SIZE_ is maximum send()/recv() size value.
 */
#if defined(MHD_POSIX_SOCKETS)
#  define MHD_SCKT_SEND_MAX_SIZE_ SSIZE_MAX
#elif defined(MHD_WINSOCK_SOCKETS)
#  define MHD_SCKT_SEND_MAX_SIZE_ (0x7FFFFFFF) /* INT_MAX */
#endif


#if defined(AF_UNIX) || \
  (defined(HAVE_DECL_AF_UNIX) && (HAVE_DECL_AF_UNIX + 0 != 0))
#  define MHD_AF_UNIX AF_UNIX
#elif defined(AF_LOCAL) || \
  (defined(HAVE_DECL_AF_LOCAL) && (HAVE_DECL_AF_LOCAL + 0 != 0))
#  define MHD_AF_UNIX AF_LOCAL
#endif /* AF_UNIX */


#if defined(__FreeBSD__) || defined(__FreeBSD_kernel__) || \
  defined(__OpenBSD__) || defined(__NetBSD__) || \
  defined(MHD_WINSOCK_SOCKETS) || defined(__MACH__) || defined(__sun) || \
  defined(SOMEBSD)
/* Most of the OSes inherit nonblocking setting from the listen socket */
#  define MHD_ACCEPTED_INHERITS_NONBLOCK 1
#elif defined(__gnu_linux__) || defined(__linux__)
#  define MHD_ACCEPTED_DOES_NOT_INHERIT_NONBLOCK 1
#endif


#if defined(MHD_socket_nosignal_) || \
  (defined(SOL_SOCKET) && defined(SO_NOSIGPIPE))
/**
 * Indicate that SIGPIPE can be suppressed by MHD for normal send() by flags
 * or socket options.
 * If this macro is undefined, MHD cannot suppress SIGPIPE for socket functions
 * so sendfile() or writev() calls are avoided in application threads.
 */
#  define mhd_SEND_SPIPE_SUPPRESS_POSSIBLE   1
#endif /* MHD_WINSOCK_SOCKETS || MHD_socket_nosignal_ || MSG_NOSIGNAL */


#if ! defined(MHD_WINSOCK_SOCKETS)
/**
 * Indicate that suppression of SIGPIPE is required for some network
 * system calls.
 */
#  define mhd_SEND_SPIPE_SUPPRESS_NEEDED     1
#endif


#endif /* ! MHD_SYS_SOCKETS_HEADERS_H */
