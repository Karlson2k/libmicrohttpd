/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2014-2024 Karlson2k (Evgeny Grin)

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
 * @file src/mhd2/mhd_sockets_macros.h
 * @brief  Various helper macros functions related to sockets
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_SOCKETS_MACROS_H
#define MHD_SOCKETS_MACROS_H 1

#include "mhd_sys_options.h"

#include "mhd_socket_type.h"
#include "sys_base_types.h"
#include "sys_sockets_headers.h"

#if defined(MHD_POSIX_SOCKETS)
#  include "sys_errno.h"
#  ifdef HAVE_UNISTD_H
#    include <unistd.h>
#  else
#    include <stdlib.h>
#  endif
#  include "sys_errno.h"
#elif defined(MHD_WINSOCK_SOCKETS)
#  include <winsock2.h>
#endif

/**
 * Close the socket FD
 * @param sckt the socket to close
 */
#if defined(MHD_POSIX_SOCKETS)
#  define mhd_socket_close(sckt) close (sckt)
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_socket_close(sckt) closesocket (sckt)
#endif

/**
 * mhd_sys_send4 is a wrapper for system's send()
 * @param s the socket to use
 * @param b the buffer with data to send
 * @param l the length of data in @a b
 * @param f the additional flags
 * @return ssize_t type value
 */
#define mhd_sys_send4(s,b,l,f) \
        ((ssize_t) send ((s),(const void*) (b),(mhd_SCKT_SEND_SIZE) (l), \
                         ((mhd_MSG_NOSIGNAL) | (f))))


/**
 * mhd_sys_send is a simple wrapper for system's send()
 * @param s the socket to use
 * @param b the buffer with data to send
 * @param l the length of data in @a b
 * @return ssize_t type value
 */
#define mhd_sys_send(s,b,l) mhd_sys_send4 ((s),(b),(l), 0)


/**
 * mhd_recv is wrapper for system's recv()
 * @param s the socket to use
 * @param b the buffer for data to receive
 * @param l the length of @a b
 * @return ssize_t type value
 */
#define mhd_sys_recv(s,b,l) \
        ((ssize_t) recv ((s),(void*) (b),(mhd_SCKT_SEND_SIZE) (l), 0))

/**
 * Last socket error
 */
#if defined(MHD_POSIX_SOCKETS)
#  define mhd_SCKT_GET_LERR() errno
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_GET_LERR() (WSAGetLastError ())
#endif

#if defined(MHD_POSIX_SOCKETS)
#  if defined(EAGAIN) && defined(EWOULDBLOCK) && \
  ((EWOULDBLOCK + 0) != (EAGAIN + 0))
#    define mhd_SCKT_ERR_IS_EAGAIN(err) \
        ((EAGAIN == (err)) || (EWOULDBLOCK == (err)))
#  elif defined(EAGAIN)
#    define mhd_SCKT_ERR_IS_EAGAIN(err) (EAGAIN == (err))
#  elif defined(EWOULDBLOCK)
#    define mhd_SCKT_ERR_IS_EAGAIN(err) (EWOULDBLOCK == (err))
#  else
#    define mhd_SCKT_ERR_IS_EAGAIN(err) ((void) (err), ! ! 0)
#  endif
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_ERR_IS_EAGAIN(err) (WSAEWOULDBLOCK == (err))
#endif

#define mhd_SCKT_LERR_IS_EAGAIN() mhd_SCKT_ERR_IS_EAGAIN (mhd_SCKT_GET_LERR ())

#if defined(MHD_POSIX_SOCKETS)
#  ifdef EAFNOSUPPORT
#    define mhd_SCKT_ERR_IS_AF(err) (EAFNOSUPPORT == (err))
#  else
#    define mhd_SCKT_ERR_IS_AF(err) ((void) (err), ! ! 0)
#  endif
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_ERR_IS_AF(err) (WSAEAFNOSUPPORT == (err))
#endif

#define mhd_SCKT_LERR_IS_AF() mhd_SCKT_ERR_IS_AF (mhd_SCKT_GET_LERR ())

#if defined(MHD_POSIX_SOCKETS)
#  ifdef EINVAL
#    define mhd_SCKT_ERR_IS_EINVAL(err) (EINVAL == (err))
#  else
#    define mhd_SCKT_ERR_IS_EINVAL(err) ((void) (err), ! ! 0)
#  endif
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_ERR_IS_EINVAL(err) (WSAEINVAL == (err))
#endif

#if defined(MHD_POSIX_SOCKETS)
#  ifdef EINTR
#    define mhd_SCKT_ERR_IS_EINTR(err) (EINTR == (err))
#  else
#    define mhd_SCKT_ERR_IS_EINTR(err) ((void) (err), ! ! 0)
#  endif
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_ERR_IS_EINTR(err) (WSAEINTR == (err))
#endif

#if defined(MHD_POSIX_SOCKETS)
#  ifdef ECONNRESET
#    define mhd_SCKT_ERR_IS_CONNRESET(err) (ECONNRESET == (err))
#  else
#    define mhd_SCKT_ERR_IS_CONNRESET(err) ((void) (err), ! ! 0)
#  endif
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_ERR_IS_CONNRESET(err) (WSAECONNRESET == (err))
#endif

#if defined(MHD_POSIX_SOCKETS)
#  ifdef ENOTCONN
#    define mhd_SCKT_ERR_IS_NOTCONN(err) (ENOTCONN == (err))
#  else
#    define mhd_SCKT_ERR_IS_NOTCONNT(err) ((void) (err), ! ! 0)
#  endif
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_ERR_IS_NOTCONN(err) (WSAENOTCONN == (err))
#endif

#if defined(MHD_POSIX_SOCKETS)
#  ifdef EOPNOTSUPP
#    define mhd_SCKT_ERR_IS_OPNOTSUPP(err) (EOPNOTSUPP == (err))
#  else
#    define mhd_SCKT_ERR_IS_OPNOTSUPP(err) ((void) (err), ! ! 0)
#  endif
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_ERR_IS_OPNOTSUPP(err) (WSAEOPNOTSUPP == (err))
#endif

#if defined(MHD_POSIX_SOCKETS)
#  ifdef ENOPROTOOPT
#    define mhd_SCKT_ERR_IS_NOPROTOOPT(err) (ENOPROTOOPT == (err))
#  else
#    define mhd_SCKT_ERR_IS_NOPROTOOPT(err) ((void) (err), ! ! 0)
#  endif
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_ERR_IS_NOPROTOOPT(err) (WSAENOPROTOOPT == (err))
#endif

#if defined(MHD_POSIX_SOCKETS)
#  ifdef EBADF
#    define mhd_SCKT_ERR_IS_BADF(err) (EBADF == (err))
#  else
#    define mhd_SCKT_ERR_IS_BADF(err) ((void) (err), ! ! 0)
#  endif
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_ERR_IS_BADF(err) ((void) (err), ! ! 0)
#endif

#if defined(MHD_POSIX_SOCKETS)
#  ifdef ENOTSOCK
#    define mhd_SCKT_ERR_IS_NOTSOCK(err) (ENOTSOCK == (err))
#  else
#    define mhd_SCKT_ERR_IS_NOTSOCK(err) ((void) (err), ! ! 0)
#  endif
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_ERR_IS_NOTSOCK(err) (WSAENOTSOCK == (err))
#endif

#if defined(MHD_POSIX_SOCKETS)
#  ifdef EPIPE
#    define mhd_SCKT_ERR_IS_PIPE(err) (EPIPE == (err))
#  else
#    define mhd_SCKT_ERR_IS_PIPE(err) ((void) (err), ! ! 0)
#  endif
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_ERR_IS_PIPE(err) (WSAESHUTDOWN == (err))
#endif

/**
 * Check whether is given socket error is type of "incoming connection
 * was disconnected before 'accept()' is called".
 * @return boolean true is @a err match described socket error code,
 *         boolean false otherwise.
 */
#if defined(MHD_POSIX_SOCKETS)
#  ifdef ECONNABORTED
#    define mhd_SCKT_ERR_IS_DISCNN_BEFORE_ACCEPT(err) (ECONNABORTED == (err))
#  else
#    define mhd_SCKT_ERR_IS_DISCNN_BEFORE_ACCEPT(err) ((void) (err), ! ! 0)
#  endif
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_ERR_IS_DISCNN_BEFORE_ACCEPT(err) (WSAECONNRESET == (err))
#endif

/**
 * Error for any reason when the system detects connection broke, but not
 * because of the peer.
 * It can be keep-alive ping failure or timeout to get ACK for the
 * transmitted data.
 */
#if defined(MHD_POSIX_SOCKETS)
/* + EHOSTUNREACH: probably reported by intermediate
   + ETIMEDOUT: probably keep-alive ping failure
   + ENETUNREACH: probably cable physically disconnected or similar */
#    define mhd_SCKT_ERR_IS_CONN_BROKEN(err) \
        ((0 != (err)) && \
         ((mhd_EHOSTUNREACH_OR_ZERO == (err)) || \
          (mhd_ETIMEDOUT_OR_ZERO == (err)) || \
          (mhd_ENETUNREACH_OR_ZERO == (err))))
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_ERR_IS_CONN_BROKEN(err) \
        ( (WSAENETRESET == (err)) || (WSAECONNABORTED == (err)) || \
          (WSAETIMEDOUT == (err)) )
#endif

/**
 * Check whether given socket error is any kind of "low resource" error.
 * @return boolean true if @a err is any kind of "low resource" error,
 *         boolean false otherwise.
 */
#if defined(MHD_POSIX_SOCKETS)
#    define mhd_SCKT_ERR_IS_LOW_RESOURCES(err) \
        ((0 != (err)) && \
         ((mhd_EMFILE_OR_ZERO == (err)) || (mhd_ENFILE_OR_ZERO == (err)) || \
          (mhd_ENOMEM_OR_ZERO == (err)) || (mhd_ENOBUFS_OR_ZERO == (err))))
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_ERR_IS_LOW_RESOURCES(err) \
        ( (WSAEMFILE == (err)) || (WSAENOBUFS == (err)) )
#endif

/**
 * Check whether given socket error is any kind of "low memory" error.
 * This is subset of #mhd_SCKT_ERR_IS_LOW_RESOURCES()
 * @return boolean true if @a err is any kind of "low memory" error,
 *         boolean false otherwise.
 */
#if defined(MHD_POSIX_SOCKETS)
#    define mhd_SCKT_ERR_IS_LOW_MEM(err) \
        ((0 != (err)) && \
         ((mhd_ENOMEM_OR_ZERO == (err)) || (mhd_ENOBUFS_OR_ZERO == (err))))
#elif defined(MHD_WINSOCK_SOCKETS)
#  define mhd_SCKT_ERR_IS_LOW_MEM(err) (WSAENOBUFS == (err))
#endif


#if defined(MHD_POSIX_SOCKETS)
#  ifdef HAVE_SOCKETPAIR
#    ifdef MHD_AF_UNIX
#      define mhd_socket_pair(fdarr_ptr) \
        (0 != socketpair (MHD_AF_UNIX, SOCK_STREAM, 0, (fdarr_ptr)))
#    else
#      define mhd_socket_pair(fdarr_ptr) \
        (0 != socketpair (AF_INET, SOCK_STREAM, 0, (fdarr_ptr))) /* Fallback, could be broken on many platforms */
#    endif
#    if defined(HAVE_SOCK_NONBLOCK)
#      ifdef MHD_AF_UNIX
#        define mhd_socket_pair_nblk(fdarr_ptr) \
        (0 != socketpair (MHD_AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, \
                          (fdarr_ptr)))
#      else
#        define mhd_socket_pair_nblk(fdarr_ptr) \
        (0 != socketpair (AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0, (fdarr_ptr))) /* Fallback, could be broken on many platforms */
#      endif
#    endif /* HAVE_SOCK_NONBLOCK*/
#  endif /* HAVE_SOCKETPAIR */
#endif

#ifndef mhd_socket_pair
/* mhd_socket_pair() implemented in "mhd_sockets_funcs.h" based on local function */
#endif

#if defined(SOL_SOCKET) && defined(SO_NOSIGPIPE)
/**
 * Helper for mhd_socket_nosignal()
 */
#  ifdef HAVE_COMPOUND_LITERALS_LVALUES
#    define mhd_socket_nosig_helper_int_one ((int){1})
#  else
/**
 * Internal static const helper for mhd_socket_nosignal()
 */
static const int mhd_socket_nosig_helper_int_one = 1;
#  endif


/**
 * Change socket options to no signal on remote disconnect / broken connection.
 *
 * @param sock socket to manipulate
 * @return non-zero if succeeded, zero otherwise
 */
#  define mhd_socket_nosignal(sock) \
        (! setsockopt ((sock),SOL_SOCKET,SO_NOSIGPIPE, \
                       &mhd_socket_nosig_helper_int_one, sizeof(int)))
#endif /* SOL_SOCKET && SO_NOSIGPIPE */


#endif /* ! MHD_SOCKETS_MACROS_H */
