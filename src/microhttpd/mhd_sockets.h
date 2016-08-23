/*
  This file is part of libmicrohttpd
  Copyright (C) 2014-2016 Karlson2k (Evgeny Grin)

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

*/

/**
 * @file microhttpd/mhd_sockets.c
 * @brief  Header for platform-independent sockets abstraction
 * @author Karlson2k (Evgeny Grin)
 *
 * Provides basic abstraction for sockets.
 * Any functions can be implemented as macro on some platforms
 * unless explicitly marked otherwise.
 * Any function argument can be skipped in macro, so avoid
 * variable modification in function parameters.
 */

#ifndef MHD_SOCKETS_H
#define MHD_SOCKETS_H 1
#include "mhd_options.h"

#include <errno.h>

#if !defined(MHD_POSIX_SOCKETS) && !defined(MHD_WINSOCK_SOCKETS)
#  if !defined(_WIN32) || defined(__CYGWIN__)
#    define MHD_POSIX_SOCKETS 1
#  else  /* defined(_WIN32) && !defined(__CYGWIN__) */
#    define MHD_WINSOCK_SOCKETS 1
#  endif /* defined(_WIN32) && !defined(__CYGWIN__) */
#endif /* !MHD_POSIX_SOCKETS && !MHD_WINSOCK_SOCKETS */

/*
 * MHD require headers that define socket type, socket basic functions
 * (socket(), accept(), listen(), bind(), send(), recv(), select()), socket
 * parameters like SOCK_CLOEXEC, SOCK_NONBLOCK, additional socket functions
 * (poll(), epoll(), accept4()), struct timeval and other types, required
 * for socket function.
 */
#if defined(MHD_POSIX_SOCKETS)
#  if HAVE_SYS_SOCKET_H
#    include <sys/socket.h>
#  endif
#  if defined(__VXWORKS__) || defined(__vxworks) || defined(OS_VXWORKS)
#    ifdef HAVE_SOCKLIB_H
#      include <sockLib.h>
#    endif /* HAVE_SOCKLIB_H */
#    ifdef HAVE_INETLIB_H
#      include <inetLib.h>
#    endif /* HAVE_INETLIB_H */
#    include <strings.h>  /* required for FD_SET (bzero() function) */
#  endif /* __VXWORKS__ || __vxworks || OS_VXWORKS */
#  ifdef HAVE_NETINET_IN_H
#    include <netinet/in.h>
#  endif /* HAVE_NETINET_IN_H */
#  if HAVE_ARPA_INET_H
#    include <arpa/inet.h>
#  endif
#  ifdef HAVE_NET_IF_H
#    include <net/if.h>
#  endif
#  if HAVE_SYS_TIME_H
#    include <sys/time.h>
#  endif
#  if HAVE_TIME_H
#    include <time.h>
#  endif
#  if HAVE_NETDB_H
#    include <netdb.h>
#  endif
#  if HAVE_SYS_SELECT_H
#    include <sys/select.h>
#  endif
#  if EPOLL_SUPPORT
#    include <sys/epoll.h>
#  endif
#  if HAVE_NETINET_TCP_H
     /* for TCP_FASTOPEN and TCP_CORK */
#    include <netinet/tcp.h>
#  endif
#  ifdef HAVE_STRING_H
#    include <string.h> /* for strerror() */
#  endif
#  if defined(HAVE_SYS_TYPES_H)
#    include <sys/types.h> /* required on old platforms */
#  endif /* (!HAVE_SYS_SOCKET_H || !HAVE_SYS_SOCKET_H) && HAVE_SYS_TYPES_H */
#elif defined(MHD_WINSOCK_SOCKETS)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN 1
#  endif /* !WIN32_LEAN_AND_MEAN */
#  include <winsock2.h>
#  include <ws2tcpip.h>
#endif /* MHD_WINSOCK_SOCKETS */

#if defined(HAVE_POLL_H) && defined(HAVE_POLL)
#  include <poll.h>
#endif

#ifdef _MHD_FD_SETSIZE_IS_DEFAULT
#  define _MHD_SYS_DEFAULT_FD_SETSIZE FD_SETSIZE
#else  /* ! _MHD_FD_SETSIZE_IS_DEFAULT */
#  include "sysfdsetsize.h"
#  define _MHD_SYS_DEFAULT_FD_SETSIZE get_system_fdsetsize_value()
#endif /* ! _MHD_FD_SETSIZE_IS_DEFAULT */

#ifndef MHD_SOCKET_DEFINED
/**
 * MHD_socket is type for socket FDs
 */
#  if defined(MHD_POSIX_SOCKETS)
     typedef int MHD_socket;
#    define MHD_INVALID_SOCKET (-1)
#  elif defined(MHD_WINSOCK_SOCKETS)
     typedef SOCKET MHD_socket;
#    define MHD_INVALID_SOCKET (INVALID_SOCKET)
#  endif /* MHD_WINSOCK_SOCKETS */

#  define MHD_SOCKET_DEFINED 1
#endif /* ! MHD_SOCKET_DEFINED */

#ifdef SOCK_CLOEXEC
#  define MAYBE_SOCK_CLOEXEC SOCK_CLOEXEC
#else  /* ! SOCK_CLOEXEC */
#  define MAYBE_SOCK_CLOEXEC 0
#endif /* ! SOCK_CLOEXEC */

#ifdef HAVE_SOCK_NONBLOCK
#  define MAYBE_SOCK_NONBLOCK SOCK_NONBLOCK
#else  /* ! HAVE_SOCK_NONBLOCK */
#  define MAYBE_SOCK_NONBLOCK 0
#endif /* ! HAVE_SOCK_NONBLOCK */

#if !defined(SHUT_WR) && defined(SD_SEND)
#  define SHUT_WR SD_SEND
#endif
#if !defined(SHUT_RD) && defined(SD_RECEIVE)
#  define SHUT_RD SD_RECEIVE
#endif
#if !defined(SHUT_RDWR) && defined(SD_BOTH)
#  define SHUT_RDWR SD_BOTH
#endif

#if HAVE_ACCEPT4+0 != 0 && (defined(HAVE_SOCK_NONBLOCK) || defined(SOCK_CLOEXEC))
#  define USE_ACCEPT4 1
#endif

#if defined(HAVE_EPOLL_CREATE1) && defined(EPOLL_CLOEXEC)
#  define USE_EPOLL_CREATE1 1
#endif /* HAVE_EPOLL_CREATE1 && EPOLL_CLOEXEC */

#ifdef TCP_FASTOPEN
/**
 * Default TCP fastopen queue size.
 */
#define MHD_TCP_FASTOPEN_QUEUE_SIZE_DEFAULT 10
#endif


/**
 * _MHD_SOCKOPT_BOOL_TYPE is type for bool parameters for setsockopt()/getsockopt()
 */
#ifdef MHD_POSIX_SOCKETS
  typedef int _MHD_SOCKOPT_BOOL_TYPE;
#else /* MHD_WINSOCK_SOCKETS */
  typedef BOOL _MHD_SOCKOPT_BOOL_TYPE;
#endif /* MHD_WINSOCK_SOCKETS */

/**
 * _MHD_socket_funcs_size is type used to specify size for send and recv
 * functions
 */
#if !defined(MHD_WINSOCK_SOCKETS)
  typedef size_t _MHD_socket_funcs_size;
#else
  typedef int _MHD_socket_funcs_size;
#endif

/**
 * MHD_socket_close_(fd) close any FDs (non-W32) / close only socket
 * FDs (W32).  Note that on HP-UNIX, this function may leak the FD if
 * errno is set to EINTR.  Do not use HP-UNIX.
 *
 * @param fd descriptor to close
 * @return 0 on success (error codes like EINTR and EIO are counted as success,
 *           only EBADF counts as an error!)
 */
#if !defined(MHD_WINSOCK_SOCKETS)
#  define MHD_socket_close_(fd) (((0 != close(fd)) && (EBADF == errno)) ? -1 : 0)
#else
#  define MHD_socket_close_(fd) closesocket((fd))
#endif

/**
 * MHD_socket_errno_ is errno of last function (non-W32) / errno of
 * last socket function (W32)
 */
#if !defined(MHD_WINSOCK_SOCKETS)
#  define MHD_socket_errno_ errno
#else
#  define MHD_socket_errno_ MHD_W32_errno_from_winsock_()
#endif

 /* MHD_socket_last_strerr_ is description string of last errno (non-W32) /
  *                            description string of last socket error (W32) */
#if !defined(MHD_WINSOCK_SOCKETS)
#  define MHD_socket_last_strerr_() strerror(errno)
#else
#  define MHD_socket_last_strerr_() MHD_W32_strerror_last_winsock_()
#endif

 /* MHD_strerror_ is strerror (both non-W32/W32) */
#if !defined(MHD_WINSOCK_SOCKETS)
#  define MHD_strerror_(errnum) strerror((errnum))
#else
#  define MHD_strerror_(errnum) MHD_W32_strerror_((errnum))
#endif

 /* MHD_set_socket_errno_ set errno to errnum (non-W32) / set socket last error to errnum (W32) */
#if !defined(MHD_WINSOCK_SOCKETS)
#  define MHD_set_socket_errno_(errnum) errno=(errnum)
#else
#  define MHD_set_socket_errno_(errnum) MHD_W32_set_last_winsock_error_((errnum))
#endif

 /* MHD_SYS_select_ is wrapper macro for system select() function */
#if !defined(MHD_WINSOCK_SOCKETS)
#  define MHD_SYS_select_(n,r,w,e,t) select((n),(r),(w),(e),(t))
#else
#  define MHD_SYS_select_(n,r,w,e,t) \
( (!(r) || ((fd_set*)(r))->fd_count == 0) && \
  (!(w) || ((fd_set*)(w))->fd_count == 0) && \
  (!(e) || ((fd_set*)(e))->fd_count == 0) ) ? \
( (t) ? (Sleep((t)->tv_sec * 1000 + (t)->tv_usec / 1000), 0) : 0 ) : \
  (select((int)0,(r),(w),(e),(t)))
#endif

#if defined(HAVE_POLL)
/* MHD_sys_poll_ is wrapper macro for system poll() function */
#  if !defined(MHD_WINSOCK_SOCKETS)
#    define MHD_sys_poll_ poll
#  else  /* MHD_WINSOCK_SOCKETS */
#    define MHD_sys_poll_ WSAPoll
#  endif /* MHD_WINSOCK_SOCKETS */
#endif /* HAVE_POLL */


#ifdef MHD_WINSOCK_SOCKETS

/* POSIX-W32 compatibility functions and macros */

#  define MHDW32ERRBASE 3300

#  ifndef EWOULDBLOCK
#    define EWOULDBLOCK (MHDW32ERRBASE+1)
#  endif
#  ifndef EINPROGRESS
#    define EINPROGRESS (MHDW32ERRBASE+2)
#  endif
#  ifndef EALREADY
#    define EALREADY (MHDW32ERRBASE+3)
#  endif
#  ifndef ENOTSOCK
#    define ENOTSOCK (MHDW32ERRBASE+4)
#  endif
#  ifndef EDESTADDRREQ
#    define EDESTADDRREQ (MHDW32ERRBASE+5)
#  endif
#  ifndef EMSGSIZE
#    define EMSGSIZE (MHDW32ERRBASE+6)
#  endif
#  ifndef EPROTOTYPE
#    define EPROTOTYPE (MHDW32ERRBASE+7)
#  endif
#  ifndef ENOPROTOOPT
#    define ENOPROTOOPT (MHDW32ERRBASE+8)
#  endif
#  ifndef EPROTONOSUPPORT
#    define EPROTONOSUPPORT (MHDW32ERRBASE+9)
#  endif
#  ifndef EOPNOTSUPP
#    define EOPNOTSUPP (MHDW32ERRBASE+10)
#  endif
#  ifndef EAFNOSUPPORT
#    define EAFNOSUPPORT (MHDW32ERRBASE+11)
#  endif
#  ifndef EADDRINUSE
#    define EADDRINUSE (MHDW32ERRBASE+12)
#  endif
#  ifndef EADDRNOTAVAIL
#    define EADDRNOTAVAIL (MHDW32ERRBASE+13)
#  endif
#  ifndef ENETDOWN
#    define ENETDOWN (MHDW32ERRBASE+14)
#  endif
#  ifndef ENETUNREACH
#    define ENETUNREACH (MHDW32ERRBASE+15)
#  endif
#  ifndef ENETRESET
#    define ENETRESET (MHDW32ERRBASE+16)
#  endif
#  ifndef ECONNABORTED
#    define ECONNABORTED (MHDW32ERRBASE+17)
#  endif
#  ifndef ECONNRESET
#    define ECONNRESET (MHDW32ERRBASE+18)
#  endif
#  ifndef ENOBUFS
#    define ENOBUFS (MHDW32ERRBASE+19)
#  endif
#  ifndef EISCONN
#    define EISCONN (MHDW32ERRBASE+20)
#  endif
#  ifndef ENOTCONN
#    define ENOTCONN (MHDW32ERRBASE+21)
#  endif
#  ifndef ETOOMANYREFS
#    define ETOOMANYREFS (MHDW32ERRBASE+22)
#  endif
#  ifndef ECONNREFUSED
#    define ECONNREFUSED (MHDW32ERRBASE+23)
#  endif
#  ifndef ELOOP
#    define ELOOP (MHDW32ERRBASE+24)
#  endif
#  ifndef EHOSTDOWN
#    define EHOSTDOWN (MHDW32ERRBASE+25)
#  endif
#  ifndef EHOSTUNREACH
#    define EHOSTUNREACH (MHDW32ERRBASE+26)
#  endif
#  ifndef EPROCLIM
#    define EPROCLIM (MHDW32ERRBASE+27)
#  endif
#  ifndef EUSERS
#    define EUSERS (MHDW32ERRBASE+28)
#  endif
#  ifndef EDQUOT
#    define EDQUOT (MHDW32ERRBASE+29)
#  endif
#  ifndef ESTALE
#    define ESTALE (MHDW32ERRBASE+30)
#  endif
#  ifndef EREMOTE
#    define EREMOTE (MHDW32ERRBASE+31)
#  endif
#  ifndef ESOCKTNOSUPPORT
#    define ESOCKTNOSUPPORT (MHDW32ERRBASE+32)
#  endif
#  ifndef EPFNOSUPPORT
#    define EPFNOSUPPORT (MHDW32ERRBASE+33)
#  endif
#  ifndef ESHUTDOWN
#    define ESHUTDOWN (MHDW32ERRBASE+34)
#  endif
#  ifndef ENODATA
#    define ENODATA (MHDW32ERRBASE+35)
#  endif
#  ifndef ETIMEDOUT
#    define ETIMEDOUT (MHDW32ERRBASE+36)
#  endif

/**
 * Return errno equivalent of last winsock error
 * @return errno equivalent of last winsock error
 */
  int MHD_W32_errno_from_winsock_(void);

/**
 * Return pointer to string description of errnum error
 * Works fine with both standard errno errnums
 * and errnums from MHD_W32_errno_from_winsock_
 * @param errnum the errno or value from MHD_W32_errno_from_winsock_()
 * @return pointer to string description of error
 */
  const char* MHD_W32_strerror_(int errnum);

/**
 * Return pointer to string description of last winsock error
 * @return pointer to string description of last winsock error
 */
  const char* MHD_W32_strerror_last_winsock_(void);

/**
 * Set last winsock error to equivalent of given errno value
 * @param errnum the errno value to set
 */
  void MHD_W32_set_last_winsock_error_(int errnum);


#endif /* MHD_WINSOCK_SOCKETS */

#endif /* ! MHD_SOCKETS_H */
