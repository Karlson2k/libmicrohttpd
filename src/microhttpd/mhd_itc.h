/*
  This file is part of libmicrohttpd
  Copyright (C) 2016 Karlson2k (Evgeny Grin)

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
 * @brief  Header for platform-independent inter-thread communication
 * @author Karlson2k (Evgeny Grin)
 *
 * Provides basic abstraction for inter-thread communication.
 * Any functions can be implemented as macro on some platforms
 * unless explicitly marked otherwise.
 * Any function argument can be skipped in macro, so avoid
 * variable modification in function parameters.
 */

#ifndef MHD_ITC_H
#define MHD_ITC_H 1
#include "mhd_options.h"

/* Force don't use pipes on W32 */
#if defined(_WIN32) && !defined(MHD_DONT_USE_PIPES)
#define MHD_DONT_USE_PIPES 1
#endif /* defined(_WIN32) && !defined(MHD_DONT_USE_PIPES) */

#ifndef MHD_DONT_USE_PIPES
#  ifdef HAVE_STRING_H
#    include <string.h> /* for strerror() */
#  endif
#else
#  include "mhd_sockets.h"
#endif /* MHD_DONT_USE_PIPES */

/* MHD_pipe is type for pipe FDs*/
#ifndef MHD_DONT_USE_PIPES
  typedef int MHD_pipe;
#else /* ! MHD_DONT_USE_PIPES */
  typedef MHD_socket MHD_pipe;
#endif /* ! MHD_DONT_USE_PIPES */

/* MHD_pipe_ create pipe (!MHD_DONT_USE_PIPES) /
 *           create two connected sockets (MHD_DONT_USE_PIPES) */
#ifndef MHD_DONT_USE_PIPES
#  define MHD_pipe_(fdarr) pipe((fdarr))
#else /* MHD_DONT_USE_PIPES */
#  if !defined(_WIN32) || defined(__CYGWIN__)
#    define MHD_pipe_(fdarr) socketpair(AF_LOCAL, SOCK_STREAM, 0, (fdarr))
#  else /* !defined(_WIN32) || defined(__CYGWIN__) */
#    define MHD_pipe_(fdarr) MHD_W32_pair_of_sockets_((fdarr))
#  endif /* !defined(_WIN32) || defined(__CYGWIN__) */
#endif /* MHD_DONT_USE_PIPES */

/* MHD_pipe_last_strerror_ is description string of last errno (!MHD_DONT_USE_PIPES) /
 *                            description string of last pipe error (MHD_DONT_USE_PIPES) */
#ifndef MHD_DONT_USE_PIPES
#  define MHD_pipe_last_strerror_() strerror(errno)
#else
#  define MHD_pipe_last_strerror_() MHD_socket_last_strerr_()
#endif

/* MHD_pipe_write_ write data to real pipe (!MHD_DONT_USE_PIPES) /
 *                 write data to emulated pipe (MHD_DONT_USE_PIPES) */
#ifndef MHD_DONT_USE_PIPES
#  define MHD_pipe_write_(fd, ptr, sz) write((fd), (const void*)(ptr), (sz))
#else
#  define MHD_pipe_write_(fd, ptr, sz) send((fd), (const char*)(ptr), (sz), 0)
#endif

/* MHD_pipe_drain_ drain data from real pipe (!MHD_DONT_USE_PIPES) /
 *                drain data from emulated pipe (MHD_DONT_USE_PIPES) */
#ifndef MHD_DONT_USE_PIPES
#  define MHD_pipe_drain_(fd) do { long tmp; while (0 < read((fd), (void*)&tmp, sizeof (tmp))) ; } while (0)
#else
#  define MHD_pipe_drain_(fd) do { long tmp; while (0 < recv((fd), (void*)&tmp, sizeof (tmp), 0)) ; } while (0)
#endif

/* MHD_pipe_close_(fd) close any FDs (non-W32) /
 *                     close emulated pipe FDs (W32) */
#ifndef MHD_DONT_USE_PIPES
#  define MHD_pipe_close_(fd) close((fd))
#else
#  define MHD_pipe_close_(fd) MHD_socket_close_((fd))
#endif

/* MHD_INVALID_PIPE_ is a value of bad pipe FD */
#ifndef MHD_DONT_USE_PIPES
#  define MHD_INVALID_PIPE_ (-1)
#else
#  define MHD_INVALID_PIPE_ MHD_INVALID_SOCKET
#endif

#if defined(_WIN32) && !defined(__CYGWIN__)
/**
 * Create pair of mutually connected TCP/IP sockets on loopback address
 * @param sockets_pair array to receive resulted sockets
 * @return zero on success, -1 otherwise
 */
int MHD_W32_pair_of_sockets_(SOCKET sockets_pair[2]);
#endif /* _WIN32 && ! __CYGWIN__ */

#ifndef MHD_DONT_USE_PIPES
/**
 * Change itc FD options to be non-blocking.
 *
 * @param fd the FD to manipulate
 * @return non-zero if succeeded, zero otherwise
 */
   int
   MHD_itc_nonblocking_ (MHD_pipe fd);
#else
#  define MHD_itc_nonblocking_(f) MHD_socket_nonblocking_((f))
#endif

#endif /* MHD_ITC_H */
