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

/**
 * Data type for a MHD pipe.
 */
struct MHD_Pipe
{
#ifndef MHD_DONT_USE_PIPES
  int fd[2];
#else /* ! MHD_DONT_USE_PIPES */
  MHD_socket fd[2];
#endif /* ! MHD_DONT_USE_PIPES */
};


/* MHD_pipe_ create pipe (!MHD_DONT_USE_PIPES) /
 *           create two connected sockets (MHD_DONT_USE_PIPES) */
#ifndef MHD_DONT_USE_PIPES
#  define MHD_pipe_(pip) (!pipe((pip.fd)))
#else /* MHD_DONT_USE_PIPES */
#  define MHD_pipe_(pip) MHD_socket_pair_((pip.fd))
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
#  define MHD_pipe_write_(pip, ptr, sz) write((pip.fd[1]), (const void*)(ptr), (sz))
#else
#  define MHD_pipe_write_(pip, ptr, sz) send((pip.fd[1]), (const char*)(ptr), (sz), 0)
#endif


#ifndef MHD_DONT_USE_PIPES
#  define MHD_pipe_get_read_fd_(pip) (pip.fd[0])
#else
#  define MHD_pipe_get_read_fd_(pip) (pip.fd[0])
#endif


#ifndef MHD_DONT_USE_PIPES
#  define MHD_pipe_get_write_fd_(pip) (pip.fd[1])
#else
#  define MHD_pipe_get_write_fd_(pip) (pip.fd[1])
#endif



/* MHD_pipe_drain_ drain data from real pipe (!MHD_DONT_USE_PIPES) /
 *                drain data from emulated pipe (MHD_DONT_USE_PIPES) */
#ifndef MHD_DONT_USE_PIPES
#  define MHD_pipe_drain_(pip) do { long tmp; while (0 < read((pip.fd[0]), (void*)&tmp, sizeof (tmp))) ; } while (0)
#else
#  define MHD_pipe_drain_(pip) do { long tmp; while (0 < recv((pip.fd[0]), (void*)&tmp, sizeof (tmp), 0)) ; } while (0)
#endif

/* MHD_pipe_close_(fd) close any FDs (non-W32) /
 *                     close emulated pipe FDs (W32) */
#ifndef MHD_DONT_USE_PIPES
#  define MHD_pipe_close_(pip) do { close(pip.fd[0]); close(pip.fd[1]); } while (0)
#else
#  define MHD_pipe_close_(fd) do { MHD_socket_close_(pip.fd[0]); MHD_socket_close_(pip.fd[1]); } while (0)
#endif

/* MHD_INVALID_PIPE_ is a value of bad pipe FD */
#ifndef MHD_DONT_USE_PIPES
#  define MHD_INVALID_PIPE_(pip)  (-1 == pip.fd[0])
#else
#  define MHD_INVALID_PIPE_(pip)  (MHD_INVALID_SOCKET == pip.fd[0])
#endif

#ifndef MHD_DONT_USE_PIPES
#define MHD_make_invalid_pipe_(pip) do { \
    pip.fd[0] = pip.fd[1] = -1; \
  } while (0)
#else
#define MHD_make_invalid_pipe_(pip) do { \
    pip.fd[0] = pip.fd[1] = MHD_INVALID_SOCKET; \
  } while (0)
#endif


#ifndef MHD_DONT_USE_PIPES
/**
 * Change itc FD options to be non-blocking.
 *
 * @param fd the FD to manipulate
 * @return non-zero if succeeded, zero otherwise
 */
int
MHD_itc_nonblocking_ (struct MHD_Pipe fd);
#else
#  define MHD_itc_nonblocking_(pip) (MHD_socket_nonblocking_((pip.fd[0])) && MHD_socket_nonblocking_((pip.fd[1])))
#endif

#endif /* MHD_ITC_H */
