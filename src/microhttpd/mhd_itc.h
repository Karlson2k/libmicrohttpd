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

/* **************** STANDARD UNIX PIPE implementation ********** */

#  ifdef HAVE_STRING_H
#    include <string.h> /* for strerror() */
#  endif

/**
 * Data type for a MHD pipe.
 */
struct MHD_Pipe
{
  int fd[2];
};

/**
 * create pipe
 */
#define MHD_pipe_(pip) (!pipe((pip.fd)))

/***
 * Get description string of last errno for pipe operations.
 */
#define MHD_pipe_last_strerror_() strerror(errno)

/**
 * write data to real pipe
 */
#define MHD_pipe_write_(pip, ptr, sz) write((pip.fd[1]), (const void*)(ptr), (sz))

#define MHD_pipe_get_read_fd_(pip) (pip.fd[0])

#define MHD_pipe_get_write_fd_(pip) (pip.fd[1])

/**
 * drain data from real pipe
 */
#define MHD_pipe_drain_(pip) do { \
   long tmp; \
   while (0 < read((pip.fd[0]), (void*)&tmp, sizeof (tmp))) ; \
 } while (0)

/**
 * Close any FDs of the pipe (non-W32)
 */
#define MHD_pipe_close_(pip) do { \
  close (pip.fd[0]); \
  close (pip.fd[1]); \
  } while (0)

/**
 * Check if we have an uninitialized pipe
 */
#define MHD_INVALID_PIPE_(pip)  (-1 == pip.fd[0])

/**
 * Setup uninitialized @a pip data structure.
 */
#define MHD_make_invalid_pipe_(pip) do { \
    pip.fd[0] = pip.fd[1] = -1; \
  } while (0)

/**
 * Change itc FD options to be non-blocking.
 *
 * @param fd the FD to manipulate
 * @return non-zero if succeeded, zero otherwise
 */
int
MHD_itc_nonblocking_ (struct MHD_Pipe fd);


/* **************** END OF STANDARD UNIX PIPE implementation ********** */

#else /* MHD_DONT_USE_PIPES */

/* **************** PIPE EMULATION by socket pairs ********** */

#include "mhd_sockets.h"

/**
 * Data type for a MHD pipe.
 */
struct MHD_Pipe
{
  MHD_socket fd[2];
};


/**
 * Create two connected sockets to emulate a pipe.
 */
#define MHD_pipe_(pip) MHD_socket_pair_((pip.fd))

/**
 * Get description string of last pipe error
 */
#define MHD_pipe_last_strerror_() MHD_socket_last_strerr_()

/**
 * Write data to emulated pipe
 */
#define MHD_pipe_write_(pip, ptr, sz) send((pip.fd[1]), (const char*)(ptr), (sz), 0)

#define MHD_pipe_get_read_fd_(pip) (pip.fd[0])

#define MHD_pipe_get_write_fd_(pip) (pip.fd[1])

/**
 * Drain data from emulated pipe
 */
#define MHD_pipe_drain_(pip) do { long tmp; while (0 < recv((pip.fd[0]), (void*)&tmp, sizeof (tmp), 0)) ; } while (0)


/**
 * Close emulated pipe FDs
 */
#define MHD_pipe_close_(fd) do { \
   MHD_socket_close_(pip.fd[0]); \
   MHD_socket_close_(pip.fd[1]); \
} while (0)

/**
 * Check for uninitialized pipe @a pip
 */
#define MHD_INVALID_PIPE_(pip)  (MHD_INVALID_SOCKET == pip.fd[0])

/**
 * Setup uninitialized @a pip data structure.
 */
#define MHD_make_invalid_pipe_(pip) do { \
    pip.fd[0] = pip.fd[1] = MHD_INVALID_SOCKET; \
  } while (0)


#define MHD_itc_nonblocking_(pip) (MHD_socket_nonblocking_((pip.fd[0])) && MHD_socket_nonblocking_((pip.fd[1])))

/* **************** END OF PIPE EMULATION by socket pairs ********** */

#endif /* MHD_DONT_USE_PIPES */



#endif /* MHD_ITC_H */
