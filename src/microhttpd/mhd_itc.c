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
 * @brief  Implementation of inter-thread communication functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_itc.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <fcntl.h>

#ifndef MHD_DONT_USE_PIPES
#if !defined(_WIN32) || defined(__CYGWIN__)


/**
 * Change itc FD options to be non-blocking.
 *
 * @param fd the FD to manipulate
 * @return non-zero if succeeded, zero otherwise
 */
int
MHD_itc_nonblocking_ (MHD_pipe fd)
{
  int flags;

  flags = fcntl (fd, F_GETFL);
  if (-1 == flags)
    return 0;

  if ( ((flags | O_NONBLOCK) != flags) &&
       (0 != fcntl (fd, F_SETFL, flags | O_NONBLOCK)) )
    return 0;

  return !0;
}
#endif /* _WIN32 && ! __CYGWIN__ */
#endif /* ! MHD_DONT_USE_PIPES */
