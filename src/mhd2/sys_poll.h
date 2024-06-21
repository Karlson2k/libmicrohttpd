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
 * @file src/mhd2/sys_poll.h
 * @brief  The header for the system 'poll()' function and related data types
 * @author Karlson2k (Evgeny Grin)
 *
 * This header includes system macros for 'poll()' and also has related
 * MHD macros.
 */

#ifndef MHD_SYS_POLL_H
#define MHD_SYS_POLL_H 1

#include "mhd_sys_options.h"

#ifdef MHD_USE_POLL
#  include "mhd_socket_type.h"
#  if defined(MHD_POSIX_SOCKETS)
#    include <poll.h>
#    define mhd_poll poll
#  elif defined(MHD_WINSOCK_SOCKETS)
#    include <winsock2.h>
#    define mhd_poll WSAPoll
#  else
#error Uknown sockets type
#  endif

#  if (defined(HAVE_DECL_POLLRDNORM) && (0 != HAVE_DECL_POLLRDNORM + 0)) || \
  defined(POLLRDNORM)
#    define MHD_POLL_IN POLLRDNORM
#  else
#    define MHD_POLL_IN POLLIN
#  endif

#  if (defined(HAVE_DECL_POLLWRNORM) && (0 != HAVE_DECL_POLLWRNORM + 0)) || \
  defined(POLLWRNORM)
#    define MHD_POLL_OUT POLLWRNORM
#  else
#    define MHD_POLL_OUT POLLOUT
#  endif

#  if (defined(HAVE_DECL_POLLRDBAND) && (0 != HAVE_DECL_POLLRDBAND + 0)) || \
  defined(POLLRDBAND)
#    define MHD_POLLRDBAND POLLRDBAND
#  else
#    define MHD_POLLRDBAND (0)
#  endif

#  if (defined(HAVE_DECL_POLLWRBAND) && (0 != HAVE_DECL_POLLWRBAND + 0)) || \
  defined(POLLWRBAND)
#    define MHD_POLLWRBAND POLLWRBAND
#  else
#    define MHD_POLLWRBAND (0)
#  endif

#  if (defined(HAVE_DECL_POLLPRI) && (0 != HAVE_DECL_POLLPRI + 0)) || \
  defined(POLLWRBAND)
#    define MHD_POLLPRI POLLPRI
#  else
#    define MHD_POLLPRI (0)
#  endif


#  if (defined(__APPLE__) && defined(__MACH__)) || defined(__CYGWIN__)
/* The platform incorrectly sets POLLHUP when remote use SHUT_WR.
   The correct behaviour must be POLLHUP only on remote close/disconnect */
#    define MHD_POLLHUP_ON_REM_SHUT_WR 1
#  endif

#endif /* MHD_USE_POLL */

#endif /* ! MHD_SYS_POLL_H */
