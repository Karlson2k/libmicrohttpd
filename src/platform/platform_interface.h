/*
  This file is part of libmicrohttpd
  (C) 2014 Karlson2k (Evgeny Grin)

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library. 
  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file platform/platfrom_interface.h
 * @brief  internal platform abstraction functions
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_PLATFORM_INTERFACE_H
#define MHD_PLATFORM_INTERFACE_H

#if defined(_WIN32) && !defined(__CYGWIN__)
#include "w32functions.h"
#endif

/* MHD_socket_close_(fd) close any FDs (non-W32) / close only socket FDs (W32) */
#if !defined(_WIN32) || defined(__CYGWIN__)
#define MHD_socket_close_(fd) close((fd))
#else
#define MHD_socket_close_(fd) closesocket((fd))
#endif

/* MHD_socket_errno_ is errno of last function (non-W32) / errno of last socket function (W32) */
#if !defined(_WIN32) || defined(__CYGWIN__)
#define MHD_socket_errno_ errno
#else
#define MHD_socket_errno_ MHD_W32_errno_from_winsock_()
#endif

/* MHD_socket_last_strerr_ is description string of last errno (non-W32) /
 *                            description string of last socket error (W32) */
#if !defined(_WIN32) || defined(__CYGWIN__)
#define MHD_socket_last_strerr_() strerror(errno)
#else
#define MHD_socket_last_strerr_() MHD_W32_strerror_last_winsock_()
#endif

/* MHD_strerror_ is strerror (both non-W32/W32) */
#if !defined(_WIN32) || defined(__CYGWIN__)
#define MHD_strerror_(errnum) strerror((errnum))
#else
#define MHD_strerror_(errnum) MHD_W32_strerror_((errnum))
#endif

/* MHD_set_socket_errno_ set errno to errnum (non-W32) / set socket last error to errnum (W32) */
#if !defined(_WIN32) || defined(__CYGWIN__)
#define MHD_set_socket_errno_(errnum) errno=(errnum)
#else
#define MHD_set_socket_errno_(errnum) MHD_W32_set_last_winsock_error_((errnum))
#endif

#endif // MHD_PLATFORM_INTERFACE_H
