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

/* MHD_socket_close_(fd) close any FDs (non-W32) / close only socket FDs (W32) */
#if !defined(_WIN32) || defined(__CYGWIN__)
#define MHD_socket_close_(fd) close((fd))
#else
#define MHD_socket_close_(fd) closesocket((fd))
#endif

#endif // MHD_PLATFORM_INTERFACE_H
