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
 * @file src/mhd2/sys_socket_types.h
 * @brief  The header for system types related to sockets
 * @author Karlson2k (Evgeny Grin)
 *
 * This header should provide declaration of 'struct sockaddr'.
 */

#ifndef MHD_SYS_SOCKET_TYPES_H
#define MHD_SYS_SOCKET_TYPES_H 1

#include "mhd_sys_options.h"

#include "mhd_socket_type.h"

#ifdef MHD_POSIX_SOCKETS
#  include <sys/socket.h>
#else
#  include <winsock2.h>
#endif

#endif /* ! MHD_SYS_SOCKET_TYPES_H */
