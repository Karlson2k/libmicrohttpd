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
 * @file src/mhd2/mhd_socket_error_funcs.h
 * @brief  The declarations of functions for getting enum mhd_SocketError values
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_SOCKET_ERROR_FUNCS_H
#define MHD_SOCKET_ERROR_FUNCS_H 1

#include "mhd_sys_options.h"

#include "mhd_socket_type.h"
#include "mhd_socket_error.h"

/**
 * Map recv() / send() system socket error to the enum value
 * @param socket_err the system socket error
 * @return the enum value for the @a socket_err
 */
MHD_INTERNAL enum mhd_SocketError
mhd_socket_error_get_from_sys_err (int socket_err);

/**
 * Get the last socket error recoded for the given socket
 * @param fd the socket to check for the error
 * @return the recorded error @a fd,
 *         #mhd_SOCKET_ERR_NOT_CHECKED if not possible to check @a fd for
 *         the error
 */
MHD_INTERNAL enum mhd_SocketError
mhd_socket_error_get_from_socket (MHD_Socket fd);

#endif /* ! MHD_SOCKET_ERROR_FUNCS_H */
