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
 * @file src/mhd2/mhd_public_api.h
 * @brief  The header for the MHD public API
 * @author Karlson2k (Evgeny Grin)
 *
 * This header acts as a wrapper for "microhttpd2.h", with correct system
 * headers included for the types used in the public API.
 */

#ifndef MHD_PUBLIC_API_H
#define MHD_PUBLIC_API_H 1

#include "mhd_sys_options.h"

#include "sys_base_types.h"
#include "mhd_socket_type.h"
#include "sys_sockets_types.h"

#include "microhttpd2.h"

#endif /* ! MHD_PUBLIC_API_H */
