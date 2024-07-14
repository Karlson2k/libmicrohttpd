/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2021-2024 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/http_prot_ver.h
 * @brief  The definition of the HTTP versions enum
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_HTTP_PROT_VER_H
#define MHD_HTTP_PROT_VER_H 1

#include "mhd_sys_options.h"

#ifndef MHD_HTTP_PROTOCOL_VER_DEFINED

/**
 * @brief HTTP protocol versions
 * @defgroup versions HTTP versions
 * @{
 */
enum MHD_FIXED_ENUM_MHD_SET_ MHD_HTTP_ProtocolVersion
{
  MHD_HTTP_VERSION_INVALID = 0
  ,
  MHD_HTTP_VERSION_1_0 = 1
  ,
  MHD_HTTP_VERSION_1_1 = 2
  ,
  MHD_HTTP_VERSION_2 = 3
  ,
  MHD_HTTP_VERSION_3 = 4
  ,
  MHD_HTTP_VERSION_FUTURE = 255
};


#define MHD_HTTP_PROTOCOL_VER_DEFINED 1
#endif /* ! MHD_HTTP_PROTOCOL_VER_DEFINED */

/**
 * Check whether version of HTTP protocol is supported
 */
#define MHD_HTTP_VERSION_IS_SUPPORTED(v) \
        ((MHD_HTTP_VERSION_1_0 <= (v)) && (MHD_HTTP_VERSION_1_1 >= (v)))

/**
 * Check whether version of HTTP protocol is valid
 */
#define MHD_HTTP_VERSION_IS_VALID(v) \
        (((MHD_HTTP_VERSION_1_0 <= (v)) && (MHD_HTTP_VERSION_3 >= (v))) || \
         (MHD_HTTP_VERSION_FUTURE == (v)))

#endif /* ! MHD_HTTP_PROT_VER_H */
