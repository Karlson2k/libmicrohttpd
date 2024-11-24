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
 * @file src/mhd2/mhd_tls_enums.h
 * @brief  The definition of internal enums used for TLS communication
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_TLS_ENUMS_H
#define MHD_TLS_ENUMS_H 1

#include "mhd_sys_options.h"

#ifndef MHD_ENABLE_HTTPS
#error This header should be used only if HTTPS is enabled
#endif

/**
 * Result of performing TLS procedure
 */
enum MHD_FIXED_ENUM_ mhd_TlsProcedureResult
{
  /**
   * Completed successfully
   */
  mhd_TLS_PROCED_SUCCESS = 0
  ,
  /**
   * In progress, receive operation interrupted
   */
  mhd_TLS_PROCED_RECV_INTERRUPTED
  ,
  /**
   * In progress, send operation interrupted
   */
  mhd_TLS_PROCED_SEND_INTERRUPTED
  ,
  /**
   * In progress, need to receive more data
   */
  mhd_TLS_PROCED_RECV_MORE_NEEDED
  ,
  /**
   * In progress, need to send more data
   */
  mhd_TLS_PROCED_SEND_MORE_NEEDED
  ,
  /**
   * Procedure failed
   */
  mhd_TLS_PROCED_FAILED
};

#endif /* ! MHD_TLS_ENUMS_H */
