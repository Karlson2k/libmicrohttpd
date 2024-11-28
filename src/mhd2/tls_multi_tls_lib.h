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
 * @file src/mhd2/tls_multi_tls_lib.h
 * @brief  The header for virtual "MultiTLS" backend
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_TLS_MULTI_TLS_LIB_H
#define MHD_TLS_MULTI_TLS_LIB_H 1

#include "mhd_sys_options.h"

#include "mhd_tls_choice.h"

#ifndef MHD_USE_MULTITLS
#error This header can be used only when MultiTLS is enabled
#endif

/**
 * The underlying TLS backend choice
 */
enum mhd_TlsMultiRoute
{
  /**
   * No TLS backend.
   * Invalid value if TLS is used.
   */
  mhd_TLS_MULTI_ROUTE_NONE = 0
#ifdef MHD_USE_GNUTLS
  ,
  /**
   * Use GnuTLS backend
   */
  mhd_TLS_MULTI_ROUTE_GNU
#endif
#ifdef MHD_USE_OPENSSL
  ,
  /**
   * Use OpenSSL backend
   */
  mhd_TLS_MULTI_ROUTE_OPEN
#endif
};

#endif /* ! MHD_TLS_MULTI_TLS_LIB_H */
