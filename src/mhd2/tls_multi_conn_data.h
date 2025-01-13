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
 * @file src/mhd2/tls_multi_conn_data.h
 * @brief  The definition of MultiTLS daemon-specific data structures
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_TLS_MULTI_CONN_DATA_H
#define MHD_TLS_MULTI_CONN_DATA_H 1

#include "mhd_sys_options.h"

#include "tls_multi_tls_lib.h"

#ifndef MHD_USE_MULTITLS
#error This header can be used only if MultiTLS is enabled
#endif

#ifdef MHD_SUPPORT_GNUTLS
struct mhd_TlsGnuConnData;      /* forward declaration */
#endif
#ifdef MHD_SUPPORT_OPENSSL
struct mhd_TlsOpenConnData;     /* forward declaration */
#endif

/**
 * The pointer to the underlying TLS backend connection data
 */
struct mhd_TlsMultiConnRoutePtr
{
#ifdef MHD_SUPPORT_GNUTLS
  /**
   * Pointer to GnuTLS connection-specific data
   */
  struct mhd_TlsGnuConnData *gnutls;
#endif
#ifdef MHD_SUPPORT_OPENSSL
  /**
   * Pointer to OpenSSL connection-specific data
   */
  struct mhd_TlsOpenConnData *openssl;
#endif
};

/**
 * The structure with connection-specific MultiTLS data
 */
struct mhd_TlsMultiConnData
{
  /**
   * The underlying TLS backend choice
   */
  enum mhd_TlsMultiRoute choice;

  /**
   * The pointer to the underlying TLS backend connection data
   */
  struct mhd_TlsMultiConnRoutePtr data;
};

#endif /* ! MHD_TLS_MULTI_CONN_DATA_H */
