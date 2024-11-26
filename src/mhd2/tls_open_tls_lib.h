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
 * @file src/mhd2/tls_open_tls_lib.h
 * @brief  The MHD wrapper for OpenSSL headers
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_TLS_OPEN_TLS_LIB_H
#define MHD_TLS_OPEN_TLS_LIB_H 1

#include "mhd_sys_options.h"

#ifndef MHD_USE_OPENSSL
#error This header can be used only if GnuTLS is enabled
#endif

/* Declare compatibility with OpenSSL versions >= 3.0 */
#define OPENSSL_API_COMPAT 30000
/* Request to hide all symbols deprecated before OPENSSL_API_COMPAT version */
#define OPENSSL_NO_DEPRECATED   1

#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/pem.h>

#ifndef OPENSSL_VERSION_NUMBER
#error OPENSSL_VERSION_NUMBER is not defined
#endif

#ifndef OPENSSL_VERSION_PREREQ
#error OPENSSL_VERSION_PREREQ is not defined
#endif

#endif /* ! MHD_TLS_OPEN_TLS_LIB_H */
