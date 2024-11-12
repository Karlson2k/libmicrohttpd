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
 * @file src/mhd2/mhd_tls_funcs.h
 * @brief  The TLS backend functions generic declaration, mapped to specific TLS
 *         backend at compile-time
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_TLS_FUNCS_H
#define MHD_TLS_FUNCS_H 1

#include "mhd_sys_options.h"

#include "mhd_tls_choice.h"
#ifndef MHD_ENABLE_HTTPS
#error This header should be used only if HTTPS is enabled
#endif

#ifdef MHD_USE_GNUTLS
#  include "tls_gnu_funcs.h"
#endif

/**
 * Perform one-time global initialisation of TLS backend
 */
#define mhd_tls_global_init_once()        \
        mhd_MACRO_CONCAT3 (mhd_tls_,mhd_TLS_FUNC_NAME_ID,_global_init_once)()

/**
 * Perform de-initialisation of TLS backend
 */
#define mhd_tls_global_deinit()           \
        mhd_MACRO_CONCAT3 (mhd_tls_,mhd_TLS_FUNC_NAME_ID,_global_deinit)()

/**
 * Perform re-initialisation of TLS backend
 */
#define mhd_tls_global_re_init()          \
        mhd_MACRO_CONCAT3 (mhd_tls_,mhd_TLS_FUNC_NAME_ID,_global_re_init)()


#endif /* ! MHD_TLS_FUNCS_H */
