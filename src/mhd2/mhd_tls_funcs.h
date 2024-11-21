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

#include "sys_bool_type.h"

#include "mhd_tls_choice.h"
#ifndef MHD_ENABLE_HTTPS
#error This header should be used only if HTTPS is enabled
#endif

#if defined(MHD_USE_MULTITLS)
// TODO: Multi-TLS implementation
#elif defined(MHD_USE_GNUTLS)
#  include "tls_gnu_funcs.h"
#endif

#ifndef MHD_USE_GNUTLS
#  define mhd_tls_gnu_is_inited_fine()   (0)
#endif

/* ** Global initialisation / de-initialisation ** */

/**
 * Perform one-time global initialisation of TLS backend
 */
#define mhd_tls_global_init_once()        mhd_TLS_FUNC (_global_init_once)()

/**
 * Perform de-initialisation of TLS backend
 */
#define mhd_tls_global_deinit()           mhd_TLS_FUNC (_global_deinit)()

/**
 * Perform re-initialisation of TLS backend
 */
#define mhd_tls_global_re_init()          mhd_TLS_FUNC (_global_re_init)()

/* ** Daemon initialisation / de-initialisation ** */

/**
 * Allocate and initialise daemon TLS parameters
 * @param d the daemon handle
 * @param s the daemon settings
 * @param p_d_tls the pointer to variable to set the pointer to
 *                the daemon's TLS settings (allocated by this function)
 * @return #MHD_SC_OK on success (p_d_tls set to the allocated settings),
 *         error code otherwise
 */
#define mhd_tls_daemon_init(d,s,p_d_tls)        \
        mhd_TLS_FUNC (_daemon_init)((d),(s),(p_d_tls))

/**
 * De-initialise daemon TLS parameters (and free memory allocated for TLS
 * settings)
 * @param d_tls the pointer to  the daemon's TLS settings
 */
#define mhd_tls_daemon_deinit(d_tls)    \
        mhd_TLS_FUNC (_daemon_deinit)((d_tls))


/**
 * Result of TLS backend availability check
 */
enum mhd_TlsBackendAvailable
{
  /**
   * The TLS backend is available and can be used
   */
  mhd_TLS_BACKEND_AVAIL_OK = 0
  ,
  /**
   * The TLS backend support is not enabled in this MHD build
   */
  mhd_TLS_BACKEND_AVAIL_NOT_SUPPORTED
  ,
  /**
   * The TLS backend supported, but not available
   */
  mhd_TLS_BACKEND_AVAIL_NOT_AVAILABLE
};

/**
 * Check whether the requested TLS backend is available
 * @param s the daemon settings
 * @return 'mhd_TLS_BACKEND_AVAIL_OK' if requested backend is available,
 *         error code otherwise
 */
MHD_INTERNAL enum mhd_TlsBackendAvailable
mhd_tls_is_backend_available (struct DaemonOptions *s)
MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_;

#endif /* ! MHD_TLS_FUNCS_H */
