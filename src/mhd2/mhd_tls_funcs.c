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
 * @file src/mhd2/mhd_tls_funcs.c
 * @brief  The TLS backend generic functions implementation
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "mhd_tls_funcs.h"

/* Include all supported TLS backends headers */
#if defined(MHD_SUPPORT_GNUTLS)
#  include "tls_gnu_funcs.h"
#endif
#if defined(MHD_SUPPORT_OPENSSL)
#  include "tls_open_funcs.h"
#endif

#include "mhd_assert.h"

#include "mhd_public_api.h"
#include "daemon_options.h"

MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_
enum mhd_TlsBackendAvailable
mhd_tls_is_backend_available (struct DaemonOptions *s)
{
  mhd_assert (MHD_TLS_BACKEND_NONE != s->tls);
  if (MHD_TLS_BACKEND_ANY == s->tls)
    return (mhd_tls_gnu_is_inited_fine ()
            || mhd_tls_open_is_inited_fine ()) ?
           mhd_TLS_BACKEND_AVAIL_OK :
           mhd_TLS_BACKEND_AVAIL_NOT_AVAILABLE;
#ifdef MHD_SUPPORT_GNUTLS
  if (MHD_TLS_BACKEND_GNUTLS == s->tls)
    return mhd_tls_gnu_is_inited_fine () ?
           mhd_TLS_BACKEND_AVAIL_OK :
           mhd_TLS_BACKEND_AVAIL_NOT_AVAILABLE;
#endif
#ifdef MHD_SUPPORT_OPENSSL
  if (MHD_TLS_BACKEND_OPENSSL == s->tls)
    return mhd_tls_open_is_inited_fine () ?
           mhd_TLS_BACKEND_AVAIL_OK :
           mhd_TLS_BACKEND_AVAIL_NOT_AVAILABLE;
#endif
  return mhd_TLS_BACKEND_AVAIL_NOT_SUPPORTED;
}
