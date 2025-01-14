/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024-2025 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/lib_get_info.c
 * @brief  The implementation of MHD_lib_get_info_*() functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include "mhd_assert.h"

#include "mhd_str_types.h"
#include "mhd_str_macros.h"

#include "sys_sockets_headers.h"
#include "sys_ip_headers.h"

#ifdef MHD_SUPPORT_THREADS
#  include "mhd_threads.h"
#endif

#include "mhd_itc.h"

#ifndef VERSION
#  include "mhd_str.h"
#endif

#ifdef MHD_ENABLE_HTTPS
#  include "mhd_tls_choice.h"
/* Include all supported TLS backends headers */
#  if defined(MHD_SUPPORT_GNUTLS)
#    include "tls_gnu_funcs.h"
#  endif
#  if defined(MHD_SUPPORT_OPENSSL)
#    include "tls_open_funcs.h"
#  endif
#endif

#ifdef MHD_SUPPORT_MD5
#  include "mhd_md5.h"
#endif
#ifdef MHD_SUPPORT_SHA256
#  include "mhd_sha256.h"
#endif
#ifdef MHD_SUPPORT_SHA512_256
#  include "mhd_sha512_256.h"
#endif

#include "mhd_lib_init.h"

#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif

#include "mhd_public_api.h"


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_OUT_ (2) enum MHD_StatusCode
MHD_lib_get_info_fixed_sz (enum MHD_LibInfoFixed info_type,
                           union MHD_LibInfoFixedData *return_data,
                           size_t return_data_size)
{
  switch (info_type)
  {

  /* * Basic MHD information * */

  case MHD_LIB_INFO_FIXED_VERSION_NUM:
    if (sizeof(return_data->v_uint32) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! MHD_VERSION
#error MHD_VERSION is not defined
#endif
    return_data->v_uint32 = (uint_fast32_t) MHD_VERSION;
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_VERSION_STR:
    if (sizeof(return_data->v_string) <= return_data_size)
    {
#ifdef VERSION
      static const struct MHD_String ver_str =
        mhd_MSTR_INIT (VERSION);
      return_data->v_string.len = ver_str.len;
      return_data->v_string.cstr = ver_str.cstr;
      return MHD_SC_OK;
#else  /* ! VERSION */
      static char str_buf[10] =
      {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1};   /* Larger than needed */
      if (0 != str_buf[8])
      {
        uint_fast32_t ver_num = MHD_VERSION;
        uint8_t digit;

        digit = (uint8_t) (ver_num >> 24);
        (void) mhd_bin_to_hex (&digit,
                               1,
                               str_buf);
        str_buf[2] = '.';
        digit = (uint8_t) (ver_num >> 16);
        (void) mhd_bin_to_hex (&digit,
                               1,
                               str_buf + 3);
        str_buf[5] = '.';
        digit = (uint8_t) (ver_num >> 8);
        (void) mhd_bin_to_hex (&digit,
                               1,
                               str_buf + 6);
        str_buf[8] = 0;
      }
      return_data->v_string.len = 8;
      return_data->v_string.cstr = str_buf;
      return MHD_SC_OK;
#endif /* ! VERSION */
    }
    return MHD_SC_INFO_GET_BUFF_TOO_SMALL;

  /* * Basic MHD features, buid-time configurable * */

  case MHD_LIB_INFO_FIXED_HAS_LOG_MESSAGES:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_LOG_FUNCTIONALITY
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_AUTO_REPLIES_BODIES:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_ENABLE_AUTO_MESSAGES_BODIES
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_IS_NON_DEBUG:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef NDEBUG
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_THREADS:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_THREADS
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_COOKIE_PARSER:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_COOKIES
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_POST_PARSER:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_POST_PARSER
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_UPGRADE:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_UPGRADE
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_AUTH_BASIC:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_AUTH_BASIC
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_AUTH_DIGEST:
  case MHD_LIB_INFO_FIXED_HAS_DIGEST_AUTH_RFC2069:
  case MHD_LIB_INFO_FIXED_HAS_DIGEST_AUTH_USERHASH:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_AUTH_DIGEST
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_TYPE_DIGEST_AUTH_MD5:
    if (sizeof(return_data->v_d_algo) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! defined(MHD_SUPPORT_MD5)
    return_data->v_d_algo = MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_NOT_AVAILABLE;
#elif ! defined(MHD_MD5_EXTR)
    return_data->v_d_algo = MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_BUILT_IN;
#elif ! defined(mhd_MD5_HAS_EXT_ERROR)
    return_data->v_d_algo =
      MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_EXTERNAL_NEVER_FAIL;
#else
    return_data->v_d_algo =
      MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_EXTERNAL_MAY_FAIL;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_TYPE_DIGEST_AUTH_SHA256:
    if (sizeof(return_data->v_d_algo) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! defined(MHD_SUPPORT_SHA256)
    return_data->v_d_algo = MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_NOT_AVAILABLE;
#elif ! defined(MHD_SHA256_EXTR)
    return_data->v_d_algo = MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_BUILT_IN;
#elif ! defined(mhd_SHA256_HAS_EXT_ERROR)
    return_data->v_d_algo =
      MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_EXTERNAL_NEVER_FAIL;
#else
    return_data->v_d_algo =
      MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_EXTERNAL_MAY_FAIL;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_TYPE_DIGEST_AUTH_SHA512_256:
    if (sizeof(return_data->v_d_algo) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! defined(MHD_SUPPORT_SHA512_256)
    return_data->v_d_algo = MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_NOT_AVAILABLE;
#elif ! defined(MHD_SHA512_256_EXTR)
    return_data->v_d_algo = MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_BUILT_IN;
#elif ! defined(mhd_SHA512_256_HAS_EXT_ERROR)
    return_data->v_d_algo =
      MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_EXTERNAL_NEVER_FAIL;
#else
    return_data->v_d_algo =
      MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_EXTERNAL_MAY_FAIL;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_DIGEST_AUTH_AUTH_INT:
  case MHD_LIB_INFO_FIXED_HAS_DIGEST_AUTH_ALGO_SESSION:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    return_data->v_bool = MHD_NO;
    return MHD_SC_OK;

  /* * Platform-dependent features, some are configurable at build-time * */

  case MHD_LIB_INFO_FIXED_TYPE_SOCKETS_POLLING:
    if (sizeof(return_data->v_polling) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_SELECT
    return_data->v_polling.func_select = MHD_YES;
#else
    return_data->v_polling.func_select = MHD_NO;
#endif
#ifdef MHD_SUPPORT_POLL
    return_data->v_polling.func_poll = MHD_YES;
#else
    return_data->v_polling.func_poll = MHD_NO;
#endif
#ifdef MHD_SUPPORT_EPOLL
    return_data->v_polling.tech_epoll = MHD_YES;
#else
    return_data->v_polling.tech_epoll = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_AGGREGATE_FD:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_EPOLL
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_TYPE_IPV6:
    if (sizeof(return_data->v_ipv6) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! defined(HAVE_INET6)
    return_data->v_ipv6 = MHD_LIB_INFO_FIXED_IPV6_TYPE_NONE;
#elif ! defined(HAVE_DCLR_IPV6_V6ONLY)
    return_data->v_ipv6 = MHD_LIB_INFO_FIXED_IPV6_TYPE_DUAL_ONLY;
#else
    return_data->v_ipv6 = MHD_LIB_INFO_FIXED_IPV6_TYPE_IPV6_PURE;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_TCP_FASTOPEN:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef HAVE_DCLR_TCP_FASTOPEN
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_AUTODETECT_BIND_PORT:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_USE_GETSOCKNAME
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_SENDFILE:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef mhd_USE_SENDFILE
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_AUTOSUPPRESS_SIGPIPE_INT:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! defined (mhd_SEND_SPIPE_SUPPRESS_NEEDED)
    return_data->v_bool = MHD_YES;
#elif defined (mhd_SEND_SPIPE_SUPPRESS_POSSIBLE) \
    || defined(mhd_HAVE_MHD_THREAD_BLOCK_SIGPIPE)
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_AUTOSUPPRESS_SIGPIPE_EXT:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! defined (mhd_SEND_SPIPE_SUPPRESS_NEEDED)
    return_data->v_bool = MHD_YES;
#elif defined (mhd_SEND_SPIPE_SUPPRESS_POSSIBLE)
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_THREAD_NAMES:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef mhd_USE_THREAD_NAME
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_TYPE_ITC:
    if (sizeof(return_data->v_itc) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! defined(MHD_SUPPORT_THREADS)
    return_data->v_itc = MHD_LIB_INFO_FIXED_ITC_TYPE_NONE;
#elif defined(MHD_ITC_SOCKETPAIR_)
    return_data->v_itc = MHD_LIB_INFO_FIXED_ITC_TYPE_SOCKETPAIR;
#elif defined(MHD_ITC_PIPE_)
    return_data->v_itc = MHD_LIB_INFO_FIXED_ITC_TYPE_PIPE;
#elif defined(MHD_ITC_EVENTFD_)
    return_data->v_itc = MHD_LIB_INFO_FIXED_ITC_TYPE_EVENTFD;
#else
#error The type of ITC is not defined
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_LARGE_FILE:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! defined(HAVE_PREAD) && defined(lseek64)
    return_data->v_bool = MHD_YES;
#elif defined(HAVE_PREAD64)
    return_data->v_bool = MHD_YES;
#elif defined(mhd_W32_NATIVE)
    return_data->v_bool = MHD_YES;
#else
    return_data->v_bool =
      (0x7FFFFFFFFFFFFFFF == ((off_t) 0x7FFFFFFFFFFFFFFF)) ? MHD_YES : MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_TYPE_TLS:
  case MHD_LIB_INFO_FIXED_HAS_TLS_KEY_PASSWORD: /* Both backends have support */
    if (sizeof(return_data->v_tls) <= return_data_size)
    {
#ifndef MHD_ENABLE_HTTPS
      return_data->v_tls.tls_supported = MHD_NO;
      return_data->v_tls.backend_gnutls = MHD_NO;
      return_data->v_tls.backend_openssl = MHD_NO;
#else
      return_data->v_tls.tls_supported = MHD_YES;
#  ifdef MHD_SUPPORT_GNUTLS
      return_data->v_tls.backend_gnutls = MHD_YES;
#  else  /* ! MHD_SUPPORT_GNUTLS */
      return_data->v_tls.backend_gnutls = MHD_NO;
#  endif /* ! MHD_SUPPORT_GNUTLS */
#  ifdef MHD_SUPPORT_OPENSSL
      return_data->v_tls.backend_openssl = MHD_YES;
#  else  /* ! MHD_SUPPORT_OPENSSL */
      return_data->v_tls.backend_openssl = MHD_NO;
#  endif /* ! MHD_SUPPORT_OPENSSL */
#endif
      return MHD_SC_OK;
    }
    return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    break;
  case MHD_LIB_INFO_FIXED_SENTINEL:
  default:
    break;
  }
  return MHD_SC_INFO_GET_TYPE_UNKNOWN;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (2)
MHD_FN_PAR_OUT_ (2) enum MHD_StatusCode
MHD_lib_get_info_dynamic_sz (enum MHD_LibInfoDynamic info_type,
                             union MHD_LibInfoDynamicData *return_data,
                             size_t return_data_size)
{
  switch (info_type)
  {
  case MHD_LIB_INFO_DYNAMIC_INITED_FULLY_ONCE:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    return_data->v_bool =
      mhd_lib_is_fully_initialised_once () ? MHD_YES : MHD_NO;
    return MHD_SC_OK;
  case MHD_LIB_INFO_DYNAMIC_INITED_FULLY_NOW:
    if (sizeof(return_data->v_bool) > return_data_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    return_data->v_bool =
      mhd_lib_is_fully_initialised_now () ? MHD_YES : MHD_NO;
    return MHD_SC_OK;
  case MHD_LIB_INFO_DYNAMIC_TYPE_TLS:
    if (sizeof(return_data->v_tls) <= return_data_size)
    {
#ifndef MHD_ENABLE_HTTPS
      return_data->v_tls.tls_supported = MHD_NO;
      return_data->v_tls.backend_gnutls = MHD_NO;
      return_data->v_tls.backend_openssl = MHD_NO;
#else
      bool gnutls_avail;
      bool openssl_avail;

      if (! mhd_lib_init_global_if_needed ())
        return MHD_SC_INFO_GET_TYPE_UNAVAILALBE;

      gnutls_avail = mhd_tls_gnu_is_inited_fine ();
      openssl_avail = mhd_tls_open_is_inited_fine ();

      return_data->v_tls.tls_supported =
        (gnutls_avail || openssl_avail) ?
        MHD_YES : MHD_NO;
      return_data->v_tls.backend_gnutls = gnutls_avail ? MHD_YES : MHD_NO;
      return_data->v_tls.backend_openssl = openssl_avail ? MHD_YES : MHD_NO;

      mhd_lib_deinit_global_if_needed ();
#endif
      return MHD_SC_OK;
    }
    return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
  case MHD_LIB_INFO_DYNAMIC_SENTINEL:
  default:
    break;
  }
  return MHD_SC_INFO_GET_TYPE_UNKNOWN;
}
