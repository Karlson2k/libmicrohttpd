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
                           union MHD_LibInfoFixedData *output_buf,
                           size_t output_buf_size)
{
  switch (info_type)
  {

  /* * Basic MHD information * */

  case MHD_LIB_INFO_FIXED_VERSION_NUM:
    if (sizeof(output_buf->v_uint32) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! MHD_VERSION
#error MHD_VERSION is not defined
#endif
    output_buf->v_uint32 = (uint_fast32_t) MHD_VERSION;
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_VERSION_STR:
    if (sizeof(output_buf->v_string) <= output_buf_size)
    {
#ifdef VERSION
      static const struct MHD_String ver_str =
        mhd_MSTR_INIT (VERSION);
      output_buf->v_string.len = ver_str.len;
      output_buf->v_string.cstr = ver_str.cstr;
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
      output_buf->v_string.len = 8;
      output_buf->v_string.cstr = str_buf;
      return MHD_SC_OK;
#endif /* ! VERSION */
    }
    return MHD_SC_INFO_GET_BUFF_TOO_SMALL;

  /* * Basic MHD features, buid-time configurable * */

  case MHD_LIB_INFO_FIXED_HAS_LOG_MESSAGES:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_LOG_FUNCTIONALITY
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_AUTO_REPLIES_BODIES:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_ENABLE_AUTO_MESSAGES_BODIES
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_IS_NON_DEBUG:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef NDEBUG
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_THREADS:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_THREADS
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_COOKIE_PARSER:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_COOKIES
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_POST_PARSER:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_POST_PARSER
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_UPGRADE:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_UPGRADE
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_AUTH_BASIC:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_AUTH_BASIC
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_AUTH_DIGEST:
  case MHD_LIB_INFO_FIXED_HAS_DIGEST_AUTH_RFC2069:
  case MHD_LIB_INFO_FIXED_HAS_DIGEST_AUTH_USERHASH:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_AUTH_DIGEST
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_TYPE_DIGEST_AUTH_MD5:
    if (sizeof(output_buf->v_d_algo) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! defined(MHD_SUPPORT_MD5)
    output_buf->v_d_algo = MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_NOT_AVAILABLE;
#elif ! defined(MHD_MD5_EXTR)
    output_buf->v_d_algo = MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_BUILT_IN;
#elif ! defined(mhd_MD5_HAS_EXT_ERROR)
    output_buf->v_d_algo =
      MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_EXTERNAL_NEVER_FAIL;
#else
    output_buf->v_d_algo =
      MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_EXTERNAL_MAY_FAIL;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_TYPE_DIGEST_AUTH_SHA256:
    if (sizeof(output_buf->v_d_algo) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! defined(MHD_SUPPORT_SHA256)
    output_buf->v_d_algo = MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_NOT_AVAILABLE;
#elif ! defined(MHD_SHA256_EXTR)
    output_buf->v_d_algo = MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_BUILT_IN;
#elif ! defined(mhd_SHA256_HAS_EXT_ERROR)
    output_buf->v_d_algo =
      MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_EXTERNAL_NEVER_FAIL;
#else
    output_buf->v_d_algo =
      MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_EXTERNAL_MAY_FAIL;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_TYPE_DIGEST_AUTH_SHA512_256:
    if (sizeof(output_buf->v_d_algo) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! defined(MHD_SUPPORT_SHA512_256)
    output_buf->v_d_algo = MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_NOT_AVAILABLE;
#elif ! defined(MHD_SHA512_256_EXTR)
    output_buf->v_d_algo = MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_BUILT_IN;
#elif ! defined(mhd_SHA512_256_HAS_EXT_ERROR)
    output_buf->v_d_algo =
      MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_EXTERNAL_NEVER_FAIL;
#else
    output_buf->v_d_algo =
      MHD_LIB_INFO_FIXED_DIGEST_ALGO_TYPE_EXTERNAL_MAY_FAIL;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_DIGEST_AUTH_AUTH_INT:
  case MHD_LIB_INFO_FIXED_HAS_DIGEST_AUTH_ALGO_SESSION:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_bool = MHD_NO;
    return MHD_SC_OK;

  /* * Platform-dependent features, some are configurable at build-time * */

  case MHD_LIB_INFO_FIXED_TYPE_SOCKETS_POLLING:
    if (sizeof(output_buf->v_polling) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_SELECT
    output_buf->v_polling.func_select = MHD_YES;
#else
    output_buf->v_polling.func_select = MHD_NO;
#endif
#ifdef MHD_SUPPORT_POLL
    output_buf->v_polling.func_poll = MHD_YES;
#else
    output_buf->v_polling.func_poll = MHD_NO;
#endif
#ifdef MHD_SUPPORT_EPOLL
    output_buf->v_polling.tech_epoll = MHD_YES;
#else
    output_buf->v_polling.tech_epoll = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_AGGREGATE_FD:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_SUPPORT_EPOLL
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_TYPE_IPV6:
    if (sizeof(output_buf->v_ipv6) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! defined(HAVE_INET6)
    output_buf->v_ipv6 = MHD_LIB_INFO_FIXED_IPV6_TYPE_NONE;
#elif ! defined(HAVE_DCLR_IPV6_V6ONLY)
    output_buf->v_ipv6 = MHD_LIB_INFO_FIXED_IPV6_TYPE_DUAL_ONLY;
#else
    output_buf->v_ipv6 = MHD_LIB_INFO_FIXED_IPV6_TYPE_IPV6_PURE;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_TCP_FASTOPEN:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef HAVE_DCLR_TCP_FASTOPEN
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_AUTODETECT_BIND_PORT:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef MHD_USE_GETSOCKNAME
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_SENDFILE:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef mhd_USE_SENDFILE
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_AUTOSUPPRESS_SIGPIPE_INT:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! defined (mhd_SEND_SPIPE_SUPPRESS_NEEDED)
    output_buf->v_bool = MHD_YES;
#elif defined (mhd_SEND_SPIPE_SUPPRESS_POSSIBLE) \
    || defined(mhd_HAVE_MHD_THREAD_BLOCK_SIGPIPE)
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_AUTOSUPPRESS_SIGPIPE_EXT:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! defined (mhd_SEND_SPIPE_SUPPRESS_NEEDED)
    output_buf->v_bool = MHD_YES;
#elif defined (mhd_SEND_SPIPE_SUPPRESS_POSSIBLE)
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_THREAD_NAMES:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#ifdef mhd_USE_THREAD_NAME
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool = MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_TYPE_ITC:
    if (sizeof(output_buf->v_itc) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! defined(MHD_SUPPORT_THREADS)
    output_buf->v_itc = MHD_LIB_INFO_FIXED_ITC_TYPE_NONE;
#elif defined(MHD_ITC_SOCKETPAIR_)
    output_buf->v_itc = MHD_LIB_INFO_FIXED_ITC_TYPE_SOCKETPAIR;
#elif defined(MHD_ITC_PIPE_)
    output_buf->v_itc = MHD_LIB_INFO_FIXED_ITC_TYPE_PIPE;
#elif defined(MHD_ITC_EVENTFD_)
    output_buf->v_itc = MHD_LIB_INFO_FIXED_ITC_TYPE_EVENTFD;
#else
#error The type of ITC is not defined
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_HAS_LARGE_FILE:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
#if ! defined(HAVE_PREAD) && defined(lseek64)
    output_buf->v_bool = MHD_YES;
#elif defined(HAVE_PREAD64)
    output_buf->v_bool = MHD_YES;
#elif defined(mhd_W32_NATIVE)
    output_buf->v_bool = MHD_YES;
#else
    output_buf->v_bool =
      (0x7FFFFFFFFFFFFFFF == ((off_t) 0x7FFFFFFFFFFFFFFF)) ? MHD_YES : MHD_NO;
#endif
    return MHD_SC_OK;
  case MHD_LIB_INFO_FIXED_TYPE_TLS:
  case MHD_LIB_INFO_FIXED_HAS_TLS_KEY_PASSWORD: /* Both backends have support */
    if (sizeof(output_buf->v_tls) <= output_buf_size)
    {
#ifndef MHD_ENABLE_HTTPS
      output_buf->v_tls.tls_supported = MHD_NO;
      output_buf->v_tls.backend_gnutls = MHD_NO;
      output_buf->v_tls.backend_openssl = MHD_NO;
#else
      output_buf->v_tls.tls_supported = MHD_YES;
#  ifdef MHD_SUPPORT_GNUTLS
      output_buf->v_tls.backend_gnutls = MHD_YES;
#  else  /* ! MHD_SUPPORT_GNUTLS */
      output_buf->v_tls.backend_gnutls = MHD_NO;
#  endif /* ! MHD_SUPPORT_GNUTLS */
#  ifdef MHD_SUPPORT_OPENSSL
      output_buf->v_tls.backend_openssl = MHD_YES;
#  else  /* ! MHD_SUPPORT_OPENSSL */
      output_buf->v_tls.backend_openssl = MHD_NO;
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
                             union MHD_LibInfoDynamicData *output_buf,
                             size_t output_buf_size)
{
  switch (info_type)
  {
  case MHD_LIB_INFO_DYNAMIC_INITED_FULLY_ONCE:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_bool =
      mhd_lib_is_fully_initialised_once () ? MHD_YES : MHD_NO;
    return MHD_SC_OK;
  case MHD_LIB_INFO_DYNAMIC_INITED_FULLY_NOW:
    if (sizeof(output_buf->v_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_bool =
      mhd_lib_is_fully_initialised_now () ? MHD_YES : MHD_NO;
    return MHD_SC_OK;
  case MHD_LIB_INFO_DYNAMIC_TYPE_TLS:
    if (sizeof(output_buf->v_tls) <= output_buf_size)
    {
#ifndef MHD_ENABLE_HTTPS
      output_buf->v_tls.tls_supported = MHD_NO;
      output_buf->v_tls.backend_gnutls = MHD_NO;
      output_buf->v_tls.backend_openssl = MHD_NO;
#else
      bool gnutls_avail;
      bool openssl_avail;

      if (! mhd_lib_init_global_if_needed ())
        return MHD_SC_INFO_GET_TYPE_UNOBTAINABLE;

      gnutls_avail = mhd_tls_gnu_is_inited_fine ();
      openssl_avail = mhd_tls_open_is_inited_fine ();

      output_buf->v_tls.tls_supported =
        (gnutls_avail || openssl_avail) ?
        MHD_YES : MHD_NO;
      output_buf->v_tls.backend_gnutls = gnutls_avail ? MHD_YES : MHD_NO;
      output_buf->v_tls.backend_openssl = openssl_avail ? MHD_YES : MHD_NO;

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
