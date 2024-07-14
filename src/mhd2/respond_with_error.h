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
 * @file src/mhd2/respond_with_error.h
 * @brief  The declaration of error response functions and helper macros
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_RESPOND_WITH_ERROR_H
#define MHD_RESPOND_WITH_ERROR_H 1

#include "mhd_sys_options.h"
#include "sys_base_types.h"
#include "sys_null_macro.h"
#include "mhd_str_macros.h"

struct MHD_Connection; /* forward declaration */

MHD_INTERNAL void
respond_with_error_len (struct MHD_Connection *c,
                        unsigned int http_code,
                        size_t msg_len,
                        const char *msg,
                        size_t add_hdr_name_len,
                        const char *add_hdr_name,
                        size_t add_hdr_value_len,
                        const char *add_hdr_value)
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_CSTR_ (4) MHD_FN_PAR_CSTR_ (6) MHD_FN_PAR_CSTR_ (8);

#ifdef HAVE_HTTP_AUTO_MESSAGES_BODIES
/**
 * Transmit static string as error response
 */
#  define mhd_RESPOND_WITH_ERROR_STATIC(c, code, msg) \
        respond_with_error_len ((c), (code), \
                                mhd_SSTR_LEN (msg), (msg), \
                                0, NULL, 0, NULL)

/**
 * Transmit static string as error response and add specified header
 */
#  define mhd_RESPOND_WITH_ERROR_HEADER(c,code,m,hd_n_l,hd_n,hd_v_l,hd_v) \
        respond_with_error_len ((c), (code), \
                                mhd_SSTR_LEN (m), (m), \
                                (hd_n_l), (hd_n), \
                                (hd_v_l), (hd_v))

#else
/**
 * Transmit static string as error response
 */
#  define mhd_RESPOND_WITH_ERROR_STATIC(c, code, msg) \
        respond_with_error_len ((c), (code), \
                                0, NULL, \
                                0, NULL, 0, NULL)

/**
 * Transmit static string as error response and add specified header
 */
#  define mhd_RESPOND_WITH_ERROR_HEADER(c,code,m,hd_n_l,hd_n,hd_v_l,hd_v) \
        respond_with_error_len ((c), (code), \
                                0, NULL, \
                                (hd_n_l), (hd_n), \
                                (hd_v_l), (hd_v))
#endif

#endif /* ! MHD_RESPOND_WITH_ERROR_H */
