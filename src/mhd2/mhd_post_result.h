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
 * @file src/mhd2/mhd_post_result.h
 * @brief  The definition of enum for POST parsing result
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_POST_RESULT_H
#define MHD_POST_RESULT_H 1

#include "mhd_sys_options.h"

// TODO: describe and copy to the main header

#ifndef MHD_POST_PARSE_RESULT_DEFINED

enum MHD_FIXED_ENUM_MHD_SET_ MHD_PostParseResult
{
  /**
   * The POST data parse successfully and completely.
   */
  MHD_POST_PARSE_RES_OK = 0
  ,
  /**
   * The POST request has no content or zero-length content.
   */
  MHD_POST_PARSE_RES_REQUEST_EMPTY = 1
  ,
  /**
   * Parsing of the POST data is incomplete because client used incorrect
   * format of POST encoding.
   * Some POST data is available or has been provided via callback.
   */
  MHD_POST_PARSE_RES_PARTIAL_INVALID_POST_FORMAT = 2
  ,
  /**
   * The POST data cannot be parsed completely because the stream has
   * no free pool memory.
   * Some POST data may be parsed.
   */
  MHD_POST_PARSE_RES_FAILED_NO_POOL_MEM = 60
  ,
  /**
   * The POST data cannot be parsed completely because no "large shared buffer"
   * space is available.
   * Some POST data may be parsed.
   */
  MHD_POST_PARSE_RES_FAILED_NO_LARGE_BUF_MEM = 61
  ,
  /**
   * The POST data cannot be parsed because 'Content-Type:' is unknown.
   */
  MHD_POST_PARSE_RES_FAILED_UNKNOWN_CNTN_TYPE = 80
  ,
  /**
   * The POST data cannot be parsed because 'Content-Type:' header is not set.
   */
  MHD_POST_PARSE_RES_FAILED_NO_CNTN_TYPE = 81
  ,
  /**
   * The POST data cannot be parsed because "Content-Type:" request header has
   * no "boundary" parameter for "multipart/form-data"
   */
  MHD_POST_PARSE_RES_FAILED_HEADER_NO_BOUNDARY = 82
  ,
  /**
   * The POST data cannot be parsed because "Content-Type: multipart/form-data"
   * request header is misformed
   */
  MHD_POST_PARSE_RES_FAILED_HEADER_MISFORMED = 83
  ,
  /**
   * The application set POST encoding to "multipart/form-data", but the request
   * has no "Content-Type: multipart/form-data" header which is required
   * to find "boundary" used in this encoding
   */
  MHD_POST_PARSE_RES_FAILED_HEADER_NOT_MPART = 84
  ,
  /**
   * The POST data cannot be parsed because client used incorrect format
   * of POST encoding.
   */
  MHD_POST_PARSE_RES_FAILED_INVALID_POST_FORMAT = 90

};

#define MHD_POST_PARSE_RESULT_DEFINED 1
#endif /* ! MHD_POST_PARSE_RESULT_DEFINED */


#endif /* ! MHD_POST_RESULT_H */
