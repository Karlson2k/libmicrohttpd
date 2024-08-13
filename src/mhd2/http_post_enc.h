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
 * @file src/mhd2/http_post_enc.h
 * @brief  The definition of the enum for POST encoding types
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_HTTP_POST_ENC_H
#define MHD_HTTP_POST_ENC_H 1

#include "mhd_sys_options.h"


#ifndef MHD_HTTP_POSTENCODING_DEFINED

/**
 * @brief Possible encodings for HTML forms submitted as HTTP POST requests
 *
 * @defgroup postenc HTTP POST encodings
 * See also: https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#form-submission-2
 * @{
 */
enum MHD_FIXED_ENUM_MHD_APP_SET_ MHD_HTTP_PostEncoding
{
  /**
   * No post encoding / broken data / unknown encoding
   */
  MHD_HTTP_POST_ENCODING_OTHER = 0
  ,
  /**
   * "application/x-www-form-urlencoded"
   * See https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#url-encoded-form-data
   * See https://url.spec.whatwg.org/#application/x-www-form-urlencoded
   * See https://datatracker.ietf.org/doc/html/rfc3986#section-2
   */
  MHD_HTTP_POST_ENCODING_FORM_URLENCODED = 1
  ,
  /**
   * "multipart/form-data"
   * See https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#multipart-form-data
   * See https://www.rfc-editor.org/rfc/rfc7578.html
   */
  MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA = 2
  ,
  /**
   * "text/plain"
   * Introduced by HTML5
   * See https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#plain-text-form-data
   * @warning Format is ambiguous. Do not use unless there is a very strong reason.
   */
  MHD_HTTP_POST_ENCODING_TEXT_PLAIN = 3
};


/** @} */ /* end of group postenc */

#  define MHD_HTTP_POSTENCODING_DEFINED 1
#endif /* ! MHD_HTTP_POSTENCODING_DEFINED */



#endif /* ! MHD_HTTP_POST_ENC_H */
