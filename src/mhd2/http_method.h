/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2021-2024 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/http_method.h
 * @brief  The definition of the enums for the HTTP methods
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_HTTP_METHOD_H
#define MHD_HTTP_METHOD_H 1

#include "mhd_sys_options.h"

#ifndef MHD_HTTP_METHOD_DEFINED

enum MHD_FIXED_ENUM_MHD_SET_ MHD_HTTP_Method
{

  /**
   * Method did not match any of the methods given below.
   */
  MHD_HTTP_METHOD_OTHER = 255
  ,
  /* Main HTTP methods. */

  /**
   * "GET"
   * Safe.     Idempotent.     RFC9110, Section 9.3.1.
   */
  MHD_HTTP_METHOD_GET = 1
  ,
  /**
   * "HEAD"
   * Safe.     Idempotent.     RFC9110, Section 9.3.2.
   */
  MHD_HTTP_METHOD_HEAD = 2
  ,
  /**
   * "POST"
   * Not safe. Not idempotent. RFC9110, Section 9.3.3.
   */
  MHD_HTTP_METHOD_POST = 3
  ,
  /**
   * "PUT"
   * Not safe. Idempotent.     RFC9110, Section 9.3.4.
   */
  MHD_HTTP_METHOD_PUT = 4
  ,
  /**
   * "DELETE"
   * Not safe. Idempotent.     RFC9110, Section 9.3.5.
   */
  MHD_HTTP_METHOD_DELETE = 5
  ,
  /**
   * "CONNECT"
   * Not safe. Not idempotent. RFC9110, Section 9.3.6.
   */
  MHD_HTTP_METHOD_CONNECT = 6
  ,
  /**
   * "OPTIONS"
   * Safe.     Idempotent.     RFC9110, Section 9.3.7.
   */
  MHD_HTTP_METHOD_OPTIONS = 7
  ,
  /**
   * "TRACE"
   * Safe.     Idempotent.     RFC9110, Section 9.3.8.
   */
  MHD_HTTP_METHOD_TRACE = 8
  ,
  /**
   * "*"
   * Not safe. Not idempotent. RFC9110, Section 18.2.
   */
  MHD_HTTP_METHOD_ASTERISK = 9
};


#define MHD_HTTP_METHOD_DEFINED 1
#endif /* ! MHD_HTTP_METHOD_DEFINED */

/**
 * Internal version of MHD_HTTP_Method
 * Extended with the #mhd_HTTP_METHOD_NO_METHOD value
 */
enum MHD_FIXED_ENUM_ mhd_HTTP_Method
{

  /**
   * No method has been detected yet
   */
  mhd_HTTP_METHOD_NO_METHOD = 0
  ,

  /**
   * Method did not match any of the methods given below.
   */
  mhd_HTTP_METHOD_OTHER = MHD_HTTP_METHOD_OTHER
  ,
  /* Main HTTP methods. */

  /**
   * "GET"
   * Safe.     Idempotent.     RFC9110, Section 9.3.1.
   */
  mhd_HTTP_METHOD_GET = MHD_HTTP_METHOD_GET
  ,
  /**
   * "HEAD"
   * Safe.     Idempotent.     RFC9110, Section 9.3.2.
   */
  mhd_HTTP_METHOD_HEAD = MHD_HTTP_METHOD_HEAD
  ,
  /**
   * "POST"
   * Not safe. Not idempotent. RFC9110, Section 9.3.3.
   */
  mhd_HTTP_METHOD_POST = MHD_HTTP_METHOD_POST
  ,
  /**
   * "PUT"
   * Not safe. Idempotent.     RFC9110, Section 9.3.4.
   */
  mhd_HTTP_METHOD_PUT = MHD_HTTP_METHOD_PUT
  ,
  /**
   * "DELETE"
   * Not safe. Idempotent.     RFC9110, Section 9.3.5.
   */
  mhd_HTTP_METHOD_DELETE = MHD_HTTP_METHOD_DELETE
  ,
  /**
   * "CONNECT"
   * Not safe. Not idempotent. RFC9110, Section 9.3.6.
   */
  mhd_HTTP_METHOD_CONNECT = MHD_HTTP_METHOD_CONNECT
  ,
  /**
   * "OPTIONS"
   * Safe.     Idempotent.     RFC9110, Section 9.3.7.
   */
  mhd_HTTP_METHOD_OPTIONS = MHD_HTTP_METHOD_OPTIONS
  ,
  /**
   * "TRACE"
   * Safe.     Idempotent.     RFC9110, Section 9.3.8.
   */
  mhd_HTTP_METHOD_TRACE = MHD_HTTP_METHOD_TRACE
  ,
  /**
   * "*"
   * Not safe. Not idempotent. RFC9110, Section 18.2.
   */
  mhd_HTTP_METHOD_ASTERISK = MHD_HTTP_METHOD_ASTERISK
};

#define MHD_HTTP_METHOD_DEFINED 1
#endif /* ! MHD_HTTP_METHOD_H */
