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
 * @file src/mhd2/request_get_info.c
 * @brief  The implementation of MHD_request_get_info_*() functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include "mhd_assert.h"

#include "mhd_cntnr_ptr.h"

#include "mhd_request.h"
#include "mhd_connection.h"

#include "mhd_public_api.h"

MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_ (3)
MHD_FN_PURE_ enum MHD_StatusCode
MHD_request_get_info_fixed_sz (
  struct MHD_Request *MHD_RESTRICT request,
  enum MHD_RequestInfoFixedType info_type,
  union MHD_RequestInfoFixedData *MHD_RESTRICT return_value,
  size_t return_value_size)
{
  switch (info_type)
  {
  case MHD_REQUEST_INFO_FIXED_STREAM:
    mhd_assert (0 && "Not implemented yet");
    break;
  case MHD_REQUEST_INFO_FIXED_CONNECTION:
    if (sizeof(return_value->v_connection) > return_value_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    return_value->v_connection =
      mhd_CNTNR_PTR (request, struct MHD_Connection, rq);
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_FIXED_DAEMON:
    if (sizeof(return_value->v_daemon) > return_value_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    return_value->v_daemon =
      mhd_CNTNR_PTR (request, struct MHD_Connection, rq)->daemon;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_FIXED_HTTP_VER:
    if (sizeof(return_value->v_http_ver) > return_value_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    return_value->v_http_ver = request->http_ver;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_FIXED_HTTP_METHOD:
    if (sizeof(return_value->v_http_method) > return_value_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    mhd_assert (mhd_HTTP_METHOD_NO_METHOD != request->http_mthd);
    return_value->v_http_method = (enum MHD_HTTP_Method) request->http_mthd;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_FIXED_SENTINEL:
  default:
  }

  return MHD_SC_INFO_TYPE_UNKNOWN;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_ (3)
MHD_FN_PURE_ enum MHD_StatusCode
MHD_request_get_info_dynamic_sz (
  struct MHD_Request *MHD_RESTRICT request,
  enum MHD_RequestInfoDynamicType info_type,
  union MHD_RequestInfoDynamicData *MHD_RESTRICT return_value,
  size_t return_value_size)
{
  switch (info_type)
  {
  case MHD_REQUEST_INFO_DYNAMIC_HTTP_METHOD_STR:
    /* TODO: check stage */
    if (sizeof(return_value->v_str) > return_value_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    return_value->v_str = request->method;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_DYNAMIC_URI:
    /* TODO: check stage */
    if (sizeof(return_value->v_str) > return_value_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    return_value->v_str.cstr = request->url;
    return_value->v_str.len = request->url_len;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_DYNAMIC_NUMBER_GET_PARAMS:
  case MHD_REQUEST_INFO_DYNAMIC_NUMBER_COOKIES:
  case MHD_REQUEST_INFO_DYNAMIC_NUMBER_POST_PARAMS:
  case MHD_REQUEST_INFO_DYNAMIC_UPLOAD_PRESENT:
  case MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_TOTAL:
  case MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_RECIEVED:
  case MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_TO_RECIEVE:
  case MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_PROCESSED:
  case MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_TO_PROCESS:
    mhd_assert (0 && "Not implemented yet");
    break;
  case MHD_REQUEST_INFO_DYNAMIC_HEADER_SIZE:
    /* TODO: check stage */
    if (sizeof(return_value->v_sizet) > return_value_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    return_value->v_sizet = request->header_size;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_DYNAMIC_APP_CONTEXT:
    mhd_assert (0 && "Not implemented yet");
    break;
  case MHD_REQUEST_INFO_DYNAMIC_DAUTH_USERNAME_INFO:
  case MHD_REQUEST_INFO_DYNAMIC_DAUTH_REQ_INFO:
    mhd_assert (0 && "Not implemented yet");
    break;
  case MHD_REQUEST_INFO_DYNAMIC_BAUTH_REQ_INFO:
    mhd_assert (0 && "Not implemented yet");
    break;
  case MHD_REQUEST_INFO_DYNAMIC_SENTINEL:
  default:
  }

  return MHD_SC_INFO_TYPE_UNKNOWN;
}
