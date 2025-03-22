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

#ifdef MHD_SUPPORT_AUTH_BASIC
#  include "auth_basic.h"
#endif
#ifdef MHD_SUPPORT_AUTH_DIGEST
#  include "auth_digest.h"
#endif

#ifdef MHD_SUPPORT_COOKIES
#  include "mhd_daemon.h"
#endif

#include "mhd_public_api.h"

MHD_EXTERN_ MHD_FN_MUST_CHECK_RESULT_
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_ (3) enum MHD_StatusCode
MHD_request_get_info_fixed_sz (
  struct MHD_Request *MHD_RESTRICT request,
  enum MHD_RequestInfoFixedType info_type,
  union MHD_RequestInfoFixedData *MHD_RESTRICT output_buf,
  size_t output_buf_size)
{
  switch (info_type)
  {
  case MHD_REQUEST_INFO_FIXED_HTTP_VER:
    if (mhd_HTTP_STAGE_REQ_LINE_RECEIVED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_EARLY;
    if (sizeof(output_buf->v_http_ver) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_http_ver = request->http_ver;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_FIXED_HTTP_METHOD:
    if (mhd_HTTP_METHOD_NO_METHOD == request->http_mthd)
      return MHD_SC_TOO_EARLY;
    if (sizeof(output_buf->v_http_method) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_http_method = (enum MHD_HTTP_Method) request->http_mthd;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_FIXED_DAEMON:
    if (sizeof(output_buf->v_daemon) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_daemon =
      mhd_CNTNR_PTR (request, \
                     struct MHD_Connection, \
                     rq)->daemon;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_FIXED_CONNECTION:
    if (sizeof(output_buf->v_connection) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_connection =
      mhd_CNTNR_PTR (request, \
                     struct MHD_Connection, \
                     rq);
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_FIXED_STREAM:
    if (sizeof(output_buf->v_stream) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_stream =
      &(mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->h1_stream);
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_FIXED_APP_CONTEXT:
    if (sizeof(output_buf->v_app_context_ppvoid) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_app_context_ppvoid = &(request->app_context);
    return MHD_SC_OK;

  case MHD_REQUEST_INFO_FIXED_SENTINEL:
  default:
    break;
  }

  return MHD_SC_INFO_GET_TYPE_UNKNOWN;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_OUT_ (3) enum MHD_StatusCode
MHD_request_get_info_dynamic_sz (
  struct MHD_Request *MHD_RESTRICT request,
  enum MHD_RequestInfoDynamicType info_type,
  union MHD_RequestInfoDynamicData *MHD_RESTRICT output_buf,
  size_t output_buf_size)
{
  switch (info_type)
  {
  case MHD_REQUEST_INFO_DYNAMIC_HTTP_METHOD_STRING:
    if (mhd_HTTP_STAGE_REQ_RECV_FINISHED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_LATE;
    if (0 == request->method.len)
      return MHD_SC_TOO_EARLY;
    if (sizeof(output_buf->v_http_method_string) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_http_method_string = request->method;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_DYNAMIC_URI:
    if (mhd_HTTP_STAGE_REQ_LINE_RECEIVED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_EARLY;
    if (mhd_HTTP_STAGE_REQ_RECV_FINISHED <
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_LATE;
    if (sizeof(output_buf->v_uri_string) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_uri_string.cstr = request->url;
    output_buf->v_uri_string.len = request->url_len;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_DYNAMIC_NUMBER_URI_PARAMS:
    if (mhd_HTTP_STAGE_REQ_LINE_RECEIVED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_EARLY;
    if (mhd_HTTP_STAGE_REQ_RECV_FINISHED <
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_LATE;
    if (sizeof(output_buf->v_number_uri_params_sizet) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_number_uri_params_sizet =
      MHD_request_get_values_cb (request,
                                 MHD_VK_GET_ARGUMENT,
                                 NULL,
                                 NULL);
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_DYNAMIC_NUMBER_COOKIES:
#ifdef MHD_SUPPORT_COOKIES
    if (mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->daemon->req_cfg.disable_cookies)
      return MHD_SC_INFO_GET_TYPE_NOT_APPLICABLE;
    if (mhd_HTTP_STAGE_HEADERS_PROCESSED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_EARLY;
    if (mhd_HTTP_STAGE_REQ_RECV_FINISHED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_LATE;
    if (sizeof(output_buf->v_number_cookies_sizet) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_number_cookies_sizet =
      MHD_request_get_values_cb (request,
                                 MHD_VK_COOKIE,
                                 NULL,
                                 NULL);
    return MHD_SC_OK;
#else
    return MHD_SC_FEATURE_DISABLED;
#endif
    break;
  case MHD_REQUEST_INFO_DYNAMIC_HEADER_SIZE:
    if (mhd_HTTP_STAGE_HEADERS_PROCESSED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_EARLY;
    if (mhd_HTTP_STAGE_REQ_RECV_FINISHED <
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_LATE;
    if (sizeof(output_buf->v_header_size_sizet) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_header_size_sizet = request->header_size;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_DYNAMIC_NUMBER_POST_PARAMS:
#ifdef MHD_SUPPORT_POST_PARSER
    if (mhd_HTTP_STAGE_HEADERS_PROCESSED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_EARLY;
    if (mhd_HTTP_STAGE_REQ_RECV_FINISHED <
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_LATE;
    if (sizeof(output_buf->v_number_post_params_sizet) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_number_post_params_sizet =
      MHD_request_get_values_cb (request,
                                 MHD_VK_POSTDATA,
                                 NULL,
                                 NULL);
    return MHD_SC_OK;
#else
    return MHD_SC_FEATURE_DISABLED;
#endif
    break;
  case MHD_REQUEST_INFO_DYNAMIC_UPLOAD_PRESENT:
    if (mhd_HTTP_STAGE_HEADERS_PROCESSED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_EARLY;
    if (sizeof(output_buf->v_upload_present_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_upload_present_bool =
      request->cntn.cntn_present ? MHD_YES : MHD_NO;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_DYNAMIC_UPLOAD_CHUNKED:
    if (mhd_HTTP_STAGE_HEADERS_PROCESSED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_EARLY;
    if (sizeof(output_buf->v_upload_chunked_bool) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_upload_chunked_bool =
      (MHD_SIZE_UNKNOWN == request->cntn.cntn_size) ? MHD_YES : MHD_NO;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_TOTAL:
    if (mhd_HTTP_STAGE_HEADERS_PROCESSED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_EARLY;
    if (sizeof(output_buf->v_upload_size_total_uint64) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_upload_size_total_uint64 = request->cntn.cntn_size;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_RECIEVED:
    if (mhd_HTTP_STAGE_HEADERS_PROCESSED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_EARLY;
    if (sizeof(output_buf->v_upload_size_recieved_uint64) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_upload_size_recieved_uint64 = request->cntn.recv_size;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_TO_RECIEVE:
    if (mhd_HTTP_STAGE_HEADERS_PROCESSED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_EARLY;
    if (sizeof(output_buf->v_upload_size_to_recieve_uint64) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_upload_size_to_recieve_uint64 =
      (MHD_SIZE_UNKNOWN == request->cntn.cntn_size) ?
      MHD_SIZE_UNKNOWN : (request->cntn.cntn_size - request->cntn.recv_size);
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_PROCESSED:
    if (mhd_HTTP_STAGE_HEADERS_PROCESSED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_EARLY;
    if (sizeof(output_buf->v_upload_size_processed_uint64) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_upload_size_processed_uint64 = request->cntn.proc_size;
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_DYNAMIC_UPLOAD_SIZE_TO_PROCESS:
    if (mhd_HTTP_STAGE_HEADERS_PROCESSED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_EARLY;
    if (sizeof(output_buf->v_upload_size_to_process_uint64) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    output_buf->v_upload_size_to_process_uint64 =
      (MHD_SIZE_UNKNOWN == request->cntn.cntn_size) ?
      MHD_SIZE_UNKNOWN : (request->cntn.cntn_size - request->cntn.proc_size);
    return MHD_SC_OK;
  case MHD_REQUEST_INFO_DYNAMIC_AUTH_DIGEST_INFO:
    if (mhd_HTTP_STAGE_HEADERS_PROCESSED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_EARLY;
    if (mhd_HTTP_STAGE_REQ_RECV_FINISHED <
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_LATE;
#ifdef MHD_SUPPORT_AUTH_DIGEST
    if (sizeof(output_buf->v_auth_basic_creds) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    return mhd_request_get_auth_digest_info (request,
                                             &(output_buf->
                                               v_auth_digest_info));
#else  /* ! MHD_SUPPORT_AUTH_DIGEST */
    return MHD_SC_FEATURE_DISABLED;
#endif /* ! MHD_SUPPORT_AUTH_DIGEST */
    break;
  case MHD_REQUEST_INFO_DYNAMIC_AUTH_BASIC_CREDS:
    if (mhd_HTTP_STAGE_HEADERS_PROCESSED >
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_EARLY;
    if (mhd_HTTP_STAGE_REQ_RECV_FINISHED <
        mhd_CNTNR_PTR (request, \
                       struct MHD_Connection, \
                       rq)->stage)
      return MHD_SC_TOO_LATE;
#ifdef MHD_SUPPORT_AUTH_BASIC
    if (sizeof(output_buf->v_auth_basic_creds) > output_buf_size)
      return MHD_SC_INFO_GET_BUFF_TOO_SMALL;
    return mhd_request_get_auth_basic_creds (request,
                                             &(output_buf->
                                               v_auth_basic_creds));
#else  /* MHD_SUPPORT_AUTH_BASIC */
    return MHD_SC_FEATURE_DISABLED;
#endif /* MHD_SUPPORT_AUTH_BASIC */
    break;

  case MHD_REQUEST_INFO_DYNAMIC_SENTINEL:
  default:
    break;
  }

  return MHD_SC_INFO_GET_TYPE_UNKNOWN;
}
