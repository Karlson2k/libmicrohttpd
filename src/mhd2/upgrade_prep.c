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
 * @file src/mhd2/upgrade_prep.c
 * @brief  The implementation of functions for preparing for MHD Action for
 *         HTTP-Upgrade
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include <string.h>

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include "upgrade_prep.h"

#include "mhd_cntnr_ptr.h"

#include "mhd_str_types.h"
#include "mhd_str_macros.h"

#include "mhd_assert.h"
#include "mhd_str.h"

#include "daemon_logger.h"

#include "mhd_request.h"
#include "mhd_connection.h"

#include "mhd_upgrade.h"
#include "stream_funcs.h"

#include "mhd_public_api.h"

/**
 * Check whether the provided data fits the buffer and append provided data
 * to the buffer
 * @param buf_size the size of the @a buf buffer
 * @param buf the buffer to use
 * @param[in,out] pbuf_used the pointer to the variable with current offset in
 *                          the @a buf buffer, updated if @a copy_data is added
 * @param copy_size the size of the @a copy_data
 * @param copy_data the data to append to the buffer
 * @return 'true' if @a copy_data has been appended to the @a buf buffer,
 *         'false' if @a buf buffer has not enough space
 */
MHD_static_inline_
MHD_FN_PAR_OUT_SIZE_ (2,1)
MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_INOUT_ (3)
MHD_FN_PAR_IN_SIZE_ (5,4) bool
buf_append (size_t buf_size,
            char buf[MHD_FN_PAR_DYN_ARR_SIZE_ (buf_size)],
            size_t *restrict pbuf_used,
            size_t copy_size,
            const char copy_data[MHD_FN_PAR_DYN_ARR_SIZE_ (copy_size)])
{
  if ((*pbuf_used + copy_size > buf_size) ||
      (((size_t) (*pbuf_used + copy_size)) < copy_size))
    return false;

  memcpy (buf + *pbuf_used, copy_data, copy_size);
  *pbuf_used += copy_size;

  return true;
}


/**
 * The build_reply_header() results
 */
enum mhd_UpgradeHeaderBuildRes
{
  /**
   * Success
   */
  MHD_UPGRADE_HDR_BUILD_OK = 0
  ,
  /**
   * Not enough buffer size (not logged)
   */
  MHD_UPGRADE_HDR_BUILD_NO_MEM
  ,
  /**
   * Some other error (already logged)
   */
  MHD_UPGRADE_HDR_BUILD_OTHER_ERR
};

/**
 * Build full reply header for the upgrade action.
 * The reply header serves as a preamble, as soon as it sent the connection
 * switched to the "upgraded" mode.
 * @param c the connection to use
 * @param buf_size the size of the @a buf buffer
 * @param[out] buf the buffer to build the reply
 * @param[out] pbuf_used the pointer to the variable receiving the size of
 *                       the reply header in the @a buf buffer
 * @param upgrade_hdr_value the value of the "Upgrade:" reply header
 * @param num_headers the number of elements in the @a headers array,
 *                    must be zero if @a headers is NULL
 * @param headers the array of string pairs used as reply headers,
 *        can be NULL
 * @return #MHD_UPGRADE_HDR_BUILD_OK if reply has been built successfully and
 *         @a pbuf_used has been updated,
 *         #MHD_UPGRADE_HDR_BUILD_NO_MEM if @a buf has not enough space to build
 *         the reply header (the error is not yet logged),
 *         #MHD_UPGRADE_HDR_BUILD_NO_MEM if any other error occurs (the error
 *         has been logged)
 */
static MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (3)
MHD_FN_PAR_OUT_SIZE_ (3,2) MHD_FN_PAR_OUT_ (4) MHD_FN_PAR_CSTR_ (5)
MHD_FN_PAR_IN_SIZE_ (7,6) enum mhd_UpgradeHeaderBuildRes
build_reply_header (struct MHD_Connection *restrict c,
                    const size_t buf_size,
                    char buf[MHD_FN_PAR_DYN_ARR_SIZE_ (buf_size)],
                    size_t *pbuf_used,
                    const char *restrict upgrade_hdr_value,
                    size_t num_headers,
                    const struct MHD_NameValueCStr *restrict headers)
{
  static const struct MHD_String rp_100_cntn_msg =
    mhd_MSTR_INIT (mdh_HTTP_1_1_100_CONTINUE_REPLY);
  static const struct MHD_String status_line =
    mhd_MSTR_INIT (MHD_HTTP_VERSION_1_1_STR " 101 Switching Protocols\r\n");
  static const struct MHD_String upgrade_hdr_start =
    mhd_MSTR_INIT (MHD_HTTP_HEADER_UPGRADE ": ");
  size_t upgrade_hdr_value_len;
  size_t buf_used;
  size_t i;
  bool has_conn_hdr;
  bool hdr_name_invalid;

  mhd_assert (MHD_HTTP_VERSION_1_1 == c->rq.http_ver);
  mhd_assert ((0 == c->rq.cntn.cntn_size) || \
              (MHD_CONNECTION_FULL_REQ_RECEIVED == c->state));

  buf_used = 0;

  if (c->rq.have_expect_100 && ! c->rp.sent_100_cntn)
  {
    /* Must send "100 Continue" before switching to data pumping */
    if (! buf_append (buf_size,
                      buf,
                      &buf_used,
                      rp_100_cntn_msg.len,
                      rp_100_cntn_msg.cstr))
      return MHD_UPGRADE_HDR_BUILD_NO_MEM;
  }

  /* Status line */
  if (! buf_append (buf_size,
                    buf,
                    &buf_used,
                    status_line.len,
                    status_line.cstr))
    return MHD_UPGRADE_HDR_BUILD_NO_MEM;

  /* "Upgrade:" header */
  if (! buf_append (buf_size,
                    buf,
                    &buf_used,
                    upgrade_hdr_start.len,
                    upgrade_hdr_start.cstr))
    return MHD_UPGRADE_HDR_BUILD_NO_MEM;

  upgrade_hdr_value_len = strcspn (upgrade_hdr_value,
                                   "\n\r");
  if ((0 == upgrade_hdr_value_len) ||
      (0 != upgrade_hdr_value[upgrade_hdr_value_len]))
  {
    mhd_LOG_MSG (c->daemon, \
                 MHD_SC_RESP_HEADER_VALUE_INVALID, \
                 "The provided value of the \"Upgrade:\" header " \
                 "is invalid.");
    return MHD_UPGRADE_HDR_BUILD_OTHER_ERR;
  }
  if ((buf_used + upgrade_hdr_value_len + 2 > buf_size) ||
      (((size_t) (buf_used + upgrade_hdr_value_len + 2)) < buf_used))
    return MHD_UPGRADE_HDR_BUILD_NO_MEM;
  memcpy (buf + buf_used,
          upgrade_hdr_value,
          upgrade_hdr_value_len);
  buf_used += upgrade_hdr_value_len;
  buf[buf_used++] = '\r';
  buf[buf_used++] = '\n';

  /* User headers */
  has_conn_hdr = false;
  hdr_name_invalid = false;
  for (i = 0; i < num_headers; ++i)
  {
    static const struct MHD_String conn_hdr_prefix =
      mhd_MSTR_INIT ("upgrade, ");
    size_t hdr_name_len;
    size_t hdr_value_len;
    size_t line_len;
    bool is_conn_hdr;

    if (NULL == headers[i].name)
    {
      hdr_name_invalid = true;
      break;
    }

    hdr_name_len = strcspn (headers[i].name,
                            "\n\r \t:,;\"");

    if ((0 == hdr_name_len) ||
        (0 != headers[i].name[hdr_name_len]))
    {
      hdr_name_invalid = true;
      break;
    }

    if (NULL == headers[i].value)
      break;

    hdr_value_len = strcspn (headers[i].value,
                             "\n\r");

    if (0 != headers[i].value[hdr_value_len])
      break;

    if (mhd_str_equal_caseless_n_st (MHD_HTTP_HEADER_UPGRADE, \
                                     headers[i].name, \
                                     hdr_name_len))
      break;

    line_len = hdr_name_len + 2 + hdr_value_len + 2;

    is_conn_hdr =
      mhd_str_equal_caseless_n_st (MHD_HTTP_HEADER_CONNECTION, \
                                   headers[i].name, \
                                   hdr_name_len);
    if (is_conn_hdr)
    {
      if (0 == hdr_value_len)
        continue; /* Skip the header, proper "Connection:" header will be added below */
      if (has_conn_hdr)
        break; /* Two "Connection:" headers */
      has_conn_hdr = true;

      if (mhd_str_has_s_token_caseless (headers[i].value, "close"))
        break;
      if (mhd_str_has_s_token_caseless (headers[i].value, "keep-alive"))
        break;

      line_len += conn_hdr_prefix.len;
      if (line_len < conn_hdr_prefix.len)
        return MHD_UPGRADE_HDR_BUILD_NO_MEM;
    }

    if ((buf_used + line_len > buf_size) ||
        (((size_t) (buf_used + line_len)) < line_len) ||
        (line_len < hdr_value_len))
      return MHD_UPGRADE_HDR_BUILD_NO_MEM;

    memcpy (buf + buf_used,
            headers[i].name,
            hdr_name_len);
    buf_used += hdr_name_len;
    buf[buf_used++] = ':';
    buf[buf_used++] = ' ';

    if (is_conn_hdr)
    {
      memcpy (buf + buf_used,
              conn_hdr_prefix.cstr,
              conn_hdr_prefix.len);
      buf_used += conn_hdr_prefix.len;
    }

    memcpy (buf + buf_used,
            headers[i].name,
            hdr_name_len);
    buf[buf_used++] = '\r';
    buf[buf_used++] = '\n';
  }
  mhd_assert (buf_size >= buf_used);
  mhd_assert (! hdr_name_invalid || (i < num_headers));

  if (i < num_headers)
  {
    if (hdr_name_invalid)
      mhd_LOG_PRINT (c->daemon, \
                     MHD_SC_RESP_HEADER_NAME_INVALID, \
                     mhd_LOG_FMT ("The name of the provided header " \
                                  "number %lu is invalid. " \
                                  "Header name: '%s'. " \
                                  "Header Value: '%s'."),
                     (unsigned long) i,
                     headers[i].name ? headers[i].name : "(NULL)",
                     headers[i].value ? headers[i].value : "(NULL)");
    else
      mhd_LOG_PRINT (c->daemon, \
                     MHD_SC_RESP_HEADER_VALUE_INVALID, \
                     mhd_LOG_FMT ("The value of the provided header " \
                                  "number %lu is invalid. " \
                                  "Header name: '%s'. " \
                                  "Header Value: '%s'."),
                     (unsigned long) i,
                     headers[i].name ? headers[i].name : "(NULL)",
                     headers[i].value ? headers[i].value : "(NULL)");

    return MHD_UPGRADE_HDR_BUILD_OTHER_ERR;
  }

  /* "Connection:" header (if has not been added already) */
  if (! has_conn_hdr)
  {
    static const struct MHD_String conn_hdr_line =
      mhd_MSTR_INIT (MHD_HTTP_HEADER_CONNECTION ": upgrade\r\n");

    if (! buf_append (buf_size,
                      buf,
                      &buf_used,
                      conn_hdr_line.len,
                      conn_hdr_line.cstr))
      return MHD_UPGRADE_HDR_BUILD_NO_MEM;
  }

  /* End of reply header */
  if ((buf_used + 2 > buf_size) ||
      (((size_t) (buf_used + 2)) < 2))
    return MHD_UPGRADE_HDR_BUILD_NO_MEM;

  buf[buf_used++] = '\r';
  buf[buf_used++] = '\n';

  mhd_assert (buf_size >= buf_used);
  *pbuf_used = buf_used;

  return MHD_UPGRADE_HDR_BUILD_OK;
}


/**
 * Prepare connection to be used with the HTTP "Upgrade" action
 * @param c the connection object
 * @param upgrade_hdr_value the value of the "Upgrade:" header, mandatory
 *                          string
 * @param num_headers number of elements in the @a headers array,
 *                    must be zero if @a headers is NULL
 * @param headers the optional pointer to the array of the headers (the strings
 *                are copied and does not need to be valid after return from
 *                this function),
 *                can be NULL if @a num_headers is zero
 * @return 'true' if succeed,
 *         'false' otherwise
 */
static MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_IN_SIZE_ (4,3) bool
connection_prepare_for_upgrade (
  struct MHD_Connection *restrict c,
  const char *restrict upgrade_hdr_value,
  size_t num_headers,
  const struct MHD_NameValueCStr *restrict headers)
{
  enum mhd_UpgradeHeaderBuildRes res;

  mhd_assert (NULL == c->write_buffer);
  mhd_assert (0 == c->write_buffer_size);
  mhd_assert (0 == c->write_buffer_send_offset);

  mhd_stream_shrink_read_buffer (c);
  mhd_stream_maximize_write_buffer (c);
  mhd_assert (0 == c->write_buffer_append_offset);

  res = build_reply_header (c,
                            c->write_buffer_size,
                            c->write_buffer,
                            &c->write_buffer_append_offset,
                            upgrade_hdr_value,
                            num_headers,
                            headers);
  if (MHD_UPGRADE_HDR_BUILD_OK == res)
    return true; /* Success exit point */

  /* Header build failed */
  if (MHD_UPGRADE_HDR_BUILD_NO_MEM == res)
    mhd_LOG_MSG (c->daemon, \
                 MHD_SC_REPLY_HEADERS_TOO_LARGE, \
                 "No space in the connection memory pool to create complete " \
                 "HTTP \"Upgrade\" response header.");

  mhd_stream_release_write_buffer (c);

  return false;
}


MHD_INTERNAL
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_IN_SIZE_ (4,3) bool
mhd_upgrade_prep_for_action (struct MHD_Request *restrict req,
                             const char *restrict upgrade_hdr_value,
                             size_t num_headers,
                             const struct MHD_NameValueCStr *restrict headers,
                             bool is_upload_act)
{
  struct MHD_Connection *const c =
    mhd_cntnr_ptr (req, struct MHD_Connection, rq);

  mhd_assert (MHD_CONNECTION_HEADERS_PROCESSED <= c->state);
  mhd_assert (MHD_CONNECTION_FULL_REQ_RECEIVED >= c->state);

  if (req->have_chunked_upload &&
      (MHD_CONNECTION_FOOTERS_RECEIVED >= c->state))
    return false; /* The request has not been fully received */

  if (! is_upload_act)
  {
    if (MHD_CONNECTION_HEADERS_PROCESSED != c->state)
      return false;
  }
  else
  {
    if (MHD_CONNECTION_BODY_RECEIVING > c->state)
      return false;
  }

  return connection_prepare_for_upgrade (c,
                                         upgrade_hdr_value,
                                         num_headers,
                                         headers);
}
