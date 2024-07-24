/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2015-2024 Evgeny Grin (Karlson2k)
  Copyright (C) 2007-2020 Daniel Pittman and Christian Grothoff

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
 * @file src/mhd2/conn_data_send.c
 * @brief  The implementation of data sending functions for connection
 * @author Karlson2k (Evgeny Grin)
 *
 * Based on the MHD v0.x code by Daniel Pittman, Christian Grothoff, Evgeny Grin
 * and other contributors.
 */

#include "mhd_sys_options.h"

#include "conn_data_send.h"
#include "sys_bool_type.h"
#include "sys_base_types.h"
#include "mhd_str_macros.h"

#include "mhd_assert.h"

#include "mhd_connection.h"
#include "mhd_response.h"

#include "mhd_socket_error.h"

#include "mhd_send.h"
#include "stream_funcs.h"


/**
 * Check if we are done sending the write-buffer.
 * If so, transition into "next_state".
 *
 * @param connection connection to check write status for
 * @param next_state the next state to transition to
 * @return #MHD_NO if we are not done, #MHD_YES if we are
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
check_write_done (struct MHD_Connection *restrict connection,
                  enum MHD_CONNECTION_STATE next_state)
{
  // TODO: integrate into states processing
  if ( (connection->write_buffer_append_offset !=
        connection->write_buffer_send_offset)
       /* || data_in_tls_buffers == true  */
       )
    return false;
  connection->write_buffer_append_offset = 0;
  connection->write_buffer_send_offset = 0;
  connection->state = next_state;
  return true;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_conn_data_send (struct MHD_Connection *restrict c)
{
  static const char http_100_continue_msg[] =
    mdh_HTTP_1_1_100_CONTINUE_REPLY;
  static const size_t http_100_continue_msg_len =
    mhd_SSTR_LEN (mdh_HTTP_1_1_100_CONTINUE_REPLY);
  enum mhd_SocketError res;
  size_t sent;

  // TODO: assert check suspended

#ifdef HTTPS_SUPPORT
  // TODO: TLS support, handshake
#endif /* HTTPS_SUPPORT */

  // TODO: MOVE out STATES PROCESSING

  res = mhd_SOCKET_ERR_INTERNAL;

  if (MHD_CONNECTION_CONTINUE_SENDING == c->state)
  {
    res = mhd_send_data (c,
                         http_100_continue_msg_len
                         - c->continue_message_write_offset,
                         http_100_continue_msg
                         + c->continue_message_write_offset,
                         true,
                         &sent);
    if (mhd_SOCKET_ERR_NO_ERROR == res)
      c->continue_message_write_offset += sent;
  }
  else if (MHD_CONNECTION_HEADERS_SENDING == c->state)
  {
    struct MHD_Response *const restrict resp = c->rp.response;
    const size_t wb_ready = c->write_buffer_append_offset
                            - c->write_buffer_send_offset;
    mhd_assert (c->write_buffer_append_offset >= \
                c->write_buffer_send_offset);
    mhd_assert (NULL != resp);
    mhd_assert ((mhd_CONN_MUST_UPGRADE != c->conn_reuse) || \
                (! c->rp.props.send_reply_body));

    // TODO: support body generating alongside with header sending

    if ((c->rp.props.send_reply_body) &&
        (mhd_REPLY_CNTN_LOC_RESP_BUF == c->rp.cntn_loc))
    {
      /* Send response headers alongside the response body, if the body
       * data is available. */
      mhd_assert (mhd_RESPONSE_CONTENT_DATA_BUFFER == resp->cntn_dtype);
      mhd_assert (! c->rp.props.chunked);

      res = mhd_send_hdr_and_body (c,
                                   wb_ready,
                                   c->write_buffer
                                   + c->write_buffer_send_offset,
                                   false,
                                   resp->cntn_size,
                                   (const char *) resp->cntn.buf,
                                   true,
                                   &sent);
    }
    else
    {
      /* This is response for HEAD request or reply body is not allowed
       * for any other reason or reply body is dynamically generated. */
      /* Do not send the body data even if it's available. */
      res = mhd_send_hdr_and_body (c,
                                   wb_ready,
                                   c->write_buffer
                                   + c->write_buffer_send_offset,
                                   false,
                                   0,
                                   NULL,
                                   ((0 == resp->cntn_size) ||
                                    (! c->rp.props.send_reply_body)),
                                   &sent);
    }
    if (mhd_SOCKET_ERR_NO_ERROR == res)
    {
      mhd_assert (MHD_CONNECTION_HEADERS_SENDING == c->state);

      if (sent > wb_ready)
      {
        /* The complete header and some response data have been sent,
         * update both offsets. */
        mhd_assert (0 == c->rp.rsp_cntn_read_pos);
        mhd_assert (! c->rp.props.chunked);
        mhd_assert (c->rp.props.send_reply_body);
        c->state = MHD_CONNECTION_UNCHUNKED_BODY_READY;
        c->write_buffer_send_offset += wb_ready;
        c->rp.rsp_cntn_read_pos = sent - wb_ready;
        if (c->rp.rsp_cntn_read_pos == c->rp.response->cntn_size)
          c->state = MHD_CONNECTION_FULL_REPLY_SENT;
      }
      else
      {
        c->write_buffer_send_offset += sent;
        // TODO: move it to data processing
        check_write_done (c,
                          MHD_CONNECTION_HEADERS_SENT);
      }


    }

  }
  else if ((MHD_CONNECTION_UNCHUNKED_BODY_READY == c->state) ||
           (MHD_CONNECTION_CHUNKED_BODY_READY == c->state))
  {
    struct MHD_Response *const restrict resp = c->rp.response;
    mhd_assert (c->rp.props.send_reply_body);
    mhd_assert (c->rp.rsp_cntn_read_pos < resp->cntn_size);
    mhd_assert ((MHD_CONNECTION_CHUNKED_BODY_READY != c->state) || \
                (mhd_REPLY_CNTN_LOC_CONN_BUF == c->rp.cntn_loc));
    if (mhd_REPLY_CNTN_LOC_RESP_BUF == c->rp.cntn_loc)
    {
      mhd_assert (mhd_RESPONSE_CONTENT_DATA_BUFFER == resp->cntn_dtype);

      res = mhd_send_data (c,
                           c->rp.rsp_cntn_read_pos - resp->cntn_size,
                           (const char *) resp->cntn.buf
                           + c->rp.rsp_cntn_read_pos,
                           true,
                           &sent);
    }
    else if (mhd_REPLY_CNTN_LOC_CONN_BUF == c->rp.cntn_loc)
    {
      mhd_assert (c->write_buffer_append_offset > \
                  c->write_buffer_send_offset);

      res = mhd_send_data (c,
                           c->write_buffer_append_offset
                           - c->write_buffer_send_offset,
                           c->write_buffer + c->write_buffer_send_offset,
                           true,
                           &sent);
    }
    else if (mhd_REPLY_CNTN_LOC_IOV == c->rp.cntn_loc)
    {
      mhd_assert (mhd_RESPONSE_CONTENT_DATA_IOVEC == resp->cntn_dtype);

      res = mhd_send_iovec (c,
                            &c->rp.resp_iov,
                            true,
                            &sent);
    }
#if defined(MHD_USE_SENDFILE)
    else if (mhd_REPLY_CNTN_LOC_FILE == c->rp.cntn_loc)
    {
      mhd_assert (mhd_RESPONSE_CONTENT_DATA_FILE == resp->cntn_dtype);

      res = mhd_send_sendfile (c, &sent);
      if (mhd_SOCKET_ERR_INTR == res)
      {
        if (! c->rp.response->cntn.file.use_sf)
        { /* Switch to filereader */
          mhd_assert (! c->rp.props.chunked);
          c->rp.cntn_loc = mhd_REPLY_CNTN_LOC_CONN_BUF;
          c->state = MHD_CONNECTION_UNCHUNKED_BODY_UNREADY;
        }
      }
    }
#endif /* MHD_USE_SENDFILE */
    else
    {
      mhd_assert (0 && "Should be unreachable");
      res = mhd_SOCKET_ERR_INTERNAL;
    }

    if (mhd_SOCKET_ERR_NO_ERROR == res)
    {
      if (mhd_REPLY_CNTN_LOC_CONN_BUF == c->rp.cntn_loc)
      {
        enum MHD_CONNECTION_STATE next_state;
        c->write_buffer_send_offset += sent;
        // TODO: move it to data processing
        if (MHD_CONNECTION_CHUNKED_BODY_READY == c->state)
          next_state =
            (c->rp.response->cntn_size == c->rp.rsp_cntn_read_pos) ?
            MHD_CONNECTION_CHUNKED_BODY_SENT :
            MHD_CONNECTION_CHUNKED_BODY_UNREADY;
        else
          next_state =
            (c->rp.rsp_cntn_read_pos == resp->cntn_size) ?
            MHD_CONNECTION_FULL_REPLY_SENT :
            MHD_CONNECTION_UNCHUNKED_BODY_UNREADY;
        check_write_done (c,
                          next_state);
      }
      else
      {
        c->rp.rsp_cntn_read_pos += sent;
        if (c->rp.rsp_cntn_read_pos == resp->cntn_size)
          c->state = MHD_CONNECTION_FULL_REPLY_SENT;
      }
    }

  }
  else if (MHD_CONNECTION_FOOTERS_SENDING == c->state)
  {
    res = mhd_send_data (c,
                         c->write_buffer_append_offset
                         - c->write_buffer_send_offset,
                         c->write_buffer
                         + c->write_buffer_send_offset,
                         true,
                         &sent);
    if (mhd_SOCKET_ERR_NO_ERROR == res)
    {
      c->write_buffer_send_offset += sent;
      // TODO: move it to data processing
      check_write_done (c,
                        MHD_CONNECTION_FULL_REPLY_SENT);
    }
  }
  else
  {
    mhd_assert (0 && "Should be unreachable");
    res = mhd_SOCKET_ERR_INTERNAL;
  }

  if (mhd_SOCKET_ERR_NO_ERROR == res)
  {
    mhd_stream_update_activity_mark (c);  // TODO: centralise activity mark updates
  }
  else if (mhd_SOCKET_ERR_IS_HARD (res))
  {
    c->sk_discnt_err = res;
    c->sk_ready =
      (enum mhd_SocketNetState) (((unsigned int) c->sk_ready)
                                 | mhd_SOCKET_NET_STATE_ERROR_READY);
  }
}
