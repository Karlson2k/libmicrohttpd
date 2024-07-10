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
 * @file src/mhd2/stream_process_states.h
 * @brief  The definitions of internal functions for processing
 *         stream states
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"
#include "sys_bool_type.h"

#include "mhd_connection.h"
#include "stream_process_states.h"


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_conn_process_data (struct MHD_Connection *restrict c)
{
  struct MHD_Daemon *const restrict d = c->daemon;

  enum MHD_Result ret;

  /* 'daemon' is not used if epoll is not available and asserts are disabled */
  (void) d; /* Mute compiler warning */

  if ((mhd_SOCKET_ERR_NO_ERROR != c->sk_discnt_err) ||
      (0 != (c->sk_ready & mhd_SOCKET_NET_STATE_ERROR_READY)))
  {
    mhd_assert ((mhd_SOCKET_ERR_NO_ERROR != c->sk_discnt_err) || \
                mhd_SOCKET_ERR_IS_HARD(c->sk_discnt_err));
    if ((mhd_SOCKET_ERR_NO_ERROR == c->sk_discnt_err) ||
        (mhd_SOCKET_ERR_NOT_CHECKED == c->sk_discnt_err))
      c->sk_discnt_err = mhd_socket_error_get_from_socket(c->socket_fd);
    mhd_conn_pre_close_skt_err (c);
    return false;
  }

  while (true) // TODO: support suspend
  {
#ifdef HTTPS_SUPPORT
    // TODO: support TLS, handshake
#endif /* HTTPS_SUPPORT */
    switch (c->state)
    {
    case MHD_CONNECTION_INIT:
    case MHD_CONNECTION_REQ_LINE_RECEIVING:
      if (mhd_get_request_line (c))
      {
        mhd_assert (MHD_CONNECTION_REQ_LINE_RECEIVING < c->state);
        mhd_assert ((MHD_IS_HTTP_VER_SUPPORTED (c->rq.http_ver)) \
                    || (c->discard_request));
        continue;
      }
      mhd_assert (MHD_CONNECTION_REQ_LINE_RECEIVING >= c->state);
      break;
    case MHD_CONNECTION_REQ_LINE_RECEIVED:
      mhd_switch_to_rq_headers_processing (c);
      mhd_assert (MHD_CONNECTION_REQ_LINE_RECEIVED != c->state);
      continue;
    case MHD_CONNECTION_REQ_HEADERS_RECEIVING:
      if (mhd_get_req_headers (c, false))
      {
        mhd_assert (MHD_CONNECTION_REQ_HEADERS_RECEIVING < c->state);
        mhd_assert ((MHD_CONNECTION_HEADERS_RECEIVED == c->state) || \
                    (c->discard_request));
        continue;
      }
      mhd_assert (MHD_CONNECTION_REQ_HEADERS_RECEIVING == c->state);
      break;
    case MHD_CONNECTION_HEADERS_RECEIVED:
      mhd_parse_connection_headers (c);
      if (MHD_CONNECTION_HEADERS_RECEIVED != c->state)
        continue;
      c->state = MHD_CONNECTION_HEADERS_PROCESSED;
      if (c->suspended)
        break;
      continue;
    case MHD_CONNECTION_HEADERS_PROCESSED:
      call_connection_handler (c);
      if (MHD_CONNECTION_HEADERS_PROCESSED != c->state)
        continue;
      if (c->suspended)
        continue;

      if ( (NULL == c->rp.response) &&
           (need_100_continue (c)) &&
           /* If the client is already sending the payload (body)
              there is no need to send "100 Continue" */
           (0 == c->read_buffer_offset) )
      {
        c->state = MHD_CONNECTION_CONTINUE_SENDING;
        break;
      }
      if ( (NULL != c->rp.response) &&
           (0 != c->rq.remaining_upload_size) )
      {
        /* we refused (no upload allowed!) */
        c->rq.remaining_upload_size = 0;
        /* force close, in case client still tries to upload... */
        c->discard_request = true;
      }
      c->state = (0 == c->rq.remaining_upload_size)
                          ? MHD_CONNECTION_FULL_REQ_RECEIVED
                          : MHD_CONNECTION_BODY_RECEIVING;
      if (c->suspended)
        break;
      continue;
    case MHD_CONNECTION_CONTINUE_SENDING:
      if (c->continue_message_write_offset ==
          mhd_SSTR_LEN (HTTP_100_CONTINUE))
      {
        c->state = MHD_CONNECTION_BODY_RECEIVING;
        continue;
      }
      break;
    case MHD_CONNECTION_BODY_RECEIVING:
      mhd_assert (0 != c->rq.remaining_upload_size);
      mhd_assert (! c->discard_request);
      mhd_assert (NULL == c->rp.response);
      if (0 != c->read_buffer_offset)
      {
        process_request_body (c);           /* loop call */
        if (MHD_CONNECTION_BODY_RECEIVING != c->state)
          continue;
      }
      /* Modify here when queueing of the response during data processing
         will be supported */
      mhd_assert (! c->discard_request);
      mhd_assert (NULL == c->rp.response);
      if (0 == c->rq.remaining_upload_size)
      {
        c->state = MHD_CONNECTION_BODY_RECEIVED;
        continue;
      }
      break;
    case MHD_CONNECTION_BODY_RECEIVED:
      mhd_assert (! c->discard_request);
      mhd_assert (NULL == c->rp.response);
      if (0 == c->rq.remaining_upload_size)
      {
        if (c->rq.have_chunked_upload)
        {
          /* Reset counter variables reused for footers */
          c->rq.num_cr_sp_replaced = 0;
          c->rq.skipped_broken_lines = 0;
          reset_rq_header_processing_state (c);
          c->state = MHD_CONNECTION_FOOTERS_RECEIVING;
        }
        else
          c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
        continue;
      }
      break;
    case MHD_CONNECTION_FOOTERS_RECEIVING:
      if (get_req_headers (c, true))
      {
        mhd_assert (MHD_CONNECTION_FOOTERS_RECEIVING < c->state);
        mhd_assert ((MHD_CONNECTION_FOOTERS_RECEIVED == c->state) || \
                    (c->discard_request));
        continue;
      }
      mhd_assert (MHD_CONNECTION_FOOTERS_RECEIVING == c->state);
      break;
    case MHD_CONNECTION_FOOTERS_RECEIVED:
      /* The header, the body, and the footers of the request has been received,
       * switch to the final processing of the request. */
      c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
      continue;
    case MHD_CONNECTION_FULL_REQ_RECEIVED:
      call_connection_handler (c);     /* "final" call */
      if (c->state != MHD_CONNECTION_FULL_REQ_RECEIVED)
        continue;
      if (NULL == c->rp.response)
        break;                  /* try again next time */
      /* Response is ready, start reply */
      c->state = MHD_CONNECTION_START_REPLY;
      continue;
    case MHD_CONNECTION_START_REPLY:
      mhd_assert (NULL != c->rp.response);
      connection_switch_from_recv_to_send (c);
      if (MHD_NO == build_header_response (c))
      {
        /* oops - close! */
        CONNECTION_CLOSE_ERROR (c,
                                _ ("Closing connection (failed to create "
                                   "response header).\n"));
        continue;
      }
      c->state = MHD_CONNECTION_HEADERS_SENDING;
      break;

    case MHD_CONNECTION_HEADERS_SENDING:
      /* no default action */
      break;
    case MHD_CONNECTION_HEADERS_SENT:
      mhd_assert (0 && "Not implemented yet");
#if 0 //def UPGRADE_SUPPORT // TODO: upgrade support
      if (NULL != c->rp.response->upgrade_handler)
      {
        c->state = MHD_CONNECTION_UPGRADE;
        /* This connection is "upgraded".  Pass socket to application. */
        if (MHD_NO ==
            MHD_response_execute_upgrade_ (c->rp.response,
                                           connection))
        {
          /* upgrade failed, fail hard */
          CONNECTION_CLOSE_ERROR (connection,
                                  NULL);
          continue;
        }
        /* Response is not required anymore for this connection. */
        if (1)
        {
          struct MHD_Response *const resp = c->rp.response;

          c->rp.response = NULL;
          MHD_destroy_response (resp);
        }
        continue;
      }
#endif /* UPGRADE_SUPPORT */

      if (c->rp.props.send_reply_body)
      {
        if (c->rp.props.chunked)
          c->state = MHD_CONNECTION_CHUNKED_BODY_UNREADY;
        else
          c->state = MHD_CONNECTION_NORMAL_BODY_UNREADY;
      }
      else
        c->state = MHD_CONNECTION_FULL_REPLY_SENT;
      continue;
    case MHD_CONNECTION_NORMAL_BODY_READY:
      mhd_assert (c->rp.props.send_reply_body);
      mhd_assert (! c->rp.props.chunked);
      /* nothing to do here */
      break;
    case MHD_CONNECTION_NORMAL_BODY_UNREADY:
      mhd_assert (c->rp.props.send_reply_body);
      mhd_assert (! c->rp.props.chunked);
      if (0 == c->rp.response->cntn_size)
      {
        if (c->rp.props.chunked)
          c->state = MHD_CONNECTION_CHUNKED_BODY_SENT;
        else
          c->state = MHD_CONNECTION_FULL_REPLY_SENT;
        continue;
      }
      if (MHD_NO != try_ready_normal_body (c))
      {
        c->state = MHD_CONNECTION_NORMAL_BODY_READY;
        /* Buffering for flushable socket was already enabled*/

        break;
      }
      /* mutex was already unlocked by "try_ready_normal_body */
      /* not ready, no socket action */
      break;
    case MHD_CONNECTION_CHUNKED_BODY_READY:
      mhd_assert (c->rp.props.send_reply_body);
      mhd_assert (c->rp.props.chunked);
      /* nothing to do here */
      break;
    case MHD_CONNECTION_CHUNKED_BODY_UNREADY:
      mhd_assert (c->rp.props.send_reply_body);
      mhd_assert (c->rp.props.chunked);
      if ( (0 == c->rp.response->cntn_size) ||
           (c->rp.rsp_cntn_read_pos ==
            c->rp.response->cntn_size) )
      {
        c->state = MHD_CONNECTION_CHUNKED_BODY_SENT;
        continue;
      }
      if (1)
      { /* pseudo-branch for local variables scope */
        bool finished;
        if (MHD_NO != try_ready_chunked_body (c, &finished))
        {
          c->state = finished ? MHD_CONNECTION_CHUNKED_BODY_SENT :
                              MHD_CONNECTION_CHUNKED_BODY_READY;
          continue;
        }
        /* mutex was already unlocked by try_ready_chunked_body */
      }
      break;
    case MHD_CONNECTION_CHUNKED_BODY_SENT:
      mhd_assert (c->rp.props.send_reply_body);
      mhd_assert (c->rp.props.chunked);
      mhd_assert (c->write_buffer_send_offset <= \
                  c->write_buffer_append_offset);

      if (MHD_NO == build_connection_chunked_response_footer (c))
      {
        /* oops - close! */
        CONNECTION_CLOSE_ERROR (c,
                                _ ("Closing connection (failed to create " \
                                   "response footer)."));
        continue;
      }
      mhd_assert (c->write_buffer_send_offset < \
                  c->write_buffer_append_offset);
      c->state = MHD_CONNECTION_FOOTERS_SENDING;
      continue;
    case MHD_CONNECTION_FOOTERS_SENDING:
      mhd_assert (c->rp.props.send_reply_body);
      mhd_assert (c->rp.props.chunked);
      /* no default action */
      break;
    case MHD_CONNECTION_FULL_REPLY_SENT:
      // FIXME: support MHD_HTTP_STATUS_PROCESSING ?
      /* Reset connection after complete reply */
      connection_reset (c,
                        MHD_CONN_USE_KEEPALIVE == c->keepalive &&
                        ! c->read_closed &&
                        ! c->discard_request);
      continue;
    case MHD_CONNECTION_CLOSED:
      cleanup_connection (c);
      return MHD_NO;
#if 0 // def UPGRADE_SUPPORT
    case MHD_CONNECTION_UPGRADE:
      return MHD_YES;     /* keep open */
#endif /* UPGRADE_SUPPORT */
    default:
      mhd_assert (0);
      break;
    }
    break;
  }
  if (connection_check_timedout (c))
  {
    MHD_connection_close_ (c,
                           MHD_REQUEST_TERMINATED_TIMEOUT_REACHED);
    return MHD_YES;
  }
  mhd_conn_update_active_state (c);
  /* MHD_connection_update_event_loop_info (c);*/

  return true;
}
