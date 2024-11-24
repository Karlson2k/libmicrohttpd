/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2014-2024 Evgeny Grin (Karlson2k)
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
 * @file src/mhd2/stream_process_states.h
 * @brief  The definitions of internal functions for processing
 *         stream states
 * @author Karlson2k (Evgeny Grin)
 *
 * Based on the MHD v0.x code by Daniel Pittman, Christian Grothoff and other
 * contributors.
 */

#include "mhd_sys_options.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include "mhd_str_macros.h"
#include "mhd_socket_error_funcs.h"

#include "mhd_daemon.h"
#include "mhd_connection.h"
#include "mhd_response.h"

#include "stream_process_states.h"
#include "stream_funcs.h"
#include "stream_process_request.h"
#include "stream_process_reply.h"

#include "conn_mark_ready.h"

#ifdef MHD_UPGRADE_SUPPORT
#  include "upgrade_proc.h"
#endif /* MHD_UPGRADE_SUPPORT */

MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_conn_event_loop_state_update (struct MHD_Connection *restrict c)
{
  /* Do not update states of suspended connection */
  mhd_assert (! c->suspended);

  if (0 != (c->sk.ready & mhd_SOCKET_NET_STATE_ERROR_READY))
  {
    mhd_assert (0 && "Should be handled earlier");
    mhd_conn_start_closing_skt_err (c);
    return false;
  }

#if 0 // def HTTPS_SUPPORT // TODO: implement TLS support
  if (MHD_TLS_CONN_NO_TLS != connection->tls_state)
  {   /* HTTPS connection. */
    switch (connection->tls_state)
    {
    }
  }
#endif /* HTTPS_SUPPORT */
  switch (c->stage)
  {
  case mhd_HTTP_STAGE_INIT:
  case mhd_HTTP_STAGE_REQ_LINE_RECEIVING:
    c->event_loop_info = MHD_EVENT_LOOP_INFO_RECV;
    break;
  case mhd_HTTP_STAGE_REQ_LINE_RECEIVED:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    break;
  case mhd_HTTP_STAGE_REQ_HEADERS_RECEIVING:
    c->event_loop_info = MHD_EVENT_LOOP_INFO_RECV;
    break;
  case mhd_HTTP_STAGE_HEADERS_RECEIVED:
  case mhd_HTTP_STAGE_HEADERS_PROCESSED:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    break;
  case mhd_HTTP_STAGE_CONTINUE_SENDING:
    c->event_loop_info = MHD_EVENT_LOOP_INFO_SEND;
    break;
  case mhd_HTTP_STAGE_BODY_RECEIVING:
    c->event_loop_info = MHD_EVENT_LOOP_INFO_RECV;
    break;
  case mhd_HTTP_STAGE_BODY_RECEIVED:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    break;
  case mhd_HTTP_STAGE_FOOTERS_RECEIVING:
    c->event_loop_info = MHD_EVENT_LOOP_INFO_RECV;
    break;
  case mhd_HTTP_STAGE_FOOTERS_RECEIVED:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    break;
  case mhd_HTTP_STAGE_FULL_REQ_RECEIVED:
    mhd_assert (0 && "Should not be possible");
    c->event_loop_info = MHD_EVENT_LOOP_INFO_PROCESS;
    break;
  case mhd_HTTP_STAGE_REQ_RECV_FINISHED:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    break;
  case mhd_HTTP_STAGE_START_REPLY:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    break;
  case mhd_HTTP_STAGE_HEADERS_SENDING:
    /* headers in buffer, keep writing */
    c->event_loop_info = MHD_EVENT_LOOP_INFO_SEND;
    break;
  case mhd_HTTP_STAGE_HEADERS_SENT:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    break;
#ifdef MHD_UPGRADE_SUPPORT
  case mhd_HTTP_STAGE_UPGRADE_HEADERS_SENDING:
    c->event_loop_info = MHD_EVENT_LOOP_INFO_SEND;
    break;
#endif /* MHD_UPGRADE_SUPPORT */
  case mhd_HTTP_STAGE_UNCHUNKED_BODY_UNREADY:
    mhd_assert (0 && "Should not be possible");
    c->event_loop_info = MHD_EVENT_LOOP_INFO_PROCESS;
    break;
  case mhd_HTTP_STAGE_UNCHUNKED_BODY_READY:
    c->event_loop_info = MHD_EVENT_LOOP_INFO_SEND;
    break;
  case mhd_HTTP_STAGE_CHUNKED_BODY_UNREADY:
    mhd_assert (0 && "Should not be possible");
    c->event_loop_info = MHD_EVENT_LOOP_INFO_PROCESS;
    break;
  case mhd_HTTP_STAGE_CHUNKED_BODY_READY:
    c->event_loop_info = MHD_EVENT_LOOP_INFO_SEND;
    break;
  case mhd_HTTP_STAGE_CHUNKED_BODY_SENT:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    break;
  case mhd_HTTP_STAGE_FOOTERS_SENDING:
    c->event_loop_info = MHD_EVENT_LOOP_INFO_SEND;
    break;
  case mhd_HTTP_STAGE_FULL_REPLY_SENT:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    break;
#ifdef MHD_UPGRADE_SUPPORT
  case mhd_HTTP_STAGE_UPGRADING:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    break;
  case mhd_HTTP_STAGE_UPGRADED:
    mhd_assert (0 && "Should not be possible");
    c->event_loop_info = MHD_EVENT_LOOP_INFO_UPGRADED;
    break;
  case mhd_HTTP_STAGE_UPGRADED_CLEANING:
    mhd_assert (0 && "Should be unreachable");
    c->event_loop_info = MHD_EVENT_LOOP_INFO_CLEANUP;
    break;
#endif /* MHD_UPGRADE_SUPPORT */
  case mhd_HTTP_STAGE_PRE_CLOSING:
    mhd_assert (0 && "Should be unreachable");
    c->event_loop_info = MHD_EVENT_LOOP_INFO_CLEANUP;
    break;
  case mhd_HTTP_STAGE_CLOSED:
    mhd_assert (0 && "Should be unreachable");
    c->event_loop_info = MHD_EVENT_LOOP_INFO_CLEANUP;
    break;
  default:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
  }
}


/**
 * Update current processing state: need to receive, need to send.
 * Mark stream as ready or not ready for processing.
 * Grow the receive buffer if neccesary, close stream if no buffer space left,
 * but connection needs to receive.
 * @param c the connection to update
 * @return true if connection states updated successfully,
 *         false if connection has been prepared for closing
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
update_active_state (struct MHD_Connection *restrict c)
{
  /* Do not update states of suspended connection */
  mhd_assert (! c->suspended);

  if (0 != (c->sk.ready & mhd_SOCKET_NET_STATE_ERROR_READY))
  {
    mhd_assert (0 && "Should be handled earlier");
    mhd_conn_start_closing_skt_err (c);
    return false;
  }

  mhd_conn_event_loop_state_update (c);

  if (0 != (MHD_EVENT_LOOP_INFO_RECV & c->event_loop_info))
  {
    /* Check whether the space is available to receive data */
    if (! mhd_stream_check_and_grow_read_buffer_space (c))
    {
      mhd_assert (c->discard_request);
      return false;
    }
  }

  /* Current MHD design assumes that data must be always processes when
   * available. If it is not possible, connection must be suspended. */
  mhd_assert (MHD_EVENT_LOOP_INFO_PROCESS != c->event_loop_info);

  /* Sockets errors must be already handled */
  mhd_assert (0 == (c->sk.ready & mhd_SOCKET_NET_STATE_ERROR_READY));

  mhd_conn_mark_ready_update (c);

  return true;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_conn_process_data (struct MHD_Connection *restrict c)
{
  struct MHD_Daemon *const d = c->daemon;
  bool daemon_closing;

  /* 'daemon' is not used if epoll is not available and asserts are disabled */
  (void) d; /* Mute compiler warning */

  if ((c->sk.state.rmt_shut_wr) && (mhd_HTTP_STAGE_START_REPLY > c->stage))
  {
    if (0 == c->read_buffer_offset)
    { /* Read buffer is empty, connection state is actual */
      mhd_conn_start_closing (c,
                              (mhd_HTTP_STAGE_INIT == c->stage) ?
                              mhd_CONN_CLOSE_HTTP_COMPLETED :
                              mhd_CONN_CLOSE_CLIENT_SHUTDOWN_EARLY,
                              NULL);
      return false;
    }
  }

  mhd_assert (c->resuming || ! c->suspended);
  if (c->resuming)
  {
    // TODO: finish resuming, update activity mark
    // TODO: move to special function
    (void) 0;
  }

  if ((mhd_SOCKET_ERR_NO_ERROR != c->sk.state.discnt_err) ||
      (0 != (c->sk.ready & mhd_SOCKET_NET_STATE_ERROR_READY)))
  {
    mhd_assert ((mhd_SOCKET_ERR_NO_ERROR == c->sk.state.discnt_err) || \
                mhd_SOCKET_ERR_IS_HARD (c->sk.state.discnt_err));
    if ((mhd_SOCKET_ERR_NO_ERROR == c->sk.state.discnt_err) ||
        (mhd_SOCKET_ERR_NOT_CHECKED == c->sk.state.discnt_err))
      c->sk.state.discnt_err = mhd_socket_error_get_from_socket (c->sk.fd);
    mhd_conn_start_closing_skt_err (c);
    return false;
  }

  daemon_closing = (mhd_DAEMON_STATE_STOPPING == d->state);
#ifdef MHD_USE_THREADS
  daemon_closing = daemon_closing || d->threading.stop_requested;
#endif /* MHD_USE_THREADS */
  if (daemon_closing)
  {
    mhd_conn_start_closing_d_shutdown (c);
    return false;
  }

  while (! c->suspended)
  {
#ifdef HTTPS_SUPPORT
    // TODO: support TLS, handshake
#endif /* HTTPS_SUPPORT */
    switch (c->stage)
    {
    case mhd_HTTP_STAGE_INIT:
    case mhd_HTTP_STAGE_REQ_LINE_RECEIVING:
      if (mhd_stream_get_request_line (c))
      {
        mhd_assert (mhd_HTTP_STAGE_REQ_LINE_RECEIVING < c->stage);
        mhd_assert ((MHD_HTTP_VERSION_IS_SUPPORTED (c->rq.http_ver)) \
                    || (c->discard_request));
        continue;
      }
      mhd_assert (mhd_HTTP_STAGE_REQ_LINE_RECEIVING >= c->stage);
      break;
    case mhd_HTTP_STAGE_REQ_LINE_RECEIVED:
      mhd_stream_switch_to_rq_headers_proc (c);
      mhd_assert (mhd_HTTP_STAGE_REQ_LINE_RECEIVED != c->stage);
      continue;
    case mhd_HTTP_STAGE_REQ_HEADERS_RECEIVING:
      if (mhd_stream_get_request_headers (c, false))
      {
        mhd_assert (mhd_HTTP_STAGE_REQ_HEADERS_RECEIVING < c->stage);
        mhd_assert ((mhd_HTTP_STAGE_HEADERS_RECEIVED == c->stage) || \
                    (c->discard_request));
        continue;
      }
      mhd_assert (mhd_HTTP_STAGE_REQ_HEADERS_RECEIVING == c->stage);
      break;
    case mhd_HTTP_STAGE_HEADERS_RECEIVED:
      mhd_stream_parse_request_headers (c);
      mhd_assert (c->stage != mhd_HTTP_STAGE_HEADERS_RECEIVED);
      continue;
    case mhd_HTTP_STAGE_HEADERS_PROCESSED:
      if (mhd_stream_call_app_request_cb (c))
      {
        mhd_assert (mhd_HTTP_STAGE_HEADERS_PROCESSED < c->stage);
        continue;
      }
      // TODO: add assert
      break;
    case mhd_HTTP_STAGE_CONTINUE_SENDING:
      if (c->continue_message_write_offset ==
          mhd_SSTR_LEN (mdh_HTTP_1_1_100_CONTINUE_REPLY))
      {
#ifdef MHD_UPGRADE_SUPPORT
        c->rp.sent_100_cntn = true;
#endif /* MHD_UPGRADE_SUPPORT */
        c->stage = mhd_HTTP_STAGE_BODY_RECEIVING;
        continue;
      }
      break;
    case mhd_HTTP_STAGE_BODY_RECEIVING:
      mhd_assert (c->rq.cntn.recv_size < c->rq.cntn.cntn_size);
      mhd_assert (! c->discard_request);
      mhd_assert (NULL == c->rp.response);
      if (0 == c->read_buffer_offset)
        break; /* Need more data to process */

      if (mhd_stream_process_request_body (c))
        continue;
      mhd_assert (! c->discard_request);
      mhd_assert (NULL == c->rp.response);
      break;
    case mhd_HTTP_STAGE_BODY_RECEIVED:
      mhd_assert (! c->discard_request);
      mhd_assert (NULL == c->rp.response);
      mhd_assert (c->rq.have_chunked_upload);
      /* Reset counter variables reused for footers */
      c->rq.num_cr_sp_replaced = 0;
      c->rq.skipped_broken_lines = 0;
      mhd_stream_reset_rq_hdr_proc_state (c);
      c->stage = mhd_HTTP_STAGE_FOOTERS_RECEIVING;
      continue;
    case mhd_HTTP_STAGE_FOOTERS_RECEIVING:
      mhd_assert (c->rq.have_chunked_upload);
      if (mhd_stream_get_request_headers (c, true))
      {
        mhd_assert (mhd_HTTP_STAGE_FOOTERS_RECEIVING < c->stage);
        mhd_assert ((mhd_HTTP_STAGE_FOOTERS_RECEIVED == c->stage) || \
                    (c->discard_request));
        continue;
      }
      mhd_assert (mhd_HTTP_STAGE_FOOTERS_RECEIVING == c->stage);
      break;
    case mhd_HTTP_STAGE_FOOTERS_RECEIVED:
      mhd_assert (c->rq.have_chunked_upload);
      c->stage = mhd_HTTP_STAGE_FULL_REQ_RECEIVED;
      continue;
    case mhd_HTTP_STAGE_FULL_REQ_RECEIVED:
      if (mhd_stream_call_app_final_upload_cb (c))
      {
        mhd_assert (mhd_HTTP_STAGE_FOOTERS_RECEIVING != c->stage);
        continue;
      }
      break;
    case mhd_HTTP_STAGE_REQ_RECV_FINISHED:
      if (mhd_stream_process_req_recv_finished (c))
        continue;
      break;
    // TODO: add stage for setup and full request buffers cleanup
    case mhd_HTTP_STAGE_START_REPLY:
      mhd_assert (NULL != c->rp.response);
      mhd_stream_switch_from_recv_to_send (c);
      if (! mhd_stream_build_header_response (c))
        continue;
      mhd_assert (mhd_HTTP_STAGE_START_REPLY != c->stage);
      break;
    case mhd_HTTP_STAGE_HEADERS_SENDING:
      /* no default action, wait for sending all the headers */
      break;
    case mhd_HTTP_STAGE_HEADERS_SENT:
      if (c->rp.props.send_reply_body)
      {
        if (c->rp.props.chunked)
          c->stage = mhd_HTTP_STAGE_CHUNKED_BODY_UNREADY;
        else
          c->stage = mhd_HTTP_STAGE_UNCHUNKED_BODY_UNREADY;
      }
      else
        c->stage = mhd_HTTP_STAGE_FULL_REPLY_SENT;
      continue;
#ifdef MHD_UPGRADE_SUPPORT
    case mhd_HTTP_STAGE_UPGRADE_HEADERS_SENDING:
      if (! mhd_upgrade_try_start_upgrading (c))
        break;
      continue;
#endif /* MHD_UPGRADE_SUPPORT */
    case mhd_HTTP_STAGE_UNCHUNKED_BODY_READY:
      mhd_assert (c->rp.props.send_reply_body);
      mhd_assert (! c->rp.props.chunked);
      /* nothing to do here, send the data */
      break;
    case mhd_HTTP_STAGE_UNCHUNKED_BODY_UNREADY:
      mhd_assert (c->rp.props.send_reply_body);
      mhd_assert (! c->rp.props.chunked);
      if (0 == c->rp.response->cntn_size)
      { /* a shortcut */
        c->stage = mhd_HTTP_STAGE_FULL_REPLY_SENT;
        continue;
      }
      if (mhd_stream_prep_unchunked_body (c))
        continue;
      break;
    case mhd_HTTP_STAGE_CHUNKED_BODY_READY:
      mhd_assert (c->rp.props.send_reply_body);
      mhd_assert (c->rp.props.chunked);
      /* nothing to do here */
      break;
    case mhd_HTTP_STAGE_CHUNKED_BODY_UNREADY:
      mhd_assert (c->rp.props.send_reply_body);
      mhd_assert (c->rp.props.chunked);
      if ( (0 == c->rp.response->cntn_size) ||
           (c->rp.rsp_cntn_read_pos ==
            c->rp.response->cntn_size) )
      {
        c->stage = mhd_HTTP_STAGE_CHUNKED_BODY_SENT;
        continue;
      }
      if (mhd_stream_prep_chunked_body (c))
        continue;
      break;
    case mhd_HTTP_STAGE_CHUNKED_BODY_SENT:
      mhd_assert (c->rp.props.send_reply_body);
      mhd_assert (c->rp.props.chunked);
      mhd_assert (c->write_buffer_send_offset <= \
                  c->write_buffer_append_offset);
      mhd_stream_call_dcc_cleanup_if_needed (c);
      if (mhd_stream_prep_chunked_footer (c))
        continue;
      break;
    case mhd_HTTP_STAGE_FOOTERS_SENDING:
      mhd_assert (c->rp.props.send_reply_body);
      mhd_assert (c->rp.props.chunked);
      /* no default action */
      break;
    case mhd_HTTP_STAGE_FULL_REPLY_SENT:
      // FIXME: support MHD_HTTP_STATUS_PROCESSING ?
      /* Reset connection after complete reply */
      mhd_stream_finish_req_serving ( \
        c,
        mhd_CONN_KEEPALIVE_POSSIBLE == c->conn_reuse
        && ! c->discard_request
        && ! c->sk.state.rmt_shut_wr);
      continue;
#ifdef MHD_UPGRADE_SUPPORT
    case mhd_HTTP_STAGE_UPGRADING:
      if (mhd_upgrade_finish_switch_to_upgraded (c))
        return true;     /* Do not close connection */
      mhd_assert (mhd_HTTP_STAGE_PRE_CLOSING == c->stage);
      continue;
    case mhd_HTTP_STAGE_UPGRADED:
      mhd_assert (0 && "Should be unreachable");
      MHD_UNREACHABLE_;
      break;
    case mhd_HTTP_STAGE_UPGRADED_CLEANING:
      mhd_assert (0 && "Should be unreachable");
      MHD_UNREACHABLE_;
      break;
#endif /* MHD_UPGRADE_SUPPORT */
    case mhd_HTTP_STAGE_PRE_CLOSING:
      return false;
    case mhd_HTTP_STAGE_CLOSED:
      mhd_assert (0 && "Should be unreachable");
      MHD_UNREACHABLE_;
      break;
    default:
      mhd_assert (0 && "Impossible value");
      MHD_UNREACHABLE_;
      break;
    }
    break;
  }

  mhd_assert (mhd_HTTP_STAGE_CLOSED != c->stage);

  if (mhd_HTTP_STAGE_PRE_CLOSING == c->stage)
  {
    mhd_assert (0 && "Pre-closing should be already caught in the loop");
    MHD_UNREACHABLE_;
    return false;
  }

  if (c->suspended)
  {
    // TODO: process
    mhd_assert (0 && "Not implemented yet");
    return true;
  }

  if ((c->sk.state.rmt_shut_wr) && (mhd_HTTP_STAGE_START_REPLY > c->stage))
  {
    mhd_conn_start_closing (c,
                            (mhd_HTTP_STAGE_INIT == c->stage) ?
                            mhd_CONN_CLOSE_HTTP_COMPLETED :
                            mhd_CONN_CLOSE_CLIENT_SHUTDOWN_EARLY,
                            NULL);
    return false;
  }

  if (mhd_stream_is_timeout_expired (c)) // TODO: centralise timeout checks
  {
    mhd_conn_start_closing_timedout (c);
    return false;
  }

  if (! update_active_state (c))
    return false;

  return true;
}
