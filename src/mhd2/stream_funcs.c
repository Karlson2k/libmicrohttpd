/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2022-2024 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/stream_funcs.c
 * @brief  The definition of the stream internal functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "stream_funcs.h"

#include <string.h>
#ifdef MHD_USE_EPOLL
#  include <sys/epoll.h>
#endif
#include "sys_malloc.h"

#include "mhd_daemon.h"
#include "mhd_connection.h"
#include "mhd_response.h"
#include "mhd_assert.h"
#include "mhd_mempool.h"
#include "mhd_str.h"
#include "mhd_str_macros.h"

#include "mhd_sockets_funcs.h"

#include "request_get_value.h"
#include "response_destroy.h"
#include "mhd_mono_clock.h"
#include "daemon_logger.h"
#include "daemon_funcs.h"
#include "conn_mark_ready.h"
#include "stream_process_reply.h"

#include "mhd_public_api.h"


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void *
mhd_stream_alloc_memory (struct MHD_Connection *restrict c,
                         size_t size)
{
  struct mhd_MemoryPool *const restrict pool = c->pool;     /* a short alias */
  size_t need_to_be_freed = 0; /**< The required amount of additional free memory */
  void *res;

  res = mhd_pool_try_alloc (pool,
                            size,
                            &need_to_be_freed);
  if (NULL != res)
    return res;

  if (mhd_pool_is_resizable_inplace (pool,
                                     c->write_buffer,
                                     c->write_buffer_size))
  {
    if (c->write_buffer_size - c->write_buffer_append_offset >=
        need_to_be_freed)
    {
      char *buf;
      const size_t new_buf_size = c->write_buffer_size - need_to_be_freed;
      buf = mhd_pool_reallocate (pool,
                                 c->write_buffer,
                                 c->write_buffer_size,
                                 new_buf_size);
      mhd_assert (c->write_buffer == buf);
      mhd_assert (c->write_buffer_append_offset <= new_buf_size);
      mhd_assert (c->write_buffer_send_offset <= new_buf_size);
      c->write_buffer_size = new_buf_size;
      c->write_buffer = buf;
    }
    else
      return NULL;
  }
  else if (mhd_pool_is_resizable_inplace (pool,
                                          c->read_buffer,
                                          c->read_buffer_size))
  {
    if (c->read_buffer_size - c->read_buffer_offset >= need_to_be_freed)
    {
      char *buf;
      const size_t new_buf_size = c->read_buffer_size - need_to_be_freed;
      buf = mhd_pool_reallocate (pool,
                                 c->read_buffer,
                                 c->read_buffer_size,
                                 new_buf_size);
      mhd_assert (c->read_buffer == buf);
      mhd_assert (c->read_buffer_offset <= new_buf_size);
      c->read_buffer_size = new_buf_size;
      c->read_buffer = buf;
    }
    else
      return NULL;
  }
  else
    return NULL;
  res = mhd_pool_allocate (pool, size, true);
  mhd_assert (NULL != res); /* It has been checked that pool has enough space */
  return res;
}


/**
 * Shrink stream read buffer to the zero size of free space in the buffer
 * @param c the connection whose read buffer is being manipulated
 */
MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_stream_shrink_read_buffer (struct MHD_Connection *restrict c)
{
  void *new_buf;

  if ((NULL == c->read_buffer) || (0 == c->read_buffer_size))
  {
    mhd_assert (0 == c->read_buffer_size);
    mhd_assert (0 == c->read_buffer_offset);
    return;
  }

  mhd_assert (c->read_buffer_offset <= c->read_buffer_size);
  if (0 == c->read_buffer_offset)
  {
    mhd_pool_deallocate (c->pool, c->read_buffer, c->read_buffer_size);
    c->read_buffer = NULL;
    c->read_buffer_size = 0;
  }
  else
  {
    mhd_assert (mhd_pool_is_resizable_inplace (c->pool, c->read_buffer, \
                                               c->read_buffer_size));
    new_buf = mhd_pool_reallocate (c->pool, c->read_buffer, c->read_buffer_size,
                                   c->read_buffer_offset);
    mhd_assert (c->read_buffer == new_buf);
    c->read_buffer = new_buf;
    c->read_buffer_size = c->read_buffer_offset;
  }
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ size_t
mhd_stream_maximize_write_buffer (struct MHD_Connection *restrict c)
{
  struct mhd_MemoryPool *const restrict pool = c->pool;
  void *new_buf;
  size_t new_size;
  size_t free_size;

  mhd_assert ((NULL != c->write_buffer) || (0 == c->write_buffer_size));
  mhd_assert (c->write_buffer_append_offset >= c->write_buffer_send_offset);
  mhd_assert (c->write_buffer_size >= c->write_buffer_append_offset);

  free_size = mhd_pool_get_free (pool);
  if (0 != free_size)
  {
    new_size = c->write_buffer_size + free_size;
    /* This function must not move the buffer position.
     * mhd_pool_reallocate () may return the new position only if buffer was
     * allocated 'from_end' or is not the last allocation,
     * which should not happen. */
    mhd_assert ((NULL == c->write_buffer) || \
                mhd_pool_is_resizable_inplace (pool, c->write_buffer, \
                                               c->write_buffer_size));
    new_buf = mhd_pool_reallocate (pool,
                                   c->write_buffer,
                                   c->write_buffer_size,
                                   new_size);
    mhd_assert ((c->write_buffer == new_buf) || (NULL == c->write_buffer));
    c->write_buffer = new_buf;
    c->write_buffer_size = new_size;
    if (c->write_buffer_send_offset == c->write_buffer_append_offset)
    {
      /* All data have been sent, reset offsets to zero. */
      c->write_buffer_send_offset = 0;
      c->write_buffer_append_offset = 0;
    }
  }

  return c->write_buffer_size - c->write_buffer_append_offset;
}


#ifndef MHD_MAX_REASONABLE_HEADERS_SIZE_
/**
 * A reasonable headers size (excluding request line) that should be sufficient
 * for most requests.
 * If incoming data buffer free space is not enough to process the complete
 * header (the request line and all headers) and the headers size is larger than
 * this size then the status code 431 "Request Header Fields Too Large" is
 * returned to the client.
 * The larger headers are processed by MHD if enough space is available.
 */
#  define MHD_MAX_REASONABLE_HEADERS_SIZE_ (6 * 1024)
#endif /* ! MHD_MAX_REASONABLE_HEADERS_SIZE_ */

#ifndef MHD_MAX_REASONABLE_REQ_TARGET_SIZE_
/**
 * A reasonable request target (the request URI) size that should be sufficient
 * for most requests.
 * If incoming data buffer free space is not enough to process the complete
 * header (the request line and all headers) and the request target size is
 * larger than this size then the status code 414 "URI Too Long" is
 * returned to the client.
 * The larger request targets are processed by MHD if enough space is available.
 * The value chosen according to RFC 9112 Section 3, paragraph 5
 */
#  define MHD_MAX_REASONABLE_REQ_TARGET_SIZE_ 8000
#endif /* ! MHD_MAX_REASONABLE_REQ_TARGET_SIZE_ */

#ifndef MHD_MIN_REASONABLE_HEADERS_SIZE_
/**
 * A reasonable headers size (excluding request line) that should be sufficient
 * for basic simple requests.
 * When no space left in the receiving buffer try to avoid replying with
 * the status code 431 "Request Header Fields Too Large" if headers size
 * is smaller then this value.
 */
#  define MHD_MIN_REASONABLE_HEADERS_SIZE_ 26
#endif /* ! MHD_MIN_REASONABLE_HEADERS_SIZE_ */

#ifndef MHD_MIN_REASONABLE_REQ_TARGET_SIZE_
/**
 * A reasonable request target (the request URI) size that should be sufficient
 * for basic simple requests.
 * When no space left in the receiving buffer try to avoid replying with
 * the status code 414 "URI Too Long" if the request target size is smaller then
 * this value.
 */
#  define MHD_MIN_REASONABLE_REQ_TARGET_SIZE_ 40
#endif /* ! MHD_MIN_REASONABLE_REQ_TARGET_SIZE_ */

#ifndef MHD_MIN_REASONABLE_REQ_METHOD_SIZE_
/**
 * A reasonable request method string size that should be sufficient
 * for basic simple requests.
 * When no space left in the receiving buffer try to avoid replying with
 * the status code 501 "Not Implemented" if the request method size is
 * smaller then this value.
 */
#  define MHD_MIN_REASONABLE_REQ_METHOD_SIZE_ 16
#endif /* ! MHD_MIN_REASONABLE_REQ_METHOD_SIZE_ */

#ifndef MHD_MIN_REASONABLE_REQ_CHUNK_LINE_LENGTH_
/**
 * A reasonable minimal chunk line length.
 * When no space left in the receiving buffer reply with 413 "Content Too Large"
 * if the chunk line length is larger than this value.
 */
#  define MHD_MIN_REASONABLE_REQ_CHUNK_LINE_LENGTH_ 4
#endif /* ! MHD_MIN_REASONABLE_REQ_CHUNK_LINE_LENGTH_ */


MHD_INTERNAL
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_IN_SIZE_ (4,3) unsigned int
mhd_stream_get_no_space_err_status_code (struct MHD_Connection *restrict c,
                                         enum MHD_ProcRecvDataStage stage,
                                         size_t add_element_size,
                                         const char *restrict add_element)
{
  size_t method_size;
  size_t uri_size;
  size_t opt_headers_size;
  size_t host_field_line_size;

  mhd_assert (MHD_CONNECTION_REQ_LINE_RECEIVED < c->state);
  mhd_assert (MHD_PROC_RECV_HEADERS <= stage);
  mhd_assert ((0 == add_element_size) || (NULL != add_element));

  c->rq.too_large = true;

  if (MHD_CONNECTION_HEADERS_RECEIVED > c->state)
  {
    mhd_assert (NULL != c->rq.field_lines.start);
    opt_headers_size =
      (size_t) ((c->read_buffer + c->read_buffer_offset)
                - c->rq.field_lines.start);
  }
  else
    opt_headers_size = c->rq.field_lines.size;

  /* The read buffer is fully used by the request line, the field lines
     (headers) and internal information.
     The return status code works as a suggestion for the client to reduce
     one of the request elements. */

  if ((MHD_PROC_RECV_BODY_CHUNKED == stage) &&
      (MHD_MIN_REASONABLE_REQ_CHUNK_LINE_LENGTH_ < add_element_size))
  {
    /* Request could be re-tried easily with smaller chunk sizes */
    return MHD_HTTP_STATUS_CONTENT_TOO_LARGE;
  }

  host_field_line_size = 0;
  /* The "Host:" field line is mandatory.
     The total size of the field lines (headers) cannot be smaller than
     the size of the "Host:" field line. */
  if ((MHD_PROC_RECV_HEADERS == stage)
      && (0 != add_element_size))
  {
    static const size_t header_host_key_len =
      mhd_SSTR_LEN (MHD_HTTP_HEADER_HOST);
    const bool is_host_header =
      (header_host_key_len + 1 <= add_element_size)
      && ( (0 == add_element[header_host_key_len])
           || (':' == add_element[header_host_key_len]) )
      && mhd_str_equal_caseless_bin_n (MHD_HTTP_HEADER_HOST,
                                       add_element,
                                       header_host_key_len);
    if (is_host_header)
    {
      const bool is_parsed = ! (
        (MHD_CONNECTION_HEADERS_RECEIVED > c->state) &&
        (add_element_size == c->read_buffer_offset) &&
        (c->read_buffer == add_element) );
      size_t actual_element_size;

      mhd_assert (! is_parsed || (0 == add_element[header_host_key_len]));
      /* The actual size should be larger due to CRLF or LF chars,
         however the exact termination sequence is not known here and
         as perfect precision is not required, to simplify the code
         assume the minimal length. */
      if (is_parsed)
        actual_element_size = add_element_size + 1;  /* "1" for LF */
      else
        actual_element_size = add_element_size;

      host_field_line_size = actual_element_size;
      mhd_assert (opt_headers_size >= actual_element_size);
      opt_headers_size -= actual_element_size;
    }
  }
  if (0 == host_field_line_size)
  {
    static const size_t host_field_name_len =
      mhd_SSTR_LEN (MHD_HTTP_HEADER_HOST);
    const struct MHD_StringNullable *host_value;
    host_value = mhd_request_get_value_n (&(c->rq),
                                          MHD_VK_HEADER,
                                          host_field_name_len,
                                          MHD_HTTP_HEADER_HOST);
    if (NULL != host_value)
    {
      /* Calculate the minimal size of the field line: no space between
         colon and the field value, line terminated by LR */
      host_field_line_size =
        host_field_name_len + host_value->len + 2; /* "2" for ':' and LF */

      /* The "Host:" field could be added by application */
      if (opt_headers_size >= host_field_line_size)
      {
        opt_headers_size -= host_field_line_size;
        /* Take into account typical space after colon and CR at the end of the line */
        if (opt_headers_size >= 2)
          opt_headers_size -= 2;
      }
      else
        host_field_line_size = 0; /* No "Host:" field line set by the client */
    }
  }

  uri_size = c->rq.req_target_len;
  if (mhd_HTTP_METHOD_OTHER != c->rq.http_mthd)
    method_size = 0; /* Do not recommend shorter request method */
  else
  {
    mhd_assert (NULL != c->rq.method);
    method_size = strlen (c->rq.method);
  }

  if ((size_t) MHD_MAX_REASONABLE_HEADERS_SIZE_ < opt_headers_size)
  {
    /* Typically the easiest way to reduce request header size is
       a removal of some optional headers. */
    if (opt_headers_size > (uri_size / 8))
    {
      if ((opt_headers_size / 2) > method_size)
        return MHD_HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE;
      else
        return MHD_HTTP_STATUS_NOT_IMPLEMENTED; /* The length of the HTTP request method is unreasonably large */
    }
    else
    { /* Request target is MUCH larger than headers */
      if ((uri_size / 16) > method_size)
        return MHD_HTTP_STATUS_URI_TOO_LONG;
      else
        return MHD_HTTP_STATUS_NOT_IMPLEMENTED; /* The length of the HTTP request method is unreasonably large */
    }
  }
  if ((size_t) MHD_MAX_REASONABLE_REQ_TARGET_SIZE_ < uri_size)
  {
    /* If request target size if larger than maximum reasonable size
       recommend client to reduce the request target size (length). */
    if ((uri_size / 16) > method_size)
      return MHD_HTTP_STATUS_URI_TOO_LONG;     /* Request target is MUCH larger than headers */
    else
      return MHD_HTTP_STATUS_NOT_IMPLEMENTED;  /* The length of the HTTP request method is unreasonably large */
  }

  /* The read buffer is too small to handle reasonably large requests */

  if ((size_t) MHD_MIN_REASONABLE_HEADERS_SIZE_ < opt_headers_size)
  {
    /* Recommend application to retry with minimal headers */
    if ((opt_headers_size * 4) > uri_size)
    {
      if (opt_headers_size > method_size)
        return MHD_HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE;
      else
        return MHD_HTTP_STATUS_NOT_IMPLEMENTED; /* The length of the HTTP request method is unreasonably large */
    }
    else
    { /* Request target is significantly larger than headers */
      if (uri_size > method_size * 4)
        return MHD_HTTP_STATUS_URI_TOO_LONG;
      else
        return MHD_HTTP_STATUS_NOT_IMPLEMENTED; /* The length of the HTTP request method is unreasonably large */
    }
  }
  if ((size_t) MHD_MIN_REASONABLE_REQ_TARGET_SIZE_ < uri_size)
  {
    /* Recommend application to retry with a shorter request target */
    if (uri_size > method_size * 4)
      return MHD_HTTP_STATUS_URI_TOO_LONG;
    else
      return MHD_HTTP_STATUS_NOT_IMPLEMENTED; /* The length of the HTTP request method is unreasonably large */
  }

  if ((size_t) MHD_MIN_REASONABLE_REQ_METHOD_SIZE_ < method_size)
  {
    /* The request target (URI) and headers are (reasonably) very small.
       Some non-standard long request method is used. */
    /* The last resort response as it means "the method is not supported
       by the server for any URI". */
    return MHD_HTTP_STATUS_NOT_IMPLEMENTED;
  }

  /* The almost impossible situation: all elements are small, but cannot
     fit the buffer. The application set the buffer size to
     critically low value? */

  if ((1 < opt_headers_size) || (1 < uri_size))
  {
    if (opt_headers_size >= uri_size)
      return MHD_HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE;
    else
      return MHD_HTTP_STATUS_URI_TOO_LONG;
  }

  /* Nothing to reduce in the request.
     Reply with some status. */
  if (0 != host_field_line_size)
    return MHD_HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE;

  return MHD_HTTP_STATUS_URI_TOO_LONG;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_stream_switch_from_recv_to_send (struct MHD_Connection *c)
{
  /* Read buffer is not needed for this request, shrink it.*/
  mhd_stream_shrink_read_buffer (c);
}


/**
 * Finish request serving.
 * The stream will be re-used or closed.
 *
 * @param c the connection to use.
 */
MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_stream_finish_req_serving (struct MHD_Connection *restrict c,
                               bool reuse)
{
  struct MHD_Daemon *const restrict d = c->daemon;

  if (! reuse)
  {
    mhd_assert (! c->stop_with_error || (NULL == c->rp.response) || \
                (c->rp.response->cfg.int_err_resp));
    /* Next function will destroy response, notify client,
     * destroy memory pool and set connection state to "CLOSED" */
    mhd_conn_pre_close (c,
                        c->stop_with_error ?
                        mhd_CONN_CLOSE_ERR_REPLY_SENT :
                        mhd_CONN_CLOSE_HTTP_COMPLETED,
                        NULL);
  }
  else
  {
    /* Reset connection to process the next request */
    size_t new_read_buf_size;
    mhd_assert (! c->stop_with_error);
    mhd_assert (! c->discard_request);
    mhd_assert (NULL == c->rq.cntn.lbuf.buf);

#if 0 // TODO: notification callback
    if ( (NULL != d->notify_completed) &&
         (c->rq.app_aware) )
      d->notify_completed (d->notify_completed_cls,
                           c,
                           &c->rq.app_context,
                           MHD_REQUEST_TERMINATED_COMPLETED_OK);
    c->rq.app_aware = false;
#endif

    mhd_stream_call_dcc_cleanup_if_needed (c);
    if (NULL != c->rp.resp_iov.iov)
    {
      free (c->rp.resp_iov.iov);
      c->rp.resp_iov.iov = NULL;
    }

    if (NULL != c->rp.response)
      mhd_response_dec_use_count (c->rp.response);
    c->rp.response = NULL;

    c->conn_reuse = mhd_CONN_KEEPALIVE_POSSIBLE;
    c->state = MHD_CONNECTION_INIT;
    c->event_loop_info =
      (0 == c->read_buffer_offset) ?
      MHD_EVENT_LOOP_INFO_READ : MHD_EVENT_LOOP_INFO_PROCESS;

    memset (&c->rq, 0, sizeof(c->rq));

    /* iov (if any) will be deallocated by mhd_pool_reset */
    memset (&c->rp, 0, sizeof(c->rp));

    // TODO: set all rq and tp pointers to NULL manually. Do the same in other places.

    c->write_buffer = NULL;
    c->write_buffer_size = 0;
    c->write_buffer_send_offset = 0;
    c->write_buffer_append_offset = 0;
    c->continue_message_write_offset = 0;

    /* Reset the read buffer to the starting size,
       preserving the bytes we have already read. */
    new_read_buf_size = d->conns.cfg.mem_pool_size / 2;
    if (c->read_buffer_offset > new_read_buf_size)
      new_read_buf_size = c->read_buffer_offset;

    c->read_buffer
      = mhd_pool_reset (c->pool,
                        c->read_buffer,
                        c->read_buffer_offset,
                        new_read_buf_size);
    c->read_buffer_size = new_read_buf_size;
  }
  c->rq.app_context = NULL;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_stream_check_timedout (struct MHD_Connection *restrict c)
{
  const uint_fast64_t timeout = c->connection_timeout_ms;
  uint_fast64_t now;
  uint_fast64_t since_actv;

  mhd_assert (! c->suspended);

  if (0 == timeout)
    return false;

  now = MHD_monotonic_msec_counter (); // TODO: Get and use timer value one time only per round
  since_actv = now - c->last_activity;
  /* Keep the next lines in sync with #connection_get_wait() to avoid
   * undesired side-effects like busy-waiting. */
  if (timeout < since_actv)
  {
    const uint_fast64_t jump_back = c->last_activity - now;
    if (jump_back < since_actv)
    {
      /* Very unlikely that it is more than quarter-million years pause.
       * More likely that system clock jumps back. */
      if (4000 >= jump_back)
      {
        c->last_activity = now; /* Avoid repetitive messages.
                                   Warn: the order of connections sorted
                                   by timeout is not updated. */
        mhd_LOG_PRINT (c->daemon, MHD_SC_SYS_CLOCK_JUMP_BACK_CORRECTED, \
                       mhd_LOG_FMT ("Detected system clock %u " \
                                    "milliseconds jump back."),
                       (unsigned int) jump_back);
        return false;
      }
      mhd_LOG_PRINT (c->daemon, MHD_SC_SYS_CLOCK_JUMP_BACK_LARGE, \
                     mhd_LOG_FMT ("Detected too large system clock %" \
                                  PRIuFAST64 " milliseconds jump back"),
                     jump_back);
    }
    return true;
  }
  return false;
}


/**
 * Update last activity mark to the current time..
 * @param c the connection to update
 */
MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_stream_update_activity_mark (struct MHD_Connection *restrict c)
{
  struct MHD_Daemon *const restrict d = c->daemon;
#if defined(MHD_USE_THREADS)
  mhd_assert (! mhd_D_HAS_WORKERS (d));
#endif /* MHD_USE_THREADS */

  mhd_assert (! c->suspended);

  if (0 == c->connection_timeout_ms)
    return;  /* Skip update of activity for connections
               without timeout timer. */

  c->last_activity = MHD_monotonic_msec_counter (); // TODO: Get and use time value one time per round
  if (mhd_D_HAS_THR_PER_CONN (d))
    return; /* each connection has personal timeout */

  if (c->connection_timeout_ms != d->conns.cfg.timeout)
    return; /* custom timeout, no need to move it in "normal" DLL */

  /* move connection to head of timeout list (by remove + add operation) */
  mhd_DLINKEDL_DEL_D (&(d->conns.def_timeout), c, by_timeout);
  mhd_DLINKEDL_INS_FIRST_D (&(d->conns.def_timeout), c, by_timeout);
}


MHD_INTERNAL
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_CSTR_ (3) void
mhd_conn_pre_close (struct MHD_Connection *restrict c,
                    enum mhd_ConnCloseReason reason,
                    const char *log_msg)
{
  bool close_hard;
  bool use_local_lingering;
  enum MHD_RequestTerminationCode term_code;
  enum MHD_StatusCode sc;

  sc = MHD_SC_INTERNAL_ERROR;
  switch (reason)
  {
  case mhd_CONN_CLOSE_CLIENT_HTTP_ERR_ABORT_CONN:
    close_hard = true;
    term_code = MHD_REQUEST_TERMINATED_HTTP_PROTOCOL_ERROR;
    sc = MHD_SC_REQ_MALFORMED;
    break;
  case mhd_CONN_CLOSE_NO_POOL_MEM_FOR_REQUEST:
    close_hard = true;
    term_code = MHD_REQUEST_TERMINATED_NO_RESOURCES;
    break;
  case mhd_CONN_CLOSE_CLIENT_SHUTDOWN_EARLY:
    close_hard = true;
    term_code = MHD_REQUEST_TERMINATED_CLIENT_ABORT;
    sc = MHD_SC_REPLY_POOL_ALLOCATION_FAILURE;
    break;
  case mhd_CONN_CLOSE_NO_POOL_MEM_FOR_REPLY:
    close_hard = true;
    term_code = (! c->stop_with_error || c->rq.too_large) ?
                MHD_REQUEST_TERMINATED_NO_RESOURCES :
                MHD_REQUEST_TERMINATED_HTTP_PROTOCOL_ERROR;
    sc = MHD_SC_REPLY_POOL_ALLOCATION_FAILURE;
    break;
  case mhd_CONN_CLOSE_NO_MEM_FOR_ERR_RESPONSE:
    close_hard = true;
    term_code = c->rq.too_large ?
                MHD_REQUEST_TERMINATED_NO_RESOURCES :
                MHD_REQUEST_TERMINATED_HTTP_PROTOCOL_ERROR;
    sc = MHD_SC_ERR_RESPONSE_ALLOCATION_FAILURE;
    break;
  case mhd_CONN_CLOSE_APP_ERROR:
    close_hard = true;
    term_code = MHD_REQUEST_TERMINATED_BY_APP_ERROR;
    sc = MHD_SC_APPLICATION_DATA_GENERATION_FAILURE_CLOSED;
    break;
  case mhd_CONN_CLOSE_APP_ABORTED:
    close_hard = true;
    term_code = MHD_REQUEST_TERMINATED_BY_APP_ABORT;
    sc = MHD_SC_APPLICATION_CALLBACK_ABORT_ACTION;
    break;
  case mhd_CONN_CLOSE_INT_ERROR:
    close_hard = true;
    term_code = MHD_REQUEST_TERMINATED_NO_RESOURCES;
    break;
  case mhd_CONN_CLOSE_SOCKET_ERR:
    close_hard = true;
    switch (c->sk_discnt_err)
    {
    case mhd_SOCKET_ERR_NOMEM:
      term_code = MHD_REQUEST_TERMINATED_NO_RESOURCES;
      break;
    case mhd_SOCKET_ERR_REMT_DISCONN:
      close_hard = false;
      term_code = (MHD_CONNECTION_INIT == c->state) ?
                  MHD_REQUEST_TERMINATED_COMPLETED_OK /* Not used */ :
      MHD_REQUEST_TERMINATED_CLIENT_ABORT;
      break;
    case mhd_SOCKET_ERR_CONNRESET:
      term_code = MHD_REQUEST_TERMINATED_CLIENT_ABORT;
      break;
    case mhd_SOCKET_ERR_CONN_BROKEN:
    case mhd_SOCKET_ERR_NOTCONN:
    case mhd_SOCKET_ERR_TLS:
    case mhd_SOCKET_ERR_PIPE:
    case mhd_SOCKET_ERR_NOT_CHECKED:
    case mhd_SOCKET_ERR_BADF:
    case mhd_SOCKET_ERR_INVAL:
    case mhd_SOCKET_ERR_OPNOTSUPP:
    case mhd_SOCKET_ERR_NOTSOCK:
    case mhd_SOCKET_ERR_OTHER:
    case mhd_SOCKET_ERR_INTERNAL:
    case mhd_SOCKET_ERR_NO_ERROR:
      term_code = MHD_REQUEST_TERMINATED_CONNECTION_ERROR;
      break;
    case mhd_SOCKET_ERR_AGAIN:
    case mhd_SOCKET_ERR_INTR:
    default:
      mhd_assert (0 && "Impossible value");
      MHD_UNREACHABLE_;
    }
    break;
  case mhd_CONN_CLOSE_DAEMON_SHUTDOWN:
    close_hard = true;
    term_code = MHD_REQUEST_TERMINATED_DAEMON_SHUTDOWN;
    break;

  case mhd_CONN_CLOSE_TIMEDOUT:
    if (MHD_CONNECTION_INIT == c->state)
    {
      close_hard = false;
      term_code = MHD_REQUEST_TERMINATED_COMPLETED_OK; /* Not used */
      break;
    }
    close_hard = true;
    term_code = MHD_REQUEST_TERMINATED_TIMEOUT_REACHED;
    break;

  case mhd_CONN_CLOSE_ERR_REPLY_SENT:
    close_hard = false;
    term_code = c->rq.too_large ?
                MHD_REQUEST_TERMINATED_NO_RESOURCES :
                MHD_REQUEST_TERMINATED_HTTP_PROTOCOL_ERROR;
    break;
  case mhd_CONN_CLOSE_HTTP_COMPLETED:
    close_hard = false;
    term_code = MHD_REQUEST_TERMINATED_COMPLETED_OK;
    break;

  default:
    mhd_assert (0 && "Unreachable code");
    MHD_UNREACHABLE_;
    term_code = MHD_REQUEST_TERMINATED_COMPLETED_OK;
    close_hard = false;
  }

  mhd_assert ((NULL == log_msg) || (MHD_SC_INTERNAL_ERROR != sc));

  use_local_lingering = false;
  /* Make changes on the socket early to let the kernel and the remote
   * to process the changes in parallel. */
  if (close_hard)
  {
    /* Use abortive closing, send RST to remote to indicate a problem */
    (void) mhd_socket_set_hard_close (c->socket_fd);
    c->state = MHD_CONNECTION_CLOSED;
    c->event_loop_info = MHD_EVENT_LOOP_INFO_CLEANUP;
  }
  else
  {
    if (mhd_socket_shut_wr (c->socket_fd) && (! c->sk_rmt_shut_wr))
    {
      (void) 0; // TODO: start local lingering phase
      c->state = MHD_CONNECTION_CLOSED; // TODO: start local lingering phase
      c->event_loop_info = MHD_EVENT_LOOP_INFO_CLEANUP; // TODO: start local lingering phase
      // use_local_lingering = true;
    }
    else
    {  /* No need / not possible to linger */
      c->state = MHD_CONNECTION_CLOSED;
      c->event_loop_info = MHD_EVENT_LOOP_INFO_CLEANUP;
    }
  }

#ifdef HAVE_LOG_FUNCTIONALITY
  if (NULL != log_msg)
  {
    mhd_LOG_MSG (c->daemon, sc, log_msg);
  }
#else  /* ! HAVE_LOG_FUNCTIONALITY */
  (void) log_msg;
#endif /* ! HAVE_LOG_FUNCTIONALITY */

  mhd_stream_call_dcc_cleanup_if_needed (c);
  if (NULL != c->rp.resp_iov.iov)
  {
    free (c->rp.resp_iov.iov);
    c->rp.resp_iov.iov = NULL;
  }

#if 0 // TODO: notification callback
  mhd_assert ((MHD_CONNECTION_INIT != c->state) || (! c->rq.app_aware));
  if ( (NULL != d->notify_completed) &&
       (c->rq.app_aware) )
    d->notify_completed (d->notify_completed_cls,
                         c,
                         &c->rq.app_context,
                         MHD_REQUEST_TERMINATED_COMPLETED_OK);
#else
  (void) term_code;
#endif
  c->rq.app_aware = false;

  if (! mhd_D_HAS_THR_PER_CONN (c->daemon))
  {
    if (c->connection_timeout_ms == c->daemon->conns.cfg.timeout)
      mhd_DLINKEDL_DEL_D (&(c->daemon->conns.def_timeout), \
                          c, by_timeout);
    else
      mhd_DLINKEDL_DEL_D (&(c->daemon->conns.cust_timeout), \
                          c, by_timeout);
  }

#ifndef NDEBUG
  c->dbg.pre_closed = true;
#endif

  if (! use_local_lingering)
    mhd_conn_pre_clean (c);
}


MHD_INTERNAL
MHD_FN_PAR_NONNULL_ (1) void
mhd_conn_pre_clean (struct MHD_Connection *restrict c)
{
  // TODO: support suspended connections

  mhd_conn_mark_unready (c, c->daemon);

  if (NULL != c->rq.cntn.lbuf.buf)
    mhd_daemon_free_lbuf (c->daemon, &(c->rq.cntn.lbuf));
  c->rq.cntn.lbuf.buf = NULL;
  if (NULL != c->rp.response)
    mhd_response_dec_use_count (c->rp.response);
  c->rp.response = NULL;

  mhd_assert (NULL != c->pool);
  c->read_buffer_offset = 0;
  c->read_buffer_size = 0;
  c->read_buffer = NULL;
  c->write_buffer_send_offset = 0;
  c->write_buffer_append_offset = 0;
  c->write_buffer_size = 0;
  c->write_buffer = NULL;
  // TODO: call in the thread where it was allocated for thread-per-connection
  mhd_pool_destroy (c->pool);
  c->pool = NULL;

#ifdef MHD_USE_EPOLL
  if (mhd_POLL_TYPE_EPOLL == c->daemon->events.poll_type)
  {
    struct epoll_event event;

    event.events = 0;
    event.data.ptr = NULL;
    if (0 != epoll_ctl (c->daemon->events.data.epoll.e_fd,
                        EPOLL_CTL_DEL,
                        c->socket_fd,
                        &event))
    {
      mhd_LOG_MSG (c->daemon, MHD_SC_EPOLL_CTL_REMOVE_FAILED,
                   "Failed to remove connection socket from epoll.");
    }
  }
#endif /* MHD_USE_EPOLL */

#ifndef NDEBUG
  c->dbg.pre_cleaned = true;
#endif
}
