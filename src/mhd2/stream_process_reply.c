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
 * @file src/mhd2/stream_process_reply.h
 * @brief  The implementation of internal functions for forming and sending
 *         replies for requests
 * @author Karlson2k (Evgeny Grin)
 *
 * Based on the MHD v0.x code by Daniel Pittman, Christian Grothoff and other
 * contributors.
 */

#include "mhd_sys_options.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include <string.h>
#ifdef HAVE_TIME_H
#  include <time.h>
#endif

#include "mhd_daemon.h"
#include "mhd_response.h"
#include "mhd_reply.h"
#include "mhd_connection.h"

#include "daemon_logger.h"
#include "mhd_assert.h"

#include "mhd_str.h"
#include "http_status_str.h"
#include "stream_process_reply.h"
#include "stream_funcs.h"
#include "request_get_value.h"

#include "mhd_public_api.h"

MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_stream_call_dcc_cleanup_if_needed (struct MHD_Connection *restrict c)
{
  if (mhd_DCC_ACTION_CONTINUE != c->rp.app_act.act)
    return;
  if (NULL == c->rp.app_act.data.cntnue.iov_data)
    return;

  mhd_assert (mhd_RESPONSE_CONTENT_DATA_CALLBACK == \
              c->rp.response->cntn_dtype);

  if (NULL != c->rp.app_act.data.cntnue.iov_data->iov_fcb)
  {
    c->rp.app_act.data.cntnue.iov_data->iov_fcb (
      c->rp.app_act.data.cntnue.iov_data->iov_fcb_cls);
  }

  c->rp.app_act.data.cntnue.iov_data = NULL;
}


/**
 * This enum type describes requirements for reply body and reply bode-specific
 * headers (namely Content-Length, Transfer-Encoding).
 */
enum replyBodyUse
{
  /**
   * No reply body allowed.
   * Reply body headers 'Content-Length:' or 'Transfer-Encoding: chunked' are
   * not allowed as well.
   */
  RP_BODY_NONE = 0,

  /**
   * Do not send reply body.
   * Reply body headers 'Content-Length:' or 'Transfer-Encoding: chunked' are
   * allowed, but optional.
   */
  RP_BODY_HEADERS_ONLY = 1,

  /**
   * Send reply body and
   * reply body headers 'Content-Length:' or 'Transfer-Encoding: chunked'.
   * Reply body headers are required.
   */
  RP_BODY_SEND = 2
};


/**
 * Is it allowed to reuse the connection?
 * The TCP stream can be reused for the next requests if the connection
 * is HTTP 1.1 and the "Connection" header either does not exist or
 * is not set to "close", or if the connection is HTTP 1.0 and the
 * "Connection" header is explicitly set to "keep-alive".
 * If no HTTP version is specified (or if it is not 1.0 or 1.1), the connection
 * is definitively closed.  If the "Connection" header is not exactly "close"
 * or "keep-alive", connection is reused if is it HTTP/1.1.
 * If response has HTTP/1.0 flag or has "Connection: close" header
 * then connection must be closed.
 * If full request has not been read then connection must be closed
 * as well as more client data may be sent.
 *
 * @param c the connection to check for re-use
 * @return mhd_CONN_KEEPALIVE_POSSIBLE if (based on the request and
 *         the response) a connection could be reused,
 *         MHD_CONN_MUST_CLOSE if connection must be closed after sending
 *         complete reply,
 *         mhd_CONN_MUST_UPGRADE if connection must be upgraded.
 */
static MHD_FN_PAR_NONNULL_ALL_ enum mhd_ConnReuse
get_conn_reuse (struct MHD_Connection *c)
{
  const struct MHD_Response *const restrict rp = c->rp.response;

  mhd_assert (NULL != rp);
  if (mhd_CONN_MUST_CLOSE == c->conn_reuse)
    return mhd_CONN_MUST_CLOSE;

  mhd_assert ( (! c->stop_with_error) || (c->discard_request));
  if ((c->sk_rmt_shut_wr) || (c->discard_request))
    return mhd_CONN_MUST_CLOSE;

  if (rp->cfg.close_forced)
    return mhd_CONN_MUST_CLOSE;

  mhd_assert ((MHD_SIZE_UNKNOWN != rp->cntn_size) || \
              (! rp->cfg.mode_1_0));

  if (! MHD_HTTP_VERSION_IS_SUPPORTED (c->rq.http_ver))
    return mhd_CONN_MUST_CLOSE;

  if (rp->cfg.mode_1_0 &&
      ! mhd_stream_has_header_token_st (c,
                                        MHD_HTTP_HEADER_CONNECTION,
                                        "keep-alive"))
    return mhd_CONN_MUST_CLOSE;

#if 0 // def UPGRADE_SUPPORT // TODO: Implement upgrade support
  /* TODO: Move below the next check when MHD stops closing connections
   * when response is queued in first callback */
  if (NULL != r->upgrade_handler)
  {
    /* No "close" token is enforced by 'add_response_header_connection()' */
    mhd_assert (0 == (r->flags_auto & MHD_RAF_HAS_CONNECTION_CLOSE));
    /* Valid HTTP version is enforced by 'MHD_queue_response()' */
    mhd_assert (MHD_IS_HTTP_VER_SUPPORTED (c->rq.http_ver));
    mhd_assert (! c->stop_with_error);
    return mhd_CONN_MUST_UPGRADE;
  }
#endif /* UPGRADE_SUPPORT */

  return mhd_CONN_KEEPALIVE_POSSIBLE;
}


/**
 * Check whether reply body must be used.
 *
 * If reply body is needed, it could be zero-sized.
 *
 * @param c the connection to check
 * @param rcode the response code
 * @return enum value indicating whether response body can be used and
 *         whether response body length headers are allowed or required.
 * @sa is_reply_body_header_needed()
 */
static enum replyBodyUse
is_reply_body_needed (struct MHD_Connection *restrict c,
                      uint_fast16_t rcode)
{
  mhd_assert (100 <= rcode);
  mhd_assert (999 >= rcode);

  if (199 >= rcode)
    return RP_BODY_NONE;

  if (MHD_HTTP_STATUS_NO_CONTENT == rcode)
    return RP_BODY_NONE;

#if 0
  /* This check is not needed as upgrade handler is used only with code 101 */
#ifdef UPGRADE_SUPPORT
  if (NULL != rp.response->upgrade_handler)
    return RP_BODY_NONE;
#endif /* UPGRADE_SUPPORT */
#endif

#if 0
  /* CONNECT is not supported by MHD */
  /* Successful responses for connect requests are filtered by
   * MHD_queue_response() */
  if ( (mhd_HTTP_METHOD_CONNECT == c->rq.http_mthd) &&
       (2 == rcode / 100) )
    return false; /* Actually pass-through CONNECT is not supported by MHD */
#endif

  /* Reply body headers could be used.
   * Check whether reply body itself must be used. */

  if (mhd_HTTP_METHOD_HEAD == c->rq.http_mthd)
    return RP_BODY_HEADERS_ONLY;

  if (MHD_HTTP_STATUS_NOT_MODIFIED == rcode)
    return RP_BODY_HEADERS_ONLY;

  /* Reply body must be sent.
   * The body may have zero length, but body size must be indicated by
   * headers ('Content-Length:' or 'Transfer-Encoding: chunked'). */
  return RP_BODY_SEND;
}


/**
 * Setup connection reply properties.
 *
 * Reply properties include presence of reply body, transfer-encoding
 * type and other.
 *
 * @param connection to connection to process
 */
static MHD_FN_PAR_NONNULL_ALL_ void
setup_reply_properties (struct MHD_Connection *restrict c)
{
  struct MHD_Response *const restrict r = c->rp.response;  /**< a short alias */
  enum replyBodyUse use_rp_body;
  bool use_chunked;
  bool end_by_closing;

  mhd_assert (NULL != r);

  /* ** Adjust reply properties ** */

  c->conn_reuse = get_conn_reuse (c);
  use_rp_body = is_reply_body_needed (c, r->sc);
  c->rp.props.send_reply_body = (use_rp_body > RP_BODY_HEADERS_ONLY);
  c->rp.props.use_reply_body_headers = (use_rp_body >= RP_BODY_HEADERS_ONLY);

#if 0 // def UPGRADE_SUPPORT // TODO: upgrade support
  mhd_assert ( (NULL == r->upgrade_handler) ||
               (RP_BODY_NONE == use_rp_body) );
#endif /* UPGRADE_SUPPORT */

  use_chunked = false;
  end_by_closing = false;
  if (c->rp.props.use_reply_body_headers)
  {
    if (r->cfg.chunked)
    {
      mhd_assert (! r->cfg.mode_1_0);
      use_chunked = (MHD_HTTP_VERSION_1_1 == c->rq.http_ver);
    }
    if ((MHD_SIZE_UNKNOWN == r->cntn_size) &&
        (! use_chunked) &&
        (c->rp.props.send_reply_body))
    {
      /* End of the stream is indicated by closure */
      end_by_closing = true;
    }
  }

  if (end_by_closing)
  {
    mhd_assert (mhd_CONN_MUST_UPGRADE != c->conn_reuse);
    /* End of the stream is indicated by closure */
    c->conn_reuse = mhd_CONN_MUST_CLOSE;
  }

  c->rp.props.chunked = use_chunked;
  c->rp.props.end_by_closing = end_by_closing;

  if ((! c->rp.props.send_reply_body) || (0 == r->cntn_size))
    c->rp.cntn_loc = mhd_REPLY_CNTN_LOC_NOWHERE;
  else if (c->rp.props.chunked)
    c->rp.cntn_loc = mhd_REPLY_CNTN_LOC_CONN_BUF;
  else
  {
    switch (r->cntn_dtype)
    {
    case mhd_RESPONSE_CONTENT_DATA_BUFFER:
      c->rp.cntn_loc = mhd_REPLY_CNTN_LOC_RESP_BUF;
      break;
    case mhd_RESPONSE_CONTENT_DATA_IOVEC:
      c->rp.cntn_loc = mhd_REPLY_CNTN_LOC_IOV;
      break;
    case mhd_RESPONSE_CONTENT_DATA_FILE:
#if 0 // TODO: TLS support
      if (use_tls)
      {
        c->rp.cntn_loc = mhd_REPLY_CNTN_LOC_CONN_BUF;
        break;
      }
#endif
#ifdef MHD_USE_SENDFILE
      if (r->cntn.file.use_sf)
      {
        c->rp.cntn_loc = mhd_REPLY_CNTN_LOC_FILE;
        break;
      }
#endif
      c->rp.cntn_loc = mhd_REPLY_CNTN_LOC_CONN_BUF;
      break;
    case mhd_RESPONSE_CONTENT_DATA_CALLBACK:
      c->rp.cntn_loc = mhd_REPLY_CNTN_LOC_CONN_BUF;
      break;
    case mhd_RESPONSE_CONTENT_DATA_INVALID:
    default:
      mhd_assert (0 && "Impossible value");
      MHD_UNREACHABLE_;
      c->rp.cntn_loc = mhd_REPLY_CNTN_LOC_NOWHERE;
      break;
    }
  }

#ifdef _DEBUG
  c->rp.props.set = true;
#endif /* _DEBUG */
}


/**
 * Check whether queued response is suitable for @a connection.
 * @param connection to connection to check
 */
static void
check_connection_reply (struct MHD_Connection *restrict c)
{
  struct MHD_Response *const restrict r = c->rp.response;  /**< a short alias */

  mhd_assert (c->rp.props.set);

  if ( (! c->rp.props.use_reply_body_headers) &&
       (0 != r->cntn_size) )
  {
    mhd_LOG_PRINT (c->daemon, MHD_SC_REPLY_NOT_EMPTY_RESPONSE,
                   mhd_LOG_FMT ("This reply with response code %u " \
                                "cannot use reply content. Non-empty " \
                                "response content is ignored and not used."),
                   (unsigned) (c->rp.response->sc));
  }
  if ( (! c->rp.props.use_reply_body_headers) &&
       (r->cfg.cnt_len_by_app) )
  {
    mhd_LOG_PRINT (c->daemon, MHD_SC_REPLY_CONTENT_LENGTH_NOT_ALLOWED,
                   mhd_LOG_FMT ("This reply with response code %u " \
                                "cannot use reply content. Application " \
                                "defined \"Content-Length\" header " \
                                "violates HTTP specification."),
                   (unsigned) (c->rp.response->sc));
  }
}


/**
 * Produce time stamp.
 *
 * Result is NOT null-terminated.
 * Result is always 29 bytes long.
 *
 * @param[out] date where to write the time stamp, with
 *             at least 29 bytes of savailable space.
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (1) bool
get_date_str (char *date)
{
  static const char *const days[] = {
    "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
  };
  static const char *const mons[] = {
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
  };
  static const size_t buf_len = 29;
  struct tm now;
  time_t t;
  const char *src;
#if ! defined(HAVE_C11_GMTIME_S) && ! defined(HAVE_W32_GMTIME_S) && \
  ! defined(HAVE_GMTIME_R)
  struct tm *pNow;
#endif

  if ((time_t) -1 == time (&t))
    return false;
#if defined(HAVE_GMTIME_R)
  if (NULL == gmtime_r (&t,
                        &now))
    return false;
#elif defined(HAVE_C11_GMTIME_S)
  if (NULL == gmtime_s (&t,
                        &now))
    return false;
#elif defined(HAVE_W32_GMTIME_S)
  if (0 != gmtime_s (&now,
                     &t))
    return false;
#else
  pNow = gmtime (&t);
  if (NULL == pNow)
    return false;
  now = *pNow;
#endif

  /* Day of the week */
  src = days[now.tm_wday % 7];
  date[0] = src[0];
  date[1] = src[1];
  date[2] = src[2];
  date[3] = ',';
  date[4] = ' ';
  /* Day of the month */
  if (2 != mhd_uint8_to_str_pad ((uint8_t) now.tm_mday, 2,
                                 date + 5, buf_len - 5))
    return false;
  date[7] = ' ';
  /* Month */
  src = mons[now.tm_mon % 12];
  date[8] = src[0];
  date[9] = src[1];
  date[10] = src[2];
  date[11] = ' ';
  /* Year */
  if (4 != mhd_uint16_to_str ((uint_least16_t) (1900 + now.tm_year), date + 12,
                              buf_len - 12))
    return false;
  date[16] = ' ';
  /* Time */
  mhd_uint8_to_str_pad ((uint8_t) now.tm_hour, 2, date + 17, buf_len - 17);
  date[19] = ':';
  mhd_uint8_to_str_pad ((uint8_t) now.tm_min, 2, date + 20, buf_len - 20);
  date[22] = ':';
  mhd_uint8_to_str_pad ((uint8_t) now.tm_sec, 2, date + 23, buf_len - 23);
  date[25] = ' ';
  date[26] = 'G';
  date[27] = 'M';
  date[28] = 'T';

  return true;
}


/**
 * Produce HTTP DATE header.
 * Result is always 37 bytes long (plus one terminating null).
 *
 * @param[out] header where to write the header, with
 *             at least 38 bytes available space.
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (1) bool
get_date_header (char *header)
{
  header[0] = 'D';
  header[1] = 'a';
  header[2] = 't';
  header[3] = 'e';
  header[4] = ':';
  header[5] = ' ';
  if (! get_date_str (header + 6))
  {
    header[0] = 0;
    return false;
  }
  header[35] = '\r';
  header[36] = '\n';
  header[37] = 0;
  return true;
}


/**
 * Append data to the buffer if enough space is available,
 * update position.
 * @param[out] buf the buffer to append data to
 * @param[in,out] ppos the pointer to position in the @a buffer
 * @param buf_size the size of the @a buffer
 * @param append the data to append
 * @param append_size the size of the @a append
 * @return true if data has been added and position has been updated,
 *         false if not enough space is available
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
buffer_append (char *buf,
               size_t *ppos,
               size_t buf_size,
               const char *append,
               size_t append_size)
{
  mhd_assert (NULL != buf); /* Mute static analyzer */
  if (buf_size < *ppos + append_size)
    return false;
  memcpy (buf + *ppos, append, append_size);
  *ppos += append_size;
  return true;
}


/**
 * Add user-defined headers from response object to
 * the text buffer.
 *
 * @param buf the buffer to add headers to
 * @param ppos the pointer to the position in the @a buf
 * @param buf_size the size of the @a buf
 * @param response the response
 * @param filter_content_len skip "Content-Length" header if any
 * @param add_close add "close" token to the
 *                  "Connection:" header (if any), ignored if no "Connection:"
 *                  header was added by user or if "close" token is already
 *                  present in "Connection:" header
 * @param add_keep_alive add "Keep-Alive" token to the
 *                       "Connection:" header (if any)
 * @return true if succeed,
 *         false if buffer is too small
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
add_user_headers (char *restrict buf,
                  size_t *restrict ppos,
                  size_t buf_size,
                  struct MHD_Response *restrict r,
                  bool filter_content_len,
                  bool add_close,
                  bool add_keep_alive)
{
  struct mhd_ResponseHeader *hdr; /**< Iterates through User-specified headers */
  size_t el_size; /**< the size of current element to be added to the @a buf */

  mhd_assert (! add_close || ! add_keep_alive);
  mhd_assert (! add_keep_alive || ! add_close);

  if (r->cfg.has_hdr_conn)
  {
    add_close = false;          /* No such header */
    add_keep_alive = false;     /* No such header */
  }

  for (hdr = mhd_DLINKEDL_GET_FIRST (r, headers);
       NULL != hdr;
       hdr = mhd_DLINKEDL_GET_NEXT (hdr, headers))
  {
    size_t initial_pos = *ppos;

    if (filter_content_len)
    { /* Need to filter-out "Content-Length" */
      if (mhd_str_equal_caseless_n_st (MHD_HTTP_HEADER_CONTENT_LENGTH, \
                                       hdr->name.cstr,
                                       hdr->name.len))
      {
        /* Reset filter flag  */
        filter_content_len = false;
        continue; /* Skip "Content-Length" header */
      }
    }

    /* Add user header */
    el_size = hdr->name.len + 2 + hdr->value.len + 2;
    if (buf_size < *ppos + el_size)
      return false;
    memcpy (buf + *ppos, hdr->name.cstr, hdr->name.len);
    (*ppos) += hdr->name.len;
    buf[(*ppos)++] = ':';
    buf[(*ppos)++] = ' ';
    if (add_close || add_keep_alive)
    {
      /* "Connection:" header must be always the first one */
      mhd_assert (mhd_str_equal_caseless_n (hdr->name.cstr, \
                                            MHD_HTTP_HEADER_CONNECTION, \
                                            hdr->name.len));

      if (add_close)
      {
        el_size += mhd_SSTR_LEN ("close, ");
        if (buf_size < initial_pos + el_size)
          return false;
        memcpy (buf + *ppos, "close, ",
                mhd_SSTR_LEN ("close, "));
        *ppos += mhd_SSTR_LEN ("close, ");
      }
      else
      {
        el_size += mhd_SSTR_LEN ("Keep-Alive, ");
        if (buf_size < initial_pos + el_size)
          return false;
        memcpy (buf + *ppos, "Keep-Alive, ",
                mhd_SSTR_LEN ("Keep-Alive, "));
        *ppos += mhd_SSTR_LEN ("Keep-Alive, ");
      }
      add_close = false;
      add_keep_alive = false;
    }
    if (0 != hdr->value.len)
      memcpy (buf + *ppos, hdr->value.cstr, hdr->value.len);
    *ppos += hdr->value.len;
    buf[(*ppos)++] = '\r';
    buf[(*ppos)++] = '\n';
    mhd_assert (initial_pos + el_size == (*ppos));
  }
  return true;
}


/**
 * Append static string to the buffer if enough space is available,
 * update position.
 * @param[out] buf the buffer to append data to
 * @param[in,out] ppos the pointer to position in the @a buffer
 * @param buf_size the size of the @a buffer
 * @param str the static string to append
 * @return true if data has been added and position has been updated,
 *         false if not enough space is available
 */
#define buffer_append_s(buf,ppos,buf_size,str) \
        buffer_append (buf,ppos,buf_size,str, mhd_SSTR_LEN (str))

/**
 * Allocate the connection's write buffer and fill it with all of the
 * headers from the response.
 * Inner version of the function.
 *
 * @param c the connection to process
 * @return 'true' if state has been update,
 *         'false' if connection is going to be aborted
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
build_header_response_inn (struct MHD_Connection *restrict c)
{
  struct MHD_Response *const restrict r = c->rp.response;
  char *restrict buf;                            /**< the output buffer */
  size_t pos;                                    /**< append offset in the @a buf */
  size_t buf_size;                               /**< the size of the @a buf */
  size_t el_size;                                /**< the size of current element to be added to the @a buf */
  uint_fast16_t rcode;                           /**< the response code */
  bool use_conn_close;                           /**< Use "Connection: close" header */
  bool use_conn_k_alive;                         /**< Use "Connection: Keep-Alive" header */

  mhd_assert (NULL != r);

  /* ** Adjust response properties ** */
  setup_reply_properties (c);

  mhd_assert (c->rp.props.set);
  mhd_assert ((mhd_CONN_MUST_CLOSE == c->conn_reuse) || \
              (mhd_CONN_KEEPALIVE_POSSIBLE == c->conn_reuse) || \
              (mhd_CONN_MUST_UPGRADE == c->conn_reuse));
#if 0 // def UPGRADE_SUPPORT // TODO: upgrade support
  mhd_assert ((NULL == r->upgrade_handler) || \
              (mhd_CONN_MUST_UPGRADE == c->keepalive));
#else  /* ! UPGRADE_SUPPORT */
  mhd_assert (mhd_CONN_MUST_UPGRADE != c->conn_reuse);
#endif /* ! UPGRADE_SUPPORT */
  mhd_assert ((! c->rp.props.chunked) || c->rp.props.use_reply_body_headers);
  mhd_assert ((! c->rp.props.send_reply_body) || \
              c->rp.props.use_reply_body_headers);
  mhd_assert ((! c->rp.props.end_by_closing) || \
              (mhd_CONN_MUST_CLOSE == c->conn_reuse));
#if 0 // def UPGRADE_SUPPORT  // TODO: upgrade support
  mhd_assert (NULL == r->upgrade_handler || \
              ! c->rp.props.use_reply_body_headers);
#endif /* UPGRADE_SUPPORT */

  check_connection_reply (c);

  rcode = (uint_fast16_t) c->rp.response->sc;
  if (mhd_CONN_MUST_CLOSE == c->conn_reuse)
  {
    /* The closure of connection must be always indicated by header
     * to avoid hung connections */
    use_conn_close = true;
    use_conn_k_alive = false;
  }
  else if (mhd_CONN_KEEPALIVE_POSSIBLE == c->conn_reuse)
  {
    mhd_assert (! r->cfg.mode_1_0);
    use_conn_close = false;
    /* Add "Connection: keep-alive" if request is HTTP/1.0 or
     * if reply is HTTP/1.0
     * For HTTP/1.1 add header only if explicitly requested by app
     * (by response flag), as "Keep-Alive" is default for HTTP/1.1. */
    if (r->cfg.mode_1_0 ||
        (MHD_HTTP_VERSION_1_0 == c->rq.http_ver))
      use_conn_k_alive = true;
    else
      use_conn_k_alive = false;
  }
  else
  {
    use_conn_close = false;
    use_conn_k_alive = false;
  }

  /* ** Actually build the response header ** */

  /* Get all space available */
  mhd_stream_maximize_write_buffer (c);
  buf = c->write_buffer;
  pos = c->write_buffer_append_offset;
  buf_size = c->write_buffer_size;
  if (0 == buf_size)
    return false;
  mhd_assert (NULL != buf);

  // TODO: use pre-calculated header size
  /* * The status line * */

  /* The HTTP version */
  if (! c->rp.responseIcy)
  { /* HTTP reply */
    if (! r->cfg.mode_1_0)
    { /* HTTP/1.1 reply */
      /* Use HTTP/1.1 responses for HTTP/1.0 clients.
       * See https://datatracker.ietf.org/doc/html/rfc7230#section-2.6 */
      if (! buffer_append_s (buf, &pos, buf_size, MHD_HTTP_VERSION_1_1_STR))
        return false;
    }
    else
    { /* HTTP/1.0 reply */
      if (! buffer_append_s (buf, &pos, buf_size, MHD_HTTP_VERSION_1_0_STR))
        return false;
    }
  }
  else
  { /* ICY reply */
    if (! buffer_append_s (buf, &pos, buf_size, "ICY"))
      return false;
  }

  /* The response code */
  if (buf_size < pos + 5) /* space + code + space */
    return false;
  buf[pos++] = ' ';
  pos += mhd_uint16_to_str ((uint16_t) rcode, buf + pos,
                            buf_size - pos);
  buf[pos++] = ' ';

  /* The reason phrase */
  if (1)
  {
    const struct MHD_String *stat_str;
    stat_str = mhd_HTTP_status_code_to_string_int (rcode);
    mhd_assert (0 != stat_str->len);
    if (! buffer_append (buf, &pos, buf_size,
                         stat_str->cstr,
                         stat_str->len))
      return false;
  }
  /* The linefeed */
  if (buf_size < pos + 2)
    return false;
  buf[pos++] = '\r';
  buf[pos++] = '\n';

  /* * The headers * */

  /* A special custom header */
  if (0 != r->special_resp.spec_hdr_len)
  {
    mhd_assert (r->cfg.int_err_resp);
    if (buf_size < pos + r->special_resp.spec_hdr_len + 2)
      return false;
    memcpy (buf + pos,
            r->special_resp.spec_hdr,
            r->special_resp.spec_hdr_len);
    buf[pos++] = '\r';
    buf[pos++] = '\n';
  }

  /* Main automatic headers */

  /* The "Date:" header */
  if ( (! r->cfg.has_hdr_date) &&
       (! c->daemon->req_cfg.suppress_date) )
  {
    /* Additional byte for unused zero-termination */
    if (buf_size < pos + 38)
      return false;
    if (get_date_header (buf + pos))
      pos += 37;
  }
  /* The "Connection:" header */
  mhd_assert (! use_conn_close || ! use_conn_k_alive);
  mhd_assert (! use_conn_k_alive || ! use_conn_close);
  if (! r->cfg.has_hdr_conn)
  {
    if (use_conn_close)
    {
      if (! buffer_append_s (buf, &pos, buf_size,
                             MHD_HTTP_HEADER_CONNECTION ": close\r\n"))
        return false;
    }
    else if (use_conn_k_alive)
    {
      if (! buffer_append_s (buf, &pos, buf_size,
                             MHD_HTTP_HEADER_CONNECTION ": Keep-Alive\r\n"))
        return false;
    }
  }

  /* User-defined headers */

  if (! add_user_headers (buf, &pos, buf_size, r,
                          ! c->rp.props.use_reply_body_headers,
                          use_conn_close,
                          use_conn_k_alive))
    return false;

  /* Other automatic headers */

  if (c->rp.props.use_reply_body_headers)
  {
    /* Body-specific headers */

    if (c->rp.props.chunked)
    { /* Chunked encoding is used */
      mhd_assert (! c->rp.props.end_by_closing);
      if (! buffer_append_s (buf, &pos, buf_size,
                             MHD_HTTP_HEADER_TRANSFER_ENCODING ": " \
                             "chunked\r\n"))
        return false;
    }
    else /* Chunked encoding is not used */
    {
      if ((MHD_SIZE_UNKNOWN != r->cntn_size) &&
          (! c->rp.props.end_by_closing) &&
          (! r->cfg.chunked) &&
          (! r->cfg.head_only))
      { /* The size is known and can be indicated by the header */
        if (! r->cfg.cnt_len_by_app)
        { /* The response does not have app-defined "Content-Length" header */
          if (! buffer_append_s (buf, &pos, buf_size,
                                 MHD_HTTP_HEADER_CONTENT_LENGTH ": "))
            return false;
          el_size = mhd_uint64_to_str (r->cntn_size,
                                       buf + pos,
                                       buf_size - pos);
          if (0 == el_size)
            return false;
          pos += el_size;

          if (buf_size < pos + 2)
            return false;
          buf[pos++] = '\r';
          buf[pos++] = '\n';
        }
      }
      else
      {
        mhd_assert ((! c->rp.props.send_reply_body) || \
                    (mhd_CONN_MUST_CLOSE == c->conn_reuse));
        (void) 0;
      }
    }
  }

  /* * Header termination * */
  if (buf_size < pos + 2)
    return false;
  buf[pos++] = '\r';
  buf[pos++] = '\n';

  c->write_buffer_append_offset = pos;
  return true;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_stream_build_header_response (struct MHD_Connection *restrict c)
{
  if (! build_header_response_inn (c))
  {
    mhd_STREAM_ABORT (c,
                      mhd_CONN_CLOSE_NO_POOL_MEM_FOR_REPLY,
                      "No memory in the pool for the reply headers.");
    return false;
  }
  c->state = MHD_CONNECTION_HEADERS_SENDING;
  return true;
}


/**
 * Pre-process DCC action provided by application.
 * 'abort' and 'suspend' actions are fully processed,
 * 'continue' and 'finish' actions needs to be processed by the caller.
 * @param c the stream to use
 * @param act the action provided by application
 * @return 'true' if action if 'continue' or 'finish' and need to be
 *         processed,
 *         'false' if action is 'suspend' or 'abort' and is already processed.
 */
static MHD_FN_PAR_NONNULL_ (1) bool
preprocess_dcc_action (struct MHD_Connection *restrict c,
                       const struct MHD_DynamicContentCreatorAction *act)
{
  /**
   * The action created for the current request
   */
  struct MHD_DynamicContentCreatorAction *const a =
    &(c->rp.app_act);

  if (NULL != act)
  {
    if ((a != act) ||
        ! mhd_DCC_ACTION_IS_VALID (c->rp.app_act.act) ||
        ((MHD_SIZE_UNKNOWN != c->rp.response->cntn_size) &&
         (mhd_DCC_ACTION_FINISH == c->rp.app_act.act)))
    {
      mhd_LOG_MSG (c->daemon, MHD_SC_ACTION_INVALID, \
                   "Provided Dynamic Content Creator action is not " \
                   "a correct action generated for the current request.");
      act = NULL;
    }
  }
  if (NULL == act)
    a->act = mhd_DCC_ACTION_ABORT;

  switch (a->act)
  {
  case mhd_DCC_ACTION_CONTINUE:
    return true;
  case mhd_DCC_ACTION_FINISH:
    mhd_assert (MHD_SIZE_UNKNOWN == c->rp.response->cntn_size);
    return true;
  case mhd_DCC_ACTION_SUSPEND:
    mhd_assert (0 && "Not implemented yet");
    // TODO: Implement suspend;
    mhd_STREAM_ABORT (c,
                      mhd_CONN_CLOSE_INT_ERROR,
                      "Suspending connection is not implemented yet");
    return false;
  case mhd_DCC_ACTION_ABORT:
    mhd_STREAM_ABORT (c,
                      mhd_CONN_CLOSE_APP_ABORTED,
                      "Dynamic Content Creator requested abort " \
                      "of the request");
    return false;
  case mhd_DCC_ACTION_NO_ACTION:
  default:
    break;
  }
  mhd_assert (0 && "Impossible value");
  MHD_UNREACHABLE_;
  mhd_STREAM_ABORT (c,
                    mhd_CONN_CLOSE_INT_ERROR,
                    "Impossible code path");
  return false;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_stream_prep_unchunked_body (struct MHD_Connection *restrict c)
{
  struct MHD_Response *const restrict r = c->rp.response;

  mhd_assert (c->rp.props.send_reply_body);
  mhd_assert (c->rp.rsp_cntn_read_pos != r->cntn_size);

  mhd_stream_call_dcc_cleanup_if_needed (c);

  if (0 == r->cntn_size)
  { /* 0-byte response is always ready */
    c->state = MHD_CONNECTION_FULL_REPLY_SENT;
    return true;
  }

  mhd_assert (mhd_REPLY_CNTN_LOC_NOWHERE != c->rp.cntn_loc);
  if (mhd_REPLY_CNTN_LOC_RESP_BUF == c->rp.cntn_loc)
  {
    (void) 0; /* Nothing to do, buffers are ready */
  }
  else if (mhd_REPLY_CNTN_LOC_CONN_BUF == c->rp.cntn_loc)
  {
    if (mhd_RESPONSE_CONTENT_DATA_CALLBACK == r->cntn_dtype)
    {
      const struct MHD_DynamicContentCreatorAction *act;
      const size_t size_to_fill =
        c->write_buffer_size - c->write_buffer_append_offset;
      size_t filled;

      mhd_assert (c->write_buffer_append_offset < c->write_buffer_size);
      mhd_assert (NULL == c->rp.app_act_ctx.connection);

      c->rp.app_act_ctx.connection = c;
      c->rp.app_act.act = mhd_DCC_ACTION_NO_ACTION;

      act =
        r->cntn.dyn.cb (r->cntn.dyn.cls,
                        &(c->rp.app_act_ctx),
                        c->rp.rsp_cntn_read_pos,
                        (void *)
                        (c->write_buffer + c->write_buffer_append_offset),
                        size_to_fill);
      c->rp.app_act_ctx.connection = NULL; /* Block any attempt to create a new action */
      if (! preprocess_dcc_action (c, act))
        return false;
      if (mhd_DCC_ACTION_FINISH == c->rp.app_act.act)
      {
        mhd_assert (MHD_SIZE_UNKNOWN == r->cntn_size);
        mhd_assert (c->rp.props.end_by_closing);

        c->state = MHD_CONNECTION_FULL_REPLY_SENT;

        return true;
      }
      mhd_assert (mhd_DCC_ACTION_CONTINUE == c->rp.app_act.act);
      // TODO: implement iov sending

      filled = c->rp.app_act.data.cntnue.buf_data_size;
      if (size_to_fill < filled)
      {
        mhd_STREAM_ABORT (c,
                          mhd_CONN_CLOSE_APP_ERROR,
                          "Closing connection (application returned more data "
                          "than requested).");
        return false;
      }
      c->rp.rsp_cntn_read_pos += filled;
      c->write_buffer_append_offset += filled;
    }
    else if (mhd_RESPONSE_CONTENT_DATA_FILE == r->cntn_dtype)
    {
      // TODO: implement fallback
      mhd_assert (0 && "Not implemented yet");
      c->rp.cntn_loc = mhd_REPLY_CNTN_LOC_NOWHERE;
      c->rp.rsp_cntn_read_pos = r->cntn_size;
    }
    else
    {
      mhd_assert (0 && "Impossible value");
      MHD_UNREACHABLE_;
      c->rp.cntn_loc = mhd_REPLY_CNTN_LOC_NOWHERE;
      c->rp.rsp_cntn_read_pos = r->cntn_size;
    }

    mhd_assert (0 && "Not implemented yet");
    c->rp.cntn_loc = mhd_REPLY_CNTN_LOC_NOWHERE;
    c->rp.rsp_cntn_read_pos = r->cntn_size;
  }
  else if (mhd_REPLY_CNTN_LOC_IOV == c->rp.cntn_loc)
  {
    size_t copy_size;

    mhd_assert (NULL == c->rp.resp_iov.iov);
    mhd_assert (mhd_RESPONSE_CONTENT_DATA_IOVEC == r->cntn_dtype);

    copy_size = r->cntn.iovec.cnt * sizeof(mhd_iovec);
    c->rp.resp_iov.iov = mhd_stream_alloc_memory (c,
                                                  copy_size);
    if (NULL == c->rp.resp_iov.iov)
    {
      /* not enough memory */
      mhd_STREAM_ABORT (c,
                        mhd_CONN_CLOSE_NO_POOL_MEM_FOR_REPLY,
                        "No memory in the pool for the response data.");
      return false;
    }
    memcpy (c->rp.resp_iov.iov,
            &(r->cntn.iovec.iov),
            copy_size);
    c->rp.resp_iov.cnt = r->cntn.iovec.cnt;
    c->rp.resp_iov.sent = 0;
  }
#if defined(MHD_USE_SENDFILE)
  else if (mhd_REPLY_CNTN_LOC_FILE == c->rp.cntn_loc)
  {
    (void) 0; /* Nothing to do, file should be read directly */
  }
#endif /* MHD_USE_SENDFILE */
  else
  {
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    c->rp.cntn_loc = mhd_REPLY_CNTN_LOC_NOWHERE;
    c->rp.rsp_cntn_read_pos = r->cntn_size;
  }

  c->state = MHD_CONNECTION_UNCHUNKED_BODY_READY;
  return false;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_stream_prep_chunked_body (struct MHD_Connection *restrict c)
{
  size_t filled;
  struct MHD_Response *const restrict r = c->rp.response;
  static const size_t max_chunk = 0xFFFFFF;
  char chunk_hdr[6];            /* 6: max strlen of "FFFFFF" */
  /* "FFFFFF" + "\r\n" */
  static const size_t max_chunk_hdr_len = sizeof(chunk_hdr) + 2;
  /* "FFFFFF" + "\r\n" + "\r\n" (chunk termination) */
  static const size_t max_chunk_overhead = sizeof(chunk_hdr) + 2 + 2;
  size_t chunk_hdr_len;
  uint64_t left_to_send;
  size_t size_to_fill;

  mhd_assert (0 == c->write_buffer_append_offset);
  mhd_assert (0 == c->write_buffer_send_offset);

  mhd_stream_call_dcc_cleanup_if_needed (c);

  /* The buffer must be reasonably large enough */
  if (32 > c->write_buffer_size)
  {
    mhd_STREAM_ABORT (c,
                      mhd_CONN_CLOSE_NO_POOL_MEM_FOR_REPLY,
                      "No memory in the pool for the reply chunked content.");
  }
  mhd_assert (max_chunk_overhead < \
              (c->write_buffer_size));

  if (MHD_SIZE_UNKNOWN == r->cntn_size)
    left_to_send = MHD_SIZE_UNKNOWN;
  else
    left_to_send = r->cntn_size - c->rp.rsp_cntn_read_pos;

  mhd_assert (0 != left_to_send);
  if (0 != left_to_send)
  {
    size_to_fill =
      c->write_buffer_size - max_chunk_overhead;
    /* Limit size for the callback to the max usable size */
    if (max_chunk < size_to_fill)
      size_to_fill = max_chunk;
    if (left_to_send < size_to_fill)
      size_to_fill = (size_t) left_to_send;
  }
  else
    size_to_fill = 0;

  if ((0 == left_to_send) &&
      (mhd_RESPONSE_CONTENT_DATA_CALLBACK != r->cntn_dtype))
  {
    c->state = MHD_CONNECTION_CHUNKED_BODY_SENT;
    return true;
  }
  else if (mhd_RESPONSE_CONTENT_DATA_BUFFER == r->cntn_dtype)
  {
    mhd_assert (size_to_fill <= \
                r->cntn_size - (size_t) c->rp.rsp_cntn_read_pos);
    memcpy (c->write_buffer + max_chunk_hdr_len,
            r->cntn.buf + (size_t) c->rp.rsp_cntn_read_pos,
            size_to_fill);
    filled = size_to_fill;
  }
  else if (mhd_RESPONSE_CONTENT_DATA_CALLBACK == r->cntn_dtype)
  {
    const struct MHD_DynamicContentCreatorAction *act;

    mhd_assert (NULL == c->rp.app_act_ctx.connection);

    c->rp.app_act_ctx.connection = c;
    c->rp.app_act.act = mhd_DCC_ACTION_NO_ACTION;

    act =
      r->cntn.dyn.cb (r->cntn.dyn.cls,
                      &(c->rp.app_act_ctx),
                      c->rp.rsp_cntn_read_pos,
                      (void *)
                      (c->write_buffer + max_chunk_hdr_len),
                      size_to_fill);
    c->rp.app_act_ctx.connection = NULL; /* Block any attempt to create a new action */
    if (! preprocess_dcc_action (c, act))
      return false;
    if (mhd_DCC_ACTION_FINISH == c->rp.app_act.act)
    {
      mhd_assert (MHD_SIZE_UNKNOWN == r->cntn_size);
      c->state = MHD_CONNECTION_CHUNKED_BODY_SENT;

      return true;
    }
    mhd_assert (mhd_DCC_ACTION_CONTINUE == c->rp.app_act.act);
    // TODO: implement iov sending

    filled = c->rp.app_act.data.cntnue.buf_data_size;
    if (size_to_fill < filled)
    {
      mhd_STREAM_ABORT (c,
                        mhd_CONN_CLOSE_APP_ERROR,
                        "Closing connection (application returned more data "
                        "than requested).");
      return false;
    }
    c->rp.rsp_cntn_read_pos += filled;
    c->write_buffer_append_offset += filled;
  }
  else
  {
    mhd_assert (0 && "Not implemented yet");
    filled = 0;
  }

  chunk_hdr_len = mhd_uint32_to_strx ((uint_fast32_t) filled,
                                      chunk_hdr,
                                      sizeof(chunk_hdr));
  mhd_assert (chunk_hdr_len != 0);
  mhd_assert (chunk_hdr_len < sizeof(chunk_hdr));
  c->write_buffer_send_offset = max_chunk_hdr_len - (chunk_hdr_len + 2);
  memcpy (c->write_buffer + c->write_buffer_send_offset,
          chunk_hdr,
          chunk_hdr_len);
  c->write_buffer[max_chunk_hdr_len - 2] = '\r';
  c->write_buffer[max_chunk_hdr_len - 1] = '\n';
  c->write_buffer[max_chunk_hdr_len + filled] = '\r';
  c->write_buffer[max_chunk_hdr_len + filled + 1] = '\n';
  c->write_buffer_append_offset = max_chunk_hdr_len + filled + 2;
  if (0 != filled)
    c->rp.rsp_cntn_read_pos += filled;
  else
    c->rp.rsp_cntn_read_pos = r->cntn_size;

  c->state = MHD_CONNECTION_CHUNKED_BODY_READY;

  return false;
}


/**
 * Allocate the connection's write buffer (if necessary) and fill it
 * with response footers.
 * Inner version.
 *
 * @param c the connection
 * @return 'true' if footers formed successfully,
 *         'false' if not enough buffer
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
prep_chunked_footer_inn (struct MHD_Connection *restrict c)
{
  char *buf;           /**< the buffer to write footers to */
  size_t buf_size;     /**< the size of the @a buf */
  size_t used_size;    /**< the used size of the @a buf */
  // struct MHD_HTTP_Res_Header *pos;

  mhd_assert (c->rp.props.chunked);
  mhd_assert (MHD_CONNECTION_CHUNKED_BODY_SENT == c->state);
  mhd_assert (NULL != c->rp.response);

  buf_size = mhd_stream_maximize_write_buffer (c);
  /* '5' is the minimal size of chunked footer ("0\r\n\r\n") */
  if (buf_size < 5)
    return false;
  mhd_assert (NULL != c->write_buffer);
  buf = c->write_buffer + c->write_buffer_append_offset;
  mhd_assert (NULL != buf);
  used_size = 0;
  buf[used_size++] = '0';
  buf[used_size++] = '\r';
  buf[used_size++] = '\n';

#if 0 // TODO: use dynamic/connection's footers
  for (pos = c->rp.response->first_header; NULL != pos; pos = pos->next)
  {
    if (MHD_FOOTER_KIND == pos->kind)
    {
      size_t new_used_size; /* resulting size with this header */
      /* '4' is colon, space, linefeeds */
      new_used_size = used_size + pos->header_size + pos->value_size + 4;
      if (new_used_size > buf_size)
        return MHD_NO;
      memcpy (buf + used_size, pos->header, pos->header_size);
      used_size += pos->header_size;
      buf[used_size++] = ':';
      buf[used_size++] = ' ';
      memcpy (buf + used_size, pos->value, pos->value_size);
      used_size += pos->value_size;
      buf[used_size++] = '\r';
      buf[used_size++] = '\n';
      mhd_assert (used_size == new_used_size);
    }
  }
#endif

  if (used_size + 2 > buf_size)
    return false;
  buf[used_size++] = '\r';
  buf[used_size++] = '\n';

  c->write_buffer_append_offset += used_size;
  mhd_assert (c->write_buffer_append_offset <= c->write_buffer_size);

  return true;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_stream_prep_chunked_footer (struct MHD_Connection *restrict c)
{
  if (! prep_chunked_footer_inn (c))
  {
    mhd_STREAM_ABORT (c,
                      mhd_CONN_CLOSE_NO_POOL_MEM_FOR_REPLY,
                      "No memory in the pool for the reply chunked footer.");
    return;
  }
  c->state = MHD_CONNECTION_FOOTERS_SENDING;
}
