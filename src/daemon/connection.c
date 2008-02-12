/*
     This file is part of libmicrohttpd
     (C) 2007 Daniel Pittman and Christian Grothoff

     This library is free software; you can redistribute it and/or
     modify it under the terms of the GNU Lesser General Public
     License as published by the Free Software Foundation; either
     version 2.1 of the License, or (at your option) any later version.

     This library is distributed in the hope that it will be useful,
     but WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Lesser General Public License for more details.

     You should have received a copy of the GNU Lesser General Public
     License along with this library; if not, write to the Free Software
     Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

*/

/**
 * @file connection.c
 * @brief  Methods for managing connections
 * @author Daniel Pittman
 * @author Christian Grothoff
 */

#include "internal.h"
#include "connection.h"
#include "memorypool.h"
#include "response.h"
#include "reason_phrase.h"

#ifndef LINUX
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#endif


/**
 * Message to transmit when http 1.1 request is received
 */
#define HTTP_100_CONTINUE "HTTP/1.1 100 Continue\r\n\r\n"

/**
 * Response text used when the request (http header) is too big to
 * be processed.
 *
 * Intentionally empty here to keep our memory footprint
 * minimal.
 */
#define REQUEST_TOO_BIG ""

/**
 * Response text used when the request (http header) does not
 * contain a "Host:" header and still claims to be HTTP 1.1.
 *
 * Intentionally empty here to keep our memory footprint
 * minimal.
 */
#define REQUEST_LACKS_HOST ""

#define EXTRA_CHECKS MHD_YES

#if EXTRA_CHECKS
#define EXTRA_CHECK(a) if (!(a)) abort();
#else
#define EXTRA_CHECK(a)
#endif

/**
 * Add extra debug messages with reasons for closing connections
 * (non-error reasons).
 */
#define DEBUG_CLOSE MHD_NO

/**
 * Should all data send be printed to stderr?
 */
#define DEBUG_SEND_DATA MHD_NO

/**
 * Should all state transitions be printed to stderr?
 */
#define DEBUG_STATES MHD_NO

/**
 * Get all of the headers from the request.
 *
 * @param iterator callback to call on each header;
 *        maybe NULL (then just count headers)
 * @param iterator_cls extra argument to iterator
 * @return number of entries iterated over
 */
int
MHD_get_connection_values (struct MHD_Connection *connection,
                           enum MHD_ValueKind kind,
                           MHD_KeyValueIterator iterator, void *iterator_cls)
{
  int ret;
  struct MHD_HTTP_Header *pos;

  if (connection == NULL)
    return -1;
  ret = 0;
  pos = connection->headers_received;
  while (pos != NULL)
    {
      if (0 != (pos->kind & kind))
        {
          ret++;
          if ((iterator != NULL) &&
              (MHD_YES != iterator (iterator_cls,
                                    kind, pos->header, pos->value)))
            return ret;
        }
      pos = pos->next;
    }
  return ret;
}

/**
 * Get a particular header value.  If multiple
 * values match the kind, return any one of them.
 *
 * @param key the header to look for
 * @return NULL if no such item was found
 */
const char *
MHD_lookup_connection_value (struct MHD_Connection *connection,
                             enum MHD_ValueKind kind, const char *key)
{
  struct MHD_HTTP_Header *pos;

  if (connection == NULL)
    return NULL;
  pos = connection->headers_received;
  while (pos != NULL)
    {
      if ((0 != (pos->kind & kind)) && (0 == strcasecmp (key, pos->header)))
        return pos->value;
      pos = pos->next;
    }
  return NULL;
}

/**
 * Queue a response to be transmitted to the client (as soon as
 * possible).
 *
 * @param connection the connection identifying the client
 * @param status_code HTTP status code (i.e. 200 for OK)
 * @param response response to transmit
 * @return MHD_NO on error (i.e. reply already sent),
 *         MHD_YES on success or if message has been queued
 */
int
MHD_queue_response (struct MHD_Connection *connection,
                    unsigned int status_code, struct MHD_Response *response)
{
  if ((connection == NULL) ||
      (response == NULL) ||
      (connection->response != NULL) ||
      ((connection->state != MHD_CONNECTION_HEADERS_PROCESSED) &&
       (connection->state != MHD_CONNECTION_FOOTERS_RECEIVED)))
    return MHD_NO;
  MHD_increment_response_rc (response);
  connection->response = response;
  connection->responseCode = status_code;
  if ((connection->method != NULL) &&
      (0 == strcasecmp (connection->method, MHD_HTTP_METHOD_HEAD)))
    {
      /* if this is a "HEAD" request, pretend that we
         have already sent the full message body */
      connection->response_write_position = response->total_size;
    }
  if ((response->total_size == -1) &&
      (0 == strcasecmp (connection->version, MHD_HTTP_VERSION_1_1)))
    connection->have_chunked_response = MHD_YES;
  else
    connection->have_chunked_response = MHD_NO;
  if (connection->state == MHD_CONNECTION_HEADERS_PROCESSED)
    {
      /* response was queued "early",
         refuse to read body / footers or further
         requests! */
      SHUTDOWN (connection->socket_fd, SHUT_RD);
      connection->read_closed = MHD_YES;
      connection->state = MHD_CONNECTION_FOOTERS_RECEIVED;
    }
  return MHD_YES;
}

/**
 * Do we (still) need to send a 100 continue
 * message for this connection?
 */
static int
need_100_continue (struct MHD_Connection *connection)
{
  const char *expect;

  return ((connection->response == NULL) &&
          (connection->version != NULL) &&
          (0 == strcasecmp (connection->version,
                            MHD_HTTP_VERSION_1_1)) &&
          (NULL != (expect = MHD_lookup_connection_value (connection,
                                                          MHD_HEADER_KIND,
                                                          MHD_HTTP_HEADER_EXPECT)))
          && (0 == strcasecmp (expect, "100-continue"))
          && (connection->continue_message_write_offset <
              strlen (HTTP_100_CONTINUE)));
}

/**
 * A serious error occured, close the
 * connection (and notify the application).
 */
static void
connection_close_error (struct MHD_Connection *connection)
{
  SHUTDOWN (connection->socket_fd, SHUT_RDWR);
  CLOSE (connection->socket_fd);
  connection->socket_fd = -1;
  connection->state = MHD_CONNECTION_CLOSED;
  if (connection->daemon->notify_completed != NULL)
    connection->daemon->notify_completed (connection->daemon->
                                          notify_completed_cls, connection,
                                          &connection->client_context,
                                          MHD_REQUEST_TERMINATED_WITH_ERROR);
}

/**
 * Prepare the response buffer of this connection for
 * sending.  Assumes that the response mutex is
 * already held.  If the transmission is complete,
 * this function may close the socket (and return
 * MHD_NO).
 *
 * @return MHD_NO if readying the response failed
 */
static int
try_ready_normal_body (struct MHD_Connection *connection)
{
  int ret;
  struct MHD_Response *response;

  response = connection->response;
  if (response->crc == NULL)
    return MHD_YES;
  ret = response->crc (response->crc_cls,
                       connection->response_write_position,
                       response->data,
                       MIN (response->data_buffer_size,
                            response->total_size -
                            connection->response_write_position));
  if (ret == -1)
    {
      /* either error or http 1.0 transfer, close
         socket! */
#if DEBUG_CLOSE
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon, "Closing connection (end of response)\n");
#endif
#endif
      response->total_size = connection->response_write_position;
      connection_close_error (connection);
      return MHD_NO;
    }
  response->data_start = connection->response_write_position;
  response->data_size = ret;
  if (ret == 0)
    return MHD_NO;
  return MHD_YES;
}

/**
 * Prepare the response buffer of this connection for
 * sending.  Assumes that the response mutex is
 * already held.  If the transmission is complete,
 * this function may close the socket (and return
 * MHD_NO).
 *
 * @return MHD_NO if readying the response failed
 */
static int
try_ready_chunked_body (struct MHD_Connection *connection)
{
  int ret;
  char *buf;
  struct MHD_Response *response;
  unsigned int size;
  char cbuf[9];

  response = connection->response;
  if (connection->write_buffer_size == 0)
    {
      size = connection->daemon->pool_size;
      do
        {
          size /= 2;
          if (size < 128)
            {
              /* not enough memory */
#if DEBUG_CLOSE
#if HAVE_MESSAGES
              MHD_DLOG (connection->daemon,
                        "Closing connection (out of memory)\n");
#endif
#endif
              connection_close_error (connection);
              return MHD_NO;
            }
          buf = MHD_pool_allocate (connection->pool, size, MHD_NO);
        }
      while (buf == NULL);
      connection->write_buffer_size = size;
      connection->write_buffer = buf;
    }

  ret = response->crc (response->crc_cls,
                       connection->response_write_position,
                       &connection->write_buffer[8],
                       connection->write_buffer_size - 8 - 2);
  if (ret == -1)
    {
      /* end of message, signal other side! */
      strcpy (connection->write_buffer, "0\r\n");
      connection->write_buffer_append_offset = 3;
      connection->write_buffer_send_offset = 0;
      response->total_size = connection->response_write_position;
      return MHD_YES;
    }
  if (ret == 0)
    {
      connection->state = MHD_CONNECTION_CHUNKED_BODY_UNREADY;
      return MHD_NO;
    }
  if (ret > 0xFFFFFF)
    ret = 0xFFFFFF;
  snprintf (cbuf, 8, "%X\r\n", ret);
  memcpy (&connection->write_buffer[8 - strlen (cbuf)], cbuf, strlen (cbuf));
  memcpy (&connection->write_buffer[8 + ret], "\r\n", 2);
  connection->response_write_position += ret;
  connection->write_buffer_send_offset = 8 - strlen (cbuf);
  connection->write_buffer_append_offset = 8 + ret + 2;
  return MHD_YES;
}

/**
 * Check if we need to set some additional headers
 * for http-compiliance.
 */
static void
add_extra_headers (struct MHD_Connection *connection)
{
  const char *have;
  char buf[128];

  connection->have_chunked_upload = MHD_NO;
  if (connection->response->total_size == -1)
    {
      have = MHD_get_response_header (connection->response,
                                      MHD_HTTP_HEADER_CONNECTION);
      if ((have == NULL) || (0 != strcasecmp (have, "close")))
        {
          if ((connection->version != NULL) &&
              (0 == strcasecmp (connection->version, MHD_HTTP_VERSION_1_1)))
            {
              connection->have_chunked_upload = MHD_YES;
              have = MHD_get_response_header (connection->response,
                                              MHD_HTTP_HEADER_TRANSFER_ENCODING);
              if (have == NULL)
                MHD_add_response_header (connection->response,
                                         MHD_HTTP_HEADER_TRANSFER_ENCODING,
                                         "chunked");
            }
          else
            {
              MHD_add_response_header (connection->response,
                                       MHD_HTTP_HEADER_CONNECTION, "close");
            }
        }
    }
  else if (NULL == MHD_get_response_header (connection->response,
                                            MHD_HTTP_HEADER_CONTENT_LENGTH))
    {
      _REAL_SNPRINTF (buf,
                      128,
                      "%llu",
                      (unsigned long long) connection->response->total_size);
      MHD_add_response_header (connection->response,
                               MHD_HTTP_HEADER_CONTENT_LENGTH, buf);
    }
}

/**
 * Produce HTTP "Date:" header.
 * @param date where to write the header
 * @param max maximum number of characters to write
 */
static void
get_date_string (char *date, unsigned int max)
{
  static const char *days[] =
    { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
  static const char *mons[] =
    { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct",
    "Nov", "Dec"
  };
  struct tm now;
  time_t t;

  time (&t);
  gmtime_r (&t, &now);
  snprintf (date,
            max - 1,
            "Date: %3s, %02u %3s %04u %02u:%02u:%02u GMT\r\n",
            days[now.tm_wday % 7],
            now.tm_mday,
            mons[now.tm_mon % 12],
            now.tm_year, now.tm_hour, now.tm_min, now.tm_sec);
}

/**
 * try growing the read buffer
 * @return MHD_YES on success, MHD_NO on failure
 */
static int
try_grow_read_buffer (struct MHD_Connection *connection)
{
  void *buf;

  buf = MHD_pool_reallocate (connection->pool,
                             connection->read_buffer,
                             connection->read_buffer_size,
                             connection->read_buffer_size * 2 +
                             MHD_BUF_INC_SIZE + 1);
  if (buf == NULL)
    return MHD_NO;
  /* we can actually grow the buffer, do it! */
  connection->read_buffer = buf;
  connection->read_buffer_size =
    connection->read_buffer_size * 2 + MHD_BUF_INC_SIZE;
  return MHD_YES;
}

/**
 * Allocate the connection's write buffer and
 * fill it with all of the headers (or footers,
 * if we have already sent the body) from the
 * HTTPd's response.
 */
static int
build_header_response (struct MHD_Connection *connection)
{
  size_t size;
  size_t off;
  struct MHD_HTTP_Header *pos;
  char code[128];
  char date[128];
  char *data;
  enum MHD_ValueKind kind;
  const char *reason_phrase;

  if (connection->state == MHD_CONNECTION_FOOTERS_RECEIVED)
    {
      add_extra_headers (connection);
      reason_phrase = MHD_get_reason_phrase_for (connection->responseCode);
      _REAL_SNPRINTF (code, 128, "%s %u %s\r\n", MHD_HTTP_VERSION_1_1,
                      connection->responseCode, reason_phrase);
      off = strlen (code);
      /* estimate size */
      size = off + 2;           /* extra \r\n at the end */
      kind = MHD_HEADER_KIND;
      if (NULL == MHD_get_response_header (connection->response,
                                           MHD_HTTP_HEADER_DATE))
        get_date_string (date, sizeof (date));
      else
        date[0] = '\0';
      size += strlen (date);
    }
  else
    {
      size = 2;
      kind = MHD_FOOTER_KIND;
      off = 0;
    }
  pos = connection->response->first_header;
  while (pos != NULL)
    {
      if (pos->kind == kind)
        size += strlen (pos->header) + strlen (pos->value) + 4; /* colon, space, linefeeds */
      pos = pos->next;
    }
  /* produce data */
  data = MHD_pool_allocate (connection->pool, size + 1, MHD_YES);
  if (data == NULL)
    {
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon, "Not enough memory for write!\n");
#endif
      return MHD_NO;
    }
  if (connection->state == MHD_CONNECTION_FOOTERS_RECEIVED)
    {
      memcpy (data, code, off);
    }
  pos = connection->response->first_header;
  while (pos != NULL)
    {
      if (pos->kind == kind)
        {
          SPRINTF (&data[off], "%s: %s\r\n", pos->header, pos->value);
          off += strlen (pos->header) + strlen (pos->value) + 4;
        }
      pos = pos->next;
    }
  if (connection->state == MHD_CONNECTION_FOOTERS_RECEIVED)
    {
      strcpy (&data[off], date);
      off += strlen (date);
    }
  sprintf (&data[off], "\r\n");
  off += 2;
  if (off != size)
    abort ();
  connection->write_buffer = data;
  connection->write_buffer_append_offset = size;
  connection->write_buffer_send_offset = 0;
  connection->write_buffer_size = size + 1;
  return MHD_YES;
}

/**
 * We ran out of memory processing the
 * header.  Handle it properly by stopping to read data
 * and sending a HTTP 413 or HTTP 414 response.
 *
 * @param status_code the response code to send (413 or 414)
 */
static void
excessive_data_handler (struct MHD_Connection *connection,
                        unsigned int status_code)
{
  struct MHD_Response *response;

  /* die, header far too long to be reasonable */
  connection->state = MHD_CONNECTION_FOOTERS_RECEIVED;
  connection->read_closed = MHD_YES;
#if HAVE_MESSAGES
  MHD_DLOG (connection->daemon,
            "Received excessively long header, closing connection.\n");
#endif
  response = MHD_create_response_from_data (strlen (REQUEST_TOO_BIG),
                                            REQUEST_TOO_BIG, MHD_NO, MHD_NO);
  MHD_queue_response (connection, status_code, response);
  EXTRA_CHECK (connection->response != NULL);
  MHD_destroy_response (response);
  if (MHD_NO == build_header_response (connection))
    {
      /* oops - close! */
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon,
                "Closing connection (failed to create response header)\n");
#endif
      connection->state = MHD_CONNECTION_CLOSED;
    }
  else
    {
      connection->state = MHD_CONNECTION_HEADERS_SENDING;
    }
}

/**
 * Add "fd" to the "fd_set".  If "fd" is
 * greater than "*max", set "*max" to fd.
 */
static void
do_fd_set (int fd, fd_set * set, int *max_fd)
{
  FD_SET (fd, set);
  if (fd > *max_fd)
    *max_fd = fd;
}

/**
 * Obtain the select sets for this connection
 *
 * @return MHD_YES on success
 */
int
MHD_connection_get_fdset (struct MHD_Connection *connection,
                          fd_set * read_fd_set,
                          fd_set * write_fd_set,
                          fd_set * except_fd_set, int *max_fd)
{
  int fd;

  if (connection->pool == NULL)
    connection->pool = MHD_pool_create (connection->daemon->pool_size);
  if (connection->pool == NULL)
    {
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon, "Failed to create memory pool!\n");
#endif
      connection_close_error (connection);
      return MHD_NO;
    }
  fd = connection->socket_fd;
  if (fd == -1)
    return MHD_YES;
  while (1)
    {
#if DEBUG_STATES
      fprintf (stderr, "`%s' in state %u\n", __FUNCTION__, connection->state);
#endif
      switch (connection->state)
        {
        case MHD_CONNECTION_INIT:
        case MHD_CONNECTION_URL_RECEIVED:
        case MHD_CONNECTION_HEADER_PART_RECEIVED:
          /* while reading headers, we always grow the
             read buffer if needed, no size-check required */
          if ((connection->read_closed) &&
              (connection->read_buffer_offset == 0))
            {
              connection->state = MHD_CONNECTION_CLOSED;
              continue;
            }
          if ((connection->read_buffer_offset == connection->read_buffer_size)
              && (MHD_NO == try_grow_read_buffer (connection)))
            {
              excessive_data_handler (connection,
                                      (connection->url != NULL)
                                      ? MHD_HTTP_REQUEST_ENTITY_TOO_LARGE
                                      : MHD_HTTP_REQUEST_URI_TOO_LONG);
              continue;
            }
          if (MHD_NO == connection->read_closed)
            do_fd_set (fd, read_fd_set, max_fd);
          break;
        case MHD_CONNECTION_HEADERS_RECEIVED:
          /* we should never get here */
          EXTRA_CHECK (0);
          break;
        case MHD_CONNECTION_HEADERS_PROCESSED:
          EXTRA_CHECK (0);
          break;
        case MHD_CONNECTION_CONTINUE_SENDING:
          do_fd_set (fd, write_fd_set, max_fd);
          break;
        case MHD_CONNECTION_CONTINUE_SENT:
          if (connection->read_buffer_offset == connection->read_buffer_size)
            try_grow_read_buffer (connection);
          if (connection->read_buffer_offset < connection->read_buffer_size)
            do_fd_set (fd, read_fd_set, max_fd);
          break;
        case MHD_CONNECTION_BODY_RECEIVED:
        case MHD_CONNECTION_FOOTER_PART_RECEIVED:
          /* while reading footers, we always grow the
             read buffer if needed, no size-check required */
          if (MHD_YES == connection->read_closed)
            {
              connection->state = MHD_CONNECTION_CLOSED;
              continue;
            }
          do_fd_set (fd, read_fd_set, max_fd);
          /* transition to FOOTERS_RECEIVED
             happens in read handler */
          break;
        case MHD_CONNECTION_FOOTERS_RECEIVED:
          /* no socket action, wait for client
             to provide response */
          break;
        case MHD_CONNECTION_HEADERS_SENDING:
          /* headers in buffer, keep writing */
          do_fd_set (fd, write_fd_set, max_fd);
          break;
        case MHD_CONNECTION_HEADERS_SENT:
          EXTRA_CHECK (0);
          break;
        case MHD_CONNECTION_NORMAL_BODY_READY:
          do_fd_set (fd, write_fd_set, max_fd);
          break;
        case MHD_CONNECTION_NORMAL_BODY_UNREADY:
          /* not ready, no socket action */
          break;
        case MHD_CONNECTION_CHUNKED_BODY_READY:
          do_fd_set (fd, write_fd_set, max_fd);
          break;
        case MHD_CONNECTION_CHUNKED_BODY_UNREADY:
          /* not ready, no socket action */
          break;
        case MHD_CONNECTION_BODY_SENT:
          EXTRA_CHECK (0);
          break;
        case MHD_CONNECTION_FOOTERS_SENDING:
          do_fd_set (fd, write_fd_set, max_fd);
          break;
        case MHD_CONNECTION_FOOTERS_SENT:
          EXTRA_CHECK (0);
          break;
        case MHD_CONNECTION_CLOSED:
          if (connection->socket_fd != -1)
            connection_close_error (connection);
          return MHD_YES;       /* do nothing, not even reading */
        default:
          EXTRA_CHECK (0);
        }
      break;
    }
  return MHD_YES;
}

/**
 * Parse a single line of the HTTP header.  Advance
 * read_buffer (!) appropriately.  If the current line does not
 * fit, consider growing the buffer.  If the line is
 * far too long, close the connection.  If no line is
 * found (incomplete, buffer too small, line too long),
 * return NULL.  Otherwise return a pointer to the line.
 */
static char *
get_next_header_line (struct MHD_Connection *connection)
{
  char *rbuf;
  size_t pos;

  if (connection->read_buffer_offset == 0)
    return NULL;
  pos = 0;
  rbuf = connection->read_buffer;
  while ((pos < connection->read_buffer_offset - 1) &&
         (rbuf[pos] != '\r') && (rbuf[pos] != '\n'))
    pos++;
  if (pos == connection->read_buffer_offset - 1)
    {
      /* not found, consider growing... */
      if (connection->read_buffer_offset == connection->read_buffer_size)
        {
          rbuf = MHD_pool_reallocate (connection->pool,
                                      connection->read_buffer,
                                      connection->read_buffer_size,
                                      connection->read_buffer_size * 2 +
                                      MHD_BUF_INC_SIZE);
          if (rbuf == NULL)
            {
              excessive_data_handler (connection,
                                      (connection->url != NULL)
                                      ? MHD_HTTP_REQUEST_ENTITY_TOO_LARGE
                                      : MHD_HTTP_REQUEST_URI_TOO_LONG);
            }
          else
            {
              connection->read_buffer_size =
                connection->read_buffer_size * 2 + MHD_BUF_INC_SIZE;
              connection->read_buffer = rbuf;
            }
        }
      return NULL;
    }
  /* found, check if we have proper CRLF */
  if ((rbuf[pos] == '\r') && (rbuf[pos + 1] == '\n'))
    rbuf[pos++] = '\0';         /* skip both r and n */
  rbuf[pos++] = '\0';
  connection->read_buffer += pos;
  connection->read_buffer_size -= pos;
  connection->read_buffer_offset -= pos;
  return rbuf;
}

/**
 * @return MHD_NO on failure (out of memory), MHD_YES for success
 */
static int
connection_add_header (struct MHD_Connection *connection,
                       char *key, char *value, enum MHD_ValueKind kind)
{
  struct MHD_HTTP_Header *hdr;

  hdr = MHD_pool_allocate (connection->pool,
                           sizeof (struct MHD_HTTP_Header), MHD_YES);
  if (hdr == NULL)
    {
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon,
                "Not enough memory to allocate header record!\n");
#endif
      excessive_data_handler (connection, MHD_HTTP_REQUEST_ENTITY_TOO_LARGE);
      return MHD_NO;
    }
  hdr->next = connection->headers_received;
  hdr->header = key;
  hdr->value = value;
  hdr->kind = kind;
  connection->headers_received = hdr;
  return MHD_YES;
}

/**
 * @return MHD_NO on failure (out of memory), MHD_YES for success
 */
static int
parse_arguments (enum MHD_ValueKind kind,
                 struct MHD_Connection *connection, char *args)
{
  char *equals;
  char *amper;

  while (args != NULL)
    {
      equals = strstr (args, "=");
      if (equals == NULL)
        return MHD_NO;          /* invalid, ignore */
      equals[0] = '\0';
      equals++;
      amper = strstr (equals, "&");
      if (amper != NULL)
        {
          amper[0] = '\0';
          amper++;
        }
      MHD_http_unescape (args);
      MHD_http_unescape (equals);
      if (MHD_NO == connection_add_header (connection, args, equals, kind))
        return MHD_NO;
      args = amper;
    }
  return MHD_YES;
}

/**
 * Parse the cookie header (see RFC 2109).
 *
 * @return MHD_YES for success, MHD_NO for failure (malformed, out of memory)
 */
static int
parse_cookie_header (struct MHD_Connection *connection)
{
  const char *hdr;
  char *cpy;
  char *pos;
  char *semicolon;
  char *equals;
  int quotes;

  hdr = MHD_lookup_connection_value (connection, MHD_HEADER_KIND, "Cookie");
  if (hdr == NULL)
    return MHD_YES;
  cpy = MHD_pool_allocate (connection->pool, strlen (hdr) + 1, MHD_YES);
  if (cpy == NULL)
    {
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon, "Not enough memory to parse cookies!\n");
#endif
      excessive_data_handler (connection, MHD_HTTP_REQUEST_ENTITY_TOO_LARGE);
      return MHD_NO;
    }
  memcpy (cpy, hdr, strlen (hdr) + 1);
  pos = cpy;
  while (pos != NULL)
    {
      equals = strstr (pos, "=");
      if (equals == NULL)
        break;
      equals[0] = '\0';
      equals++;
      quotes = 0;
      semicolon = equals;
      while ((semicolon[0] != '\0') &&
             ((quotes != 0) ||
              ((semicolon[0] != ';') && (semicolon[0] != ','))))
        {
          if (semicolon[0] == '"')
            quotes = (quotes + 1) & 1;
          semicolon++;
        }
      if (semicolon[0] == '\0')
        semicolon = NULL;
      if (semicolon != NULL)
        {
          semicolon[0] = '\0';
          semicolon++;
        }
      /* remove quotes */
      if ((equals[0] == '"') && (equals[strlen (equals) - 1] == '"'))
        {
          equals[strlen (equals) - 1] = '\0';
          equals++;
        }
      if (MHD_NO == connection_add_header (connection,
                                           pos, equals, MHD_COOKIE_KIND))
        return MHD_NO;
      pos = semicolon;
    }
  return MHD_YES;
}

/**
 * Parse the first line of the HTTP HEADER.
 *
 * @param connection the connection (updated)
 * @param line the first line
 * @return MHD_YES if the line is ok, MHD_NO if it is malformed
 */
static int
parse_initial_message_line (struct MHD_Connection *connection, char *line)
{
  char *uri;
  char *httpVersion;
  char *args;

  uri = strstr (line, " ");
  if (uri == NULL)
    return MHD_NO;              /* serious error */
  uri[0] = '\0';
  connection->method = line;
  uri++;
  while (uri[0] == ' ')
    uri++;
  httpVersion = strstr (uri, " ");
  if (httpVersion != NULL)
    {
      httpVersion[0] = '\0';
      httpVersion++;
    }
  args = strstr (uri, "?");
  if (args != NULL)
    {
      args[0] = '\0';
      args++;
      parse_arguments (MHD_GET_ARGUMENT_KIND, connection, args);
    }
  connection->url = uri;
  if (httpVersion == NULL)
    connection->version = "";
  else
    connection->version = httpVersion;
  return MHD_YES;
}

/**
 * Call the handler of the application for this
 * connection.  Handles chunking of the upload
 * as well as normal uploads.
 */
static void
call_connection_handler (struct MHD_Connection *connection)
{
  unsigned int processed;
  unsigned int available;
  unsigned int used;
  int instant_retry;
  unsigned int i;
  int malformed;

  if (connection->response != NULL)
    return;                     /* already queued a response */
  do
    {
      instant_retry = MHD_NO;
      available = connection->read_buffer_offset;
      if ((connection->have_chunked_upload == MHD_YES) &&
          (connection->remaining_upload_size == -1))
        {
          if ((connection->current_chunk_offset ==
               connection->current_chunk_size)
              && (connection->current_chunk_offset != 0) && (available >= 2))
            {
              /* skip new line at the *end* of a chunk */
              i = 0;
              if ((connection->read_buffer[i] == '\r') ||
                  (connection->read_buffer[i] == '\n'))
                i++;            /* skip 1st part of line feed */
              if ((connection->read_buffer[i] == '\r') ||
                  (connection->read_buffer[i] == '\n'))
                i++;            /* skip 2nd part of line feed */
              if (i == 0)
                {
                  /* malformed encoding */
#if HAVE_MESSAGES
                  MHD_DLOG (connection->daemon,
                            "Received malformed HTTP request (bad chunked encoding), closing connection.\n");
#endif
                  connection_close_error (connection);
                  return;
                }
              connection->read_buffer_offset -= i;
              available -= i;
              memmove (connection->read_buffer,
                       &connection->read_buffer[i], available);
              connection->current_chunk_offset = 0;
              connection->current_chunk_size = 0;
            }
          if (connection->current_chunk_offset <
              connection->current_chunk_size)
            {
              /* we are in the middle of a chunk, give
                 as much as possible to the client (without
                 crossing chunk boundaries) */
              processed =
                connection->current_chunk_size -
                connection->current_chunk_offset;
              if (processed > available)
                processed = available;
              available -= processed;
              if (available > 0)
                instant_retry = MHD_YES;
            }
          else
            {
              /* we need to read chunk boundaries */
              i = 0;
              while (i < available)
                {
                  if ((connection->read_buffer[i] == '\r') ||
                      (connection->read_buffer[i] == '\n'))
                    break;
                  i++;
                  if (i >= 6)
                    break;
                }
              if (i >= available)
                return;         /* need more data... */
              malformed = (i >= 6);
              if (!malformed)
                {
                  connection->read_buffer[i] = '\0';
                  malformed = (1 != sscanf (connection->read_buffer,
                                            "%X",
                                            &connection->current_chunk_size))
                    && (1 !=
                        sscanf (connection->read_buffer, "%x",
                                &connection->current_chunk_size));
                }
              if (malformed)
                {
                  /* malformed encoding */
#if HAVE_MESSAGES
                  MHD_DLOG (connection->daemon,
                            "Received malformed HTTP request (bad chunked encoding), closing connection.\n");
#endif
                  connection_close_error (connection);
                  return;
                }
              i++;
              if ((connection->read_buffer[i] == '\r') ||
                  (connection->read_buffer[i] == '\n'))
                i++;            /* skip 2nd part of line feed */
              memmove (connection->read_buffer,
                       &connection->read_buffer[i], available - i);
              connection->read_buffer_offset -= i;
              connection->current_chunk_offset = 0;
              instant_retry = MHD_YES;
              if (connection->current_chunk_size == 0)
                {
                  connection->remaining_upload_size = 0;
                  return;
                }
              continue;
            }
        }
      else
        {
          /* no chunked encoding, give all to the client */
          processed = available;
          available = 0;
        }
      used = processed;
      if (MHD_NO ==
          connection->daemon->default_handler (connection->daemon->
                                               default_handler_cls,
                                               connection, connection->url,
                                               connection->method,
                                               connection->version,
                                               connection->read_buffer,
                                               &processed,
                                               &connection->client_context))
        {
          /* serious internal error, close connection */
#if HAVE_MESSAGES
          MHD_DLOG (connection->daemon,
                    "Internal application error, closing connection.\n");
#endif
          connection_close_error (connection);
          return;
        }
      if (processed > used)
        abort ();               /* fatal client API violation! */
      if (processed != 0)
        instant_retry = MHD_NO; /* client did not process everything */
      used -= processed;
      if (connection->have_chunked_upload == MHD_YES)
        connection->current_chunk_offset += used;
      /* dh left "processed" bytes in buffer for next time... */
      if (used > 0)
        memmove (connection->read_buffer,
                 &connection->read_buffer[used], processed + available);
      if (connection->remaining_upload_size != -1)
        connection->remaining_upload_size -= used;
      connection->read_buffer_offset = processed + available;
    }
  while (instant_retry == MHD_YES);
}

/**
 * Try reading data from the socket into the
 * read buffer of the connection.
 *
 * @return MHD_YES if something changed,
 *         MHD_NO if we were interrupted or if
 *                no space was available
 */
static int
do_read (struct MHD_Connection *connection)
{
  int bytes_read;

  if (connection->read_buffer_size == connection->read_buffer_offset)
    return MHD_NO;
  bytes_read = RECV (connection->socket_fd,
                     &connection->read_buffer[connection->read_buffer_offset],
                     connection->read_buffer_size -
                     connection->read_buffer_offset, MSG_NOSIGNAL);
  if (bytes_read < 0)
    {
      if (errno == EINTR)
        return MHD_NO;
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon,
                "Failed to receive data: %s\n", STRERROR (errno));
#endif
      connection_close_error (connection);
      return MHD_YES;
    }
  if (bytes_read == 0)
    {
      /* other side closed connection */
      connection->read_closed = MHD_YES;
      return MHD_NO;
    }
  connection->read_buffer_offset += bytes_read;
  return MHD_YES;
}

/**
 * We have received (possibly the beginning of) a line in the
 * header (or footer).  Validate (check for ":") and prepare
 * to process.
 */
static void
process_header_line (struct MHD_Connection *connection, char *line)
{
  char *colon;

  /* line should be normal header line, find colon */
  colon = strstr (line, ":");
  if (colon == NULL)
    {
      /* error in header line, die hard */
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon,
                "Received malformed line (no colon), closing connection.\n");
#endif
      connection->state = MHD_CONNECTION_CLOSED;
      return;
    }
  /* zero-terminate header */
  colon[0] = '\0';
  colon++;                      /* advance to value */
  while ((colon[0] != '\0') && ((colon[0] == ' ') || (colon[0] == '\t')))
    colon++;
  /* we do the actual adding of the connection
     header at the beginning of the while
     loop since we need to be able to inspect
     the *next* header line (in case it starts
     with a space...) */
  connection->last = line;
  connection->colon = colon;
}

/**
 * Process a header value that spans multiple lines.
 * The previous line(s) are in connection->last.
 *
 * @param line the current input line
 * @param kind if the line is complete, add a header
 *        of the given kind
 */
static void
process_broken_line (struct MHD_Connection *connection,
                     char *line, enum MHD_ValueKind kind)
{
  char *last;
  char *tmp;

  last = connection->last;
  if ((line[0] == ' ') || (line[0] == '\t'))
    {
      /* value was continued on the next line, see
         http://www.jmarshall.com/easy/http/ */
      last = MHD_pool_reallocate (connection->pool,
                                  last,
                                  strlen (last) + 1,
                                  strlen (line) + strlen (last) + 1);
      if (last == NULL)
        {
          excessive_data_handler (connection,
                                  MHD_HTTP_REQUEST_ENTITY_TOO_LARGE);
          return;
        }
      tmp = line;
      while ((tmp[0] == ' ') || (tmp[0] == '\t'))
        tmp++;                  /* skip whitespace at start of 2nd line */
      strcat (last, tmp);
      connection->last = last;
      return;                   /* possibly more than 2 lines... */
    }
  if (MHD_NO == connection_add_header (connection,
                                       last, connection->colon, kind))
    {
      excessive_data_handler (connection, MHD_HTTP_REQUEST_ENTITY_TOO_LARGE);
      return;
    }
  /* we still have the current line to deal with... */
  if (strlen (line) != 0)
    process_header_line (connection, line);
}

/**
 * Parse the various headers; figure out the size
 * of the upload and make sure the headers follow
 * the protocol.  Advance to the appropriate state.
 */
static void
parse_connection_headers (struct MHD_Connection *connection)
{
  const char *clen;
  unsigned long long cval;
  struct MHD_Response *response;

  parse_cookie_header (connection);
  if ((0 != (MHD_USE_PEDANTIC_CHECKS & connection->daemon->options))
      && (NULL != connection->version)
      && (0 == strcasecmp (MHD_HTTP_VERSION_1_1, connection->version))
      && (NULL ==
          MHD_lookup_connection_value (connection, MHD_HEADER_KIND,
                                       MHD_HTTP_HEADER_HOST)))
    {
      /* die, http 1.1 request without host and we are pedantic */
      connection->state = MHD_CONNECTION_FOOTERS_RECEIVED;
      connection->read_closed = MHD_YES;
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon,
                "Received `%s' request without `%s' header.\n",
                MHD_HTTP_VERSION_1_1, MHD_HTTP_HEADER_HOST);
#endif
      response =
        MHD_create_response_from_data (strlen (REQUEST_LACKS_HOST),
                                       REQUEST_LACKS_HOST, MHD_NO, MHD_NO);
      MHD_queue_response (connection, MHD_HTTP_BAD_REQUEST, response);
      MHD_destroy_response (response);
      return;
    }

  clen = MHD_lookup_connection_value (connection,
                                      MHD_HEADER_KIND,
                                      MHD_HTTP_HEADER_CONTENT_LENGTH);
  if (clen != NULL)
    {
      if (1 != sscanf (clen, "%llu", &cval))
        {
#if HAVE_MESSAGES
          MHD_DLOG (connection->daemon,
                    "Failed to parse `%s' header `%s', closing connection.\n",
                    MHD_HTTP_HEADER_CONTENT_LENGTH, clen);
#endif
          connection->state = MHD_CONNECTION_CLOSED;
          return;
        }
      connection->remaining_upload_size = cval;
    }
  else
    {
      if (NULL == MHD_lookup_connection_value (connection,
                                               MHD_HEADER_KIND,
                                               MHD_HTTP_HEADER_TRANSFER_ENCODING))
        {
          /* this request does not have a body */
          connection->remaining_upload_size = 0;
        }
      else
        {
          connection->remaining_upload_size = -1;       /* unknown size */
          if (0 ==
              strcasecmp (MHD_lookup_connection_value
                          (connection, MHD_HEADER_KIND,
                           MHD_HTTP_HEADER_TRANSFER_ENCODING), "chunked"))
            connection->have_chunked_upload = MHD_YES;
        }
    }
}

/**
 * This function handles a particular connection when it has been
 * determined that there is data to be read off a socket. All
 * implementations (multithreaded, external select, internal select)
 * call this function to handle reads.
 *
 * @return MHD_YES if we should continue to process the
 *         connection (not dead yet), MHD_NO if it died
 */
int
MHD_connection_handle_read (struct MHD_Connection *connection)
{
  connection->last_activity = time (NULL);
  if (connection->state == MHD_CONNECTION_CLOSED)
    return MHD_NO;
  if (MHD_NO == do_read (connection))
    return MHD_YES;
  while (1)
    {
#if DEBUG_STATES
      fprintf (stderr, "`%s' in state %u\n", __FUNCTION__, connection->state);
#endif
      switch (connection->state)
        {
        case MHD_CONNECTION_INIT:
        case MHD_CONNECTION_URL_RECEIVED:
        case MHD_CONNECTION_HEADER_PART_RECEIVED:
        case MHD_CONNECTION_HEADERS_RECEIVED:
        case MHD_CONNECTION_HEADERS_PROCESSED:
        case MHD_CONNECTION_CONTINUE_SENDING:
        case MHD_CONNECTION_CONTINUE_SENT:
        case MHD_CONNECTION_BODY_RECEIVED:
        case MHD_CONNECTION_FOOTER_PART_RECEIVED:
          /* nothing to do but default action */
          if (MHD_YES == connection->read_closed)
            {
              connection->state = MHD_CONNECTION_CLOSED;
              continue;
            }
          break;
        case MHD_CONNECTION_CLOSED:
          if (connection->socket_fd != -1)
            connection_close_error (connection);
          return MHD_NO;
        default:
          /* shrink read buffer to how much is actually used */
          MHD_pool_reallocate (connection->pool,
                               connection->read_buffer,
                               connection->read_buffer_size + 1,
                               connection->read_buffer_offset);
          break;
        }
      break;
    }
  return MHD_YES;
}

/**
 * Try writing data to the socket from the
 * write buffer of the connection.
 *
 * @return MHD_YES if something changed,
 *         MHD_NO if we were interrupted
 */
static int
do_write (struct MHD_Connection *connection)
{
  int ret;

  ret = SEND (connection->socket_fd,
              &connection->write_buffer[connection->
                                        write_buffer_send_offset],
              connection->write_buffer_append_offset -
              connection->write_buffer_send_offset, MSG_NOSIGNAL);
  if (ret < 0)
    {
      if (errno == EINTR)
        return MHD_NO;
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon,
                "Failed to send data: %s\n", STRERROR (errno));
#endif
      connection_close_error (connection);
      return MHD_YES;
    }
#if DEBUG_SEND_DATA
  fprintf (stderr,
           "Sent HEADER response: `%.*s'\n",
           ret,
           &connection->write_buffer[connection->write_buffer_send_offset]);
#endif
  connection->write_buffer_send_offset += ret;
  return MHD_YES;
}

/**
 * Check if we are done sending the write-buffer.
 * If so, transition into "next_state".
 * @return MHY_NO if we are not done, MHD_YES if we are
 */
static int
check_write_done (struct MHD_Connection *connection,
                  enum MHD_CONNECTION_STATE next_state)
{
  if (connection->write_buffer_append_offset !=
      connection->write_buffer_send_offset)
    return MHD_NO;
  connection->write_buffer_append_offset = 0;
  connection->write_buffer_send_offset = 0;
  connection->state = next_state;
  MHD_pool_reallocate (connection->pool,
                       connection->write_buffer,
                       connection->write_buffer_size, 0);
  connection->write_buffer = NULL;
  connection->write_buffer_size = 0;
  return MHD_YES;
}

/**
 * This function was created to handle writes to sockets when it has
 * been determined that the socket can be written to. All
 * implementations (multithreaded, external select, internal select)
 * call this function
 *
 * @return MHD_YES if we should continue to process the
 *         connection (not dead yet), MHD_NO if it died
 */
int
MHD_connection_handle_write (struct MHD_Connection *connection)
{
  struct MHD_Response *response;
  int ret;

  connection->last_activity = time (NULL);
  while (1)
    {
#if DEBUG_STATES
      fprintf (stderr, "`%s' in state %u\n", __FUNCTION__, connection->state);
#endif
      switch (connection->state)
        {
        case MHD_CONNECTION_INIT:
        case MHD_CONNECTION_URL_RECEIVED:
        case MHD_CONNECTION_HEADER_PART_RECEIVED:
        case MHD_CONNECTION_HEADERS_RECEIVED:
          EXTRA_CHECK (0);
          break;
        case MHD_CONNECTION_HEADERS_PROCESSED:
          break;
        case MHD_CONNECTION_CONTINUE_SENDING:
          ret = SEND (connection->socket_fd,
                      &HTTP_100_CONTINUE[connection->
                                         continue_message_write_offset],
                      strlen (HTTP_100_CONTINUE) -
                      connection->continue_message_write_offset,
                      MSG_NOSIGNAL);
          if (ret < 0)
            {
              if (errno == EINTR)
                break;
#if HAVE_MESSAGES
              MHD_DLOG (connection->daemon,
                        "Failed to send data: %s\n", STRERROR (errno));
#endif
              connection_close_error (connection);
              return MHD_NO;
            }
#if DEBUG_SEND_DATA
          fprintf (stderr,
                   "Sent 100 continue response: `%.*s'\n",
                   ret,
                   &HTTP_100_CONTINUE[connection->
                                      continue_message_write_offset]);
#endif
          connection->continue_message_write_offset += ret;
          break;
        case MHD_CONNECTION_CONTINUE_SENT:
        case MHD_CONNECTION_BODY_RECEIVED:
        case MHD_CONNECTION_FOOTER_PART_RECEIVED:
        case MHD_CONNECTION_FOOTERS_RECEIVED:
          EXTRA_CHECK (0);
          break;
        case MHD_CONNECTION_HEADERS_SENDING:
          do_write (connection);
          check_write_done (connection, MHD_CONNECTION_HEADERS_SENT);
          break;
        case MHD_CONNECTION_HEADERS_SENT:
          EXTRA_CHECK (0);
          break;
        case MHD_CONNECTION_NORMAL_BODY_READY:
          response = connection->response;
          if (response->crc != NULL)
            pthread_mutex_lock (&response->mutex);
          if (MHD_YES != try_ready_normal_body (connection))
            {
              if (response->crc != NULL)
                pthread_mutex_unlock (&response->mutex);
              connection->state = MHD_CONNECTION_NORMAL_BODY_UNREADY;
              break;
            }
          ret = SEND (connection->socket_fd,
                      &response->data[connection->response_write_position -
                                      response->data_start],
                      response->data_size -
                      (connection->response_write_position -
                       response->data_start), MSG_NOSIGNAL);
#if DEBUG_SEND_DATA
          if (ret > 0)
            fprintf (stderr,
                     "Sent DATA response: `%.*s'\n",
                     ret,
                     &response->data[connection->response_write_position -
                                     response->data_start]);
#endif
          if (response->crc != NULL)
            pthread_mutex_unlock (&response->mutex);
          if (ret < 0)
            {
              if (errno == EINTR)
                return MHD_YES;
#if HAVE_MESSAGES
              MHD_DLOG (connection->daemon,
                        "Failed to send data: %s\n", STRERROR (errno));
#endif
              connection_close_error (connection);
              return MHD_NO;
            }
          connection->response_write_position += ret;
          if (connection->response_write_position ==
              connection->response->total_size)
            connection->state = MHD_CONNECTION_FOOTERS_SENT;    /* have no footers... */
          break;
        case MHD_CONNECTION_NORMAL_BODY_UNREADY:
          EXTRA_CHECK (0);
          break;
        case MHD_CONNECTION_CHUNKED_BODY_READY:
          do_write (connection);
          check_write_done (connection,
                            (connection->response->total_size ==
                             connection->
                             response_write_position) ?
                            MHD_CONNECTION_BODY_SENT :
                            MHD_CONNECTION_CHUNKED_BODY_UNREADY);
          break;
        case MHD_CONNECTION_CHUNKED_BODY_UNREADY:
        case MHD_CONNECTION_BODY_SENT:
          EXTRA_CHECK (0);
          break;
        case MHD_CONNECTION_FOOTERS_SENDING:
          do_write (connection);
          check_write_done (connection, MHD_CONNECTION_FOOTERS_SENT);
          break;
        case MHD_CONNECTION_FOOTERS_SENT:
          EXTRA_CHECK (0);
          break;
        case MHD_CONNECTION_CLOSED:
          if (connection->socket_fd != -1)
            connection_close_error (connection);
          return MHD_NO;
        }
      break;
    }
  return MHD_YES;
}

/**
 * This function was created to handle per-connection processing that
 * has to happen even if the socket cannot be read or written to.  All
 * implementations (multithreaded, external select, internal select)
 * call this function.
 *
 * @return MHD_YES if we should continue to process the
 *         connection (not dead yet), MHD_NO if it died
 */
int
MHD_connection_handle_idle (struct MHD_Connection *connection)
{
  unsigned int timeout;
  const char *end;
  char *line;

  while (1)
    {
#if DEBUG_STATES
      fprintf (stderr, "`%s' in state %u\n", __FUNCTION__, connection->state);
#endif
      switch (connection->state)
        {
        case MHD_CONNECTION_INIT:
          line = get_next_header_line (connection);
          if (line == NULL)
            break;
          if (MHD_NO == parse_initial_message_line (connection, line))
            connection->state = MHD_CONNECTION_CLOSED;
          else
            connection->state = MHD_CONNECTION_URL_RECEIVED;
          continue;
        case MHD_CONNECTION_URL_RECEIVED:
          line = get_next_header_line (connection);
          if (line == NULL)
            break;
          if (strlen (line) == 0)
            {
              connection->state = MHD_CONNECTION_HEADERS_RECEIVED;
              continue;
            }
          process_header_line (connection, line);
          connection->state = MHD_CONNECTION_HEADER_PART_RECEIVED;
          continue;
        case MHD_CONNECTION_HEADER_PART_RECEIVED:
          line = get_next_header_line (connection);
          if (line == NULL)
            break;
          process_broken_line (connection, line, MHD_HEADER_KIND);
          if (strlen (line) == 0)
            {
              connection->state = MHD_CONNECTION_HEADERS_RECEIVED;
              continue;
            }
          continue;
        case MHD_CONNECTION_HEADERS_RECEIVED:
          parse_connection_headers (connection);
          if (connection->state == MHD_CONNECTION_CLOSED)
            continue;
          connection->state = MHD_CONNECTION_HEADERS_PROCESSED;
          continue;
        case MHD_CONNECTION_HEADERS_PROCESSED:
          call_connection_handler (connection); /* first call */
          if (connection->state == MHD_CONNECTION_CLOSED)
            continue;
          if (need_100_continue (connection))
            {
              connection->state = MHD_CONNECTION_CONTINUE_SENDING;
              break;
            }
          connection->state = (connection->remaining_upload_size == 0)
            ? MHD_CONNECTION_FOOTERS_RECEIVED : MHD_CONNECTION_CONTINUE_SENT;
          continue;
        case MHD_CONNECTION_CONTINUE_SENDING:
          if (connection->continue_message_write_offset ==
              strlen (HTTP_100_CONTINUE))
            {
              connection->state = MHD_CONNECTION_CONTINUE_SENT;
              continue;
            }
          break;
        case MHD_CONNECTION_CONTINUE_SENT:
          if (connection->read_buffer_offset != 0)
            {
              call_connection_handler (connection);     /* loop call */
              if (connection->state == MHD_CONNECTION_CLOSED)
                continue;
            }
          if ((connection->remaining_upload_size == 0) ||
              ((connection->remaining_upload_size == -1) &&
               (connection->read_buffer_offset == 0) &&
               (MHD_YES == connection->read_closed)))
            {
              if ((MHD_YES == connection->have_chunked_upload) &&
                  (MHD_NO == connection->read_closed))
                connection->state = MHD_CONNECTION_BODY_RECEIVED;
              else
                connection->state = MHD_CONNECTION_FOOTERS_RECEIVED;
              continue;
            }
          break;
        case MHD_CONNECTION_BODY_RECEIVED:
          line = get_next_header_line (connection);
          if (line == NULL)
            break;
          if (strlen (line) == 0)
            {
              connection->state = MHD_CONNECTION_FOOTERS_RECEIVED;
              continue;
            }
          process_header_line (connection, line);
          connection->state = MHD_CONNECTION_FOOTER_PART_RECEIVED;
          continue;
        case MHD_CONNECTION_FOOTER_PART_RECEIVED:
          line = get_next_header_line (connection);
          if (line == NULL)
            break;
          process_broken_line (connection, line, MHD_FOOTER_KIND);
          if (strlen (line) == 0)
            {
              connection->state = MHD_CONNECTION_FOOTERS_RECEIVED;
              continue;
            }
          continue;
        case MHD_CONNECTION_FOOTERS_RECEIVED:
          call_connection_handler (connection); /* "final" call */
          if (connection->state == MHD_CONNECTION_CLOSED)
            continue;
          if (connection->response == NULL)
            break;              /* try again next time */
          if (MHD_NO == build_header_response (connection))
            {
              /* oops - close! */
#if HAVE_MESSAGES
              MHD_DLOG (connection->daemon,
                        "Closing connection (failed to create response header)\n");
#endif
              connection->state = MHD_CONNECTION_CLOSED;
              continue;
            }
          connection->state = MHD_CONNECTION_HEADERS_SENDING;
          break;
        case MHD_CONNECTION_HEADERS_SENDING:
          /* no default action */
          break;
        case MHD_CONNECTION_HEADERS_SENT:
          if (connection->have_chunked_upload)
            connection->state = MHD_CONNECTION_CHUNKED_BODY_UNREADY;
          else
            connection->state = MHD_CONNECTION_NORMAL_BODY_UNREADY;
          continue;
        case MHD_CONNECTION_NORMAL_BODY_READY:
          /* nothing to do here */
          break;
        case MHD_CONNECTION_NORMAL_BODY_UNREADY:
          if (connection->response->crc != NULL)
            pthread_mutex_lock (&connection->response->mutex);
          if (MHD_YES == try_ready_normal_body (connection))
            {
              if (connection->response->crc != NULL)
                pthread_mutex_unlock (&connection->response->mutex);
              connection->state = MHD_CONNECTION_NORMAL_BODY_READY;
              break;
            }
          if (connection->response->crc != NULL)
            pthread_mutex_unlock (&connection->response->mutex);
          /* not ready, no socket action */
          break;
        case MHD_CONNECTION_CHUNKED_BODY_READY:
          /* nothing to do here */
          break;
        case MHD_CONNECTION_CHUNKED_BODY_UNREADY:
          if (connection->response->crc != NULL)
            pthread_mutex_lock (&connection->response->mutex);
          if (MHD_YES == try_ready_chunked_body (connection))
            {
              if (connection->response->crc != NULL)
                pthread_mutex_unlock (&connection->response->mutex);
              connection->state = MHD_CONNECTION_CHUNKED_BODY_READY;
              continue;
            }
          if (connection->response->crc != NULL)
            pthread_mutex_unlock (&connection->response->mutex);
          break;
        case MHD_CONNECTION_BODY_SENT:
          build_header_response (connection);
          if (connection->write_buffer_send_offset ==
              connection->write_buffer_append_offset)
            connection->state = MHD_CONNECTION_FOOTERS_SENT;
          else
            connection->state = MHD_CONNECTION_FOOTERS_SENDING;
          continue;
        case MHD_CONNECTION_FOOTERS_SENDING:
          /* no default action */
          break;
        case MHD_CONNECTION_FOOTERS_SENT:
          MHD_destroy_response (connection->response);
          if (connection->daemon->notify_completed != NULL)
            connection->daemon->notify_completed (connection->daemon->
                                                  notify_completed_cls,
                                                  connection,
                                                  &connection->client_context,
                                                  MHD_REQUEST_TERMINATED_COMPLETED_OK);
          end = MHD_lookup_connection_value (connection,
                                             MHD_HEADER_KIND,
                                             MHD_HTTP_HEADER_CONNECTION);
          connection->client_context = NULL;
          connection->continue_message_write_offset = 0;
          connection->responseCode = 0;
          connection->response = NULL;
          connection->headers_received = NULL;
          connection->response_write_position = 0;
          connection->have_chunked_upload = MHD_NO;
          connection->method = NULL;
          connection->url = NULL;
          connection->write_buffer = NULL;
          connection->write_buffer_size = 0;
          connection->write_buffer_send_offset = 0;
          connection->write_buffer_append_offset = 0;
          if ((end != NULL) && (0 == strcasecmp (end, "close")))
            {
              connection->read_closed = MHD_YES;
              connection->read_buffer_offset = 0;
            }
          if (((MHD_YES == connection->read_closed) &&
               (0 == connection->read_buffer_offset)) ||
              (connection->version == NULL) ||
	      (connection->method == NULL) ||
	      ( (0 != strcasecmp (MHD_HTTP_METHOD_HEAD, connection->method)) &&
		(0 != strcasecmp (MHD_HTTP_METHOD_GET, connection->method)) ) ||
	      (0 != strcasecmp (MHD_HTTP_VERSION_1_1, connection->version)))
            {
	      /* http 1.0, version-less or non-HEAD/GET requests cannot be
		 pipelined */
              connection->state = MHD_CONNECTION_CLOSED;
              MHD_pool_destroy (connection->pool);
              connection->pool = NULL;
              connection->read_buffer = NULL;
              connection->read_buffer_size = 0;
              connection->read_buffer_offset = 0;
            }
          else
            {
              connection->version = NULL;
              connection->state = MHD_CONNECTION_INIT;
              connection->read_buffer
                = MHD_pool_reset (connection->pool,
                                  connection->read_buffer,
                                  connection->read_buffer_size);
            }
          continue;
        case MHD_CONNECTION_CLOSED:
          if (connection->socket_fd != -1)
            connection_close_error (connection);
          break;
        default:
          EXTRA_CHECK (0);
          break;
        }
      break;
    }
  timeout = connection->daemon->connection_timeout;
  if ( (connection->socket_fd != -1) &&
       (timeout != 0) && (time (NULL) - timeout > connection->last_activity))
    {
      connection_close_error (connection);
      return MHD_NO;
    }
  return MHD_YES;

}

/* end of connection.c */
