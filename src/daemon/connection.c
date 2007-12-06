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

/**
 * Add extra debug messages with reasons for closing connections
 * (non-error reasons).
 */
#define DEBUG_CLOSE 0


/**
 * Should all data send be printed to stderr?
 */
#define DEBUG_SEND_DATA 0


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
      (connection->bodyReceived == MHD_NO) || (connection->headersReceived == MHD_NO))
    return MHD_NO;
  MHD_increment_response_rc (response);
  connection->response = response;
  connection->responseCode = status_code;
  if ((connection->method != NULL) &&
      (0 == strcasecmp (connection->method, MHD_HTTP_METHOD_HEAD)))
    {
      /* if this is a "HEAD" request, pretend that we
         have already sent the full message body */
      connection->messagePos = response->total_size;
    }
  return MHD_YES;
}

/**
 * Do we (still) need to send a 100 continue
 * message for this connection?
 */
static int
MHD_need_100_continue (struct MHD_Connection *connection)
{
  const char *expect;

  return ((connection->version != NULL) &&
          (0 == strcasecmp (connection->version,
                            MHD_HTTP_VERSION_1_1)) &&
          (connection->headersReceived == MHD_YES) &&
          (NULL != (expect = MHD_lookup_connection_value (connection,
                                                          MHD_HEADER_KIND,
                                                          MHD_HTTP_HEADER_EXPECT)))
          && (0 == strcasecmp (expect, "100-continue"))
          && (connection->continuePos < strlen (HTTP_100_CONTINUE)));
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
ready_response (struct MHD_Connection *connection)
{
  int ret;
  struct MHD_Response *response;

  response = connection->response;
  ret = response->crc (response->crc_cls,
                       connection->messagePos,
                       response->data,
                       MIN (response->data_buffer_size,
                            response->total_size - connection->messagePos));
  if (ret == -1)
    {
      /* end of message, signal other side by closing! */
#if DEBUG_CLOSE 
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon, "Closing connection (end of response)\n");
#endif
#endif
      response->total_size = connection->messagePos;
      connection_close_error (connection);
      return MHD_NO;
    }
  response->data_start = connection->messagePos;
  response->data_size = ret;
  if (ret == 0)
    {
      /* avoid busy-waiting when using external select
         (we assume that the main application will 
         wake up the external select once more data
         is ready).  With internal selects, we
         have no choice; if the app uses a thread
         per connection, ret==0 is likely a bug --
         the application should block until data
         is ready! */
      if ((0 ==
           (connection->daemon->
            options & (MHD_USE_SELECT_INTERNALLY |
                       MHD_USE_THREAD_PER_CONNECTION))))
        connection->response_unready = MHD_YES;
      return MHD_NO;
    }
  connection->response_unready = MHD_NO;
  return MHD_YES;
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
  void *buf;

  fd = connection->socket_fd;
  if (fd == -1)
    return MHD_YES;
  if ((connection->read_close == MHD_NO) &&
      ((connection->headersReceived == MHD_NO) ||
       (connection->readLoc < connection->read_buffer_size)))
    {
      FD_SET (fd, read_fd_set);
      if (fd > *max_fd)
        *max_fd = fd;
    }
  else
    {
      if ((connection->read_close == MHD_NO) &&
          ((connection->headersReceived == MHD_YES) &&
           (connection->readLoc == connection->read_buffer_size)))
        {
          /* try growing the read buffer, just in case */
          buf = MHD_pool_reallocate (connection->pool,
                                     connection->read_buffer,
                                     connection->read_buffer_size,
                                     connection->read_buffer_size * 2 +
                                     MHD_BUF_INC_SIZE);
          if (buf != NULL)
            {
              /* we can actually grow the buffer, do it! */
              connection->read_buffer = buf;
              connection->read_buffer_size =
                connection->read_buffer_size * 2 + MHD_BUF_INC_SIZE;
              FD_SET (fd, read_fd_set);
              if (fd > *max_fd)
                *max_fd = fd;
            }
        }
    }
  if ((connection->response != NULL) &&
      (connection->response_unready == MHD_YES))
    {
      pthread_mutex_lock (&connection->response->mutex);
      ready_response (connection);
      pthread_mutex_unlock (&connection->response->mutex);
    }
  if (((connection->response != NULL) &&
       (connection->response_unready == MHD_NO)) ||
      MHD_need_100_continue (connection))
    {
      FD_SET (fd, write_fd_set);
      if (fd > *max_fd)
        *max_fd = fd;
    }
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
MHD_excessive_data_handler (struct MHD_Connection *connection,
                            unsigned int status_code)
{
  struct MHD_Response *response;

  /* die, header far too long to be reasonable */
  connection->read_close = MHD_YES;
  connection->headersReceived = MHD_YES;
  connection->bodyReceived = MHD_YES;
#if HAVE_MESSAGES
  MHD_DLOG (connection->daemon,
            "Received excessively long header, closing connection.\n");
#endif
  response = MHD_create_response_from_data (strlen (REQUEST_TOO_BIG),
                                            REQUEST_TOO_BIG, MHD_NO, MHD_NO);
  MHD_queue_response (connection, status_code, response);
  MHD_destroy_response (response);
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
MHD_get_next_header_line (struct MHD_Connection *connection)
{
  char *rbuf;
  size_t pos;

  if (connection->readLoc == 0)
    return NULL;
  pos = 0;
  rbuf = connection->read_buffer;
  while ((pos < connection->readLoc - 1) &&
         (rbuf[pos] != '\r') && (rbuf[pos] != '\n'))
    pos++;
  if (pos == connection->readLoc - 1)
    {
      /* not found, consider growing... */
      if (connection->readLoc == connection->read_buffer_size)
        {
          rbuf = MHD_pool_reallocate (connection->pool,
                                      connection->read_buffer,
                                      connection->read_buffer_size,
                                      connection->read_buffer_size * 2 +
                                      MHD_BUF_INC_SIZE);
          if (rbuf == NULL)
            {
              MHD_excessive_data_handler (connection,
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
  connection->readLoc -= pos;
  return rbuf;
}

/**
 * @return MHD_NO on failure (out of memory), MHD_YES for success
 */
static int
MHD_connection_add_header (struct MHD_Connection *connection,
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
      MHD_excessive_data_handler (connection,
                                  MHD_HTTP_REQUEST_ENTITY_TOO_LARGE);
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
      if (MHD_NO == MHD_connection_add_header (connection,
                                               args, equals, kind))
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
MHD_parse_cookie_header (struct MHD_Connection *connection)
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
      MHD_excessive_data_handler (connection,
                                  MHD_HTTP_REQUEST_ENTITY_TOO_LARGE);
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
      if (MHD_NO == MHD_connection_add_header (connection,
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
 * This function is designed to parse the input buffer of a given connection.
 *
 * Once the header is complete, it should have set the
 * headers_received, url and method values and set
 * headersReceived to MHD_YES.  If no body is expected, it should
 * also set "bodyReceived" to MHD_YES.  Otherwise, it should
 * set "uploadSize" to the expected size of the body.  If the
 * size of the body is unknown, it should be set to -1.
 */
static void
MHD_parse_connection_headers (struct MHD_Connection *connection)
{
  char *last;
  char *line;
  char *colon;
  char *tmp;
  const char *clen;
  const char *end;
  unsigned long long cval;
  struct MHD_Response *response;

  if (connection->bodyReceived == MHD_YES)
    abort ();
  colon = NULL;                 /* make gcc happy */
  last = NULL;
  while (NULL != (line = MHD_get_next_header_line (connection)))
    {
      if (last != NULL)
        {
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
                  MHD_excessive_data_handler (connection,
                                              MHD_HTTP_REQUEST_ENTITY_TOO_LARGE);
                  break;
                }
              tmp = line;
              while ((tmp[0] == ' ') || (tmp[0] == '\t'))
                tmp++;          /* skip whitespace at start of 2nd line */
              strcat (last, tmp);
              continue;         /* possibly more than 2 lines... */
            }
          else
            {
              if (MHD_NO == MHD_connection_add_header (connection,
                                                       last,
                                                       colon,
                                                       MHD_HEADER_KIND))
                return;
              last = NULL;
            }
        }
      if (connection->url == NULL)
        {
          /* line must be request line (first line of header) */
          if (MHD_NO == parse_initial_message_line (connection, line))
            goto DIE;
          continue;
        }
      /* check if this is the end of the header */
      if (strlen (line) == 0)
        {
          /* end of header */
          connection->headersReceived = MHD_YES;
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
                  goto DIE;
                }
              connection->uploadSize = cval;
              connection->bodyReceived = cval == 0 ? MHD_YES : MHD_NO;
            }
          else
            {
              if (NULL == MHD_lookup_connection_value (connection,
                                                       MHD_HEADER_KIND,
                                                       MHD_HTTP_HEADER_TRANSFER_ENCODING))
                {
                  /* this request does not have a body */
                  connection->uploadSize = 0;
                  connection->bodyReceived = MHD_YES;
                }
              else
                {
                  connection->uploadSize = -1;  /* unknown size */
                  connection->bodyReceived = MHD_NO;
                }
            }
          end = MHD_lookup_connection_value (connection,
                                             MHD_HEADER_KIND,
                                             MHD_HTTP_HEADER_CONNECTION);
          if ((end != NULL) && (0 == strcasecmp (end, "close")))
            {
              /* other side explicitly requested
                 that we close the connection after
                 this request */
              connection->read_close = MHD_YES;
            }

          if ((0 != (MHD_USE_PEDANTIC_CHECKS & connection->daemon->options))
              && (NULL != connection->version)
              && (0 == strcasecmp (MHD_HTTP_VERSION_1_1, connection->version))
              && (NULL ==
                  MHD_lookup_connection_value (connection, MHD_HEADER_KIND,
                                               MHD_HTTP_HEADER_HOST)))
            {
              /* die, http 1.1 request without host and we are pedantic */
              connection->bodyReceived = MHD_YES;
              connection->read_close = MHD_YES;
#if HAVE_MESSAGES
              MHD_DLOG (connection->daemon,
                        "Received `%s' request without `%s' header.\n",
                        MHD_HTTP_VERSION_1_1, MHD_HTTP_HEADER_HOST);
#endif
              response =
                MHD_create_response_from_data (strlen (REQUEST_LACKS_HOST),
                                               REQUEST_LACKS_HOST, MHD_NO,
                                               MHD_NO);
              MHD_queue_response (connection, MHD_HTTP_BAD_REQUEST, response);
              MHD_destroy_response (response);
            }

          break;
        }
      /* line should be normal header line, find colon */
      colon = strstr (line, ":");
      if (colon == NULL)
        {
          /* error in header line, die hard */
#if HAVE_MESSAGES
          MHD_DLOG (connection->daemon,
                    "Received malformed line (no colon), closing connection.\n");
#endif
          goto DIE;
        }
      /* zero-terminate header */
      colon[0] = '\0';
      colon++;                  /* advance to value */
      while ((colon[0] != '\0') && ((colon[0] == ' ') || (colon[0] == '\t')))
        colon++;
      /* we do the actual adding of the connection
         header at the beginning of the while
         loop since we need to be able to inspect
         the *next* header line (in case it starts
         with a space...) */
      last = line;
    }
  if ((last != NULL) &&
      (MHD_NO == MHD_connection_add_header (connection,
                                            last, colon, MHD_HEADER_KIND)))
    return;                     /* error */
  MHD_parse_cookie_header (connection);
  return;
DIE:
#if HAVE_MESSAGES
  MHD_DLOG (connection->daemon,
            "Closing connection (problem parsing headers)\n");
#endif
  connection_close_error (connection);
}


/**
 * Find the handler responsible for this request.
 */
static struct MHD_Access_Handler *
MHD_find_access_handler (struct MHD_Connection *connection)
{
  struct MHD_Access_Handler *pos;

  pos = connection->daemon->handlers;
  while (pos != NULL)
    {
      if (0 == strcmp (connection->url, pos->uri_prefix))
        return pos;
      pos = pos->next;
    }
  return &connection->daemon->default_handler;
}


/**
 * Call the handler of the application for this
 * connection.
 */
void
MHD_call_connection_handler (struct MHD_Connection *connection)
{
  struct MHD_Access_Handler *ah;
  unsigned int processed;

  if (connection->response != NULL)
    return;                     /* already queued a response */
  if (connection->headersReceived == MHD_NO)
    abort ();                   /* bad timing... */
  ah = MHD_find_access_handler (connection);
  processed = connection->readLoc;
  if (MHD_NO == ah->dh (ah->dh_cls,
                        connection,
                        connection->url,
                        connection->method,
                        connection->version,
                        connection->read_buffer, &processed,
                        &connection->client_context))
    {
      /* serios internal error, close connection */
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon,
                "Internal application error, closing connection.\n");
#endif
      connection_close_error (connection);
      return;
    }
  /* dh left "processed" bytes in buffer for next time... */
  memmove (connection->read_buffer,
           &connection->read_buffer[connection->readLoc - processed],
           processed);
  if (connection->uploadSize != -1)
    connection->uploadSize -= (connection->readLoc - processed);
  connection->readLoc = processed;
  if ((connection->uploadSize == 0) ||
      ((connection->readLoc == 0) &&
       (connection->uploadSize == -1) && (connection->socket_fd == -1)))
    {
      connection->bodyReceived = MHD_YES;
      if (connection->read_buffer != NULL)
        MHD_pool_reallocate (connection->pool,
                             connection->read_buffer,
                             (connection->read_buffer ==
                              NULL) ? 0 : connection->read_buffer_size + 1,
                             0);
      connection->readLoc = 0;
      connection->read_buffer_size = 0;
      connection->read_buffer = NULL;
    }
}


/**
 * This function handles a particular connection when it has been
 * determined that there is data to be read off a socket. All implementations
 * (multithreaded, external select, internal select) call this function
 * to handle reads.
 */
int
MHD_connection_handle_read (struct MHD_Connection *connection)
{
  int bytes_read;
  void *tmp;

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
  if ((connection->readLoc >= connection->read_buffer_size) &&
      (connection->headersReceived == MHD_NO))
    {
      /* need to grow read buffer */
      tmp = MHD_pool_reallocate (connection->pool,
                                 connection->read_buffer,
                                 connection->read_buffer_size,
                                 connection->read_buffer_size * 2 +
                                 MHD_BUF_INC_SIZE + 1);
      if (tmp == NULL)
        {
#if HAVE_MESSAGES
          MHD_DLOG (connection->daemon,
                    "Not enough memory for reading headers!\n");
#endif
          MHD_excessive_data_handler (connection,
                                      MHD_HTTP_REQUEST_ENTITY_TOO_LARGE);
          return MHD_NO;
        }
      connection->read_buffer = tmp;
      connection->read_buffer_size =
        connection->read_buffer_size * 2 + MHD_BUF_INC_SIZE;
    }
  if (connection->readLoc >= connection->read_buffer_size)
    {
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon, "Unexpected call to %s.\n", __FUNCTION__);
#endif
      return MHD_NO;
    }
  bytes_read = RECV (connection->socket_fd,
                     &connection->read_buffer[connection->readLoc],
                     connection->read_buffer_size - connection->readLoc, 
		     MSG_NOSIGNAL);
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
      connection->read_close = MHD_YES;
      if ((connection->headersReceived == MHD_YES) && (connection->readLoc > 0))
        MHD_call_connection_handler (connection);
#if DEBUG_CLOSE
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon,
                "Shutting down connection for reading (other side closed connection)\n");
#endif
#endif
      shutdown (connection->socket_fd, SHUT_RD);
      return MHD_YES;
    }
  connection->readLoc += bytes_read;
  if (connection->headersReceived == MHD_NO)
    MHD_parse_connection_headers (connection);
  if ((connection->headersReceived == MHD_YES) && (connection->method != NULL))
    MHD_call_connection_handler (connection);
  return MHD_YES;
}

/**
 * Check if we need to set some additional headers
 * for http-compiliance.
 */
static void
MHD_add_extra_headers (struct MHD_Connection *connection)
{
  const char *have;
  char buf[128];

  if (connection->response->total_size == -1)
    {
      have = MHD_get_response_header (connection->response,
                                      MHD_HTTP_HEADER_CONNECTION);
      if (have == NULL)
        MHD_add_response_header (connection->response,
                                 MHD_HTTP_HEADER_CONNECTION, "close");
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
 * Allocate the connection's write buffer and
 * fill it with all of the headers from the
 * HTTPd's response.
 */
static int
MHD_build_header_response (struct MHD_Connection *connection)
{
  size_t size;
  size_t off;
  struct MHD_HTTP_Header *pos;
  char code[128];
  char date[128];
  char *data;

  MHD_add_extra_headers (connection);
  const char* reason_phrase = MHD_get_reason_phrase_for(connection->responseCode);
  _REAL_SNPRINTF (code, 128, "%s %u %s\r\n", MHD_HTTP_VERSION_1_1, 
                  connection->responseCode, reason_phrase);
  off = strlen (code);
  /* estimate size */
  size = off + 2;               /* extra \r\n at the end */
  pos = connection->response->first_header;
  while (pos != NULL)
    {
      size += strlen (pos->header) + strlen (pos->value) + 4;   /* colon, space, linefeeds */
      pos = pos->next;
    }
  if (NULL == MHD_get_response_header (connection->response,
                                       MHD_HTTP_HEADER_DATE))
    get_date_string (date, sizeof (date));
  else
    date[0] = '\0';
  size += strlen (date);
  /* produce data */
  data = MHD_pool_allocate (connection->pool, size + 1, MHD_YES);
  if (data == NULL)
    {
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon, "Not enough memory for write!\n");
#endif
      return MHD_NO;
    }
  memcpy (data, code, off);
  pos = connection->response->first_header;
  while (pos != NULL)
    {
      SPRINTF (&data[off], "%s: %s\r\n", pos->header, pos->value);
      off += strlen (pos->header) + strlen (pos->value) + 4;
      pos = pos->next;
    }
  strcpy (&data[off], date);
  off += strlen (date);
  sprintf (&data[off], "\r\n");
  off += 2;
  if (off != size)
    abort ();
  connection->write_buffer = data;
  connection->writeLoc = size;
  connection->writePos = 0;
  connection->write_buffer_size = size + 1;
  return MHD_YES;
}

/**
 * This function was created to handle writes to sockets when it has
 * been determined that the socket can be written to. All
 * implementations (multithreaded, external select, internal select)
 * call this function
 */
int
MHD_connection_handle_write (struct MHD_Connection *connection)
{
  struct MHD_Response *response;
  int ret;

  if (MHD_need_100_continue (connection))
    {
      ret = SEND (connection->socket_fd,
                  &HTTP_100_CONTINUE[connection->continuePos],
                  strlen (HTTP_100_CONTINUE) - connection->continuePos, 
		  MSG_NOSIGNAL);
      if (ret < 0)
        {
          if (errno == EINTR)
            return MHD_YES;
#if HAVE_MESSAGES
          MHD_DLOG (connection->daemon,
                    "Failed to send data: %s\n", STRERROR (errno));
#endif
          connection_close_error (connection);
          return MHD_YES;
        }
#if DEBUG_SEND_DATA
      fprintf (stderr,
               "Sent 100 continue response: `%.*s'\n",
               ret, &HTTP_100_CONTINUE[connection->continuePos]);
#endif
      connection->continuePos += ret;
      return MHD_YES;
    }
  response = connection->response;
  if (response == NULL)
    {
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon, "Unexpected call to %s.\n", __FUNCTION__);
#endif
      return MHD_NO;
    }
  if (MHD_NO == connection->headersSent)
    {
      if ((connection->write_buffer == NULL) &&
          (MHD_NO == MHD_build_header_response (connection)))
        {
          /* oops - close! */
#if HAVE_MESSAGES
          MHD_DLOG (connection->daemon,
                    "Closing connection (failed to create response header)\n");
#endif
          connection_close_error (connection);
          return MHD_NO;
        }
      ret = SEND (connection->socket_fd,
                  &connection->write_buffer[connection->writePos],
                  connection->writeLoc - connection->writePos, 
		  MSG_NOSIGNAL);
      if (ret < 0)
        {
          if (errno == EINTR)
            return MHD_YES;
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
               ret, &connection->write_buffer[connection->writePos]);
#endif
      connection->writePos += ret;
      if (connection->writeLoc == connection->writePos)
        {
          connection->writeLoc = 0;
          connection->writePos = 0;
          connection->headersSent = MHD_YES;
          MHD_pool_reallocate (connection->pool,
                               connection->write_buffer,
                               connection->write_buffer_size, 0);
          connection->write_buffer = NULL;
          connection->write_buffer_size = 0;
        }
      return MHD_YES;
    }
  if (response->total_size < connection->messagePos)
    abort ();                   /* internal error */
  if (response->crc != NULL)
    pthread_mutex_lock (&response->mutex);

  /* prepare send buffer */
  if ((response->crc != NULL) &&
      ((response->data_start > connection->messagePos) ||
       (response->data_start + response->data_size <=
        connection->messagePos)) && (MHD_YES != ready_response (connection)))
    {
      pthread_mutex_unlock (&response->mutex);
      return MHD_YES;
    }
  /* transmit */
  ret = SEND (connection->socket_fd,
              &response->data[connection->messagePos - response->data_start],
              response->data_size - (connection->messagePos -
                                     response->data_start), 
	      MSG_NOSIGNAL);
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
      return MHD_YES;
    }
#if DEBUG_SEND_DATA
  fprintf (stderr,
           "Sent DATA response: `%.*s'\n",
           ret,
           &response->data[connection->messagePos - response->data_start]);
#endif
  connection->messagePos += ret;
  if (connection->messagePos > response->total_size)
    abort ();                   /* internal error */
  if (connection->messagePos == response->total_size)
    {
      if ((connection->bodyReceived == MHD_NO) ||
          (connection->headersReceived == MHD_NO))
        abort ();               /* internal error */
      MHD_destroy_response (response);
      if (connection->daemon->notify_completed != NULL)
        connection->daemon->notify_completed (connection->daemon->
                                              notify_completed_cls,
                                              connection,
                                              &connection->client_context,
                                              MHD_REQUEST_TERMINATED_COMPLETED_OK);
      connection->client_context = NULL;
      connection->continuePos = 0;
      connection->responseCode = 0;
      connection->response = NULL;
      connection->headers_received = NULL;
      connection->headersReceived = MHD_NO;
      connection->headersSent = MHD_NO;
      connection->bodyReceived = MHD_NO;
      connection->messagePos = 0;
      connection->method = NULL;
      connection->url = NULL;
      if ((connection->read_close == MHD_YES) ||
          (0 != strcasecmp (MHD_HTTP_VERSION_1_1, connection->version)))
        {
          /* closed for reading => close for good! */
          if (connection->socket_fd != -1)
            {
#if DEBUG_CLOSE
#if HAVE_MESSAGES
              MHD_DLOG (connection->daemon,
                        "Closing connection (http 1.0 or end-of-stream for unknown content length)\n");
#endif
#endif
              SHUTDOWN (connection->socket_fd, SHUT_RDWR);
              CLOSE (connection->socket_fd);
            }
          connection->socket_fd = -1;
        }
      connection->version = NULL;
      connection->read_buffer = NULL;
      connection->write_buffer = NULL;
      connection->read_buffer_size = 0;
      connection->readLoc = 0;
      connection->write_buffer_size = 0;
      connection->writePos = 0;
      connection->writeLoc = 0;
      MHD_pool_destroy (connection->pool);
      connection->pool = NULL;
    }
  return MHD_YES;
}

/* end of connection.c */
