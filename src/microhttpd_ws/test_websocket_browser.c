/*
     This file is part of libmicrohttpd
     Copyright (C) 2021 David Gausmann

     libmicrohttpd is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     libmicrohttpd is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with libmicrohttpd; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/
/**
 * @file test_websocket_browser.c
 * @brief  Testcase for WebSocket decoding/encoding with external browser
 * @author David Gausmann
 */
#include <sys/types.h>
#ifndef _WIN32
#include <sys/select.h>
#include <sys/socket.h>
#include <fcntl.h>
#else
#include <winsock2.h>
#endif
#include "microhttpd.h"
#include "microhttpd_ws.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>

#define PORT 80

#define PAGE \
  "<!DOCTYPE html>\n" \
  "<html>\n" \
  "<head>\n" \
  "<meta charset=\"UTF-8\">\n" \
  "<title>Websocket External Test with Webbrowser</title>\n" \
  "<script>\n" \
  "\n" \
  "let current_mode  = 0;\n" \
  "let current_step  = 0;\n" \
  "let sent_payload  = null;\n" \
  "let charset       = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_!@%&/\\\\';\n" \
  "let step_to_bytes = [ 0, 1, 2, 3, 122, 123, 124, 125, 126, 127, 128, 32766, 32767, 32768, 65534, 65535, 65536, 65537, 1048576, 10485760 ];\n" \
  "let url = 'ws' + (window.location.protocol === 'https:' ? 's' : '')" \
    "  + ':/" "/' +\n" \
  "          window.location.host + '/websocket';\n" \
  "let socket = null;\n" \
  "\n" \
  "window.onload = function (event) {\n" \
  "  if (!window.WebSocket) {\n" \
  "    document.write ('ERROR: The WebSocket class is not supported by your browser.<br>');\n" \
  "  }\n" \
  "  if (!window.fetch) {\n" \
  "    document.write ('ERROR: The fetch-API is not supported by your browser.<br>');\n" \
  "  }\n" \
  "  document.write ('Starting tests.<br>');\n" \
  "  runTest ();\n" \
  "}\n" \
  "\n" \
  "function runTest () {\n" \
  "  switch (current_mode) {\n" \
  "  case 0:\n" \
  "    document.write ('TEXT');\n" \
  "    break;\n" \
  "  case 1:\n" \
  "    document.write ('BINARY');\n" \
  "    break;\n" \
  "  }\n" \
  "  document.write (', ' + step_to_bytes[current_step] + ' Bytes: ');\n" \
  "  socket = new WebSocket(url);\n" \
  "  socket.binaryType = 'arraybuffer';\n" \
  "  socket.onopen = function (event) {\n" \
  "    switch (current_mode) {\n" \
  "    case 0:\n" \
  "      sent_payload = randomText (step_to_bytes[current_step]);\n" \
  "      socket.send (sent_payload);\n" \
  "      break;\n" \
  "    case 1:\n" \
  "      sent_payload = randomBinary (step_to_bytes[current_step]);\n" \
  "      socket.send (sent_payload);\n" \
  "      break;\n" \
  "    }\n" \
  "  }\n" \
  "\n" \
  "  socket.onclose = function (event) {\n" \
  "    socket.onmessage = null;\n" \
  "    socket.onclose   = null;\n" \
  "    socket.onerror   = null;\n" \
  "    document.write ('CLOSED unexpectedly.<br>');\n" \
  "    notifyError ();\n" \
  "  }\n" \
  "\n" \
  "  socket.onerror = function (event) {\n" \
  "    socket.onmessage = null;\n" \
  "    socket.onclose   = null;\n" \
  "    socket.onerror   = null;\n" \
  "    document.write ('ERROR.<br>');\n" \
  "    notifyError ();\n" \
  "  }\n" \
  "\n" \
  "  socket.onmessage = async function (event) {\n" \
  "    if (compareData (event.data, sent_payload)) {\n" \
  "      document.write ('SUCCESS.<br>');\n" \
  "      socket.onmessage = null;\n" \
  "      socket.onclose   = null;\n" \
  "      socket.onerror   = null;\n" \
  "      socket.close();\n" \
  "      socket = null;\n" \
  "      if (step_to_bytes.length <= ++current_step) {\n" \
  "        current_step = 0;\n" \
  "        if (1 < ++current_mode) {\n" \
  "          document.write ('FINISHED ALL TESTS.<br>');\n" \
  "          return;\n" \
  "        }\n" \
  "      }\n" \
  "      runTest ();\n" \
  "    }" \
  "  }\n" \
  "}\n" \
  "\n" \
  "function compareData (data, data2) {\n" \
  "  if (typeof (data) === 'string' && typeof (data2) === 'string') {\n" \
  "    return (data === data2); \n" \
  "  } \n" \
  "  else if ((data instanceof ArrayBuffer) && (data2 instanceof ArrayBuffer)) {\n" \
  "    let view1 = new Uint8Array (data);\n" \
  "    let view2 = new Uint8Array (data2);\n" \
  "    if (view1.length != view2.length)\n" \
  "      return false;\n" \
  "    for (let i = 0; i < view1.length; ++i) {\n" \
  "      if (view1[i] !== view2[i])\n" \
  "        return false;\n" \
  "    }\n" \
  "    return true;\n" \
  "  }\n" \
  "  else\n" \
  "  {\n" \
  "    return false;\n" \
  "  }\n" \
  "}\n" \
  "\n" \
  "function randomText (length) {\n" \
  "  let result = new Array (length);\n" \
  "  for (let i = 0; i < length; ++i)\n" \
  "    result [i] = charset [~~(Math.random () * charset.length)];\n" \
  "  return result.join ('');\n" \
  "}\n" \
  "\n" \
  "function randomBinary (length) {\n" \
  "  let buffer = new ArrayBuffer (length);\n" \
  "  let view   = new Uint8Array (buffer);\n" \
  "  for (let i = 0; i < length; ++i)\n" \
  "    view [i] = ~~(Math.random () * 256);\n" \
  "  return buffer;\n" \
  "}\n" \
  "\n" \
  "function notifyError () {\n" \
  "  fetch('error/' + (0 == current_mode ? 'text' : 'binary') + '/' + step_to_bytes[current_step]);\n" \
  "}\n" \
  "\n" \
  "</script>\n" \
  "</head>\n" \
  "<body>\n" \
  "</body>\n" \
  "</html>"

#define PAGE_NOT_FOUND \
  "404 Not Found"

#define PAGE_INVALID_WEBSOCKET_REQUEST \
  "Invalid WebSocket request!"

static void
send_all (MHD_socket fd,
          const char *buf,
          size_t len);

static void
make_blocking (MHD_socket fd);

static void
upgrade_handler (void *cls,
                 struct MHD_Connection *connection,
                 void *req_cls,
                 const char *extra_in,
                 size_t extra_in_size,
                 MHD_socket fd,
                 struct MHD_UpgradeResponseHandle *urh)
{
  /* make the socket blocking (operating-system-dependent code) */
  make_blocking (fd);

  /* create a websocket stream for this connection */
  struct MHD_WebSocketStream *ws;
  int result = MHD_websocket_stream_init (&ws,
                                          0,
                                          0);
  if (0 != result)
  {
    /* Couldn't create the websocket stream.
     * So we close the socket and leave
     */
    MHD_upgrade_action (urh,
                        MHD_UPGRADE_ACTION_CLOSE);
    return;
  }

  /* Let's wait for incoming data */
  const size_t buf_len = 256;
  char buf[buf_len];
  ssize_t got;
  while (MHD_WEBSOCKET_VALIDITY_VALID == MHD_websocket_stream_is_valid (ws))
  {
    got = recv (fd,
                buf,
                sizeof (buf),
                0);
    if (0 >= got)
    {
      /* the TCP/IP socket has been closed */
      fprintf (stderr,
               "Error (The socket has been closed unexpectedly)\n");
      break;
    }

    /* parse the entire received data */
    size_t buf_offset = 0;
    while (buf_offset < (size_t) got)
    {
      size_t new_offset  = 0;
      char *payload_data = NULL;
      size_t payload_len = 0;
      char *frame_data   = NULL;
      size_t frame_len   = 0;
      int status = MHD_websocket_decode (ws,
                                         buf + buf_offset,
                                         ((size_t) got) - buf_offset,
                                         &new_offset,
                                         &payload_data,
                                         &payload_len);
      if (0 > status)
      {
        /* an error occurred and the connection must be closed */
        printf ("Decoding failed: status=%d, passed=%u\n", status,
                ((size_t) got) - buf_offset);
        if (NULL != payload_data)
        {
          MHD_websocket_free (ws, payload_data);
        }
        break;
      }
      else
      {
        buf_offset += new_offset;
        if (0 < status)
        {
          /* the frame is complete */
          printf (
            "Decoding succeeded: type=%d, passed=%u, parsed=%u, payload_len=%d\n",
            status, ((size_t) got) - buf_offset, new_offset, payload_len);
          switch (status)
          {
          case MHD_WEBSOCKET_STATUS_TEXT_FRAME:
          case MHD_WEBSOCKET_STATUS_BINARY_FRAME:
            /* The client has sent some data. */
            if ((NULL != payload_data) || (0 == payload_len))
            {
              /* Send the received data back to the client */
              if (MHD_WEBSOCKET_STATUS_TEXT_FRAME == status)
              {
                result = MHD_websocket_encode_text (ws,
                                                    payload_data,
                                                    payload_len,
                                                    0,
                                                    &frame_data,
                                                    &frame_len,
                                                    NULL);
              }
              else
              {
                result = MHD_websocket_encode_binary (ws,
                                                      payload_data,
                                                      payload_len,
                                                      0,
                                                      &frame_data,
                                                      &frame_len);
              }
              if (0 == result)
              {
                send_all (fd,
                          frame_data,
                          frame_len);
              }
            }
            else
            {
              /* should never happen */
              fprintf (stderr,
                       "Error (Empty buffer with payload_len != 0)\n");
            }
            break;

          default:
            /* Other frame types are ignored
             * in this test script.
             */
            break;
          }
        }
        if (NULL != payload_data)
        {
          MHD_websocket_free (ws, payload_data);
        }
        if (NULL != frame_data)
        {
          MHD_websocket_free (ws, frame_data);
        }
      }
    }
  }

  /* free the websocket stream */
  MHD_websocket_stream_free (ws);

  /* close the socket when it is not needed anymore */
  MHD_upgrade_action (urh,
                      MHD_UPGRADE_ACTION_CLOSE);
}


/* This helper function is used for the case that
 * we need to resend some data
 */
static void
send_all (MHD_socket fd,
          const char *buf,
          size_t len)
{
  ssize_t ret;
  size_t off;

  for (off = 0; off < len; off += ret)
  {
    ret = send (fd,
                &buf[off],
                (int) (len - off),
                0);
    if (0 > ret)
    {
      if (EAGAIN == errno)
      {
        ret = 0;
        continue;
      }
      break;
    }
    if (0 == ret)
      break;
  }
}


/* This helper function contains operating-system-dependent code and
 * is used to make a socket blocking.
 */
static void
make_blocking (MHD_socket fd)
{
#ifndef _WIN32
  int flags;

  flags = fcntl (fd, F_GETFL);
  if (-1 == flags)
    return;
  if ((flags & ~O_NONBLOCK) != flags)
    if (-1 == fcntl (fd, F_SETFL, flags & ~O_NONBLOCK))
      abort ();
#else
  unsigned long flags = 0;

  ioctlsocket (fd, FIONBIO, &flags);
#endif
}


static enum MHD_Result
access_handler (void *cls,
                struct MHD_Connection *connection,
                const char *url,
                const char *method,
                const char *version,
                const char *upload_data,
                size_t *upload_data_size,
                void **req_cls)
{
  static int aptr;
  struct MHD_Response *response;
  int ret;

  (void) cls;               /* Unused. Silent compiler warning. */
  (void) upload_data;       /* Unused. Silent compiler warning. */
  (void) upload_data_size;  /* Unused. Silent compiler warning. */

  if (0 != strcmp (method, "GET"))
    return MHD_NO;              /* unexpected method */
  if (&aptr != *req_cls)
  {
    /* do never respond on first call */
    *req_cls = &aptr;
    return MHD_YES;
  }
  *req_cls = NULL;                  /* reset when done */

  if (0 == strcmp (url, "/"))
  {
    /* Default page for visiting the server */
    struct MHD_Response *response = MHD_create_response_from_buffer (
      strlen (PAGE),
      PAGE,
      MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response (connection,
                              MHD_HTTP_OK,
                              response);
    MHD_destroy_response (response);
  }
  else if (0 == strncmp (url, "/error/", 7))
  {
    /* Report error */
    fprintf (stderr, "Error in test (%s)\n", url + 7);

    struct MHD_Response *response = MHD_create_response_from_buffer (
      0,
      "",
      MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response (connection,
                              MHD_HTTP_OK,
                              response);
    MHD_destroy_response (response);
  }
  else if (0 == strcmp (url, "/websocket"))
  {
    char is_valid = 1;
    const char *value = NULL;
    char sec_websocket_accept[29];

    if (0 != MHD_websocket_check_http_version (version))
    {
      is_valid = 0;
    }
    value = MHD_lookup_connection_value (connection,
                                         MHD_HEADER_KIND,
                                         MHD_HTTP_HEADER_CONNECTION);
    if (0 != MHD_websocket_check_connection_header (value))
    {
      is_valid = 0;
    }
    value = MHD_lookup_connection_value (connection,
                                         MHD_HEADER_KIND,
                                         MHD_HTTP_HEADER_UPGRADE);
    if (0 != MHD_websocket_check_upgrade_header (value))
    {
      is_valid = 0;
    }
    value = MHD_lookup_connection_value (connection,
                                         MHD_HEADER_KIND,
                                         MHD_HTTP_HEADER_SEC_WEBSOCKET_VERSION);
    if (0 != MHD_websocket_check_version_header (value))
    {
      is_valid = 0;
    }
    value = MHD_lookup_connection_value (connection,
                                         MHD_HEADER_KIND,
                                         MHD_HTTP_HEADER_SEC_WEBSOCKET_KEY);
    if (0 != MHD_websocket_create_accept_header (value, sec_websocket_accept))
    {
      is_valid = 0;
    }

    if (1 == is_valid)
    {
      /* upgrade the connection */
      response = MHD_create_response_for_upgrade (&upgrade_handler,
                                                  NULL);
      MHD_add_response_header (response,
                               MHD_HTTP_HEADER_UPGRADE,
                               "websocket");
      MHD_add_response_header (response,
                               MHD_HTTP_HEADER_SEC_WEBSOCKET_ACCEPT,
                               sec_websocket_accept);
      ret = MHD_queue_response (connection,
                                MHD_HTTP_SWITCHING_PROTOCOLS,
                                response);
      MHD_destroy_response (response);
    }
    else
    {
      /* return error page */
      struct MHD_Response *response = MHD_create_response_from_buffer (
        strlen (PAGE_INVALID_WEBSOCKET_REQUEST),
        PAGE_INVALID_WEBSOCKET_REQUEST,
        MHD_RESPMEM_PERSISTENT);
      ret = MHD_queue_response (connection,
                                MHD_HTTP_BAD_REQUEST,
                                response);
      MHD_destroy_response (response);
    }
  }
  else
  {
    struct MHD_Response *response = MHD_create_response_from_buffer (
      strlen (PAGE_NOT_FOUND),
      PAGE_NOT_FOUND,
      MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response (connection,
                              MHD_HTTP_NOT_FOUND,
                              response);
    MHD_destroy_response (response);
  }

  return ret;
}


int
main (int argc,
      char *const *argv)
{
  (void) argc;               /* Unused. Silent compiler warning. */
  (void) argv;               /* Unused. Silent compiler warning. */
  struct MHD_Daemon *daemon;

  daemon = MHD_start_daemon (MHD_USE_INTERNAL_POLLING_THREAD
                             | MHD_USE_THREAD_PER_CONNECTION
                             | MHD_ALLOW_UPGRADE
                             | MHD_USE_ERROR_LOG,
                             PORT, NULL, NULL,
                             &access_handler, NULL,
                             MHD_OPTION_END);

  if (NULL == daemon)
  {
    fprintf (stderr, "Error (Couldn't start daemon for testing)\n");
    return 1;
  }
  printf ("The server is listening now.\n");
  printf ("Access the server now with a websocket-capable webbrowser.\n\n");
  printf ("Press return to close.\n");

  (void) getc (stdin);

  MHD_stop_daemon (daemon);

  return 0;
}
