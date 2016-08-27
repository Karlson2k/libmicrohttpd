/*
     This file is part of libmicrohttpd
     Copyright (C) 2016 Christian Grothoff

     libmicrohttpd is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file test_upgrade.c
 * @brief  Testcase for libmicrohttpd upgrading a connection
 * @author Christian Grothoff
 */

#include "platform.h"
#include "microhttpd.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#ifndef WINDOWS
#include <unistd.h>
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include "mhd_sockets.h"


static void
send_all (MHD_socket sock,
          const char *text)
{
  size_t len = strlen (text);
  ssize_t ret;

  for (size_t off = 0; off < len; off += ret)
    {
      ret = write (sock,
                   &text[off],
                   len - off);
      if (-1 == ret)
        {
          if (EAGAIN == errno)
            {
              ret = 0;
              continue;
            }
          abort ();
        }
    }
}


/**
 * Read character-by-character until we
 * get '\r\n\r\n'.
 */
static void
recv_hdr (MHD_socket sock)
{
  unsigned int i;
  char next;
  char c;
  ssize_t ret;

  next = '\r';
  i = 0;
  while (i < 4)
    {
      ret = read (sock,
                  &c,
                  1);
      if (-1 == ret)
        {
          if (EAGAIN == errno)
            {
              ret = 0;
              continue;
            }
          abort ();
        }
      if (0 == ret)
        continue;
      if (c == next)
        {
          i++;
          if (next == '\r')
            next = '\n';
          else
            next = '\r';
          continue;
        }
      if (c == '\r')
        {
          i = 1;
          next = '\n';
          continue;
        }
      i = 0;
      next = '\r';
    }
}


static void
recv_all (MHD_socket sock,
          const char *text)
{
  size_t len = strlen (text);
  char buf[len];
  ssize_t ret;

  for (size_t off = 0; off < len; off += ret)
    {
      ret = read (sock,
                  &buf[off],
                  len - off);
      if (-1 == ret)
        {
          if (EAGAIN == errno)
            {
              ret = 0;
              continue;
            }
          abort ();
        }
    }
  if (0 != strncmp (text, buf, len))
    abort();
}


/**
 * Function called after a protocol "upgrade" response was sent
 * successfully and the socket should now be controlled by some
 * protocol other than HTTP.
 *
 * Any data received on the socket will be made available in
 * 'data_in'.  The function should update 'data_in_size' to
 * reflect the number of bytes consumed from 'data_in' (the remaining
 * bytes will be made available in the next call to the handler).
 *
 * Any data that should be transmitted on the socket should be
 * stored in 'data_out'.  '*data_out_size' is initially set to
 * the available buffer space in 'data_out'.  It should be set to
 * the number of bytes stored in 'data_out' (which can be zero).
 *
 * The return value is a BITMASK that indicates how the function
 * intends to interact with the event loop.  It can request to be
 * notified for reading, writing, request to UNCORK the send buffer
 * (which MHD is allowed to ignore, if it is not possible to uncork on
 * the local platform), to wait for the 'external' select loop to
 * trigger another round.  It is also possible to specify "no events"
 * to terminate the connection; in this case, the
 * #MHD_RequestCompletedCallback will be called and all resources of
 * the connection will be released.
 *
 * Except when in 'thread-per-connection' mode, implementations
 * of this function should never block (as it will still be called
 * from within the main event loop).
 *
 * @param cls closure, whatever was given to #MHD_create_response_for_upgrade().
 * @param connection original HTTP connection handle,
 *                   giving the function a last chance
 *                   to inspect the original HTTP request
 * @param con_cls last value left in `*con_cls` in the `MHD_AccessHandlerCallback`
 * @param extra_in if we happened to have read bytes after the
 *                 HTTP header already (because the client sent
 *                 more than the HTTP header of the request before
 *                 we sent the upgrade response),
 *                 these are the extra bytes already read from @a sock
 *                 by MHD.  The application should treat these as if
 *                 it had read them from @a sock.
 * @param extra_in_size number of bytes in @a extra_in
 * @param sock socket to use for bi-directional communication
 *        with the client.  For HTTPS, this may not be a socket
 *        that is directly connected to the client and thus certain
 *        operations (TCP-specific setsockopt(), getsockopt(), etc.)
 *        may not work as expected (as the socket could be from a
 *        socketpair() or a TCP-loopback)
 * @param urh argument for #MHD_upgrade_action()s on this @a connection.
 *        Applications must eventually use this function to perform the
 *        close() action on the @a sock.
 */
static void
upgrade_cb (void *cls,
            struct MHD_Connection *connection,
            void *con_cls,
            const char *extra_in,
            size_t extra_in_size,
            MHD_socket sock,
            struct MHD_UpgradeResponseHandle *urh)
{
  send_all (sock, "Hello");
  recv_all (sock, "World");
  send_all (sock, "Finished");
  MHD_upgrade_action (urh,
                      MHD_UPGRADE_ACTION_CLOSE);
}


/**
 * A client has requested the given url using the given method
 * (#MHD_HTTP_METHOD_GET, #MHD_HTTP_METHOD_PUT,
 * #MHD_HTTP_METHOD_DELETE, #MHD_HTTP_METHOD_POST, etc).  The callback
 * must call MHD callbacks to provide content to give back to the
 * client and return an HTTP status code (i.e. #MHD_HTTP_OK,
 * #MHD_HTTP_NOT_FOUND, etc.).
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param url the requested url
 * @param method the HTTP method used (#MHD_HTTP_METHOD_GET,
 *        #MHD_HTTP_METHOD_PUT, etc.)
 * @param version the HTTP version string (i.e.
 *        #MHD_HTTP_VERSION_1_1)
 * @param upload_data the data being uploaded (excluding HEADERS,
 *        for a POST that fits into memory and that is encoded
 *        with a supported encoding, the POST data will NOT be
 *        given in upload_data and is instead available as
 *        part of #MHD_get_connection_values; very large POST
 *        data *will* be made available incrementally in
 *        @a upload_data)
 * @param upload_data_size set initially to the size of the
 *        @a upload_data provided; the method must update this
 *        value to the number of bytes NOT processed;
 * @param con_cls pointer that the callback can set to some
 *        address and that will be preserved by MHD for future
 *        calls for this request; since the access handler may
 *        be called many times (i.e., for a PUT/POST operation
 *        with plenty of upload data) this allows the application
 *        to easily associate some request-specific state.
 *        If necessary, this state can be cleaned up in the
 *        global #MHD_RequestCompletedCallback (which
 *        can be set with the #MHD_OPTION_NOTIFY_COMPLETED).
 *        Initially, `*con_cls` will be NULL.
 * @return #MHD_YES if the connection was handled successfully,
 *         #MHD_NO if the socket must be closed due to a serios
 *         error while handling the request
 */
static int
ahc_upgrade (void *cls,
             struct MHD_Connection *connection,
             const char *url,
             const char *method,
             const char *version,
             const char *upload_data,
             size_t *upload_data_size,
             void **con_cls)
{
  struct MHD_Response *resp;
  int ret;

  resp = MHD_create_response_for_upgrade (&upgrade_cb,
                                          NULL);
  MHD_add_response_header (resp,
                           MHD_HTTP_HEADER_UPGRADE,
                           "Hello World Protocol");
  ret = MHD_queue_response (connection,
                            MHD_HTTP_SWITCHING_PROTOCOLS,
                            resp);
  MHD_destroy_response (resp);
  return ret;
}


static int
test_upgrade_internal_select ()
{
  struct MHD_Daemon *d;
  MHD_socket sock;
  struct sockaddr_in sa;

  d = MHD_start_daemon (MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG | MHD_USE_SUSPEND_RESUME,
                        1080,
                        NULL, NULL,
                        &ahc_upgrade, NULL,
                        MHD_OPTION_END);
  if (NULL == d)
    return 2;
  sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (MHD_INVALID_SOCKET == sock)
    abort ();
  sa.sin_family = AF_INET;
  sa.sin_port = htons (1080);
  sa.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  if (0 != connect (sock, (struct sockaddr *) &sa, sizeof (sa)))
    abort ();
  send_all (sock,
            "GET / HTTP/1.1\r\nConnection: Upgrade\r\n\r\n");
  recv_hdr (sock);
  recv_all (sock,
            "Hello");
  send_all (sock,
            "World");
  recv_all (sock,
            "Finished");
  MHD_socket_close_ (sock);
  MHD_stop_daemon (d);
  return 0;
}


int
main (int argc, char *const *argv)
{
  int errorCount = 0;

  errorCount += test_upgrade_internal_select ();
  if (errorCount != 0)
    fprintf (stderr, "Error (code: %u)\n", errorCount);
  return errorCount != 0;       /* 0 == pass */
}
