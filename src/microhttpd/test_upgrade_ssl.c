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
 * @file test_upgrade_ssl.c
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
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include "mhd_sockets.h"

#include "../testcurl/https/tls_test_keys.h"


/**
 * Thread we use to run the interaction with the upgraded socket.
 */
static pthread_t pt;

/**
 * Will be set to the upgraded socket.
 */
static MHD_socket usock;

/**
 * Fork child that connects via OpenSSL to our @a port.  Allows us to
 * talk to our port over a socket in @a sp without having to worry
 * about TLS.
 *
 * @param location where the socket is returned
 * @return -1 on error, otherwise PID of SSL child process
 */
static pid_t
openssl_connect (int *sock,
                 uint16_t port)
{
  pid_t chld;
  int sp[2];
  char destination[30];

  if (0 != socketpair (AF_UNIX,
                       SOCK_STREAM,
                       0,
                       sp))
    return -1;
  chld = fork ();
  if (0 != chld)
    {
      *sock = sp[1];
      MHD_socket_close_ (sp[0]);
      return chld;
    }
  MHD_socket_close_ (sp[1]);
  (void) close (0);
  (void) close (1);
  dup2 (sp[0], 0);
  dup2 (sp[0], 1);
  close (sp[0]);
  sprintf (destination,
           "localhost:%u",
           (unsigned int) port);
  execlp ("openssl",
          "openssl",
          "s_client",
          "-connect",
          destination,
          "-verify",
          "0",
          // "-quiet",
          (char *) NULL);
  _exit (1);
}


/**
 * Change itc FD options to be non-blocking.
 *
 * @param fd the FD to manipulate
 * @return non-zero if succeeded, zero otherwise
 */
static void
make_blocking (MHD_socket fd)
{
  int flags;

  flags = fcntl (fd, F_GETFL);
  if (-1 == flags)
    return;
  if ((flags & ~O_NONBLOCK) != flags)
    fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);
}


static void
send_all (MHD_socket sock,
          const char *text)
{
  size_t len = strlen (text);
  ssize_t ret;

  make_blocking (sock);
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

  make_blocking (sock);
  next = '\r';
  i = 0;
  while (i < 4)
    {
      ret = read (sock,
                  &c,
                  1);
      if (0 == ret)
        abort (); /* this is fatal */
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

  make_blocking (sock);
  for (size_t off = 0; off < len; off += ret)
    {
      ret = read (sock,
                  &buf[off],
                  len - off);
      if (0 == ret)
        abort (); /* this is fatal */
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
 * Main function for the thread that runs the interaction with
 * the upgraded socket.
 *
 * @param cls the handle for the upgrade
 */
static void *
run_usock (void *cls)
{
  struct MHD_UpgradeResponseHandle *urh = cls;

  fprintf (stderr,
           "Sending `Hello'\n");
  send_all (usock,
            "Hello");
  fprintf (stderr,
           "Receiving `World'\n");
  recv_all (usock,
            "World");
  fprintf (stderr,
           "Sending `Finished'\n");
  send_all (usock,
            "Finished");
  fprintf (stderr,
           "Closing socket\n");
  while (MHD_NO ==
         MHD_upgrade_action (urh,
                             MHD_UPGRADE_ACTION_FLUSH))
    usleep (1000);
  MHD_upgrade_action (urh,
                      MHD_UPGRADE_ACTION_CLOSE);
  fprintf (stderr,
           "Thread terminating\n");
  return NULL;
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
  usock = sock;
  if (0 != extra_in_size)
    abort ();
  pthread_create (&pt,
                  NULL,
                  &run_usock,
                  urh);
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
  pid_t pid;

  d = MHD_start_daemon (MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG | MHD_USE_SUSPEND_RESUME | MHD_USE_TLS,
                        1080,
                        NULL, NULL,
                        &ahc_upgrade, NULL,
                        MHD_OPTION_HTTPS_MEM_KEY, srv_signed_key_pem,
                        MHD_OPTION_HTTPS_MEM_CERT, srv_signed_cert_pem,
                        MHD_OPTION_END);
  if (NULL == d)
    return 2;
  if (-1 == (pid = openssl_connect (&sock, 1080)))
    {
      MHD_stop_daemon (d);
      return 4;
    }

  send_all (sock,
            "GET / HTTP/1.1\r\nConnection: Upgrade\r\n\r\n");
  recv_hdr (sock);
  recv_all (sock,
            "Hello");
  fprintf (stderr,
           "Received `Hello'\n");
  send_all (sock,
            "World");
  fprintf (stderr,
           "Sent `World'\n");
  recv_all (sock,
            "Finished");
  fprintf (stderr,
           "Received `Finished'\n");
  MHD_socket_close_ (sock);
  pthread_join (pt,
                NULL);
  fprintf (stderr,
           "Joined helper thread\n");
  waitpid (pid, NULL, 0);
  MHD_stop_daemon (d);
  return 0;
}


int
main (int argc,
      char *const *argv)
{
  int errorCount = 0;

  if (0 != system ("openssl version 1> /dev/null"))
    return 77; /* openssl not available, can't run the test */
  errorCount += test_upgrade_internal_select ();
  if (errorCount != 0)
    fprintf (stderr,
             "Error (code: %u)\n",
             errorCount);
  return errorCount != 0;       /* 0 == pass */
}
