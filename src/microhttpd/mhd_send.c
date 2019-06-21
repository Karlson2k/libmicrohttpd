/*
  This file is part of libmicrohttpd
  Copyright (C) 2019 ng0 <ng0@n0.is>

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
 * @file microhttpd/mhd_send.c
 * @brief Implementation of send() wrappers.
 * @author ng0 <ng0@n0.is>
 */

// to be used in: send_param_adapter, MHD_send_
// and every place where sendfile(), sendfile64(), setsockopt()
// are used.
// TODO: sendfile() wrappers.

#include "platform.h"

// NOTE: TCP_CORK == TCP_NOPUSH in FreeBSD.
//       TCP_CORK is Linux.
//       TCP_CORK/TCP_NOPUSH: don't send out partial frames.
//       TCP_NODELAY: disable Nagle (aggregate data based on
//       buffer pressur).
// TODO: It is possible that Solaris/SunOS depending on
// the linked library needs a different setsockopt usage:
// https://stackoverflow.com/questions/48670299/setsockopt-usage-in-linux-and-solaris-invalid-argument-in-solaris

enum MHD_SendSocketOptions
{
  /* definitely no corking (use NODELAY, or explicitly disable cork) */
  MHD_SSO_NO_CORK = 0,
  /* should enable corking (use MSG_MORE, or explicitly enable cork) */
  MHD_SSO_MAY_CORK = 1,
  /*
   * consider tcpi_snd_mss and consider not corking for the header
   * part if the size of the header is close to the MSS.
   * Only used if we are NOT doing 100 Continue and are still
   * sending the header (provided in full as the buffer to
   * MHD_send_on_connection_ or as the header to
   * MHD_send_on_connection2_).
   */
  MHD_SSO_HDR_CORK = 2
};

/*
 * https://svnweb.freebsd.org/base/head/sys/netinet/tcp_usrreq.c?view=markup&pathrev=346360
 * Approximately in 2007 work began to make TCP_NOPUSH in FreeBSD
 * behave like TCP_CORK in Linux. Thus we define them to be one and
 * the same, which again could be platform dependent (NetBSD does
 * (so far) only provide a FreeBSD compatibility here, for example).
 * Since we only deal with IPPROTO_TCP flags in this file and nowhere
 * else, we don't have to move this elsewhere for now.
*/
/*
#if ! defined(TCP_CORK) && defined(TCP_NOPUSH)
#define TCP_CORK TCP_NOPUSH
#endif
*/
/*
 * -- OBJECTIVE:
 * connection: use member 'socket', and remember the
 * current state of the socket-options (cork/nocork/nodelay/whatever)
 * and only call setsockopt when absolutely necessary.
 *
 * -- NOTES:
 * Send 'buffer' on connection;
 * change socket options as required,
 * return -1 on error, otherwise # bytes sent.
 *
 * MHD_Connection is defined in ./internal.h
 * MHD_socket is defined in lib/mhd_sockets.h and the type
 * depends on the platform. However it is always a socket.
 */
ssize_t
MHD_send_on_connection_ (struct MHD_Connection *connection,
                         const char *buffer,
                         size_t buffer_size,
                         enum MHD_SendSocketOptions options)
{
  //size_t length, opt1, opt2;
  // ssize_t num_bytes;
  //int errno = 0;
  bool want_cork, have_cork, have_more;
  /* The socket. */
  MHD_socket s = connection->socket_fd;

  // new code...
  /* Get socket options, change/set options if necessary. */
  switch (options)
  {
  /* No corking */
  case MHD_SSO_NO_CORK:
    want_cork = false;
    break;
  /* Do corking, consider MSG_MORE instead if available */
  case MHD_SSO_MAY_CORK:
    want_cork = true;
    break;
    /* Cork the header */
  case MHD_SSO_HDR_CORK:
    want_cork = (buffer_size >= 1024) && (buffer_size <= 1220);
    break;
  }

  // ! could be avoided by redefining the variable
  have_cork = ! connection->sk_tcp_nodelay_on;

#ifdef MSG_MORE
  have_more = true;
#else
  have_more = false;
#endif

  bool use_corknopush;

#if HAVE_NODELAY
  use_corknopush = false;
#elif HAVE_CORK
  use_corknopush = true;
#elif HAVE_NOPUSH
  use_corknopush = true;
#endif

#if HAVE_CORK
  if (use_corknopush)
  {
    if (have_cork && ! want_cork)
    {
      setsockopt (s, IPPROTO_TCP, TCP_CORK, 1, sizeof (int)) ||
        (setsockopt (s, IPPROTO_TCP, TCP_NODELAY, 1, sizeof (int)) &&connection
           ->sk_tcp_nodelay = true);
      //setsockopt (cork-on); // or nodelay on // + update connection->sk_tcp_nodelay_on
      // When we have CORK, we can have NODELAY on the same system,
      // at least since Linux 2.2 and both can be combined since
      // Linux 2.5.71. See tcp(7). No other system in 2019-06 has TCP_CORK.
    }
  }
#elif HAVE_NOPUSH
  /*
 * TCP_NOPUSH on FreeBSD is equal to cork on Linux, with the
 * exception that we know that TCP_NOPUSH will definitely
 * exist and we can disregard TCP_NODELAY unless requested.
 */
  if (use_corknopush)
  {
    if (have_cork && ! want_cork)
    {
      setsockopt (s, IPPROTO_TCP, TCP_NOPUSH, 1, sizeof (int));
      // TODO: set corknopush to true here?
      // connection->sk_tcp_cork_nopush_on = true;
    }
  }
#endif
#if HAVE_NODELAY
  if (! use_corknopush)
  {
    if (! have_cork && want_cork)
    {
      // setsockopt (nodelay-off);
      setsockopt (s, IPPROTO_TCP, TCP_NODELAY, 0, sizeof (int));
      connection->sk_tcp_nodelay = false;
    }
    // ...
  }
#endif


  ret = send (s, buffer, buffer_size, want_cork ? MSG_MORE : 0);
  eno = errno;
#if HAVE_CORK
  if (use_corknopush)
  {
    if (! have_cork && want_cork && ! have_more)
    {
      //setsockopt (cork-off); // or nodelay off // + update connection->sk_tcp_nodelay_on
      setsockopt (s, IPPROTO_TCP, TCP_CORK, 0, sizeof (int)) ||
        (setsockopt (s, IPPROTO_TCP, TCP_NODELAY, 0, sizeof (int)) &&connection
           ->sk_tcp_nodelay_on = false);
    }
  }
#elif HAVE_NOPUSH
  // We don't have MSG_MORE.
  if (use_corknopush)
  {
    // ...
  }
#endif

#if HAVE_NODELAY
  if (! use_corknopush)
  {
    if (have_cork && ! want_cork)
    {
      // setsockopt (nodelay - on);
      setsockopt (s,
                  IPPROTO_TCP,
                  TCP_NODELAY,
                  1,
                  sizeof (int)) &&connection->sk_tcp_nodelay_on = true;
    }
    // ...
  }
#endif
  errno = eno;
  return ret;
}


// * Send header followed by buffer on connection;
// * uses writev if possible to send both at once
// * returns the sum of the number of bytes sent from
// * both buffers, or -1 on error;
// * if writev is
// unavailable, this call MUST only send from 'header'
// (as we cannot handle the case that the first write
// succeeds and the 2nd fails!).
ssize_t
MHD_send_on_connection2_ (struct MHD_Connection *connection,
                          const char *header,
                          size_t header_size,
                          const char *buffer,
                          size_t buffer_size)
{
#if HAVE_WRITEV
  MHD_socket s = connection->socket_fd;
  bool have_cork, have_more;
  int iovcnt;
  struct iovec vector[2];

  have_cork = ! connection->sk_tcp_nodelay_on;
#if HAVE_NODELAY
  use_corknopush = false;
#elif HAVE_CORK
  use_corknopush = true;
#elif HAVE_NOPUSH
  use_corknopush = true;
#endif

#if HAVE_NODELAY
  if (! use_corknopush)
  {
    if (! have_cork && want_cork)
    {
      // setsockopt (nodelay-off);
      setsockopt (s, IPPROTO_TCP, TCP_NODELAY, 0, sizeof (int));
      connection->sk_tcp_nodelay = false;
    }
    // ...
  }
#endif

  vector[0].iov_base = header;
  vector[0].iov_len = strlen (header);
  vector[1].iov_base = buffer;
  vector[1].iov_len = strlen (buffer);
  iovcnt = sizeof (vector) / sizeof (struct iovec);
  ret = writev (s, vector, iovcnt);
#if HAVE_CORK
  {
    int eno;

    eno = errno;
    if ((ret == header_len + buffer_len) && have_cork)
    {
      // response complete, definitely uncork!
      // setsockopt (cork-off);
      setsockopt (s, IPPROTO_TCP, TCP_CORK, 0, sizeof (int));
      // connection->sk_tcp_cork_nopush_on = true;
    }
    errno = eno;
  }
  return ret;
#else
  return MHD_send_on_connection_ (connection,
                                  header,
                                  header_size,
                                  MHD_SSO_HDR_CORK);
#endif
}
