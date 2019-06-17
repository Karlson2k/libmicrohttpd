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
 * @brief Implementation of send() and sendfile() wrappers.
 * @author ng0 <ng0@n0.is>
 */

// to be used in: send_param_adapter, MHD_send_
// and every place where sendfile(), sendfile64(), setsockopt()
// are used.

#include "platform.h"

// NOTE: TCP_CORK == TCP_NOPUSH in FreeBSD.
//       TCP_CORK is Linux.
//       TCP_CORK/TCP_NOPUSH: don't send out partial frames.
//       TCP_NODELAY: disable Nagle (aggregate data based on
//       buffer pressur).

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
#if ! defined(TCP_CORK) && defined(TCP_NOPUSH)
#define TCP_CORK TCP_NOPUSH
#endif

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
                         enum MHD_SendSocketOptions)
{
  size_t length, opt1, opt2;
  ssize_t num_bytes;
  int errno = 0;
  /* s: the socket. */
  MHD_socket s = connection->socket_fd;

  /* Get socket options, change/set options if necessary. */
  switch (MHD_SendSocketOptions)
  {
  /* No corking */
  case 0:
    if (! connection->sk_tcp_nodelay_on)
    {
      opt1 = 1;
      opt2 = sizeof (int);
      /* 
       * TODO: It is possible that Solaris/SunOS depending on
       * the linked library needs a different setsockopt usage:
       * https://stackoverflow.com/questions/48670299/setsockopt-usage-in-linux-and-solaris-invalid-argument-in-solaris
       */
      if (0 == setsockopt (s, IPPROTO_TCP, TCP_NODELAY, &opt1, opt2))
      {
        connection->sk_tcp_nodelay_on = true;
      }
      else
      {
        /*
	 * TODO: use last return from setsockopt
	 * here, which for error is -1 when its
	 * implementation is POSIX conform.
	 */
        errno = -1;
      }
    }
  /* Do corking, do MSG_MORE instead if available */
  case 1:
#if defined(TCP_CORK) && ! defined(MSG_MORE)
    /*
     * We have TCP_CORK and we don't have MSG_MORE.
     * This means we want to enable corking.
     * Check if our corking boolean is not already set.
     */
    if (! connection->sk_tcp_cork_nopush_on)
    {
      /* 
       * corking boolean is false. We want to enable
       * Corking then.
       */
      opt1 = 1;
      opt2 = sizeof (int);
      /*
       * If we succesfully set TCP_CORK, set the corking
       * boolean to true.
       */
      if (0 == setsockopt (s, IPPROTO_TCP, TCP_CORK, &opt1, opt2))
      {
        connection->sk_tcp_cork_nopush_on = true;
      }
      /* And if we don't, set errno to -1. */
      else
      {
        errno = -1;
      }
    }
#endif
#ifdef MSG_MORE
    /*
     * We have MSG_MORE. This means we want to use MSG_MORE
     * for send() and keep the socket on NODELAY.
     * Check if our nodelay boolean is false.
     */
    if (! connection->sk_tcp_nodelay_on)
    {
      /*
       * If we have MSG_MORE, keep the
       * socket on NO_DELAY / NO_CORK.
       * Since MSG_MORE is an argument to
       * send(), in some cases we will be
       * using send() with MSG_MORE.
       */
      opt1 = 1;
      opt2 = sizeof (int);
      /*
       * If we successfully set TCP_NODELAY, set the nodelay
       * boolean to true.
       */
      if (0 == setsockopt (s, IPPROTO_TCP, TCP_NODELAY, &opt1, opt2))
      {
        connection->sk_tcp_nodelay_on = true;
      }
      else
      {
        errno = -1;
      }
    }
#endif
  /* Cork the header */
  case 2:
    if (something_with_snd_mss > (sizeof (buffer - 10)))
    { // magic guessing?
      if ((! 100_Continue) && (sending_header))
      {
        // uncork
        if (connection->sk_tcp_cork_nopush_on)
        {
          opt1 = 0;
          opt2 = sizeof (int);
          if (0 == setsockopt (s, IPPROTO_TCP, TCP_CORK, &opt1, opt2))
            connection->sk_tcp_cork_nopush_on = false;
        }
        // setsockopt() uncork flag
        opt1 = 1;
        opt2 = sizeof (int);
        if (0 == setsockopt (s, IPPROTO_TCP, TCP_NODELAY, &opt1, opt2))
          connection->sk_tcp_nodelay_on = true;
        // -> if we now cork again, would that
        // be too much for this case? If we
        // want to cork, we use case 1.
      }
    }
  }
}
if (1 == MHD_SendSocketOptions)
{
#ifdef MSG_MORE
  num_bytes = send (s, buffer, buffer_size, MSG_MORE);
#else
  num_bytes = send (s, buffer, buffer_size);
#endif
}
else
{
  num_bytes = send (s, buffer, buffer_size);
}
// -- pseudo Start:
// set socket := connect->MHD_socket
// get stateof(socket)
// in case 0,1,2 where case from MHD_SendSocketOptions do
// 	$case:
// 	setsockopt PLATFORM_ACCORDINGLY
// 	"update socket state"
// send(socket, buffer, buffer_size)
// if socketError:
// 	return -1
// return numBytes
// -- pseudo End
// error
/*
   * send() returns -1 on error, we might as well return num_bytes,
   * but we need to catch the errors before send().
   */
if (0 != errno)
  return -1;
if (0 == errno)
  return num_bytes;
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
                          size_t buffer_size,
                          enum MHD_SendSocketOptions)
{
	int errno = 0;
  MHD_socket s = connection->socket_fd;
  // -- <pseudo>
  // set socket := connect->MHD_socket
  // in case 0,1,2 where case from MHD_SendSocketOptions do
  // 	$case:
  // 	setsockopt
  // 	update boolean
  // nbuffer = header + buffer
  // #if defined(WRITEV)
  // struct iovec vector[2];
  // vector[0].iov_base = header;
  // vector[0].iov_len = header_size;
  // vector[1].iov_base = buffer;
  // vector[1].iov_len = buffer_size;
  // i = writev(s, &vector[0], 2);
  // num_bytes = send(socket, i, WHATSIZE?)
  // #else
  // //not available, send a combination of header + buffer.
  // size_t nbuffersize = buffer_size + header_size
  // num_bytes = send(socket, nbuffer, nbuffersize)
  // #endif
  // if socketError:
  // 	return -1
  // return numBytes
  // -- </pseudo>
#ifdef WRITEV
  int iovcnt;
  // TODO: iovec/writev needs no alloc, but consider looking into mmap?
  struct iovec vector[2];
  vector[0].iov_base = header;
  vector[0].iov_len = strlen (header);
  vector[1].iov_base = buffer;
  vector[1].iov_len = strlen (buffer);
  iovcnt = sizeof (vector) / sizeof (struct iovec);
  int i = writev (s, vector, iovcnt);
  fprintf (stdout, "i=%d, errno=%d\n", i, errno);
#else
  // wait for phonecall clearing this up?
  // COMMENTARY: not available, send a combination of header + buffer.
  size_t concatsize = header_size + buffer_size;
  const char *concatbuffer;
  concatbuffer = header + buffer;
#ifdef MSG_MORE
  num_bytes = send (s, concatbuffer, concatsize, MSG_MORE);
#else
  num_bytes = send (s, concatbuffer, concatsize);
#endif
#endif
  struct tcp_info *tcp_;
  size_t opt1, opt2, length;
  switch (MHD_SendSocketOptions)
  {
  case 0:
	  /* No corking */
  case 1:
  case 2:
  }
if (1 == MHD_SendSocketOptions)
{
	// bla
}
  if (0 != errno)
    return -1;
  if (0 == errno)
    return num_bytes;
}
