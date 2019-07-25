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

/* TODO: sendfile() wrapper, in connection.c */

/* Worth considering for future improvements and additions:
 * NetBSD has no sendfile or sendfile64. The way to work
 * with this seems to be to mmap the file and write(2) as
 * large a chunk as possible to the socket. Alternatively,
 * use madvise(..., MADV_SEQUENTIAL). */

/* Functions to be used in: send_param_adapter, MHD_send_
 * and every place where sendfile(), sendfile64(), setsockopt()
 * are used. */

#include "mhd_send.h"

int
post_cork_setsockopt (struct MHD_Connection *connection,
                      bool want_cork)
{
  int ret;
  bool using_tls = false;
  // const MHD_SCKT_OPT_BOOL_ state_val = val ? 1 : 0;
  const MHD_SCKT_OPT_BOOL_ off_val = 0;
  const MHD_SCKT_OPT_BOOL_ on_val = 1;
#ifdef HTTPS_SUPPORT
  using_tls = (0 != (connection->daemon->options & MHD_USE_TLS));
#endif

  if (using_tls)
    {
      // not sure.
      return 0; // ? without a value I get a return type error.
    }

#if TCP_CORK
  ret = setsockopt (connection->socket_fd,
                    IPPROTO_TCP,
                    TCP_CORK,
                    (const void *) &on_val,
                    sizeof (on_val));
#elif TCP_NODELAY
  ret = setsockopt (connection->socket_fd,
                    IPPROTO_TCP,
                    TCP_NODELAY,
                    (const void *) &off_val,
                    sizeof (off_val));
#elif TCP_NOPUSH
  ret = setsockopt (connection->socket_fd,
                    IPPROTO_TCP,
                    TCP_NOPUSH,
                    (const void *) &on_val,
                    sizeof (on_val));
#else
  ret = -1;
#endif
  if (0 == ret)
    {
      connection->sk_tcp_nodelay_on = false;
    }
  return ret;
}

int
pre_cork_setsockopt (struct MHD_Connection *connection,
                     bool want_cork,
                     bool val)
{
  int ret;
  bool using_tls = false;
  const MHD_SCKT_OPT_BOOL_ state_val = val ? 1 : 0;
  const MHD_SCKT_OPT_BOOL_ off_val = 0;
  const MHD_SCKT_OPT_BOOL_ on_val = 1;
#ifdef HTTPS_SUPPORT
  using_tls = (0 != (connection->daemon->options & MHD_USE_TLS));
#endif

  if (using_tls)
    {
      // more gnutls work?
      // or all of it because we want to somehow handle the tls and error handling for it here?
      return 0; // return type error
    }

  // if sk_tcp_nodelay_on is already what we pass in, return.
  if (connection->sk_tcp_nodelay_on == val)
    {
      return 0; // return type error
    }

#if TCP_CORK
  ret = setsockopt (connection->socket_fd,
                    IPPROTO_TCP,
                    TCP_CORK,
                    (const void *) &off_val,
                    sizeof (off_val));
#elif TCP_NODELAY
  ret = setsockopt (connection->socket_fd,
                    IPPROTO_TCP,
                    TCP_NODELAY,
                    (const void *) &on_val,
                    sizeof (on_val));
#elif TCP_NOPUSH
  ret = setsockopt (connection->socket_fd,
                    IPPROTO_TCP,
                    TCP_NOPUSH,
                    (const void *) &on_val,
                    sizeof (on_val));
#else
  ret = -1;
#endif
  if (0 == ret)
    {
      connection->sk_tcp_nodelay_on = val;
    }
}

/**
 * Set TCP_NODELAY flag on socket and save the
 * #sk_tcp_nodelay_on state.
 *
 * @param connection the MHD_Connection structure
 * @param value the state to set, boolean
 */
void
MHD_send_socket_state_nodelay_ (struct MHD_Connection *connection,
                                bool value)
{
#if TCP_NODELAY
  const MHD_SCKT_OPT_BOOL_ state_val = value ? 1 : 0;

  if (0 == setsockopt (connection->socket_fd,
                       IPPROTO_TCP,
                       TCP_NODELAY,
                       (const void *) &state_val,
                       sizeof (state_val)))
    {
      connection->sk_tcp_nodelay_on = value;
    }
#endif
}

/*
void
MHD_setsockopt_pre_ (struct MHD_Connection *connection,
                     bool value)
{
  bool using_tls = false;
#ifdef HTTPS_SUPPORT
  using_tls = (0 != (connection->daemon->options & MHD_USE_TLS));
#endif
  const MHD_SCKT_OPT_BOOL_ state_val = value ? 1 : 0;
  const MHD_SCKT_OPT_BOOL_ off_val = 0;
  const MHD_SCKT_OPT_BOOL_ on_val = 1;

  if (connection->sk_tcp_nodelay_on == value)
    {
      return
    }
  if (0 == setsockopt (connection->socket_fd,
                       IPPROTO_TCP,
#if TCP_CORK && (! using_tls)
                       TCP_CORK,
                       (const void *) &off_val,
                       sizeof (off_val)))
    {
      connection->sk_tcp_nodelay_on = on_val;
    }
#elif TCP_NODELAY
  TCP_NODELAY,
                         (const void *) &off_val,
                         sizeof (off_val)))
#endif
#if TCP_NOPUSH
#endif
                       (const void *) &state_val,
                       sizeof (state_val)))
}
*/
/*
void
MHD_setsockopt_post_ (struct MHD_Connection *connection,
                      bool value)
{
  if (connection->sk_tcp_nodelay_on == value)
    {
      return
    }
  if (0 == setsockopt (connection->socket_fd,
                       IPPROTO_TCP,
#if TCP_NODELAY
                       TCP_NODELAY,
#endif
#if TCP_NOPUSH
                       TCP_NOPUSH,
#endif
#if TCP_CORK
                       TCP_CORK,
#endif


                       (const void *) &state_val,
                       sizeof (state_val)))
    {
      // When TRUE above, this is usually FALSE, but
      // not always. We can't use the negation of
      // value for that reason.
      connection->sk_tcp_nodelay_on = state_store;
    }
}
*/
void
MHD_setsockopt_ (struct MHD_Connection *connection,
                 int optname,
                 bool value,
                 bool state_store)
{
  const MHD_SCKT_OPT_BOOL_ state_val = value ? 1 : 0;

  if (0 == setsockopt (connection->socket_fd,
                       IPPROTO_TCP,
                       optname,
                       (const void *) &state_val,
                       sizeof (state_val)))
    {
      connection->sk_tcp_nodelay_on = state_store;
    }
}

/**
 * Set TCP_NOCORK or TCP_NODELAY flag on socket and save the
 * #sk_tcp_nodelay_on state.
 *
 * @param connection the MHD_Connection structure
 * @param cork_value the state to set, boolean
 * @param cork_state the boolean value passed to #sk_tcp_nodelay_on
 * @param nodelay_value the state to set, boolean
 * @param nodelay_state the boolean value passed to #sk_tcp_nodelay_on
 */
void
MHD_send_socket_state_cork_nodelay_ (struct MHD_Connection *connection,
                                     bool cork_value,
                                     bool cork_state,
                                     bool nodelay_value,
                                     bool nodelay_state)
{
#if TCP_CORK && TCP_NODELAY
  const MHD_SCKT_OPT_BOOL_ cork_state_val = cork_value ? 1 : 0;
  const MHD_SCKT_OPT_BOOL_ nodelay_state_val = nodelay_value ? 1 : 0;

  if (0 == setsockopt (connection->socket_fd,
                       IPPROTO_TCP,
                       TCP_CORK,
                       (const void *) &cork_state_val,
                       sizeof (cork_state_val)))
    {
      connection->sk_tcp_nodelay_on = cork_state;
    }
  else if (0 == setsockopt (connection->socket_fd,
                            IPPROTO_TCP,
                            TCP_NODELAY,
                            (const void *) &nodelay_state_val,
                            sizeof (nodelay_state_val)))
    {
      connection->sk_tcp_nodelay_on = nodelay_state;
    }
#endif
}

/**
 * Set TCP_NOPUSH flag on socket and save the
 * #sk_tcp_nodelay_on state.
 *
 * @param connection the #MHD_Connection structure
 * @param value the state to set, boolean
 * @param state_store the boolean value passed to #sk_tcp_nodelay_on
 */
void
MHD_send_socket_state_nopush_ (struct MHD_Connection *connection,
                               bool value,
                               bool state_store)
{
#if TCP_NOPUSH
  const MHD_SCKT_OPT_BOOL_ state_val = value ? 1 : 0;

  if (0 == setsockopt (connection->socket_fd,
                       IPPROTO_TCP,
                       TCP_NOPUSH,
                       (const void *) &state_val,
                       sizeof (state_val)))
    {
      /* When TRUE above, this is usually FALSE, but
       * not always. We can't use the negation of
       * value for that reason. */
      connection->sk_tcp_nodelay_on = state_store;
    }
#endif
}

/**
 * Send buffer on connection, and remember the current state of
 * the socket options; only call setsockopt when absolutely
 * necessary.
 *
 * @param connection the MHD_Connection structure
 * @param buffer content of the buffer to send
 * @param buffer_size the size of the buffer (in bytes)
 * @param options the #MHD_SendSocketOptions enum,
 *         #MHD_SSO_NO_CORK: definitely no corking (use NODELAY, or explicitly disable cork),
 *         #MHD_SSO_MAY_CORK: should enable corking (use MSG_MORE, or explicitly enable cork),
 *         #MHD_SSO_HDR_CORK: consider tcpi_snd_mss and consider not corking for the header
 *         part if the size of the header is close to the MSS.
 *         Only used if we are NOT doing 100 Continue and are still sending the
 *         header (provided in full as the buffer to #MHD_send_on_connection_ or as
 *         the header to #MHD_send_on_connection2_).
 * @return sum of the number of bytes sent from both buffers or
 *         -1 on error
 */
ssize_t
MHD_send_on_connection_ (struct MHD_Connection *connection,
                         const char *buffer,
                         size_t buffer_size,
                         enum MHD_SendSocketOptions options)
{
  bool want_cork;
  bool have_cork;
  bool have_more;
  bool use_corknopush;
  bool using_tls = false;
  MHD_socket s = connection->socket_fd;
  ssize_t ret;
  const MHD_SCKT_OPT_BOOL_ off_val = 0;
  const MHD_SCKT_OPT_BOOL_ on_val = 1;

  /* error handling from send_param_adapter() */
  if ((MHD_INVALID_SOCKET == s) || (MHD_CONNECTION_CLOSED == connection->state))
  {
    return MHD_ERR_NOTCONN_;
  }

  /* from send_param_adapter() */
  if (buffer_size > MHD_SCKT_SEND_MAX_SIZE_)
    buffer_size = MHD_SCKT_SEND_MAX_SIZE_; /* return value limit */

  /* Get socket options, change/set options if necessary. */
  switch (options)
  {
  /* No corking */
  case MHD_SSO_NO_CORK:
    want_cork = false;
    break;
  /* Do corking, consider MSG_MORE instead if available. */
  case MHD_SSO_MAY_CORK:
    want_cork = true;
    break;
  /* Cork the header. */
  case MHD_SSO_HDR_CORK:
    want_cork = (buffer_size <= 1024);
    break;
  }

  /* ! could be avoided by redefining the variable. */
  have_cork = ! connection->sk_tcp_nodelay_on;

#ifdef MSG_MORE
  have_more = true;
#else
  have_more = false;
#endif

#if TCP_NODELAY
  use_corknopush = false;
#elif TCP_CORK
  use_corknopush = true;
#elif TCP_NOPUSH
  use_corknopush = true;
#endif

#ifdef HTTPS_SUPPORT
  using_tls = (0 != (connection->daemon->options & MHD_USE_TLS));
#endif

#if TCP_CORK
  /* When we have CORK, we can have NODELAY on the same system,
   * at least since Linux 2.2 and both can be combined since
   * Linux 2.5.71. For more details refer to tcp(7) on Linux.
   * No other system in 2019-06 has TCP_CORK. */
  if ((! using_tls) && (use_corknopush) && (have_cork && ! want_cork))
    {
      MHD_send_socket_state_cork_nodelay_ (connection,
                                           false,
                                           true,
                                           true,
                                           true);
    }
#elif TCP_NOPUSH
  /* TCP_NOPUSH on FreeBSD is equal to cork on Linux, with the
   * exception that we know that TCP_NOPUSH will definitely
   * exist and we can disregard TCP_NODELAY unless requested. */
  if ((! using_tls) && (use_corknopush) && (have_cork && ! want_cork))
    {
      MHD_send_socket_state_nopush_ (connection, true, false);
    }
#endif
#if TCP_NODELAY
  if ((! using_tls) && (! use_corknopush) && (! have_cork && want_cork))
    {
      MHD_setsockopt_ (connection, TCP_NODELAY, false, false);
    }
#endif

#ifdef HTTPS_SUPPORT
  if (using_tls)
  {
    if (want_cork && ! have_cork)
    {
      gnutls_record_cork (connection->tls_session);
      connection->sk_tcp_nodelay_on = false;
    }
    if (buffer_size > SSIZE_MAX)
      buffer_size = SSIZE_MAX;
    ret = gnutls_record_send (connection->tls_session,
                              buffer,
                              buffer_size);
    if ( (GNUTLS_E_AGAIN == ret) ||
         (GNUTLS_E_INTERRUPTED == ret) )
    {
#ifdef EPOLL_SUPPORT
      if (GNUTLS_E_AGAIN == ret)
        connection->epoll_state &= ~MHD_EPOLL_STATE_WRITE_READY;
#endif
      return MHD_ERR_AGAIN_;
    }
    if (ret < 0)
    {
      /* Likely 'GNUTLS_E_INVALID_SESSION' (client communication
         disrupted); interpret as a hard error */
      return MHD_ERR_NOTCONN_;
    }
#ifdef EPOLL_SUPPORT
    /* Unlike non-TLS connections, do not reset "write-ready" if
     * sent amount smaller than provided amount, as TLS
     * connections may break data into smaller parts for sending. */
#endif /* EPOLL_SUPPORT */

    if (! want_cork && have_cork)
    {
      (void) gnutls_record_uncork (connection->tls_session, 0);
      connection->sk_tcp_nodelay_on = true;
    }
  }
  else
#endif
  {
    /* plaintext transmission */
#if MSG_MORE
    ret = send (s,
                buffer,
                buffer_size,
                MAYBE_MSG_NOSIGNAL | (want_cork ? MSG_MORE : 0));
#else
    ret = send (connection->socket_fd, buffer, buffer_size, MAYBE_MSG_NOSIGNAL);
#endif

    if (0 > ret)
    {
      const int err = MHD_socket_get_error_ ();

      if (MHD_SCKT_ERR_IS_EAGAIN_ (err))
      {
#if EPOLL_SUPPORT
        /* EAGAIN, no longer write-ready */
        connection->epoll_state &= ~MHD_EPOLL_STATE_WRITE_READY;
#endif /* EPOLL_SUPPORT */
        return MHD_ERR_AGAIN_;
      }
      if (MHD_SCKT_ERR_IS_EINTR_ (err))
        return MHD_ERR_AGAIN_;
      if (MHD_SCKT_ERR_IS_ (err, MHD_SCKT_ECONNRESET_))
        return MHD_ERR_CONNRESET_;
      /* Treat any other error as hard error. */
      return MHD_ERR_NOTCONN_;
    }
#if EPOLL_SUPPORT
    else if (buffer_size > (size_t) ret)
      connection->epoll_state &= ~MHD_EPOLL_STATE_WRITE_READY;
#endif /* EPOLL_SUPPORT */
  }

  post_cork_setsockopt (connection, want_cork);
  /*
#if TCP_CORK
  if ((! using_tls) && (use_corknopush) && (! have_cork && want_cork && ! have_more))
    {
      MHD_send_socket_state_cork_nodelay_ (connection,
                                           true,
                                           false,
                                           false,
                                           false);
    }
#elif TCP_NOPUSH
  // We don't have MSG_MORE. The OS which implement NOPUSH implement
  // it in a similar way to TCP_CORK on Linux. This means we can just
  // disregard the else branch for TCP_NODELAY which we had to use
  // for the TCP_CORK case here.
  // XXX: Verify this statement and finetune if necessary for
  // other systems, as only FreeBSD was checked.
  if ((! using_tls) && (use_corknopush) && (have_cork && ! want_cork))
  {
    MHD_send_socket_state_nopush_ (connection, true, false);
  }
#endif

#if TCP_NODELAY
  if ((! using_tls) && (! use_corknopush) && (have_cork && ! want_cork))
    {
      MHD_setsockopt_ (connection, TCP_NODELAY, true, true);
    }
#endif
  */
  return ret;
}


/**
 * Send header followed by buffer on connection.
 * Uses writev if possible to send both at once
 * and returns the sum of the number of bytes sent from
 * both buffers, or -1 on error;
 * if writev is unavailable, this call MUST only send from 'header'
 * (as we cannot handle the case that the first write
 * succeeds and the 2nd fails!).
 *
 * @param connection the MHD_Connection structure
 * @param header content of header to send
 * @param header_size the size of the header (in bytes)
 * @param buffer content of the buffer to send
 * @param buffer_size the size of the buffer (in bytes)
 * @return sum of the number of bytes sent from both buffers or
 *         -1 on error
 */
ssize_t
MHD_send_on_connection2_ (struct MHD_Connection *connection,
                          const char *header,
                          size_t header_size,
                          const char *buffer,
                          size_t buffer_size)
{
#if defined(HAVE_SENDMSG) || defined(HAVE_WRITEV)
  MHD_socket s = connection->socket_fd;
  bool have_cork;
  bool have_more;
  int iovcnt;
  int eno;
  const MHD_SCKT_OPT_BOOL_ off_val = 0;
  struct iovec vector[2];

  have_cork = ! connection->sk_tcp_nodelay_on;
#if TCP_NODELAY
  use_corknopush = false;
#elif TCP_CORK
  use_corknopush = true;
#elif TCP_NOPUSH
  use_corknopush = true;
#endif

#if TCP_NODELAY
  if ((! use_corknopush) && (! have_cork && want_cork))
    {
      MHD_setsockopt_ (connection, TCP_NODELAY, false, false);
    }
#endif

  vector[0].iov_base = header;
  vector[0].iov_len = strlen (header);
  vector[1].iov_base = buffer;
  vector[1].iov_len = strlen (buffer);

#if HAVE_SENDMSG
  struct msghdr msg;
  msg.msg_iov = vector;
  memset(&msg, 0, sizeof(msg));
  ret = sendmsg (s, vector, MAYBE_MSG_NOSIGNAL);
#elif HAVE_WRITEV
  iovcnt = sizeof (vector) / sizeof (struct iovec);
  ret = writev (s, vector, iovcnt);
#endif

#if TCP_CORK
  if (use_corknopush)
  {
    eno;

    eno = errno;
    if ((ret == header_len + buffer_len) && have_cork)
      {
        // Response complete, definitely uncork!
        MHD_setsockopt_ (connection, TCP_CORK, false, true);
      }
    errno = eno;
  }
  return ret;
#elif TCP_NOPUSH
  if (use_corknopush)
    {
      eno;

      eno = errno;
      if (ret == header_len + buffer_len)
        {
          /* Response complete, set NOPUSH to off */
          MHD_setsockopt_ (connection, TCP_NOPUSH, false, false);
        }
      errno = eno;
    }
  return ret;
#endif

#else
  return MHD_send_on_connection_ (connection,
                                  header,
                                  header_size,
                                  MHD_SSO_HDR_CORK);
#endif
}
