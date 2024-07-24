/*
  This file is part of libmicrohttpd
  Copyright (C) 2017-2024 Karlson2k (Evgeny Grin), Full re-write of buffering
                          and pushing, many bugs fixes, optimisations,
                          sendfile() porting
  Copyright (C) 2019 ng0 <ng0@n0.is>, Initial version of send() wrappers

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
 * @file src/mhd2/mhd_send.c
 * @brief Implementation of send() wrappers and helper functions.
 * @author Karlson2k (Evgeny Grin)
 * @author ng0 (N. Gillmann)
 * @author Christian Grothoff
 */

/* Worth considering for future improvements and additions:
 * NetBSD has no sendfile or sendfile64. The way to work
 * with this seems to be to mmap the file and write(2) as
 * large a chunk as possible to the socket. Alternatively,
 * use madvise(..., MADV_SEQUENTIAL). */

#include "mhd_sys_options.h"

#include <string.h>

#include "mhd_send.h"
#include "sys_sockets_headers.h"
#include "sys_ip_headers.h"
#include "mhd_sockets_macros.h"
#include "daemon_logger.h"

#include "mhd_daemon.h"
#include "mhd_connection.h"
#include "mhd_response.h"

#include "mhd_iovec.h"
#ifdef HAVE_LINUX_SENDFILE
#  include <sys/sendfile.h>
#endif /* HAVE_LINUX_SENDFILE */

#if defined(HAVE_FREEBSD_SENDFILE) || defined(HAVE_DARWIN_SENDFILE)
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <sys/uio.h>
#endif /* HAVE_FREEBSD_SENDFILE || HAVE_DARWIN_SENDFILE */
#ifdef HAVE_SYS_PARAM_H
/* For FreeBSD version identification */
#  include <sys/param.h>
#endif /* HAVE_SYS_PARAM_H */
#ifdef HAVE_SYSCONF
#  include <unistd.h>
#endif /* HAVE_SYSCONF */
#include "mhd_assert.h"

#include "mhd_limits.h"

#if defined(HAVE_SENDMSG) || defined(HAVE_WRITEV) || \
  defined(MHD_WINSOCK_SOCKETS)
#  define mhd_USE_VECT_SEND 1
#endif /* HAVE_SENDMSG || HAVE_WRITEV || MHD_WINSOCK_SOCKETS */


#ifdef mhd_USE_VECT_SEND
#  if (! defined(HAVE_SENDMSG) || ! defined(MSG_NOSIGNAL)) && \
  defined(mhd_SEND_SPIPE_SUPPRESS_POSSIBLE) && \
  defined(mhd_SEND_SPIPE_SUPPRESS_NEEDED)
#    define mhd_VECT_SEND_NEEDS_SPIPE_SUPPRESSED 1
#  endif /* (!HAVE_SENDMSG || !MSG_NOSIGNAL) &&
            mhd_SEND_SPIPE_SUPPRESS_POSSIBLE && mhd_SEND_SPIPE_SUPPRESS_NEEDED */
#endif /* mhd_USE_VECT_SEND */

/**
 * sendfile() chuck size
 */
#define mhd_SENFILE_CHUNK_SIZE         (0x20000)

/**
 * sendfile() chuck size for thread-per-connection
 */
#define mhd_SENFILE_CHUNK_SIZE_FOR_THR_P_C (0x200000)

#if defined(HAVE_FREEBSD_SENDFILE) && defined(SF_FLAGS)
/**
 * FreeBSD sendfile() flags
 */
static int freebsd_sendfile_flags_;

/**
 * FreeBSD sendfile() flags for thread-per-connection
 */
static int freebsd_sendfile_flags_thd_p_c_;


/**
 * Initialises variables for FreeBSD's sendfile()
 */
static void
freebsd_sendfile_init_ (void)
{
  long sys_page_size = sysconf (_SC_PAGESIZE);
  if (0 >= sys_page_size)
  {   /* Failed to get page size. */
    freebsd_sendfile_flags_ = SF_NODISKIO;
    freebsd_sendfile_flags_thd_p_c_ = SF_NODISKIO;
  }
  else
  {
    freebsd_sendfile_flags_ =
      SF_FLAGS ((uint_least16_t) \
                ((mhd_SENFILE_CHUNK_SIZE + sys_page_size - 1) / sys_page_size) \
                & 0xFFFFU, SF_NODISKIO);
    freebsd_sendfile_flags_thd_p_c_ =
      SF_FLAGS ((uint_least16_t) \
                ((mhd_SENFILE_CHUNK_SIZE_FOR_THR_P_C + sys_page_size - 1) \
                 / sys_page_size) & 0xFFFFU, SF_NODISKIO);
  }
}


#else  /* ! HAVE_FREEBSD_SENDFILE || ! SF_FLAGS */
#  define freebsd_sendfile_init_() (void) 0
#endif /* HAVE_FREEBSD_SENDFILE */


#if defined(HAVE_SYSCONF) && defined(_SC_IOV_MAX)
/**
 * Current IOV_MAX system value
 */
static unsigned long mhd_iov_max_ = 0;

static void
iov_max_init_ (void)
{
  long res = sysconf (_SC_IOV_MAX);
  if (res >= 0)
    mhd_iov_max_ = (unsigned long) res;
  else
  {
#  if defined(IOV_MAX)
    mhd_iov_max_ = IOV_MAX;
#  else  /* ! IOV_MAX */
    mhd_iov_max_ = 8; /* Should be the safe limit */
#  endif /* ! IOV_MAX */
  }
}


/**
 * IOV_MAX (run-time) value
 */
#  define mhd_IOV_MAX    mhd_iov_max_
#else  /* ! HAVE_SYSCONF || ! _SC_IOV_MAX */
#  define iov_max_init_() (void) 0
#    if defined(IOV_MAX)

/**
 * IOV_MAX (static) value
 */
#      define mhd_IOV_MAX    IOV_MAX
#  endif /* IOV_MAX */
#endif /* ! HAVE_SYSCONF || ! _SC_IOV_MAX */


/**
 * Initialises static variables
 */
void
mhd_send_init_static_vars (void)
{
  /* FreeBSD 11 and later allow to specify read-ahead size
   * and handles SF_NODISKIO differently.
   * SF_FLAGS defined only on FreeBSD 11 and later. */
  freebsd_sendfile_init_ ();

  iov_max_init_ ();
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_connection_set_nodelay_state (struct MHD_Connection *connection,
                                  bool nodelay_state)
{
#ifdef TCP_NODELAY
  static const mhd_SCKT_OPT_BOOL off_val = 0;
  static const mhd_SCKT_OPT_BOOL on_val = 1;
  int err_code;

  if (mhd_T_IS_YES (connection->is_nonip))
    return false;

  if (0 == setsockopt (connection->socket_fd,
                       IPPROTO_TCP,
                       TCP_NODELAY,
                       (const void *) (nodelay_state ? &on_val : &off_val),
                       sizeof (off_val)))
  {
    connection->sk_nodelay = nodelay_state ? mhd_T_YES : mhd_T_NO;
    return true;
  }

  err_code = mhd_SCKT_GET_LERR ();
  if ((mhd_T_IS_NOT_YES (connection->is_nonip)) &&
      (mhd_SCKT_ERR_IS_EINVAL (err_code) ||
       mhd_SCKT_ERR_IS_NOPROTOOPT (err_code) ||
       mhd_SCKT_ERR_IS_NOTSOCK (err_code)))
  {
    connection->is_nonip = mhd_T_YES;
  }
  else
  {
    mhd_LOG_MSG (connection->daemon, MHD_SC_SOCKET_TCP_NODELAY_FAILED, \
                 "Failed to set required TCP_NODELAY option for the socket.");
  }
#else  /* ! TCP_NODELAY */
  (void) nodelay_state; /* Mute compiler warnings */
  connection->sk_nodelay = mhd_T_NO;
#endif /* ! TCP_NODELAY */
  return false;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_connection_set_cork_state (struct MHD_Connection *connection,
                               bool cork_state)
{
#if defined(mhd_TCP_CORK_NOPUSH)
  static const mhd_SCKT_OPT_BOOL off_val = 0;
  static const mhd_SCKT_OPT_BOOL on_val = 1;
  int err_code;

  if (mhd_T_IS_YES (connection->is_nonip))
    return false;

  if (0 == setsockopt (connection->socket_fd,
                       IPPROTO_TCP,
                       mhd_TCP_CORK_NOPUSH,
                       (const void *) (cork_state ? &on_val : &off_val),
                       sizeof (off_val)))
  {
    connection->sk_corked = cork_state ? mhd_T_YES : mhd_T_NO;
    return true;
  }

  err_code = mhd_SCKT_GET_LERR ();
  if ((mhd_T_IS_NOT_YES (connection->is_nonip)) &&
      (mhd_SCKT_ERR_IS_EINVAL (err_code) ||
       mhd_SCKT_ERR_IS_NOPROTOOPT (err_code) ||
       mhd_SCKT_ERR_IS_NOTSOCK (err_code)))
  {
    connection->is_nonip = mhd_T_YES;
  }
  else
  {
#  ifdef TCP_CORK
    mhd_LOG_MSG (connection->daemon, MHD_SC_SOCKET_TCP_CORK_NOPUSH_FAILED, \
                 "Failed to set required TCP_CORK option for the socket.");
#  else
    mhd_LOG_MSG (connection->daemon, MHD_SC_SOCKET_TCP_CORK_NOPUSH_FAILED, \
                 "Failed to set required TCP_NOPUSH option for the socket.");
#  endif
  }

#else  /* ! mhd_TCP_CORK_NOPUSH */
  (void) cork_state; /* Mute compiler warnings. */
  connection->sk_corked = mhd_T_NO;
#endif /* ! mhd_TCP_CORK_NOPUSH */
  return false;
}


/**
 * Handle pre-send setsockopt calls.
 *
 * @param connection the MHD_Connection structure
 * @param plain_send set to true if plain send() or sendmsg() will be called,
 *                   set to false if TLS socket send(), sendfile() or
 *                   writev() will be called.
 * @param push_data whether to push data to the network from buffers after
 *                  the next call of send function.
 */
static void
pre_send_setopt (struct MHD_Connection *connection,
                 bool plain_send,
                 bool push_data)
{
  /* Try to buffer data if not sending the final piece.
   * Final piece is indicated by push_data == true. */
  const bool buffer_data = (! push_data);

  if (mhd_T_IS_YES (connection->is_nonip))
    return;

  // TODO: support inheriting of TCP_NODELAY and TCP_NOPUSH

  /* The goal is to minimise the total number of additional sys-calls
   * before and after send().
   * The following tricky (over-)complicated algorithm typically use zero,
   * one or two additional sys-calls (depending on OS) for each response. */

  if (buffer_data)
  {
    /* Need to buffer data if possible. */
#ifdef mhd_USE_MSG_MORE
    if (plain_send)
      return; /* Data is buffered by send() with MSG_MORE flag.
               * No need to check or change anything. */
#else  /* ! mhd_USE_MSG_MORE */
    (void) plain_send; /* Mute compiler warning. */
#endif /* ! mhd_USE_MSG_MORE */

#ifdef mhd_TCP_CORK_NOPUSH
    if (mhd_T_IS_YES (connection->sk_corked))
      return; /* The connection was already corked. */

    /* Prefer 'cork' over 'no delay' as the 'cork' buffers better, regardless
     * of the number of received ACKs. */
    if (mhd_connection_set_cork_state (connection, true))
      return; /* The connection has been corked. */

    /* Failed to cork the connection.
     * Really unlikely to happen on TCP connections. */
#endif /* mhd_TCP_CORK_NOPUSH */
    if (mhd_T_IS_NO (connection->sk_nodelay))
      return; /* TCP_NODELAY was not set for the socket.
               * Nagle's algorithm will buffer some data. */

    /* Try to reset TCP_NODELAY state for the socket.
     * Ignore possible error as no other options exist to
     * buffer data. */
    mhd_connection_set_nodelay_state (connection, false);
    /* TCP_NODELAY has been (hopefully) reset for the socket.
     * Nagle's algorithm will buffer some data. */
    return;
  }

  /* Need to push data after the next send() */
  /* If additional sys-call is required, prefer to make it only after the send()
   * (if possible) as this send() may consume only part of the prepared data and
   * more send() calls will be used. */
#ifdef mhd_TCP_CORK_NOPUSH
#  ifdef mhd_CORK_RESET_PUSH_DATA
#    ifdef mhd_CORK_RESET_PUSH_DATA_ALWAYS
  /* Data can be pushed immediately by uncorking socket regardless of
   * cork state before. */
  /* This is typical for Linux, no other kernel with
   * such behaviour are known so far. */

  /* No need to check the current state of TCP_CORK / TCP_NOPUSH
   * as reset of cork will push the data anyway. */
  return; /* Data may be pushed by resetting of
           * TCP_CORK / TCP_NOPUSH after send() */
#    else  /* ! mhd_CORK_RESET_PUSH_DATA_ALWAYS */
  /* Reset of TCP_CORK / TCP_NOPUSH will push the data
   * only if socket is corked. */

#      ifdef mhd_NODELAY_SET_PUSH_DATA_ALWAYS
  /* Data can be pushed immediately by setting TCP_NODELAY regardless
   * of TCP_NODDELAY or corking state before. */

  /* Dead code currently, no known kernels with such behaviour and without
   * pushing by uncorking. */
  return; /* Data may be pushed by setting of TCP_NODELAY after send().
             No need to make extra sys-calls before send().*/
#      else  /* ! mhd_NODELAY_SET_PUSH_DATA_ALWAYS */

/* These next comment blocks are just generic description for the possible
 * choices for the code below. */
#        ifdef mhd_NODELAY_SET_PUSH_DATA
  /* Setting of TCP_NODELAY will push the data only if
   * both TCP_NODELAY and TCP_CORK / TCP_NOPUSH were not set. */

  /* Data can be pushed immediately by uncorking socket if
   * socket was corked before or by setting TCP_NODELAY if
   * socket was not corked and TCP_NODELAY was not set before. */

  /* This combination not possible currently as Linux is the only kernel that
   * pushes data by setting of TCP_NODELAY and Linux pushes data always
   * by TCP_NODELAY, regardless previous TCP_NODELAY state. */
#        else  /* ! mhd_NODELAY_SET_PUSH_DATA */
  /* Data can be pushed immediately by uncorking socket or
   * can be pushed by send() on uncorked socket if
   * TCP_NODELAY was set *before*. */

  /* This is typical modern FreeBSD and OpenBSD behaviour. */
#        endif /* ! mhd_NODELAY_SET_PUSH_DATA */

  if (mhd_T_IS_YES (connection->sk_corked))
    return; /* Socket is corked. Data can be pushed by resetting of
             * TCP_CORK / TCP_NOPUSH after send() */
  else if (mhd_T_IS_NO (connection->sk_corked))
  {
    /* The socket is not corked. */
    if (mhd_T_IS_YES (connection->sk_nodelay))
      return; /* TCP_NODELAY was already set,
               * data will be pushed automatically by the next send() */
#        ifdef mhd_NODELAY_SET_PUSH_DATA
    else if (mhd_T_IS_MAYBE (connection->sk_nodelay))
    {
      /* Setting TCP_NODELAY may push data NOW.
       * Cork socket here and uncork after send(). */
      if (mhd_connection_set_cork_state (connection, true))
        return; /* The connection has been corked.
                 * Data can be pushed by resetting of
                 * TCP_CORK / TCP_NOPUSH after send() */
      else
      {
        /* The socket cannot be corked.
         * Really unlikely to happen on TCP connections */
        /* Have to set TCP_NODELAY.
         * If TCP_NODELAY real system state was OFF then
         * already buffered data may be pushed NOW, but it is unlikely
         * to happen as this is only a backup solution when corking has failed.
         * Ignore possible error here as no other options exist to
         * push data. */
        mhd_connection_set_nodelay_state (connection, true);
        /* TCP_NODELAY has been (hopefully) set for the socket.
         * The data will be pushed by the next send(). */
        return;
      }
    }
#        endif /* mhd_NODELAY_SET_PUSH_DATA */
    else
    {
#        ifdef mhd_NODELAY_SET_PUSH_DATA
      /* The socket is not corked and TCP_NODELAY is switched off. */
#        else  /* ! mhd_NODELAY_SET_PUSH_DATA */
      /* The socket is not corked and TCP_NODELAY is not set or unknown. */
#        endif /* ! mhd_NODELAY_SET_PUSH_DATA */

      /* At least one additional sys-call before send() is required. */
      /* Setting TCP_NODELAY is optimal here as data will be pushed
       * automatically by the next send() and no additional
       * sys-call are needed after the send(). */
      if (mhd_connection_set_nodelay_state (connection, true))
        return;
      else
      {
        /* Failed to set TCP_NODELAY for the socket.
         * Really unlikely to happen on TCP connections. */
        /* Cork the socket here and make additional sys-call
         * to uncork the socket after send(). This will push the data. */
        /* Ignore possible error here as no other options exist to
         * push data. */
        mhd_connection_set_cork_state (connection, true);
        /* The connection has been (hopefully) corked.
         * Data can be pushed by resetting of TCP_CORK / TCP_NOPUSH
         * after send() */
        return;
      }
    }
  }
  /* Corked state is unknown. Need to make a sys-call here otherwise
   * data may not be pushed. */
  if (mhd_connection_set_cork_state (connection, true))
    return; /* The connection has been corked.
             * Data can be pushed by resetting of
             * TCP_CORK / TCP_NOPUSH after send() */
  /* The socket cannot be corked.
   * Really unlikely to happen on TCP connections */
  if (mhd_T_IS_YES (connection->sk_nodelay))
    return; /* TCP_NODELAY was already set,
             * data will be pushed by the next send() */

  /* Have to set TCP_NODELAY. */
#        ifdef mhd_NODELAY_SET_PUSH_DATA
  /* If TCP_NODELAY state was unknown (external connection) then
   * already buffered data may be pushed here, but this is unlikely
   * to happen as it is only a backup solution when corking has failed. */
#        endif /* mhd_NODELAY_SET_PUSH_DATA */
  /* Ignore possible error here as no other options exist to
   * push data. */
  mhd_connection_set_nodelay_state (connection, true);
  /* TCP_NODELAY has been (hopefully) set for the socket.
   * The data will be pushed by the next send(). */
  return;
#      endif /* ! mhd_NODELAY_SET_PUSH_DATA_ALWAYS */
#    endif /* ! mhd_CORK_RESET_PUSH_DATA_ALWAYS */
#  else  /* ! mhd_CORK_RESET_PUSH_DATA */

#    ifndef mhd_NODELAY_SET_PUSH_DATA
  /* Neither uncorking the socket or setting TCP_NODELAY
   * push the data immediately. */
  /* The only way to push the data is to use send() on uncorked
   * socket with TCP_NODELAY switched on . */

  /* This is old FreeBSD and Darwin behaviour. */

  /* Uncork socket if socket wasn't uncorked. */
  if (mhd_T_IS_NOT_NO (connection->sk_corked))
    mhd_connection_set_cork_state (connection, false);

  /* Set TCP_NODELAY if it wasn't set. */
  if (mhd_T_IS_NOT_YES (connection->sk_nodelay))
    mhd_connection_set_nodelay_state (connection, true);

  return;
#    else  /* mhd_NODELAY_SET_PUSH_DATA */
  /* Setting TCP_NODELAY push the data immediately. */

  /* Dead code currently as Linux kernel is only kernel which push by
   * setting TCP_NODELAY. The same kernel push data by resetting TCP_CORK. */
#      ifdef mhd_NODELAY_SET_PUSH_DATA_ALWAYS
  return; /* Data may be pushed by setting of TCP_NODELAY after send().
             No need to make extra sys-calls before send().*/
#      else  /* ! mhd_NODELAY_SET_PUSH_DATA_ALWAYS */
  /* Cannot set TCP_NODELAY here as it would push data NOW.
   * Set TCP_NODELAY after the send(), together if uncorking if necessary. */
#      endif /* ! mhd_NODELAY_SET_PUSH_DATA_ALWAYS */
#    endif /* mhd_NODELAY_SET_PUSH_DATA */
#  endif /* ! mhd_CORK_RESET_PUSH_DATA */
#else  /* ! mhd_TCP_CORK_NOPUSH */
  /* Buffering of data is controlled only by
   * Nagel's algorithm. */
  /* Set TCP_NODELAY if it wasn't set. */
  if (mhd_T_IS_NOT_YES (connection->sk_nodelay))
    mhd_connection_set_nodelay_state (connection, true);
#endif /* ! mhd_TCP_CORK_NOPUSH */
}


#ifndef mhd_CORK_RESET_PUSH_DATA_ALWAYS
/**
 * Send zero-sized data
 *
 * This function use send of zero-sized data to kick data from the socket
 * buffers to the network. The socket must not be corked and must have
 * TCP_NODELAY switched on.
 * Used only as last resort option, when other options are failed due to
 * some errors.
 * Should not be called on typical data processing.
 * @return true if succeed, false if failed
 */
static bool
zero_send (struct MHD_Connection *connection)
{
  static const int dummy = 0;

  if (mhd_T_IS_YES (connection->is_nonip))
    return false;
  mhd_assert (mhd_T_IS_NO (connection->sk_corked));
  mhd_assert (mhd_T_IS_YES (connection->sk_nodelay));
  if (0 == mhd_sys_send (connection->socket_fd, &dummy, 0))
    return true;
  mhd_LOG_MSG (connection->daemon, MHD_SC_SOCKET_ZERO_SEND_FAILED, \
               "Failed to push the data by zero-sized send.");
  return false;
}


#endif /* ! mhd_CORK_RESET_PUSH_DATA_ALWAYS */

/**
 * Handle post-send setsockopt calls.
 *
 * @param connection the MHD_Connection structure
 * @param plain_send_next set to true if plain send() or sendmsg() will be
 *                        called next,
 *                        set to false if TLS socket send(), sendfile() or
 *                        writev() will be called next.
 * @param push_data whether to push data to the network from buffers
 */
static void
post_send_setopt (struct MHD_Connection *connection,
                  bool plain_send_next,
                  bool push_data)
{
  /* Try to buffer data if not sending the final piece.
   * Final piece is indicated by push_data == true. */
  const bool buffer_data = (! push_data);

  if (mhd_T_IS_YES (connection->is_nonip))
    return;
  if (buffer_data)
    return; /* Nothing to do after the send(). */

#ifndef mhd_USE_MSG_MORE
  (void) plain_send_next; /* Mute compiler warning */
#endif /* ! mhd_USE_MSG_MORE */

  /* Need to push data. */
#ifdef mhd_TCP_CORK_NOPUSH
  if (mhd_T_IS_YES (connection->sk_nodelay) && \
      mhd_T_IS_NO (connection->sk_corked))
    return; /* Data has been already pushed by last send(). */

#  ifdef mhd_CORK_RESET_PUSH_DATA_ALWAYS
#    ifdef mhd_NODELAY_SET_PUSH_DATA_ALWAYS
#      ifdef mhd_USE_MSG_MORE
  /* This is Linux kernel.
   * The socket is corked (or unknown) or 'no delay' is not set (or unknown).
   * There are options:
   * * Push the data by setting of TCP_NODELAY (without change
   *   of the cork on the socket),
   * * Push the data by resetting of TCP_CORK.
   * The optimal choice depends on the next final send functions
   * used on the same socket.
   *
   * In general on Linux kernel TCP_NODELAY always enabled is preferred,
   * as buffering is controlled by MSG_MORE or cork/uncork.
   *
   * If next send function will not support MSG_MORE (like sendfile()
   * or TLS-connection) than push data by setting TCP_NODELAY
   * so the socket may remain corked (no additional sys-call before
   * next send()).
   *
   * If send()/sendmsg() will be used next than push data by
   * resetting of TCP_CORK so next final send without MSG_MORE will push
   * data to the network (without additional sys-call to push data).  */

  if (mhd_T_IS_NOT_YES (connection->sk_nodelay) ||
      (! plain_send_next))
  {
    if (mhd_connection_set_nodelay_state (connection, true))
      return; /* Data has been pushed by TCP_NODELAY. */
    /* Failed to set TCP_NODELAY for the socket.
     * Really unlikely to happen on TCP connections. */
    if (mhd_connection_set_cork_state (connection, false))
      return; /* Data has been pushed by uncorking the socket. */
    /* Failed to uncork the socket.
     * Really unlikely to happen on TCP connections. */

    /* The socket cannot be uncorked, no way to push data */
  }
  else
  {
    if (mhd_connection_set_cork_state (connection, false))
      return; /* Data has been pushed by uncorking the socket. */
    /* Failed to uncork the socket.
     * Really unlikely to happen on TCP connections. */
    if (mhd_connection_set_nodelay_state (connection, true))
      return; /* Data has been pushed by TCP_NODELAY. */
    /* Failed to set TCP_NODELAY for the socket.
     * Really unlikely to happen on TCP connections. */

    /* The socket cannot be uncorked, no way to push data */
  }
#      else  /* ! mhd_USE_MSG_MORE */
  /* Push data by setting TCP_NODELAY here as uncorking here
   * would require corking the socket before sending the next response. */
  if (mhd_connection_set_nodelay_state (connection, true))
    return; /* Data was pushed by TCP_NODELAY. */
  /* Failed to set TCP_NODELAY for the socket.
   * Really unlikely to happen on TCP connections. */
  if (mhd_connection_set_cork_state (connection, false))
    return; /* Data was pushed by uncorking the socket. */
  /* Failed to uncork the socket.
   * Really unlikely to happen on TCP connections. */

  /* The socket remains corked, no way to push data */
#      endif /* ! mhd_USE_MSG_MORE */
#    else  /* ! mhd_NODELAY_SET_PUSH_DATA_ALWAYS */
  if (mhd_connection_set_cork_state (connection, false))
    return; /* Data was pushed by uncorking the socket. */
  /* Failed to uncork the socket.
   * Really unlikely to happen on TCP connections. */

  /* Socket remains corked, no way to push data */
#    endif /* ! mhd_NODELAY_SET_PUSH_DATA_ALWAYS */
#  else  /* ! mhd_CORK_RESET_PUSH_DATA_ALWAYS */
  /* This is old FreeBSD or Darwin kernel. */

  if (mhd_T_IS_NO (connection->sk_corked))
  {
    mhd_assert (mhd_T_IS_NOT_YES (connection->sk_nodelay));

    /* Unlikely to reach this code.
     * TCP_NODELAY should be turned on before send(). */
    if (mhd_connection_set_nodelay_state (connection, true))
    {
      /* TCP_NODELAY has been set on uncorked socket.
       * Use zero-send to push the data. */
      if (zero_send (connection))
        return; /* The data has been pushed by zero-send. */
    }

    /* Failed to push the data by all means. */
    /* There is nothing left to try. */
  }
  else
  {
#ifdef mhd_CORK_RESET_PUSH_DATA
    enum mhd_Tristate old_cork_state = connection->sk_corked;
#endif /* mhd_CORK_RESET_PUSH_DATA */
    /* The socket is corked or cork state is unknown. */

    if (mhd_connection_set_cork_state (connection, false))
    {
#ifdef mhd_CORK_RESET_PUSH_DATA
      /* Modern FreeBSD or OpenBSD kernel */
      if (mhd_T_IS_YES (old_cork_state))
        return; /* Data has been pushed by uncorking the socket. */
#endif /* mhd_CORK_RESET_PUSH_DATA */

      /* Unlikely to reach this code.
       * The data should be pushed by uncorking (FreeBSD) or
       * the socket should be uncorked before send(). */
      if (mhd_T_IS_YES (connection->sk_nodelay) ||
          (mhd_connection_set_nodelay_state (connection, true)))
      {
        /* TCP_NODELAY is turned ON on uncorked socket.
         * Use zero-send to push the data. */
        if (zero_send (connection))
          return; /* The data has been pushed by zero-send. */
      }
    }
    /* Data cannot be pushed. */
  }
#endif /* ! mhd_CORK_RESET_PUSH_DATA_ALWAYS */
#else  /* ! mhd_TCP_CORK_NOPUSH */
  /* Corking is not supported. Buffering is controlled
   * by TCP_NODELAY only. */
  mhd_assert (mhd_T_IS_NOT_YES (connection->sk_corked));
  if (mhd_T_IS_YES (connection->sk_nodelay))
    return; /* Data was already pushed by send(). */

  /* Unlikely to reach this code.
   * TCP_NODELAY should be turned on before send(). */
  if (mhd_connection_set_nodelay_state (connection, true))
  {
    /* TCP_NODELAY has been set.
     * Use zero-send to try to push the data. */
    if (zero_send (connection))
      return; /* The data has been pushed by zero-send. */
  }

  /* Failed to push the data. */
#endif /* ! mhd_TCP_CORK_NOPUSH */
  mhd_LOG_MSG (connection->daemon, MHD_SC_SOCKET_FLUSH_LAST_PART_FAILED, \
               "Failed to force flush the last part of the response header " \
               "or the response content that might have been buffered by " \
               "the kernel. The client may experience some delay (usually " \
               "in range 200ms - 5 sec).");
  return;
}


static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_IN_SIZE_ (3,2)
MHD_FN_PAR_OUT_ (5) enum mhd_SocketError
mhd_plain_send (struct MHD_Connection *restrict c,
                size_t buf_size,
                const char buf[MHD_FN_PAR_DYN_ARR_SIZE_ (buf_size)],
                bool push_data,
                size_t *restrict sent)
{
  /* plaintext transmission */
  ssize_t res;
  bool full_buf_sent;

  if (buf_size > MHD_SCKT_SEND_MAX_SIZE_)
  {
    buf_size = MHD_SCKT_SEND_MAX_SIZE_; /* send() return value limit */
    push_data = false; /* Incomplete send */
  }

  pre_send_setopt (c, true, push_data);
#ifdef mhd_USE_MSG_MORE
  res = mhd_sys_send4 (c->socket_fd,
                       buf,
                       buf_size,
                       push_data ? 0 : MSG_MORE);
#else
  res = mhd_sys_send4 (c->socket_fd,
                       buf,
                       buf_size,
                       0);
#endif

  if (0 >= res)
  {
    enum mhd_SocketError err;

    err = mhd_socket_error_get_from_sys_err (mhd_SCKT_GET_LERR ());

    if (mhd_SOCKET_ERR_AGAIN == err)
      c->sk_ready = (enum mhd_SocketNetState) /* Clear 'send-ready' */
                    (((unsigned int) c->sk_ready)
                     & (~(enum mhd_SocketNetState)
                        mhd_SOCKET_NET_STATE_SEND_READY));

    return err;
  }
  *sent = (size_t) res;

  full_buf_sent = (buf_size == (size_t) res);

  if (! full_buf_sent)
    c->sk_ready = (enum mhd_SocketNetState) /* Clear 'send-ready' */
                  (((unsigned int) c->sk_ready)
                   & (~(enum mhd_SocketNetState)
                      mhd_SOCKET_NET_STATE_SEND_READY));

  /* If there is a need to push the data from network buffers
   * call post_send_setopt(). */
  /* It's unknown whether sendfile() (or other send function without
   * MSG_MORE support) will be used for the next reply so assume
   * that next sending will be the same, like this call. */
  if (push_data && full_buf_sent)
    post_send_setopt (c, false, push_data);

  return mhd_SOCKET_ERR_NO_ERROR;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_IN_SIZE_ (3,2)
MHD_FN_PAR_OUT_ (5) enum mhd_SocketError
mhd_send_data (struct MHD_Connection *restrict connection,
               size_t buf_size,
               const char buf[MHD_FN_PAR_DYN_ARR_SIZE_ (buf_size)],
               bool push_data,
               size_t *restrict sent)
{
  const bool tls_conn = false; // TODO: TLS support

  mhd_assert (MHD_INVALID_SOCKET != connection->socket_fd);
  mhd_assert (MHD_CONNECTION_CLOSED != connection->state);

  if (tls_conn)
  {
    enum mhd_SocketError ret;

#ifdef HTTPS_SUPPORT
    pre_send_setopt (connection,
                     (! tls_conn),
                     push_data);
    ret = mhd_SOCKET_ERR_OTHER;
    mhd_assert (0 && "Not implemented yet");
#else  /* ! HTTPS_SUPPORT  */
    ret = mhd_SOCKET_ERR_NOTCONN;
#endif /* ! HTTPS_SUPPORT  */
    return ret;
  }

  return mhd_plain_send (connection,
                         buf_size,
                         buf,
                         push_data,
                         sent);
}


MHD_INTERNAL
MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (3)
MHD_FN_PAR_IN_SIZE_ (3,2) MHD_FN_PAR_IN_SIZE_ (6,5) enum mhd_SocketError
mhd_send_hdr_and_body (struct MHD_Connection *restrict connection,
                       size_t header_size,
                       const char *restrict header,
                       bool never_push_hdr,
                       size_t body_size,
                       const char *restrict body,
                       bool complete_response,
                       size_t *restrict sent)
{
  mhd_iov_ret_type res;
  bool send_error;
  bool push_hdr;
  bool push_body;
  MHD_Socket s = connection->socket_fd;
#ifdef mhd_USE_VECT_SEND
#if defined(HAVE_SENDMSG) || defined(HAVE_WRITEV)
  struct iovec vector[2];
#ifdef HAVE_SENDMSG
  struct msghdr msg;
#endif /* HAVE_SENDMSG */
#endif /* HAVE_SENDMSG || HAVE_WRITEV */
#ifdef _WIN32
  WSABUF vector[2];
  DWORD vec_sent;
#endif /* _WIN32 */
  bool no_vec; /* Is vector-send() disallowed? */

  no_vec = false;
#ifdef HTTPS_SUPPORT
  no_vec = no_vec || (false); // TODO: TLS support
#endif /* HTTPS_SUPPORT */
#if (! defined(HAVE_SENDMSG) || ! defined(MSG_NOSIGNAL) ) && \
  defined(mhd_SEND_SPIPE_SUPPRESS_POSSIBLE) && \
  defined(mhd_SEND_SPIPE_SUPPRESS_NEEDED)
  no_vec = no_vec || (! connection->daemon->sigpipe_blocked &&
                      ! connection->sk_spipe_suppress);
#endif /* (!HAVE_SENDMSG || ! MSG_NOSIGNAL) &&
          mhd_SEND_SPIPE_SUPPRESS_POSSIBLE &&
          mhd_SEND_SPIPE_SUPPRESS_NEEDED */
#endif /* mhd_USE_VECT_SEND */

  mhd_assert ( (NULL != body) || (0 == body_size) );

  mhd_assert (MHD_INVALID_SOCKET != s);
  mhd_assert (MHD_CONNECTION_CLOSED != connection->state);

  push_body = complete_response;

  if (! never_push_hdr)
  {
    if (! complete_response)
      push_hdr = true; /* Push the header as the client may react
                        * on header alone while the body data is
                        * being prepared. */
    else
    {
      if (1400 > (header_size + body_size))
        push_hdr = false; /* Do not push the header as complete
                           * reply is already ready and the whole
                           * reply most probably will fit into
                           * the single IP packet. */
      else
        push_hdr = true;   /* Push header alone so client may react
                           * on it while reply body is being delivered. */
    }
  }
  else
    push_hdr = false;

  if (complete_response && (0 == body_size))
    push_hdr = true; /* The header alone is equal to the whole response. */

#ifndef mhd_USE_VECT_SEND
  no_vec = (no_vec || true);
#else  /* mhd_USE_VECT_SEND */
  no_vec = (no_vec || (0 == body_size));
  no_vec = (no_vec || ((sizeof(mhd_iov_elmn_size) <= sizeof(size_t)) &&
                       (((size_t) mhd_IOV_ELMN_MAX_SIZE) < header_size)));
#endif /* mhd_USE_VECT_SEND */


  if (no_vec)
  {
    enum mhd_SocketError ret;
    ret = mhd_send_data (connection,
                         header_size,
                         header,
                         push_hdr,
                         sent);

    // TODO: check 'send-ready'
    if ((mhd_SOCKET_ERR_NO_ERROR == ret) &&
        (header_size == *sent) &&
        (0 != body_size) &&
        (header_size < header_size + body_size) &&
        (connection->sk_nonblck))
    {
      size_t sent_b;
      /* The header has been sent completely.
       * Try to send the reply body without waiting for
       * the next round. */

      ret = mhd_send_data (connection,
                           body_size,
                           body,
                           push_body,
                           &sent_b);

      if (mhd_SOCKET_ERR_NO_ERROR == ret)
        *sent += sent_b;
      else if (mhd_SOCKET_ERR_IS_HARD (ret))
        return ret; /* Unrecoverable error */

      return mhd_SOCKET_ERR_NO_ERROR; /* The header has been sent successfully */
    }
    return ret;
  }
#ifdef mhd_USE_VECT_SEND

  if (header_size > (header_size + body_size))
  {
    /* Return value limit */
    body_size = SIZE_MAX - header_size;
    complete_response = false;
    push_body = complete_response;
  }
  if (((mhd_iov_ret_type) (header_size + body_size)) < 0 ||
      ((size_t) (mhd_iov_ret_type) (header_size + body_size)) !=
      (header_size + body_size))
  {
    /* Send sys-call total amount limit */
    body_size = mhd_IOV_RET_MAX_SIZE - header_size;
    complete_response = false;
    push_body = complete_response;
  }

  pre_send_setopt (connection,
#ifdef HAVE_SENDMSG
                   true,
#else  /* ! HAVE_SENDMSG */
                   false,
#endif /* ! HAVE_SENDMSG */
                   push_hdr || push_body);
  send_error = false;
#if defined(HAVE_SENDMSG) || defined(HAVE_WRITEV)
  vector[0].iov_base = mhd_DROP_CONST (header);
  vector[0].iov_len = header_size;
  vector[1].iov_base = mhd_DROP_CONST (body);
  vector[1].iov_len = body_size;

#if defined(HAVE_SENDMSG)
  memset (&msg, 0, sizeof(msg));
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = vector;
  msg.msg_iovlen = 2;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;

  res = sendmsg (s, &msg, mhd_MSG_NOSIGNAL
                 | ((push_hdr || push_body) ? 0 : mhd_MSG_MORE));
#elif defined(HAVE_WRITEV)
  res = writev (s, vector, 2);
#endif /* HAVE_WRITEV */
  if (0 < res)
    *sent = (size_t) res;
  else
    send_error = true;
#endif /* HAVE_SENDMSG || HAVE_WRITEV */
#ifdef _WIN32
  if (((mhd_iov_elmn_size) body_size) != body_size)
  {
    /* Send item size limit */
    body_size = mhd_IOV_ELMN_MAX_SIZE;
    complete_response = false;
    push_body = complete_response;
  }
  vector[0].buf = (char *) mhd_DROP_CONST (header);
  vector[0].len = (unsigned long) header_size;
  vector[1].buf = (char *) mhd_DROP_CONST (body);
  vector[1].len = (unsigned long) body_size;

  res = WSASend (s, vector, 2, &vec_sent, 0, NULL, NULL);
  if (0 == res)
    *sent = (size_t) vec_sent;
  else
    send_error = true;
#endif /* _WIN32 */

  if (send_error)
  {
    enum mhd_SocketError err;

    err = mhd_socket_error_get_from_sys_err (mhd_SCKT_GET_LERR ());

    if (mhd_SOCKET_ERR_AGAIN == err)
      connection->sk_ready = (enum mhd_SocketNetState) /* Clear 'send-ready' */
                             (((unsigned int) connection->sk_ready)
                              & (~(enum mhd_SocketNetState)
                                 mhd_SOCKET_NET_STATE_SEND_READY));

    return err;
  }
  if ((header_size + body_size) > *sent)
    connection->sk_ready = (enum mhd_SocketNetState) /* Clear 'send-ready' */
                           (((unsigned int) connection->sk_ready)
                            & (~(enum mhd_SocketNetState)
                               mhd_SOCKET_NET_STATE_SEND_READY));

  /* If there is a need to push the data from network buffers
   * call post_send_setopt(). */
  if ( (push_body) &&
       ((header_size + body_size) == *sent) )
  {
    /* Complete reply has been sent. */
    /* If TLS connection is used then next final send() will be
     * without MSG_MORE support. If non-TLS connection is used
     * it's unknown whether next 'send' will be plain send() / sendmsg() or
     * sendfile() will be used so assume that next final send() will be
     * the same, like for this response. */
    post_send_setopt (connection,
#ifdef HAVE_SENDMSG
                      true,  /* Assume the same type of the send function */
#else  /* ! HAVE_SENDMSG */
                      false, /* Assume the same type of the send function */
#endif /* ! HAVE_SENDMSG */
                      true);
  }
  else if ( (push_hdr) &&
            (header_size <= *sent))
  {
    /* The header has been sent completely and there is a
     * need to push the header data. */
    /* Luckily the type of send function will be used next is known. */
    post_send_setopt (connection,
                      true,
                      true);
  }

  return mhd_SOCKET_ERR_NO_ERROR;
#else  /* ! mhd_USE_VECT_SEND */
  mhd_assert (0 && "Should be unreachable");
  return mhd_SOCKET_ERR_INTERNAL; /* Unreachable. Mute warnings. */
#endif /* ! mhd_USE_VECT_SEND */
}


#if defined(MHD_USE_SENDFILE)

#if defined(HAVE_LINUX_SENDFILE) && defined(HAVE_SENDFILE64)
#  define mhd_off_t off64_t
#else
#  define mhd_off_t off_t
#endif

MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (2) enum mhd_SocketError
mhd_send_sendfile (struct MHD_Connection *restrict c,
                   size_t *restrict sent)
{
  enum mhd_SocketError ret;
  const bool used_thr_p_c =
    mhd_D_HAS_THR_PER_CONN (c->daemon);
  const size_t chunk_size =
    used_thr_p_c ?
    mhd_SENFILE_CHUNK_SIZE_FOR_THR_P_C : mhd_SENFILE_CHUNK_SIZE;
  const int file_fd = c->rp.response->cntn.file.fd;
  mhd_off_t offset;
  size_t send_size;
  size_t sent_bytes;
  bool push_data;
  bool fallback_to_filereader;
  mhd_assert (mhd_REPLY_CNTN_LOC_FILE == c->rp.cntn_loc);
  mhd_assert (MHD_SIZE_UNKNOWN != c->rp.response->cntn_size);
  mhd_assert (chunk_size <= (size_t) SSIZE_MAX);
  // mhd_assert (0 == (connection->daemon->options & MHD_USE_TLS)); // TODO: TLS support

  send_size = 0;
  push_data = true;
  if (1)
  {
    bool too_large;
    uint_fast64_t left;

    offset = (mhd_off_t)
             (c->rp.rsp_cntn_read_pos + c->rp.response->cntn.file.offset);
    too_large = (((uint_fast64_t) offset) < c->rp.rsp_cntn_read_pos);
    too_large = too_large ||
                (((uint_fast64_t) offset) !=
                 (c->rp.rsp_cntn_read_pos + c->rp.response->cntn.file.offset));
    too_large = too_large || (0 > offset);
    if (too_large)
    {   /* Retry to send with file reader and standard 'send()'. */
      c->rp.response->cntn.file.use_sf = false;
      return mhd_SOCKET_ERR_INTR;
    }

    left = c->rp.response->cntn_size - c->rp.rsp_cntn_read_pos;

    /* Do not allow system to stick sending on single fast connection:
     * use 128KiB chunks (2MiB for thread-per-connection). */
    if (chunk_size < left) /* This also limit to SSIZE_MAX automatically */
    {
      send_size = chunk_size;
      push_data = false; /* No need to push data, there is more to send. */
    }
    else
      send_size = (size_t) left;
  }
  mhd_assert (0 != send_size);

  pre_send_setopt (c, false, push_data);

  sent_bytes = 0;
  ret = mhd_SOCKET_ERR_NO_ERROR;
  fallback_to_filereader = false;
#if defined(HAVE_LINUX_SENDFILE)
  if (1)
  {
    ssize_t res;
#ifndef HAVE_SENDFILE64
    ret = sendfile (c->socket_fd,
                    file_fd,
                    &offset,
                    send_size);
#else  /* HAVE_SENDFILE64 */
    res = sendfile64 (c->socket_fd,
                      file_fd,
                      &offset,
                      send_size);
#endif /* HAVE_SENDFILE64 */
    if (0 > res)
    {
      const int sk_err = mhd_SCKT_GET_LERR ();

      if ((EINVAL == sk_err) ||
          (EOVERFLOW == sk_err) ||
#ifdef EIO
          (EIO == sk_err) ||
#endif
#ifdef EAFNOSUPPORT
          (EAFNOSUPPORT == sk_err) ||
#endif
          (EOPNOTSUPP == sk_err))
        fallback_to_filereader = true;
      else
        ret = mhd_socket_error_get_from_sys_err (sk_err);
    }
    else
      sent_bytes = (size_t) res;
  }
#elif defined(HAVE_FREEBSD_SENDFILE)
  if (1)
  {
    off_t sent_bytes_offt = 0;
    int flags = 0;
    bool sent_something = false;
#ifdef SF_FLAGS
    flags = used_thr_p_c ?
            freebsd_sendfile_flags_thd_p_c_ : freebsd_sendfile_flags_;
#endif /* SF_FLAGS */
    if (0 != sendfile (file_fd,
                       c->socket_fd,
                       offset,
                       send_size,
                       NULL,
                       &sent_bytes_offt,
                       flags))
    {
      const int sk_err = mhd_SCKT_GET_LERR ();

      sent_something =
        (((EAGAIN == sk_err) || (EBUSY == sk_err) || (EINTR == sk_err)) &&
         (0 != sent_bytes_offt));

      if (! sent_something)
      {
        enum mhd_SocketError err;
        if ((EINVAL == sk_err) ||
            (EIO == sk_err) ||
            (EOPNOTSUPP == sk_err))
          fallback_to_filereader = true;
        else
          ret = mhd_socket_error_get_from_sys_err (sk_err);
      }
    }
    else
      sent_something = true;

    if (sent_something)
    {
      mhd_assert (0 <= sent_bytes_offt);
      mhd_assert (SIZE_MAX >= sent_bytes_offt);
      sent_bytes = (size_t) sent_bytes_offt;
    }
  }
#elif defined(HAVE_DARWIN_SENDFILE)
  if (1)
  {
    off_t len;
    bool sent_something;

    sent_something = false;
    len = (off_t) send_size; /* chunk always fit */

    if (0 != sendfile (file_fd,
                       c->socket_fd,
                       offset,
                       &len,
                       NULL,
                       0))
    {
      const int sk_err = mhd_SCKT_GET_LERR ();

      sent_something =
        ((EAGAIN == sk_err) || (EINTR == sk_err)) &&
        (0 != len);

      if (! sent_something)
      {
        enum mhd_SocketError err;
        if ((ENOTSUP == sk_err) ||
            (EOPNOTSUPP == sk_err))
          fallback_to_filereader = true;
        else
          ret = mhd_socket_error_get_from_sys_err (sk_err);
      }
    }
    else
      sent_something = true;

    if (sent_something)
    {
      mhd_assert (0 <= len);
      mhd_assert (SIZE_MAX >= len);
      sent_bytes = (size_t) len;
    }
  }
#else
#error No sendfile() function
#endif

  mhd_assert (send_size >= sent_bytes);

  /* Some platforms indicate "beyond of the end of the file" by returning
   * success with zero bytes. Let filereader to re-detect this kind of error. */
  if ((fallback_to_filereader) ||
      ((mhd_SOCKET_ERR_NO_ERROR == ret) && (0 == sent_bytes)))
  {   /* Retry to send with file reader and standard 'send()'. */
    c->rp.response->cntn.file.use_sf = false;
    return mhd_SOCKET_ERR_INTR;
  }

  if ((mhd_SOCKET_ERR_AGAIN == ret) ||
      ((mhd_SOCKET_ERR_NO_ERROR == ret) && (send_size > sent_bytes)))
    c->sk_ready = (enum mhd_SocketNetState) /* Clear 'send-ready' */
                  (((unsigned int) c->sk_ready)
                   & (~(enum mhd_SocketNetState)
                      mhd_SOCKET_NET_STATE_SEND_READY));

  if (mhd_SOCKET_ERR_NO_ERROR != ret)
    return ret;

  /* If there is a need to push the data from network buffers
   * call post_send_setopt(). */
  /* It's unknown whether sendfile() will be used in the next
   * response so assume that next response will be the same. */
  if ((push_data) &&
      (send_size == sent_bytes))
    post_send_setopt (c, true, push_data);

  *sent = sent_bytes;
  return ret;
}


#endif /* MHD_USE_SENDFILE */

#if defined(mhd_USE_VECT_SEND)


/**
 * Function sends iov data by system sendmsg or writev function.
 *
 * Connection must be in non-TLS (non-HTTPS) mode.
 *
 * @param connection the MHD connection structure
 * @param r_iov the pointer to iov data structure with tracking
 * @param push_data set to true to force push the data to the network from
 *                  system buffers (usually set for the last piece of data),
 *                  set to false to prefer holding incomplete network packets
 *                  (more data will be send for the same reply).
 * @param[out] sent the pointer to get amount of actually sent bytes
 * @return mhd_SOCKET_ERR_NO_ERROR if send succeed (the @a sent gets
 *         the sent size) or socket error
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (4) enum mhd_SocketError
send_iov_nontls (struct MHD_Connection *restrict connection,
                 struct mhd_iovec_track *const restrict r_iov,
                 bool push_data,
                 size_t *restrict sent)
{
  bool send_error;
  size_t items_to_send;
#ifndef MHD_WINSOCK_SOCKETS
  ssize_t res;
#endif
#ifdef HAVE_SENDMSG
  struct msghdr msg;
#elif defined(MHD_WINSOCK_SOCKETS)
  DWORD bytes_sent;
  DWORD cnt_w;
#endif /* MHD_WINSOCK_SOCKETS */

  // TODO: assert for non-TLS

  mhd_assert (MHD_INVALID_SOCKET != connection->socket_fd);
  mhd_assert (MHD_CONNECTION_CLOSED != connection->state);

  send_error = false;
  items_to_send = r_iov->cnt - r_iov->sent;
#ifdef mhd_IOV_MAX
  if (mhd_IOV_MAX < items_to_send)
  {
    mhd_assert (0 < mhd_IOV_MAX);
    if (0 == mhd_IOV_MAX)
      return mhd_SOCKET_ERR_INTERNAL; /* Should never happen */
    items_to_send = mhd_IOV_MAX;
    push_data = false; /* Incomplete response */
  }
#endif /* mhd_IOV_MAX */
#ifdef HAVE_SENDMSG
  memset (&msg, 0, sizeof(struct msghdr));
  msg.msg_name = NULL;
  msg.msg_namelen = 0;
  msg.msg_iov = r_iov->iov + r_iov->sent;
  msg.msg_iovlen = items_to_send;
  msg.msg_control = NULL;
  msg.msg_controllen = 0;
  msg.msg_flags = 0;

  pre_send_setopt (connection, true, push_data);
  res = sendmsg (connection->socket_fd, &msg,
                 mhd_MSG_NOSIGNAL | (push_data ? 0 : mhd_MSG_MORE));
  if (0 < res)
    *sent = (size_t) res;
  else
    send_error = true;
#elif defined(HAVE_WRITEV)
  pre_send_setopt (connection, false, push_data);
  res = writev (connection->socket_fd, r_iov->iov + r_iov->sent,
                items_to_send);
  if (0 < res)
    *sent = (size_t) res;
  else
    send_error = true;
#elif defined(MHD_WINSOCK_SOCKETS)
#ifdef _WIN64
  if (items_to_send > ULONG_MAX)
  {
    cnt_w = ULONG_MAX;
    push_data = false; /* Incomplete response */
  }
  else
    cnt_w = (DWORD) items_to_send;
#else  /* ! _WIN64 */
  cnt_w = (DWORD) items_to_send;
#endif /* ! _WIN64 */
  pre_send_setopt (connection, true, push_data);
  if (0 == WSASend (connection->socket_fd,
                    (LPWSABUF) (r_iov->iov + r_iov->sent),
                    cnt_w,
                    &bytes_sent, 0, NULL, NULL))
    *sent = (size_t) bytes_sent;
  else
    send_error = true;
#else /* !HAVE_SENDMSG && !HAVE_WRITEV && !MHD_WINSOCK_SOCKETS */
#error No vector-send function available
#endif

  if (send_error)
  {
    enum mhd_SocketError err;

    err = mhd_socket_error_get_from_sys_err (mhd_SCKT_GET_LERR ());

    if (mhd_SOCKET_ERR_AGAIN == err)
      connection->sk_ready = (enum mhd_SocketNetState) /* Clear 'send-ready' */
                             (((unsigned int) connection->sk_ready)
                              & (~(enum mhd_SocketNetState)
                                 mhd_SOCKET_NET_STATE_SEND_READY));

    return err;
  }

  /* Some data has been sent */
  if (1)
  {
    size_t track_sent = (size_t) *sent;
    /* Adjust the internal tracking information for the iovec to
     * take this last send into account. */
    while ((0 != track_sent) && (r_iov->iov[r_iov->sent].iov_len <= track_sent))
    {
      track_sent -= r_iov->iov[r_iov->sent].iov_len;
      r_iov->sent++; /* The iov element has been completely sent */
      mhd_assert ((r_iov->cnt > r_iov->sent) || (0 == track_sent));
    }

    if (r_iov->cnt == r_iov->sent)
      post_send_setopt (connection, true, push_data);
    else
    {
      connection->sk_ready = (enum mhd_SocketNetState) /* Clear 'send-ready' */
                             (((unsigned int) connection->sk_ready)
                              & (~(enum mhd_SocketNetState)
                                 mhd_SOCKET_NET_STATE_SEND_READY));
      if (0 != track_sent)
      {
        mhd_assert (r_iov->cnt > r_iov->sent);
        /* The last iov element has been partially sent */
        r_iov->iov[r_iov->sent].iov_base =
          (void *) ((uint8_t *) r_iov->iov[r_iov->sent].iov_base + track_sent);
        r_iov->iov[r_iov->sent].iov_len -= (mhd_iov_elmn_size) track_sent;
      }
    }
  }

  return mhd_SOCKET_ERR_NO_ERROR;
}


#endif /* mhd_USE_VECT_SEND */

#if ! defined(mhd_USE_VECT_SEND) || defined(HTTPS_SUPPORT) || \
  defined(mhd_VECT_SEND_NEEDS_SPIPE_SUPPRESSED)


/**
 * Function sends iov data by sending buffers one-by-one by standard
 * data send function.
 *
 * Connection could be in HTTPS or non-HTTPS mode.
 *
 * @param connection the MHD connection structure
 * @param r_iov the pointer to iov data structure with tracking
 * @param push_data set to true to force push the data to the network from
 *                  system buffers (usually set for the last piece of data),
 *                  set to false to prefer holding incomplete network packets
 *                  (more data will be send for the same reply).
 * @param[out] sent the pointer to get amount of actually sent bytes
 * @return mhd_SOCKET_ERR_NO_ERROR if send succeed (the @a sent gets
 *         the sent size) or socket error
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (4) enum mhd_SocketError
send_iov_emu (struct MHD_Connection *restrict connection,
              struct mhd_iovec_track *const restrict r_iov,
              bool push_data,
              size_t *restrict sent)
{
  const bool non_blk = connection->sk_nonblck;
  size_t total_sent;
  size_t max_elelements_to_sent;

  mhd_assert (NULL != r_iov->iov);
  total_sent = 0;
  max_elelements_to_sent = 8; /* Do not make too many sys-calls for just one connection */
  do
  {
    enum mhd_SocketError res;
    size_t sent_el_size;

    if (total_sent > (size_t) (r_iov->iov[r_iov->sent].iov_len + total_sent))
      break; /* return value would overflow */

    res = mhd_send_data (connection,
                         r_iov->iov[r_iov->sent].iov_len,
                         r_iov->iov[r_iov->sent].iov_base,
                         push_data && (r_iov->cnt == r_iov->sent + 1),
                         &sent_el_size);
    if (mhd_SOCKET_ERR_NO_ERROR == res)
    {
      /* Result is an error */
      if (0 == total_sent)
        return res; /* Nothing was sent, return error as is */

      if (mhd_SOCKET_ERR_IS_HARD (res))
        return res; /* Any kind of a hard error */

      break; /* Return the amount of the sent data */
    }

    total_sent += sent_el_size;

    if (r_iov->iov[r_iov->sent].iov_len != sent_el_size)
    {
      /* Incomplete buffer has been sent.
       * Adjust buffer of the last element. */
      r_iov->iov[r_iov->sent].iov_base =
        (void *) ((uint8_t *) r_iov->iov[r_iov->sent].iov_base + sent_el_size);
      r_iov->iov[r_iov->sent].iov_len -= (mhd_iov_elmn_size) sent_el_size;

      break; /* Return the amount of the sent data */
    }
    /* The iov element has been completely sent */
    r_iov->sent++;
  } while ((r_iov->cnt > r_iov->sent) && 0 != (--max_elelements_to_sent) &&
           (non_blk));

  mhd_assert (0 != total_sent);
  *sent = total_sent;
  return mhd_SOCKET_ERR_NO_ERROR;
}


#endif /* !mhd_USE_VECT_SEND || HTTPS_SUPPORT
          || mhd_VECT_SEND_NEEDS_SPIPE_SUPPRESSED */

MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_OUT_ (4) enum mhd_SocketError
mhd_send_iovec (struct MHD_Connection *restrict connection,
                struct mhd_iovec_track *const restrict r_iov,
                bool push_data,
                size_t *restrict sent)
{
#ifdef mhd_USE_VECT_SEND
#if defined(HTTPS_SUPPORT) || \
  defined(mhd_VECT_SEND_NEEDS_SPIPE_SUPPRESSED)
  bool use_iov_send = true;
#endif /* HTTPS_SUPPORT || mhd_VECT_SEND_NEEDS_SPIPE_SUPPRESSED */
#endif /* mhd_USE_VECT_SEND */

  mhd_assert (NULL != connection->rp.resp_iov.iov);
  mhd_assert (mhd_RESPONSE_CONTENT_DATA_IOVEC == \
              connection->rp.response->cntn_dtype);
  mhd_assert (connection->rp.resp_iov.cnt > connection->rp.resp_iov.sent);
#ifdef mhd_USE_VECT_SEND
#if defined(HTTPS_SUPPORT) || \
  defined(mhd_VECT_SEND_NEEDS_SPIPE_SUPPRESSED)
#ifdef HTTPS_SUPPORT
  use_iov_send = use_iov_send &&
                 (true); // TODO: TLS support
#endif /* HTTPS_SUPPORT */
#ifdef mhd_VECT_SEND_NEEDS_SPIPE_SUPPRESSED
  use_iov_send = use_iov_send && (connection->daemon->sigpipe_blocked ||
                                  connection->sk_spipe_suppress);
#endif /* mhd_VECT_SEND_NEEDS_SPIPE_SUPPRESSED */
  if (use_iov_send)
#endif /* HTTPS_SUPPORT || mhd_VECT_SEND_NEEDS_SPIPE_SUPPRESSED */
  return send_iov_nontls (connection, r_iov, push_data, sent);
#endif /* mhd_USE_VECT_SEND */

#if ! defined(mhd_USE_VECT_SEND) || defined(HTTPS_SUPPORT) || \
  defined(mhd_VECT_SEND_NEEDS_SPIPE_SUPPRESSED)
  return send_iov_emu (connection, r_iov, push_data, sent);
#endif /* !mhd_USE_VECT_SEND || HTTPS_SUPPORT
          || mhd_VECT_SEND_NEEDS_SPIPE_SUPPRESSED */
}
