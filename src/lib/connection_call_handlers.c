/*
  This file is part of libmicrohttpd
  Copyright (C) 2007-2018 Daniel Pittman and Christian Grothoff

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
 * @file lib/connection_call_handlers.c
 * @brief call the connection's handlers based on the event trigger
 * @author Christian Grothoff
 */
#include "internal.h"
#include "connection_call_handlers.h"
#include "connection_update_last_activity.h"
#include "connection_close.h"

#ifdef MHD_LINUX_SOLARIS_SENDFILE
#include <sys/sendfile.h>
#endif /* MHD_LINUX_SOLARIS_SENDFILE */
#if defined(HAVE_FREEBSD_SENDFILE) || defined(HAVE_DARWIN_SENDFILE)
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#endif /* HAVE_FREEBSD_SENDFILE || HAVE_DARWIN_SENDFILE */


/**
 * sendfile() chuck size
 */
#define MHD_SENFILE_CHUNK_         (0x20000)

/**
 * sendfile() chuck size for thread-per-connection
 */
#define MHD_SENFILE_CHUNK_THR_P_C_ (0x200000)

#ifdef HAVE_FREEBSD_SENDFILE
#ifdef SF_FLAGS
/**
 * FreeBSD sendfile() flags
 */
static int freebsd_sendfile_flags_;

/**
 * FreeBSD sendfile() flags for thread-per-connection
 */
static int freebsd_sendfile_flags_thd_p_c_;
#endif /* SF_FLAGS */


/**
 * Initialises static variables.
 *
 * FIXME: make sure its actually called!
 */
void
MHD_conn_init_static_ (void)
{
/* FreeBSD 11 and later allow to specify read-ahead size
 * and handles SF_NODISKIO differently.
 * SF_FLAGS defined only on FreeBSD 11 and later. */
#ifdef SF_FLAGS
  long sys_page_size = sysconf (_SC_PAGESIZE);
  if (0 > sys_page_size)
    { /* Failed to get page size. */
      freebsd_sendfile_flags_ = SF_NODISKIO;
      freebsd_sendfile_flags_thd_p_c_ = SF_NODISKIO;
    }
  else
    {
      freebsd_sendfile_flags_ =
          SF_FLAGS((uint16_t)(MHD_SENFILE_CHUNK_ / sys_page_size), SF_NODISKIO);
      freebsd_sendfile_flags_thd_p_c_ =
          SF_FLAGS((uint16_t)(MHD_SENFILE_CHUNK_THR_P_C_ / sys_page_size), SF_NODISKIO);
    }
#endif /* SF_FLAGS */
}
#endif /* HAVE_FREEBSD_SENDFILE */



/**
 * Message to transmit when http 1.1 request is received
 */
#define HTTP_100_CONTINUE "HTTP/1.1 100 Continue\r\n\r\n"


/**
 * A serious error occured, close the
 * connection (and notify the application).
 *
 * @param connection connection to close with error
 * @param sc the reason for closing the connection
 * @param emsg error message (can be NULL)
 */
static void
connection_close_error (struct MHD_Connection *connection,
			enum MHD_StatusCode sc,
			const char *emsg)
{
#ifdef HAVE_MESSAGES
  if (NULL != emsg)
    MHD_DLOG (connection->daemon,
	      sc,
              emsg);
#else  /* ! HAVE_MESSAGES */
  (void) emsg; /* Mute compiler warning. */
  (void) sc;
#endif /* ! HAVE_MESSAGES */
  MHD_connection_close_ (connection,
                         MHD_REQUEST_TERMINATED_WITH_ERROR);
}


/**
 * Macro to only include error message in call to
 * #connection_close_error() if we have HAVE_MESSAGES.
 */
#ifdef HAVE_MESSAGES
#define CONNECTION_CLOSE_ERROR(c, sc, emsg) connection_close_error (c, sc, emsg)
#else
#define CONNECTION_CLOSE_ERROR(c, sc, emsg) connection_close_error (c, sc, NULL)
#endif


/**
 * Try growing the read buffer.  We initially claim half the available
 * buffer space for the read buffer (the other half being left for
 * management data structures; the write buffer can in the end take
 * virtually everything as the read buffer can be reduced to the
 * minimum necessary at that point.
 *
 * @param request the request for which to grow the buffer
 * @return true on success, false on failure
 */
static bool
try_grow_read_buffer (struct MHD_Request *request)
{
  struct MHD_Daemon *daemon = request->daemon;
  void *buf;
  size_t new_size;

  if (0 == request->read_buffer_size)
    new_size = daemon->connection_memory_limit_b / 2;
  else
    new_size = request->read_buffer_size +
      daemon->connection_memory_increment_b;
  buf = MHD_pool_reallocate (request->connection->pool,
                             request->read_buffer,
                             request->read_buffer_size,
                             new_size);
  if (NULL == buf)
    return false;
  /* we can actually grow the buffer, do it! */
  request->read_buffer = buf;
  request->read_buffer_size = new_size;
  return true;
}


/**
 * This function handles a particular request when it has been
 * determined that there is data to be read off a socket.
 *
 * @param request request to handle
 */
static void
MHD_request_handle_read_ (struct MHD_Request *request)
{
  struct MHD_Daemon *daemon = request->daemon;
  struct MHD_Connection *connection = request->connection;
  ssize_t bytes_read;

  if ( (MHD_REQUEST_CLOSED == request->state) ||
       (connection->suspended) )
    return;
#ifdef HTTPS_SUPPORT
  {
    struct MHD_TLS_Plugin *tls;

    if ( (NULL != (tls = daemon->tls_api)) &&
	 (! tls->handshake (tls->cls,
			    connection->tls_cs)) )
      return;
  }
#endif /* HTTPS_SUPPORT */

  /* make sure "read" has a reasonable number of bytes
     in buffer to use per system call (if possible) */
  if (request->read_buffer_offset +
      daemon->connection_memory_increment_b >
      request->read_buffer_size)
    try_grow_read_buffer (request);

  if (request->read_buffer_size == request->read_buffer_offset)
    return; /* No space for receiving data. */
  bytes_read = connection->recv_cls (connection,
                                     &request->read_buffer
                                     [request->read_buffer_offset],
                                     request->read_buffer_size -
                                     request->read_buffer_offset);
  if (bytes_read < 0)
    {
      if (MHD_ERR_AGAIN_ == bytes_read)
          return; /* No new data to process. */
      if (MHD_ERR_CONNRESET_ == bytes_read)
        {
	  CONNECTION_CLOSE_ERROR (connection,
				  (MHD_REQUEST_INIT == request->state)
				  ? MHD_SC_CONNECTION_CLOSED
				  : MHD_SC_CONNECTION_RESET_CLOSED,
				  (MHD_REQUEST_INIT == request->state) 
				  ? NULL
				  : _("Socket disconnected while reading request.\n"));
           return;
        }
      CONNECTION_CLOSE_ERROR (connection,
			      (MHD_REQUEST_INIT == request->state)
			      ? MHD_SC_CONNECTION_CLOSED
			      : MHD_SC_CONNECTION_READ_FAIL_CLOSED,
                              (MHD_REQUEST_INIT == request->state) 
			      ? NULL 
                              : _("Connection socket is closed due to error when reading request.\n"));
      return;
    }

  if (0 == bytes_read)
    { /* Remote side closed connection. */
      connection->read_closed = true;
      MHD_connection_close_ (connection,
                             MHD_REQUEST_TERMINATED_CLIENT_ABORT);
      return;
    }
  request->read_buffer_offset += bytes_read;
  MHD_connection_update_last_activity_ (connection);
#if DEBUG_STATES
  MHD_DLOG (daemon,
	    MHD_SC_STATE_MACHINE_STATUS_REPORT,
            _("In function %s handling connection at state: %s\n"),
            __FUNCTION__,
            MHD_state_to_string (request->state));
#endif
  switch (request->state)
    {
    case MHD_REQUEST_INIT:
    case MHD_REQUEST_URL_RECEIVED:
    case MHD_REQUEST_HEADER_PART_RECEIVED:
    case MHD_REQUEST_HEADERS_RECEIVED:
    case MHD_REQUEST_HEADERS_PROCESSED:
    case MHD_REQUEST_CONTINUE_SENDING:
    case MHD_REQUEST_CONTINUE_SENT:
    case MHD_REQUEST_BODY_RECEIVED:
    case MHD_REQUEST_FOOTER_PART_RECEIVED:
      /* nothing to do but default action */
      if (connection->read_closed)
        {
          MHD_connection_close_ (connection,
                                 MHD_REQUEST_TERMINATED_READ_ERROR);
        }
      return;
    case MHD_REQUEST_CLOSED:
      return;
#ifdef UPGRADE_SUPPORT
    case MHD_REQUEST_UPGRADE:
      mhd_assert (0);
      return;
#endif /* UPGRADE_SUPPORT */
    default:
      /* shrink read buffer to how much is actually used */
      MHD_pool_reallocate (connection->pool,
                           request->read_buffer,
                           request->read_buffer_size + 1,
                           request->read_buffer_offset);
      break;
    }
  return;
}


#if defined(_MHD_HAVE_SENDFILE)
/**
 * Function for sending responses backed by file FD.
 *
 * @param connection the MHD connection structure
 * @return actual number of bytes sent
 */
static ssize_t
sendfile_adapter (struct MHD_Connection *connection)
{
  struct MHD_Daemon *daemon = connection->daemon;
  struct MHD_Request *request = &connection->request;
  struct MHD_Response *response = request->response;
  ssize_t ret;
  const int file_fd = response->fd;
  uint64_t left;
  uint64_t offsetu64;
#ifndef HAVE_SENDFILE64
  const uint64_t max_off_t = (uint64_t)OFF_T_MAX;
#else  /* HAVE_SENDFILE64 */
  const uint64_t max_off_t = (uint64_t)OFF64_T_MAX;
#endif /* HAVE_SENDFILE64 */
#ifdef MHD_LINUX_SOLARIS_SENDFILE
#ifndef HAVE_SENDFILE64
  off_t offset;
#else  /* HAVE_SENDFILE64 */
  off64_t offset;
#endif /* HAVE_SENDFILE64 */
#endif /* MHD_LINUX_SOLARIS_SENDFILE */
#ifdef HAVE_FREEBSD_SENDFILE
  off_t sent_bytes;
  int flags = 0;
#endif
#ifdef HAVE_DARWIN_SENDFILE
  off_t len;
#endif /* HAVE_DARWIN_SENDFILE */
  const bool used_thr_p_c = (MHD_TM_THREAD_PER_CONNECTION == daemon->threading_model);
  const size_t chunk_size = used_thr_p_c ? MHD_SENFILE_CHUNK_THR_P_C_ : MHD_SENFILE_CHUNK_;
  size_t send_size = 0;

  mhd_assert (MHD_resp_sender_sendfile == request->resp_sender);
  offsetu64 = request->response_write_position + response->fd_off;
  left = response->total_size - request->response_write_position;
  /* Do not allow system to stick sending on single fast connection:
   * use 128KiB chunks (2MiB for thread-per-connection). */
  send_size = (left > chunk_size) ? chunk_size : (size_t) left;
  if (max_off_t < offsetu64)
    { /* Retry to send with standard 'send()'. */
      request->resp_sender = MHD_resp_sender_std;
      return MHD_ERR_AGAIN_;
    }
#ifdef MHD_LINUX_SOLARIS_SENDFILE
#ifndef HAVE_SENDFILE64
  offset = (off_t) offsetu64;
  ret = sendfile (connection->socket_fd,
                  file_fd,
                  &offset,
                  send_size);
#else  /* HAVE_SENDFILE64 */
  offset = (off64_t) offsetu64;
  ret = sendfile64 (connection->socket_fd,
                    file_fd,
                    &offset,
                    send_size);
#endif /* HAVE_SENDFILE64 */
  if (0 > ret)
    {
      const int err = MHD_socket_get_error_();
      
      if (MHD_SCKT_ERR_IS_EAGAIN_(err))
        {
#ifdef EPOLL_SUPPORT
          /* EAGAIN --- no longer write-ready */
          connection->epoll_state &= ~MHD_EPOLL_STATE_WRITE_READY;
#endif /* EPOLL_SUPPORT */
          return MHD_ERR_AGAIN_;
        }
      if (MHD_SCKT_ERR_IS_EINTR_ (err))
        return MHD_ERR_AGAIN_;
#ifdef HAVE_LINUX_SENDFILE
      if (MHD_SCKT_ERR_IS_(err,
                           MHD_SCKT_EBADF_))
        return MHD_ERR_BADF_;
      /* sendfile() failed with EINVAL if mmap()-like operations are not
         supported for FD or other 'unusual' errors occurred, so we should try
         to fall back to 'SEND'; see also this thread for info on
         odd libc/Linux behavior with sendfile:
         http://lists.gnu.org/archive/html/libmicrohttpd/2011-02/msg00015.html */
      request->resp_sender = MHD_resp_sender_std;
      return MHD_ERR_AGAIN_;
#else  /* HAVE_SOLARIS_SENDFILE */
      if ( (EAFNOSUPPORT == err) ||
           (EINVAL == err) ||
           (EOPNOTSUPP == err) )
        { /* Retry with standard file reader. */
          request->resp_sender = MHD_resp_sender_std;
          return MHD_ERR_AGAIN_;
        }
      if ( (ENOTCONN == err) ||
           (EPIPE == err) )
        {
          return MHD_ERR_CONNRESET_;
        }
      return MHD_ERR_BADF_; /* Fail hard */
#endif /* HAVE_SOLARIS_SENDFILE */
    }
#ifdef EPOLL_SUPPORT
  else if (send_size > (size_t)ret)
        connection->epoll_state &= ~MHD_EPOLL_STATE_WRITE_READY;
#endif /* EPOLL_SUPPORT */
#elif defined(HAVE_FREEBSD_SENDFILE)
#ifdef SF_FLAGS
  flags = used_thr_p_c ?
      freebsd_sendfile_flags_thd_p_c_ : freebsd_sendfile_flags_;
#endif /* SF_FLAGS */
  if (0 != sendfile (file_fd,
                     connection->socket_fd,
                     (off_t) offsetu64,
                     send_size,
                     NULL,
                     &sent_bytes,
                     flags))
    {
      const int err = MHD_socket_get_error_();
      if (MHD_SCKT_ERR_IS_EAGAIN_(err) ||
          MHD_SCKT_ERR_IS_EINTR_(err) ||
          EBUSY == err)
        {
          mhd_assert (SSIZE_MAX >= sent_bytes);
          if (0 != sent_bytes)
            return (ssize_t)sent_bytes;

          return MHD_ERR_AGAIN_;
        }
      /* Some unrecoverable error. Possibly file FD is not suitable
       * for sendfile(). Retry with standard send(). */
      request->resp_sender = MHD_resp_sender_std;
      return MHD_ERR_AGAIN_;
    }
  mhd_assert (0 < sent_bytes);
  mhd_assert (SSIZE_MAX >= sent_bytes);
  ret = (ssize_t)sent_bytes;
#elif defined(HAVE_DARWIN_SENDFILE)
  len = (off_t) send_size; /* chunk always fit */
  if (0 != sendfile (file_fd,
                     connection->socket_fd,
                     (off_t) offsetu64,
                     &len,
                     NULL,
                     0))
    {
      const int err = MHD_socket_get_error_();
      if (MHD_SCKT_ERR_IS_EAGAIN_(err) ||
          MHD_SCKT_ERR_IS_EINTR_(err))
        {
          mhd_assert (0 <= len);
          mhd_assert (SSIZE_MAX >= len);
          mhd_assert (send_size >= (size_t)len);
          if (0 != len)
            return (ssize_t)len;

          return MHD_ERR_AGAIN_;
        }
      if (ENOTCONN == err ||
          EPIPE == err)
        return MHD_ERR_CONNRESET_;
      if (ENOTSUP == err ||
          EOPNOTSUPP == err)
        { /* This file FD is not suitable for sendfile().
           * Retry with standard send(). */
          request->resp_sender = MHD_resp_sender_std;
          return MHD_ERR_AGAIN_;
        }
      return MHD_ERR_BADF_; /* Return hard error. */
    }
  mhd_assert (0 <= len);
  mhd_assert (SSIZE_MAX >= len);
  mhd_assert (send_size >= (size_t)len);
  ret = (ssize_t)len;
#endif /* HAVE_FREEBSD_SENDFILE */
  return ret;
}
#endif /* _MHD_HAVE_SENDFILE */


/**
 * Check if we are done sending the write-buffer.  If so, transition
 * into "next_state".
 *
 * @param connection connection to check write status for
 * @param next_state the next state to transition to
 * @return false if we are not done, true if we are
 */
static bool
check_write_done (struct MHD_Request *request,
                  enum MHD_REQUEST_STATE next_state)
{
  if (request->write_buffer_append_offset !=
      request->write_buffer_send_offset)
    return false;
  request->write_buffer_append_offset = 0;
  request->write_buffer_send_offset = 0;
  request->state = next_state;
  MHD_pool_reallocate (request->connection->pool,
		       request->write_buffer,
                       request->write_buffer_size,
                       0);
  request->write_buffer = NULL;
  request->write_buffer_size = 0;
  return true;
}


/**
 * Prepare the response buffer of this request for sending.  Assumes
 * that the response mutex is already held.  If the transmission is
 * complete, this function may close the socket (and return false).
 *
 * @param request the request handle
 * @return false if readying the response failed (the
 *  lock on the response will have been released already
 *  in this case).
 */
static bool
try_ready_normal_body (struct MHD_Request *request)
{
  struct MHD_Response *response = request->response;
  struct MHD_Connection *connection = request->connection;
  ssize_t ret;

  if (NULL == response->crc)
    return true;
  if ( (0 == response->total_size) ||
       (request->response_write_position == response->total_size) )
    return true; /* 0-byte response is always ready */
  if ( (response->data_start <=
	request->response_write_position) &&
       (response->data_size + response->data_start >
	request->response_write_position) )
    return true; /* response already ready */
#if defined(_MHD_HAVE_SENDFILE)
  if (MHD_resp_sender_sendfile == request->resp_sender)
    {
      /* will use sendfile, no need to bother response crc */
      return true;
    }
#endif /* _MHD_HAVE_SENDFILE */

  ret = response->crc (response->crc_cls,
                       request->response_write_position,
                       response->data,
                       (size_t) MHD_MIN ((uint64_t) response->data_buffer_size,
                                         response->total_size -
                                         request->response_write_position));
  if ( (((ssize_t) MHD_CONTENT_READER_END_OF_STREAM) == ret) ||
       (((ssize_t) MHD_CONTENT_READER_END_WITH_ERROR) == ret) )
    {
      /* either error or http 1.0 transfer, close socket! */
      response->total_size = request->response_write_position;
      MHD_mutex_unlock_chk_ (&response->mutex);
      if ( ((ssize_t)MHD_CONTENT_READER_END_OF_STREAM) == ret)
	MHD_connection_close_ (connection,
                               MHD_REQUEST_TERMINATED_COMPLETED_OK);
      else
	CONNECTION_CLOSE_ERROR (connection,
				MHD_SC_APPLICATION_DATA_GENERATION_FAILURE_CLOSED,
				_("Closing connection (application reported error generating data)\n"));
      return false;
    }
  response->data_start = request->response_write_position;
  response->data_size = ret;
  if (0 == ret)
    {
      request->state = MHD_REQUEST_NORMAL_BODY_UNREADY;
      MHD_mutex_unlock_chk_ (&response->mutex);
      return false;
    }
  return true;
}


/**
 * Prepare the response buffer of this request for sending.  Assumes
 * that the response mutex is already held.  If the transmission is
 * complete, this function may close the socket (and return false).
 *
 * @param connection the connection
 * @return false if readying the response failed
 */
static bool
try_ready_chunked_body (struct MHD_Request *request)
{
  struct MHD_Connection *connection = request->connection;
  struct MHD_Response *response = request->response;
  struct MHD_Daemon *daemon = request->daemon;
  ssize_t ret;
  char *buf;
  size_t size;
  char cbuf[10];                /* 10: max strlen of "%x\r\n" */
  int cblen;

  if (NULL == response->crc)
    return true;
  if (0 == request->write_buffer_size)
    {
      size = MHD_MIN (daemon->connection_memory_limit_b,
                      2 * (0xFFFFFF + sizeof(cbuf) + 2));
      do
        {
          size /= 2;
          if (size < 128)
            {
              MHD_mutex_unlock_chk_ (&response->mutex);
              /* not enough memory */
              CONNECTION_CLOSE_ERROR (connection,
				      MHD_SC_CONNECTION_POOL_MALLOC_FAILURE,
				      _("Closing connection (out of memory)\n"));
              return false;
            }
          buf = MHD_pool_allocate (connection->pool,
                                   size,
                                   MHD_NO);
        }
      while (NULL == buf);
      request->write_buffer_size = size;
      request->write_buffer = buf;
    }

  if (0 == response->total_size)
    ret = 0; /* response must be empty, don't bother calling crc */
  else if ( (response->data_start <=
	request->response_write_position) &&
       (response->data_start + response->data_size >
	request->response_write_position) )
    {
      /* difference between response_write_position and data_start is less
         than data_size which is size_t type, no need to check for overflow */
      const size_t data_write_offset
        = (size_t)(request->response_write_position - response->data_start);
      /* buffer already ready, use what is there for the chunk */
      ret = response->data_size - data_write_offset;
      if ( ((size_t) ret) > request->write_buffer_size - sizeof (cbuf) - 2 )
	ret = request->write_buffer_size - sizeof (cbuf) - 2;
      memcpy (&request->write_buffer[sizeof (cbuf)],
              &response->data[data_write_offset],
              ret);
    }
  else
    {
      /* buffer not in range, try to fill it */
      ret = response->crc (response->crc_cls,
                           request->response_write_position,
                           &request->write_buffer[sizeof (cbuf)],
                           request->write_buffer_size - sizeof (cbuf) - 2);
    }
  if ( ((ssize_t) MHD_CONTENT_READER_END_WITH_ERROR) == ret)
    {
      /* error, close socket! */
      response->total_size = request->response_write_position;
      MHD_mutex_unlock_chk_ (&response->mutex);
      CONNECTION_CLOSE_ERROR (connection,
			      MHD_SC_APPLICATION_DATA_GENERATION_FAILURE_CLOSED,
			      _("Closing connection (application error generating response)\n"));
      return false;
    }
  if ( (((ssize_t) MHD_CONTENT_READER_END_OF_STREAM) == ret) ||
       (0 == response->total_size) )
    {
      /* end of message, signal other side! */
      strcpy (request->write_buffer,
              "0\r\n");
      request->write_buffer_append_offset = 3;
      request->write_buffer_send_offset = 0;
      response->total_size = request->response_write_position;
      return true;
    }
  if (0 == ret)
    {
      request->state = MHD_REQUEST_CHUNKED_BODY_UNREADY;
      MHD_mutex_unlock_chk_ (&response->mutex);
      return false;
    }
  if (ret > 0xFFFFFF)
    ret = 0xFFFFFF;
  cblen = MHD_snprintf_(cbuf,
                        sizeof (cbuf),
                        "%X\r\n",
                        (unsigned int) ret);
  mhd_assert(cblen > 0);
  mhd_assert((size_t)cblen < sizeof(cbuf));
  memcpy (&request->write_buffer[sizeof (cbuf) - cblen],
          cbuf,
          cblen);
  memcpy (&request->write_buffer[sizeof (cbuf) + ret],
          "\r\n",
          2);
  request->response_write_position += ret;
  request->write_buffer_send_offset = sizeof (cbuf) - cblen;
  request->write_buffer_append_offset = sizeof (cbuf) + ret + 2;
  return true;
}


/**
 * This function was created to handle writes to sockets when it has
 * been determined that the socket can be written to.
 *
 * @param request the request to handle
 */
static void
MHD_request_handle_write_ (struct MHD_Request *request)
{
  struct MHD_Daemon *daemon = request->daemon;
  struct MHD_Connection *connection = request->connection;
  struct MHD_Response *response;
  ssize_t ret;

  if (connection->suspended)
    return;
#ifdef HTTPS_SUPPORT
  {
    struct MHD_TLS_Plugin *tls;

    if ( (NULL != (tls = daemon->tls_api)) &&
	 (! tls->handshake (tls->cls,
			    connection->tls_cs)) )
      return;
  }
#endif /* HTTPS_SUPPORT */

#if DEBUG_STATES
  MHD_DLOG (daemon,
	    MHD_SC_STATE_MACHINE_STATUS_REPORT,
            _("In function %s handling connection at state: %s\n"),
            __FUNCTION__,
            MHD_state_to_string (request->state));
#endif
  switch (request->state)
    {
    case MHD_REQUEST_INIT:
    case MHD_REQUEST_URL_RECEIVED:
    case MHD_REQUEST_HEADER_PART_RECEIVED:
    case MHD_REQUEST_HEADERS_RECEIVED:
      mhd_assert (0);
      return;
    case MHD_REQUEST_HEADERS_PROCESSED:
      return;
    case MHD_REQUEST_CONTINUE_SENDING:
      ret = connection->send_cls (connection,
                                  &HTTP_100_CONTINUE
                                  [request->continue_message_write_offset],
                                  MHD_STATICSTR_LEN_ (HTTP_100_CONTINUE) -
                                  request->continue_message_write_offset);
      if (ret < 0)
        {
          if (MHD_ERR_AGAIN_ == ret)
            return;
#ifdef HAVE_MESSAGES
          MHD_DLOG (daemon,
		    MHD_SC_CONNECTION_WRITE_FAIL_CLOSED,
                    _("Failed to send data in request for %s.\n"),
                    request->url);
#endif
          CONNECTION_CLOSE_ERROR (connection,
				  MHD_SC_CONNECTION_WRITE_FAIL_CLOSED,
                                  NULL);
          return;
        }
      request->continue_message_write_offset += ret;
      MHD_connection_update_last_activity_ (connection);
      return;
    case MHD_REQUEST_CONTINUE_SENT:
    case MHD_REQUEST_BODY_RECEIVED:
    case MHD_REQUEST_FOOTER_PART_RECEIVED:
    case MHD_REQUEST_FOOTERS_RECEIVED:
      mhd_assert (0);
      return;
    case MHD_REQUEST_HEADERS_SENDING:
      ret = connection->send_cls (connection,
                                  &request->write_buffer
                                  [request->write_buffer_send_offset],
                                  request->write_buffer_append_offset -
                                    request->write_buffer_send_offset);
      if (ret < 0)
        {
          if (MHD_ERR_AGAIN_ == ret)
            return;
          CONNECTION_CLOSE_ERROR (connection,
				  MHD_SC_CONNECTION_WRITE_FAIL_CLOSED,
                                  _("Connection was closed while sending response headers.\n"));
          return;
        }
      request->write_buffer_send_offset += ret;
      MHD_connection_update_last_activity_ (connection);
      if (MHD_REQUEST_HEADERS_SENDING != request->state)
        return;
      check_write_done (request,
                        MHD_REQUEST_HEADERS_SENT);
      return;
    case MHD_REQUEST_HEADERS_SENT:
      return;
    case MHD_REQUEST_NORMAL_BODY_READY:
      response = request->response;
      if (request->response_write_position <
          request->response->total_size)
        {
          uint64_t data_write_offset;

          if (NULL != response->crc)
            MHD_mutex_lock_chk_ (&response->mutex);
          if (! try_ready_normal_body (request))
            {
              /* mutex was already unlocked by try_ready_normal_body */
              return;
            }
#if defined(_MHD_HAVE_SENDFILE)
          if (MHD_resp_sender_sendfile == request->resp_sender)
            {
              ret = sendfile_adapter (connection);
            }
          else
#else  /* ! _MHD_HAVE_SENDFILE */
          if (1)
#endif /* ! _MHD_HAVE_SENDFILE */
            {
              data_write_offset = request->response_write_position
                                  - response->data_start;
              if (data_write_offset > (uint64_t)SIZE_MAX)
                MHD_PANIC (_("Data offset exceeds limit"));
              ret = connection->send_cls (connection,
                                          &response->data
                                          [(size_t)data_write_offset],
                                          response->data_size -
                                          (size_t)data_write_offset);
#if DEBUG_SEND_DATA
              if (ret > 0)
                fprintf (stderr,
                         _("Sent %d-byte DATA response: `%.*s'\n"),
                         (int) ret,
                         (int) ret,
                         &response->data[request->response_write_position -
                                         response->data_start]);
#endif
            }
          if (NULL != response->crc)
            MHD_mutex_unlock_chk_ (&response->mutex);
          if (ret < 0)
            {
              if (MHD_ERR_AGAIN_ == ret)
                return;
#ifdef HAVE_MESSAGES
              MHD_DLOG (daemon,
			MHD_SC_CONNECTION_WRITE_FAIL_CLOSED,
                        _("Failed to send data in request for `%s'.\n"),
                        request->url);
#endif
              CONNECTION_CLOSE_ERROR (connection,
				      MHD_SC_CONNECTION_WRITE_FAIL_CLOSED,
                                      NULL);
              return;
            }
          request->response_write_position += ret;
          MHD_connection_update_last_activity_ (connection);
        }
      if (request->response_write_position ==
          request->response->total_size)
        request->state = MHD_REQUEST_FOOTERS_SENT; /* have no footers */
      return;
    case MHD_REQUEST_NORMAL_BODY_UNREADY:
      mhd_assert (0);
      return;
    case MHD_REQUEST_CHUNKED_BODY_READY:
      ret = connection->send_cls (connection,
                                  &request->write_buffer
                                  [request->write_buffer_send_offset],
                                  request->write_buffer_append_offset -
                                    request->write_buffer_send_offset);
      if (ret < 0)
        {
          if (MHD_ERR_AGAIN_ == ret)
            return;
          CONNECTION_CLOSE_ERROR (connection,
				  MHD_SC_CONNECTION_WRITE_FAIL_CLOSED,
                                  _("Connection was closed while sending response body.\n"));
          return;
        } 
      request->write_buffer_send_offset += ret;
      MHD_connection_update_last_activity_ (connection);
      if (MHD_REQUEST_CHUNKED_BODY_READY != request->state)
        return;
      check_write_done (request,
                        (request->response->total_size ==
                         request->response_write_position) ?
                        MHD_REQUEST_BODY_SENT :
                        MHD_REQUEST_CHUNKED_BODY_UNREADY);
      return;
    case MHD_REQUEST_CHUNKED_BODY_UNREADY:
    case MHD_REQUEST_BODY_SENT:
      mhd_assert (0);
      return;
    case MHD_REQUEST_FOOTERS_SENDING:
      ret = connection->send_cls (connection,
                                  &request->write_buffer
                                  [request->write_buffer_send_offset],
                                  request->write_buffer_append_offset -
                                    request->write_buffer_send_offset);
      if (ret < 0)
        {
          if (MHD_ERR_AGAIN_ == ret)
            return;
          CONNECTION_CLOSE_ERROR (connection,
				  MHD_SC_CONNECTION_WRITE_FAIL_CLOSED,
                                  _("Connection was closed while sending response body.\n"));
          return;
        }
      request->write_buffer_send_offset += ret;
      MHD_connection_update_last_activity_ (connection);
      if (MHD_REQUEST_FOOTERS_SENDING != request->state)
        return;
      check_write_done (request,
                        MHD_REQUEST_FOOTERS_SENT);
      return;
    case MHD_REQUEST_FOOTERS_SENT:
      mhd_assert (0);
      return;
    case MHD_REQUEST_CLOSED:
      return;
    case MHD_REQUEST_IN_CLEANUP:
      mhd_assert (0);
      return;
#ifdef UPGRADE_SUPPORT
    case MHD_REQUEST_UPGRADE:
      mhd_assert (0);
      return;
#endif /* UPGRADE_SUPPORT */
    default:
      mhd_assert (0);
      CONNECTION_CLOSE_ERROR (connection,
			      MHD_SC_STATEMACHINE_FAILURE_CONNECTION_CLOSED,
                              _("Internal error\n"));
      break;
    }
  return;
}


/**
 * Convert @a method to the respective enum value.
 *
 * @param method the method string to look up enum value for
 * @return resulting enum, or generic value for "unknown"
 */
static enum MHD_Method
method_string_to_enum (const char *method)
{
  static const struct {
    const char *key;
    enum MHD_Method value;
  } methods[] = {
    { "OPTIONS", MHD_METHOD_OPTIONS },
    { "GET", MHD_METHOD_GET },
    { "HEAD", MHD_METHOD_HEAD },
    { "POST", MHD_METHOD_POST },
    { "PUT", MHD_METHOD_PUT },
    { "DELETE", MHD_METHOD_DELETE },
    { "TRACE", MHD_METHOD_TRACE },
    { "CONNECT", MHD_METHOD_CONNECT },
    { "ACL", MHD_METHOD_ACL },
    { "BASELINE_CONTROL", MHD_METHOD_BASELINE_CONTROL },
    { "BIND", MHD_METHOD_BIND },
    { "CHECKIN", MHD_METHOD_CHECKIN },
    { "CHECKOUT", MHD_METHOD_CHECKOUT },
    { "COPY", MHD_METHOD_COPY },
    { "LABEL", MHD_METHOD_LABEL },
    { "LINK", MHD_METHOD_LINK },
    { "LOCK", MHD_METHOD_LOCK },
    { "MERGE", MHD_METHOD_MERGE },
    { "MKACTIVITY", MHD_METHOD_MKACTIVITY },
    { "MKCOL", MHD_METHOD_MKCOL },
    { "MKREDIRECTREF", MHD_METHOD_MKREDIRECTREF },
    { "MKWORKSPACE", MHD_METHOD_MKWORKSPACE },
    { "MOVE", MHD_METHOD_MOVE },
    { "ORDERPATCH", MHD_METHOD_ORDERPATCH },
    { "PRI", MHD_METHOD_PRI },
    { "PROPFIND", MHD_METHOD_PROPFIND },
    { "PROPPATCH", MHD_METHOD_PROPPATCH },
    { "REBIND", MHD_METHOD_REBIND },
    { "REPORT", MHD_METHOD_REPORT },
    { "SEARCH", MHD_METHOD_SEARCH },
    { "UNBIND", MHD_METHOD_UNBIND },
    { "UNCHECKOUT", MHD_METHOD_UNCHECKOUT },
    { "UNLINK", MHD_METHOD_UNLINK },
    { "UNLOCK", MHD_METHOD_UNLOCK },
    { "UPDATE", MHD_METHOD_UPDATE },
    { "UPDATEDIRECTREF", MHD_METHOD_UPDATEDIRECTREF },
    { "VERSION-CONTROL", MHD_METHOD_VERSION_CONTROL },
    { NULL, MHD_METHOD_UNKNOWN } /* must be last! */
  };
  unsigned int i;

  for (i=0;NULL != methods[i].key;i++)
    if (0 ==
	MHD_str_equal_caseless_ (method,
				 methods[i].key))
      return methods[i].value;
  return MHD_METHOD_UNKNOWN;
}


/**
 * Parse the first line of the HTTP HEADER.
 *
 * @param connection the connection (updated)
 * @param line the first line, not 0-terminated
 * @param line_len length of the first @a line
 * @return true if the line is ok, false if it is malformed
 */
static bool
parse_initial_message_line (struct MHD_Request *request,
                            char *line,
                            size_t line_len)
{
  struct MHD_Connection *connection = request->connection;
  struct MHD_Daemon *daemon = request->daemon;
  const char *curi;
  char *uri;
  char *http_version;
  char *args;
  unsigned int unused_num_headers;

  if (NULL == (uri = memchr (line,
                             ' ',
                             line_len)))
    return false;              /* serious error */
  uri[0] = '\0';
  request->method_s = line;
  request->method = method_string_to_enum (line);
  uri++;
  /* Skip any spaces. Not required by standard but allow
     to be more tolerant. */
  while ( (' ' == uri[0]) &&
          ( (size_t)(uri - line) < line_len) )
    uri++;
  if ((size_t)(uri - line) == line_len)
    {
      curi = "";
      uri = NULL;
      request->version = "";
      args = NULL;
    }
  else
    {
      curi = uri;
      /* Search from back to accept misformed URI with space */
      http_version = line + line_len - 1;
      /* Skip any trailing spaces */
      while ( (' ' == http_version[0]) &&
              (http_version > uri) )
        http_version--;
      /* Find first space in reverse direction */
      while ( (' ' != http_version[0]) &&
              (http_version > uri) )
        http_version--;
      if (http_version > uri)
        {
          http_version[0] = '\0';
          request->version = http_version + 1;
          args = memchr (uri,
                         '?',
                         http_version - uri);
        }
      else
        {
          request->version = "";
          args = memchr (uri,
                         '?',
                         line_len - (uri - line));
        }
    }
  if (NULL != daemon->uri_log_callback)
    {
      request->client_aware = true;
      request->client_context
        = daemon->early_uri_logger_cb (daemon->early_uri_logger_cb_cls,
				       curi,
				       request);
    }
  if (NULL != args)
    {
      args[0] = '\0';
      args++;
      /* note that this call clobbers 'args' */
      MHD_parse_arguments_ (connection,
			    MHD_GET_ARGUMENT_KIND,
			    args,
			    &connection_add_header,
			    &unused_num_headers);
    }
  if (NULL != uri)
    daemon->unescape_cb (daemon->unescape_cb_cls,
			 request,
			 uri);
  request->url = curi;
  return MHD_YES;
}


/**
 * Add an entry to the HTTP headers of a request.  If this fails,
 * transmit an error response (request too big).
 *
 * @param request the request for which a value should be set
 * @param kind kind of the value
 * @param key key for the value
 * @param value the value itself
 * @return false on failure (out of memory), true for success
 */
static bool
connection_add_header (struct MHD_Request *request,
                       const char *key,
		       const char *value,
		       enum MHD_ValueKind kind)
{
  if (MHD_NO ==
      MHD_request_set_value (request,
			     kind,
			     key,
			     value))
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (request->daemon,
                _("Not enough memory in pool to allocate header record!\n"));
#endif
      transmit_error_response (request->connection,
                               MHD_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE,
                               REQUEST_TOO_BIG);
      return false;
    }
  return true;
}


/**
 * We have received (possibly the beginning of) a line in the
 * header (or footer).  Validate (check for ":") and prepare
 * to process.
 *
 * @param request the request we're processing
 * @param line line from the header to process
 * @return true on success, false on error (malformed @a line)
 */
static bool
process_header_line (struct MHD_Request *request,
                     char *line)
{
  struct MHD_Connection *connection = request->connection;
  char *colon;

  /* line should be normal header line, find colon */
  colon = strchr (line, ':');
  if (NULL == colon)
    {
      /* error in header line, die hard */
      CONNECTION_CLOSE_ERROR (connection,
			      MHD_SC_CONNECTION_PARSE_FAIL_CLOSED,
			      _("Received malformed line (no colon). Closing connection.\n"));
      return false;
    }
  if (-1 >= request->daemon->strict_for_client)
    {
      /* check for whitespace before colon, which is not allowed
	 by RFC 7230 section 3.2.4; we count space ' ' and
	 tab '\t', but not '\r\n' as those would have ended the line. */
      const char *white;

      white = strchr (line,
		      (unsigned char) ' ');
      if ( (NULL != white) &&
	   (white < colon) )
	{
	  CONNECTION_CLOSE_ERROR (connection,
				  MHD_SC_CONNECTION_PARSE_FAIL_CLOSED,
				  _("Whitespace before colon forbidden by RFC 7230. Closing connection.\n"));
	  return false;
	}
      white = strchr (line,
		      (unsigned char) '\t');
      if ( (NULL != white) &&
	   (white < colon) )
	{
	  CONNECTION_CLOSE_ERROR (connection,
				  MHD_SC_CONNECTION_PARSE_FAIL_CLOSED,
				  _("Tab before colon forbidden by RFC 7230. Closing connection.\n"));
	  return false;
	}
    }
  /* zero-terminate header */
  colon[0] = '\0';
  colon++;                      /* advance to value */
  while ( ('\0' != colon[0]) &&
          ( (' ' == colon[0]) ||
            ('\t' == colon[0]) ) )
    colon++;
  /* we do the actual adding of the connection
     header at the beginning of the while
     loop since we need to be able to inspect
     the *next* header line (in case it starts
     with a space...) */
  request->last = line;
  request->colon = colon;
  return true;
}


/**
 * Process a header value that spans multiple lines.
 * The previous line(s) are in connection->last.
 *
 * @param request the request we're processing
 * @param line the current input line
 * @param kind if the line is complete, add a header
 *        of the given kind
 * @return true if the line was processed successfully
 */
static bool
process_broken_line (struct MHD_Request *request,
                     char *line,
                     enum MHD_ValueKind kind)
{
  struct MHD_Connection *connection = request->connection;
  char *last;
  char *tmp;
  size_t last_len;
  size_t tmp_len;

  last = request->last;
  if ( (' ' == line[0]) ||
       ('\t' == line[0]) )
    {
      /* value was continued on the next line, see
         http://www.jmarshall.com/easy/http/ */
      last_len = strlen (last);
      /* skip whitespace at start of 2nd line */
      tmp = line;
      while ( (' ' == tmp[0]) ||
              ('\t' == tmp[0]) )
        tmp++;
      tmp_len = strlen (tmp);
      /* FIXME: we might be able to do this better (faster!), as most
	 likely 'last' and 'line' should already be adjacent in
	 memory; however, doing this right gets tricky if we have a
	 value continued over multiple lines (in which case we need to
	 record how often we have done this so we can check for
	 adjacency); also, in the case where these are not adjacent
	 (not sure how it can happen!), we would want to allocate from
	 the end of the pool, so as to not destroy the read-buffer's
	 ability to grow nicely. */
      last = MHD_pool_reallocate (connection->pool,
                                  last,
                                  last_len + 1,
                                  last_len + tmp_len + 1);
      if (NULL == last)
        {
          transmit_error_response (connection,
                                   MHD_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE,
                                   REQUEST_TOO_BIG);
          return MHD_NO;
        }
      memcpy (&last[last_len],
	      tmp,
	      tmp_len + 1);
      request->last = last;
      return MHD_YES;           /* possibly more than 2 lines... */
    }
  mhd_assert ( (NULL != last) &&
                (NULL != request->colon) );
  if (! request_add_header (request,
			    last,
			    request->colon,
			    kind))
    {
      transmit_error_response (connection,
                               MHD_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE,
                               REQUEST_TOO_BIG);
      return false;
    }
  /* we still have the current line to deal with... */
  if ('\0' != line[0])
    {
      if (! process_header_line (request,
				 line))
        {
          transmit_error_response (connection,
                                   MHD_HTTP_BAD_REQUEST,
                                   REQUEST_MALFORMED);
          return false;
        }
    }
  return true;
}


#ifdef REWRITE_IN_PROGRESS

/**
 * This function was created to handle per-request processing that
 * has to happen even if the socket cannot be read or written to.
 * @remark To be called only from thread that process request's
 * recv(), send() and response.
 *
 * @param request the request to handle
 * @return true if we should continue to process the
 *         request (not dead yet), false if it died
 */
bool
MHD_request_handle_idle (struct MHD_Request *request)
{
  struct MHD_Daemon *daemon = request->daemon;
  struct MHD_Connection *connection = request->connection;
  char *line;
  size_t line_len;
  int ret;

  request->in_idle = true;
  while (! connection->suspended)
    {
#ifdef HTTPS_SUPPORT
      struct MHD_TLS_Plugin *tls;
      
      if ( (NULL != (tls = daemon->tls_api)) &&
	   (! tls->idle_ready (tls->cls,
			       connection->tls_cs)) )
	break;
#endif /* HTTPS_SUPPORT */
#if DEBUG_STATES
      MHD_DLOG (daemon,
		MHD_SC_STATE_MACHINE_STATUS_REPORT,
                _("In function %s handling connection at state: %s\n"),
                __FUNCTION__,
                MHD_state_to_string (request->state));
#endif
      switch (request->state)
        {
        case MHD_REQUEST_INIT:
          line = get_next_header_line (request,
                                       &line_len);
          /* Check for empty string, as we might want
             to tolerate 'spurious' empty lines; also
             NULL means we didn't get a full line yet;
             line is not 0-terminated here. */
          if ( (NULL == line) ||
               (0 == line[0]) )
            {
              if (MHD_REQUEST_INIT != request->state)
                continue;
              if (connection->read_closed)
                {
		  CONNECTION_CLOSE_ERROR (connection,
					  MHD_SC_CONNECTION_READ_FAIL_CLOSED,
					  NULL);
                  continue;
                }
              break;
            }
          if (MHD_NO ==
	      parse_initial_message_line (request,
					  line,
					  line_len))
            CONNECTION_CLOSE_ERROR (connection,
                                    NULL);
          else
            request->state = MHD_REQUEST_URL_RECEIVED;
          continue;
        case MHD_REQUEST_URL_RECEIVED:
          line = get_next_header_line (request,
                                       NULL);
          if (NULL == line)
            {
              if (MHD_REQUEST_URL_RECEIVED != request->state)
                continue;
              if (connection->read_closed)
                {
		  CONNECTION_CLOSE_ERROR (connection,
					  MHD_SC_CONNECTION_READ_FAIL_CLOSED,
					  NULL);
                  continue;
                }
              break;
            }
          if (0 == line[0])
            {
              request->state = MHD_REQUEST_HEADERS_RECEIVED;
              request->header_size = (size_t) (line - request->read_buffer);
              continue;
            }
          if (! process_header_line (request,
				     line))
            {
              transmit_error_response (connection,
                                       MHD_HTTP_BAD_REQUEST,
                                       REQUEST_MALFORMED);
              break;
            }
          request->state = MHD_REQUEST_HEADER_PART_RECEIVED;
          continue;
        case MHD_REQUEST_HEADER_PART_RECEIVED:
          line = get_next_header_line (request,
                                       NULL);
          if (NULL == line)
            {
              if (request->state != MHD_REQUEST_HEADER_PART_RECEIVED)
                continue;
              if (connection->read_closed)
                {
		  CONNECTION_CLOSE_ERROR (connection,
					  MHD_SC_CONNECTION_READ_FAIL_CLOSED,
					  NULL);
                  continue;
                }
              break;
            }
          if (MHD_NO ==
              process_broken_line (request,
                                   line,
                                   MHD_HEADER_KIND))
            continue;
          if (0 == line[0])
            {
              request->state = MHD_REQUEST_HEADERS_RECEIVED;
              request->header_size = (size_t) (line - request->read_buffer);
              continue;
            }
          continue;
        case MHD_REQUEST_HEADERS_RECEIVED:
          parse_request_headers (request);
          if (MHD_REQUEST_CLOSED == request->state)
            continue;
          request->state = MHD_REQUEST_HEADERS_PROCESSED;
          if (connection->suspended)
            break;
          continue;
        case MHD_REQUEST_HEADERS_PROCESSED:
          call_request_handler (request); /* first call */
          if (MHD_REQUEST_CLOSED == request->state)
            continue;
          if (need_100_continue (request))
            {
              request->state = MHD_REQUEST_CONTINUE_SENDING;
              if (socket_flush_possible (connection))
                socket_start_extra_buffering (connection);
              else
                socket_start_no_buffering (connection);
              break;
            }
          if ( (NULL != request->response) &&
	       ( (MHD_str_equal_caseless_ (request->method,
                                           MHD_HTTP_METHOD_POST)) ||
		 (MHD_str_equal_caseless_ (request->method,
                                           MHD_HTTP_METHOD_PUT))) )
            {
              /* we refused (no upload allowed!) */
              request->remaining_upload_size = 0;
              /* force close, in case client still tries to upload... */
              connection->read_closed = true;
            }
          request->state = (0 == request->remaining_upload_size)
            ? MHD_REQUEST_FOOTERS_RECEIVED : MHD_REQUEST_CONTINUE_SENT;
          if (connection->suspended)
            break;
          continue;
        case MHD_REQUEST_CONTINUE_SENDING:
          if (request->continue_message_write_offset ==
              MHD_STATICSTR_LEN_ (HTTP_100_CONTINUE))
            {
              request->state = MHD_REQUEST_CONTINUE_SENT;
              if (MHD_NO != socket_flush_possible (request))
                socket_start_no_buffering_flush (request);
              else
                socket_start_normal_buffering (request);

              continue;
            }
          break;
        case MHD_REQUEST_CONTINUE_SENT:
          if (0 != request->read_buffer_offset)
            {
              process_request_body (request);     /* loop call */
              if (MHD_REQUEST_CLOSED == request->state)
                continue;
            }
          if ( (0 == request->remaining_upload_size) ||
               ( (MHD_SIZE_UNKNOWN == request->remaining_upload_size) &&
                 (0 == request->read_buffer_offset) &&
                 (request->read_closed) ) )
            {
              if ( (request->have_chunked_upload) &&
                   (! request->read_closed) )
                request->state = MHD_REQUEST_BODY_RECEIVED;
              else
                request->state = MHD_REQUEST_FOOTERS_RECEIVED;
              if (connection->suspended)
                break;
              continue;
            }
          break;
        case MHD_REQUEST_BODY_RECEIVED:
          line = get_next_header_line (request,
                                       NULL);
          if (NULL == line)
            {
              if (request->state != MHD_REQUEST_BODY_RECEIVED)
                continue;
              if (connection->read_closed)
                {
		  CONNECTION_CLOSE_ERROR (connection,
					  NULL);
                  continue;
                }
              break;
            }
          if (0 == line[0])
            {
              request->state = MHD_REQUEST_FOOTERS_RECEIVED;
              if (connection->suspended)
                break;
              continue;
            }
          if (MHD_NO == process_header_line (request,
                                             line))
            {
              transmit_error_response (connection,
                                       MHD_HTTP_BAD_REQUEST,
                                       REQUEST_MALFORMED);
              break;
            }
          request->state = MHD_REQUEST_FOOTER_PART_RECEIVED;
          continue;
        case MHD_REQUEST_FOOTER_PART_RECEIVED:
          line = get_next_header_line (request,
                                       NULL);
          if (NULL == line)
            {
              if (request->state != MHD_REQUEST_FOOTER_PART_RECEIVED)
                continue;
              if (connection->read_closed)
                {
		  CONNECTION_CLOSE_ERROR (connection,
					  NULL);
                  continue;
                }
              break;
            }
          if (MHD_NO ==
              process_broken_line (request,
                                   line,
                                   MHD_FOOTER_KIND))
            continue;
          if (0 == line[0])
            {
              request->state = MHD_REQUEST_FOOTERS_RECEIVED;
              if (connection->suspended)
                break;
              continue;
            }
          continue;
        case MHD_REQUEST_FOOTERS_RECEIVED:
          call_request_handler (request); /* "final" call */
          if (request->state == MHD_REQUEST_CLOSED)
            continue;
          if (NULL == request->response)
            break;              /* try again next time */
          if (MHD_NO == build_header_response (request))
            {
              /* oops - close! */
	      CONNECTION_CLOSE_ERROR (connection,
				      _("Closing connection (failed to create response header)\n"));
              continue;
            }
          request->state = MHD_REQUEST_HEADERS_SENDING;
          if (MHD_NO != socket_flush_possible (connection))
            socket_start_extra_buffering (connection);
          else
            socket_start_no_buffering (connection);

          break;
        case MHD_REQUEST_HEADERS_SENDING:
          /* no default action */
          break;
        case MHD_REQUEST_HEADERS_SENT:
          /* Some clients may take some actions right after header receive */
          if (MHD_NO != socket_flush_possible (connection))
            socket_start_no_buffering_flush (connection);

#ifdef UPGRADE_SUPPORT
          if (NULL != request->response->upgrade_handler)
            {
              socket_start_normal_buffering (connection);
              request->state = MHD_REQUEST_UPGRADE;
              /* This request is "upgraded".  Pass socket to application. */
              if (MHD_YES !=
                  MHD_response_execute_upgrade_ (request->response,
                                                 request))
                {
                  /* upgrade failed, fail hard */
                  CONNECTION_CLOSE_ERROR (connection,
                                          NULL);
                  continue;
                }
              /* Response is not required anymore for this request. */
              if (NULL != request->response)
                {
                  struct MHD_Response * const resp = request->response;
                  request->response = NULL;
                  MHD_destroy_response (resp);
                }
              continue;
            }
#endif /* UPGRADE_SUPPORT */
          if (MHD_NO != socket_flush_possible (connection))
            socket_start_extra_buffering (connection);
          else
            socket_start_normal_buffering (connection);

          if (request->have_chunked_upload)
            request->state = MHD_REQUEST_CHUNKED_BODY_UNREADY;
          else
            request->state = MHD_REQUEST_NORMAL_BODY_UNREADY;
          continue;
        case MHD_REQUEST_NORMAL_BODY_READY:
          /* nothing to do here */
          break;
        case MHD_REQUEST_NORMAL_BODY_UNREADY:
          if (NULL != request->response->crc)
            MHD_mutex_lock_chk_ (&request->response->mutex);
          if (0 == request->response->total_size)
            {
              if (NULL != request->response->crc)
                MHD_mutex_unlock_chk_ (&request->response->mutex);
              request->state = MHD_REQUEST_BODY_SENT;
              continue;
            }
          if (try_ready_normal_body (request))
            {
	      if (NULL != request->response->crc)
	        MHD_mutex_unlock_chk_ (&request->response->mutex);
              request->state = MHD_REQUEST_NORMAL_BODY_READY;
              /* Buffering for flushable socket was already enabled*/
              if (MHD_NO == socket_flush_possible (connection))
                socket_start_no_buffering (connection);
              break;
            }
          /* mutex was already unlocked by "try_ready_normal_body */
          /* not ready, no socket action */
          break;
        case MHD_REQUEST_CHUNKED_BODY_READY:
          /* nothing to do here */
          break;
        case MHD_REQUEST_CHUNKED_BODY_UNREADY:
          if (NULL != request->response->crc)
            MHD_mutex_lock_chk_ (&request->response->mutex);
          if ( (0 == request->response->total_size) ||
               (request->response_write_position ==
                request->response->total_size) )
            {
              if (NULL != request->response->crc)
                MHD_mutex_unlock_chk_ (&request->response->mutex);
              request->state = MHD_REQUEST_BODY_SENT;
              continue;
            }
          if (try_ready_chunked_body (request))
            {
              if (NULL != request->response->crc)
                MHD_mutex_unlock_chk_ (&request->response->mutex);
              request->state = MHD_REQUEST_CHUNKED_BODY_READY;
              /* Buffering for flushable socket was already enabled */
              if (MHD_NO == socket_flush_possible (connection))
                socket_start_no_buffering (connection);
              continue;
            }
          /* mutex was already unlocked by try_ready_chunked_body */
          break;
        case MHD_REQUEST_BODY_SENT:
          if (MHD_NO == build_header_response (request))
            {
              /* oops - close! */
	      CONNECTION_CLOSE_ERROR (connection,
				      _("Closing connection (failed to create response header)\n"));
              continue;
            }
          if ( (! request->have_chunked_upload) ||
               (request->write_buffer_send_offset ==
                request->write_buffer_append_offset) )
            request->state = MHD_REQUEST_FOOTERS_SENT;
          else
            request->state = MHD_REQUEST_FOOTERS_SENDING;
          continue;
        case MHD_REQUEST_FOOTERS_SENDING:
          /* no default action */
          break;
        case MHD_REQUEST_FOOTERS_SENT:
	  if (MHD_HTTP_PROCESSING == request->responseCode)
	  {
	    /* After this type of response, we allow sending another! */
	    request->state = MHD_REQUEST_HEADERS_PROCESSED;
	    MHD_destroy_response (request->response);
	    request->response = NULL;
	    /* FIXME: maybe partially reset memory pool? */
	    continue;
	  }
          if (MHD_NO != socket_flush_possible (connection))
            socket_start_no_buffering_flush (connection);
          else
            socket_start_normal_buffering (connection);

          MHD_destroy_response (request->response);
          connection->response = NULL;
          if ( (NULL != daemon->notify_completed) &&
               (connection->client_aware) )
          {
            connection->client_aware = false;
	    daemon->notify_completed (daemon->notify_completed_cls,
				      connection,
				      &connection->client_context,
				      MHD_REQUEST_TERMINATED_COMPLETED_OK);
          }
          if ( (MHD_CONN_USE_KEEPALIVE != request->keepalive) ||
               (connection->read_closed) )
            {
              /* have to close for some reason */
              MHD_connection_close_ (connection,
                                     MHD_REQUEST_TERMINATED_COMPLETED_OK);
              MHD_pool_destroy (connection->pool);
              connection->pool = NULL;
              request->read_buffer = NULL;
              request->read_buffer_size = 0;
              request->read_buffer_offset = 0;
            }
          else
            {
              /* can try to keep-alive */
              if (MHD_NO != socket_flush_possible (connection))
                socket_start_normal_buffering (connection);
              request->version = NULL;
              request->state = MHD_REQUEST_INIT;
              request->last = NULL;
              request->colon = NULL;
              request->header_size = 0;
              request->keepalive = MHD_CONN_KEEPALIVE_UNKOWN;
              /* Reset the read buffer to the starting size,
                 preserving the bytes we have already read. */
              request->read_buffer
                = MHD_pool_reset (connection->pool,
                                  request->read_buffer,
                                  request->read_buffer_offset,
                                  daemon->pool_size / 2);
              request->read_buffer_size
                = daemon->pool_size / 2;
            }
	  memset (&request,
		  0,
		  sizeof (struct MHD_Request));
	  request->daemon = daemon;
	  request->connection = connection;
          continue;
        case MHD_REQUEST_CLOSED:
	  cleanup_connection (connection);
          request->in_idle = false;
	  return MHD_NO;
#ifdef UPGRADE_SUPPORT
	case MHD_REQUEST_UPGRADE:
          request->in_idle = false;
          return MHD_YES; /* keep open */
#endif /* UPGRADE_SUPPORT */
       default:
          mhd_assert (0);
          break;
        }
      break;
    }
  if (! connection->suspended)
    {
      time_t timeout;
      timeout = connection->connection_timeout;
      if ( (0 != timeout) &&
           (timeout < (MHD_monotonic_sec_counter() - connection->last_activity)) )
        {
          MHD_connection_close_ (connection,
                                 MHD_REQUEST_TERMINATED_TIMEOUT_REACHED);
          request->in_idle = false;
          return MHD_YES;
        }
    }
  MHD_connection_update_event_loop_info (connection);
  ret = MHD_YES;
#ifdef EPOLL_SUPPORT
  if ( (! connection->suspended) &&
       (0 != (daemon->options & MHD_USE_EPOLL)) )
    {
      ret = MHD_connection_epoll_update_ (connection);
    }
#endif /* EPOLL_SUPPORT */
  request->in_idle = false;
  return ret;
}

// rewrite commented out
#endif


/**
 * Call the handlers for a connection in the appropriate order based
 * on the readiness as detected by the event loop.
 *
 * @param con connection to handle
 * @param read_ready set if the socket is ready for reading
 * @param write_ready set if the socket is ready for writing
 * @param force_close set if a hard error was detected on the socket;
 *        if this information is not available, simply pass #MHD_NO
 * @return #MHD_YES to continue normally,
 *         #MHD_NO if a serious error was encountered and the
 *         connection is to be closed.
 */
// FIXME: rename connection->request?
int
MHD_connection_call_handlers_ (struct MHD_Connection *con,
			       bool read_ready,
			       bool write_ready,
			       bool force_close)
{
  struct MHD_Daemon *daemon = con->daemon;
  int ret;
  bool states_info_processed = false;
  /* Fast track flag */
  bool on_fasttrack = (con->request.state == MHD_REQUEST_INIT);

#ifdef HTTPS_SUPPORT
  if (con->tls_read_ready)
    read_ready = true;
#endif /* HTTPS_SUPPORT */
  if (! force_close)
    {
      if ( (MHD_EVENT_LOOP_INFO_READ ==
	    con->request.event_loop_info) &&
	   read_ready)
        {
          MHD_request_handle_read_ (&con->request);
          ret = MHD_connection_handle_idle (con);
          states_info_processed = true;
        }
      /* No need to check value of 'ret' here as closed connection
       * cannot be in MHD_EVENT_LOOP_INFO_WRITE state. */
      if ( (MHD_EVENT_LOOP_INFO_WRITE ==
	    con->request.event_loop_info) &&
	   write_ready)
        {
          MHD_request_handle_write_ (&con->request);
          ret = MHD_connection_handle_idle (con);
          states_info_processed = true;
        }
    }
  else
    {
      MHD_connection_close_ (con,
                             MHD_REQUEST_TERMINATED_WITH_ERROR);
      return MHD_connection_handle_idle (con);
    }

  if (! states_info_processed)
    { /* Connection is not read or write ready, but external conditions
       * may be changed and need to be processed. */
      ret = MHD_connection_handle_idle (con);
    }
  /* Fast track for fast connections. */
  /* If full request was read by single read_handler() invocation
     and headers were completely prepared by single MHD_connection_handle_idle()
     then try not to wait for next sockets polling and send response
     immediately.
     As writeability of socket was not checked and it may have
     some data pending in system buffers, use this optimization
     only for non-blocking sockets. */
  /* No need to check 'ret' as connection is always in
   * MHD_CONNECTION_CLOSED state if 'ret' is equal 'MHD_NO'. */
  else if (on_fasttrack &&
	   con->sk_nonblck)
    {
      if (MHD_REQUEST_HEADERS_SENDING == con->request.state)
        {
          MHD_request_handle_write_ (&con->request);
          /* Always call 'MHD_connection_handle_idle()' after each read/write. */
          ret = MHD_connection_handle_idle (con);
        }
      /* If all headers were sent by single write_handler() and
       * response body is prepared by single MHD_connection_handle_idle()
       * call - continue. */
      if ((MHD_REQUEST_NORMAL_BODY_READY == con->request.state) ||
          (MHD_REQUEST_CHUNKED_BODY_READY == con->request.state))
        {
          MHD_request_handle_write_ (&con->request);
          ret = MHD_connection_handle_idle (con);
        }
    }

  /* All connection's data and states are processed for this turn.
   * If connection already has more data to be processed - use
   * zero timeout for next select()/poll(). */
  /* Thread-per-connection do not need global zero timeout as
   * connections are processed individually. */
  /* Note: no need to check for read buffer availability for
   * TLS read-ready connection in 'read info' state as connection
   * without space in read buffer will be market as 'info block'. */
  if ( (! daemon->data_already_pending) &&
       (MHD_TM_THREAD_PER_CONNECTION != daemon->threading_model) )
    {
      if (MHD_EVENT_LOOP_INFO_BLOCK ==
	  con->request.event_loop_info)
        daemon->data_already_pending = true;
#ifdef HTTPS_SUPPORT
      else if ( (con->tls_read_ready) &&
                (MHD_EVENT_LOOP_INFO_READ ==
		 con->request.event_loop_info) )
        daemon->data_already_pending = true;
#endif /* HTTPS_SUPPORT */
    }
  return ret;
}

/* end of connection_call_handlers.c */
