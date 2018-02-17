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


#if COMMENTED_OUT_FOR_REWRITE


/**
 * This function was created to handle per-connection processing that
 * has to happen even if the socket cannot be read or written to.
 * @remark To be called only from thread that process connection's
 * recv(), send() and response.
 *
 * @param connection connection to handle
 * @return #MHD_YES if we should continue to process the
 *         connection (not dead yet), #MHD_NO if it died
 */
int
MHD_connection_handle_idle (struct MHD_Connection *connection)
{
  struct MHD_Daemon *daemon = connection->daemon;
  char *line;
  size_t line_len;
  int ret;

  connection->in_idle = true;
  while (! connection->suspended)
    {
#ifdef HTTPS_SUPPORT
      if (MHD_TLS_CONN_NO_TLS != connection->tls_state)
        { /* HTTPS connection. */
          if ((MHD_TLS_CONN_INIT <= connection->tls_state) &&
              (MHD_TLS_CONN_CONNECTED > connection->tls_state))
            break;
        }
#endif /* HTTPS_SUPPORT */
#if DEBUG_STATES
      MHD_DLOG (daemon,
                _("In function %s handling connection at state: %s\n"),
                __FUNCTION__,
                MHD_state_to_string (connection->state));
#endif
      switch (connection->state)
        {
        case MHD_CONNECTION_INIT:
          line = get_next_header_line (connection,
                                       &line_len);
          /* Check for empty string, as we might want
             to tolerate 'spurious' empty lines; also
             NULL means we didn't get a full line yet;
             line is not 0-terminated here. */
          if ( (NULL == line) ||
               (0 == line[0]) )
            {
              if (MHD_CONNECTION_INIT != connection->state)
                continue;
              if (connection->read_closed)
                {
		  CONNECTION_CLOSE_ERROR (connection,
					  NULL);
                  continue;
                }
              break;
            }
          if (MHD_NO == parse_initial_message_line (connection,
                                                    line,
                                                    line_len))
            CONNECTION_CLOSE_ERROR (connection,
                                    NULL);
          else
            connection->state = MHD_CONNECTION_URL_RECEIVED;
          continue;
        case MHD_CONNECTION_URL_RECEIVED:
          line = get_next_header_line (connection,
                                       NULL);
          if (NULL == line)
            {
              if (MHD_CONNECTION_URL_RECEIVED != connection->state)
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
              connection->state = MHD_CONNECTION_HEADERS_RECEIVED;
              connection->header_size = (size_t) (line - connection->read_buffer);
              continue;
            }
          if (MHD_NO == process_header_line (connection,
                                             line))
            {
              transmit_error_response (connection,
                                       MHD_HTTP_BAD_REQUEST,
                                       REQUEST_MALFORMED);
              break;
            }
          connection->state = MHD_CONNECTION_HEADER_PART_RECEIVED;
          continue;
        case MHD_CONNECTION_HEADER_PART_RECEIVED:
          line = get_next_header_line (connection,
                                       NULL);
          if (NULL == line)
            {
              if (connection->state != MHD_CONNECTION_HEADER_PART_RECEIVED)
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
              process_broken_line (connection,
                                   line,
                                   MHD_HEADER_KIND))
            continue;
          if (0 == line[0])
            {
              connection->state = MHD_CONNECTION_HEADERS_RECEIVED;
              connection->header_size = (size_t) (line - connection->read_buffer);
              continue;
            }
          continue;
        case MHD_CONNECTION_HEADERS_RECEIVED:
          parse_connection_headers (connection);
          if (MHD_CONNECTION_CLOSED == connection->state)
            continue;
          connection->state = MHD_CONNECTION_HEADERS_PROCESSED;
          if (connection->suspended)
            break;
          continue;
        case MHD_CONNECTION_HEADERS_PROCESSED:
          call_connection_handler (connection); /* first call */
          if (MHD_CONNECTION_CLOSED == connection->state)
            continue;
          if (need_100_continue (connection))
            {
              connection->state = MHD_CONNECTION_CONTINUE_SENDING;
              if (MHD_NO != socket_flush_possible (connection))
                socket_start_extra_buffering (connection);
              else
                socket_start_no_buffering (connection);

              break;
            }
          if ( (NULL != connection->response) &&
	       ( (MHD_str_equal_caseless_ (connection->method,
                                           MHD_HTTP_METHOD_POST)) ||
		 (MHD_str_equal_caseless_ (connection->method,
                                           MHD_HTTP_METHOD_PUT))) )
            {
              /* we refused (no upload allowed!) */
              connection->remaining_upload_size = 0;
              /* force close, in case client still tries to upload... */
              connection->read_closed = true;
            }
          connection->state = (0 == connection->remaining_upload_size)
            ? MHD_CONNECTION_FOOTERS_RECEIVED : MHD_CONNECTION_CONTINUE_SENT;
          if (connection->suspended)
            break;
          continue;
        case MHD_CONNECTION_CONTINUE_SENDING:
          if (connection->continue_message_write_offset ==
              MHD_STATICSTR_LEN_ (HTTP_100_CONTINUE))
            {
              connection->state = MHD_CONNECTION_CONTINUE_SENT;
              if (MHD_NO != socket_flush_possible (connection))
                socket_start_no_buffering_flush (connection);
              else
                socket_start_normal_buffering (connection);

              continue;
            }
          break;
        case MHD_CONNECTION_CONTINUE_SENT:
          if (0 != connection->read_buffer_offset)
            {
              process_request_body (connection);     /* loop call */
              if (MHD_CONNECTION_CLOSED == connection->state)
                continue;
            }
          if ( (0 == connection->remaining_upload_size) ||
               ( (MHD_SIZE_UNKNOWN == connection->remaining_upload_size) &&
                 (0 == connection->read_buffer_offset) &&
                 (connection->read_closed) ) )
            {
              if ( (connection->have_chunked_upload) &&
                   (! connection->read_closed) )
                connection->state = MHD_CONNECTION_BODY_RECEIVED;
              else
                connection->state = MHD_CONNECTION_FOOTERS_RECEIVED;
              if (connection->suspended)
                break;
              continue;
            }
          break;
        case MHD_CONNECTION_BODY_RECEIVED:
          line = get_next_header_line (connection,
                                       NULL);
          if (NULL == line)
            {
              if (connection->state != MHD_CONNECTION_BODY_RECEIVED)
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
              connection->state = MHD_CONNECTION_FOOTERS_RECEIVED;
              if (connection->suspended)
                break;
              continue;
            }
          if (MHD_NO == process_header_line (connection,
                                             line))
            {
              transmit_error_response (connection,
                                       MHD_HTTP_BAD_REQUEST,
                                       REQUEST_MALFORMED);
              break;
            }
          connection->state = MHD_CONNECTION_FOOTER_PART_RECEIVED;
          continue;
        case MHD_CONNECTION_FOOTER_PART_RECEIVED:
          line = get_next_header_line (connection,
                                       NULL);
          if (NULL == line)
            {
              if (connection->state != MHD_CONNECTION_FOOTER_PART_RECEIVED)
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
              process_broken_line (connection,
                                   line,
                                   MHD_FOOTER_KIND))
            continue;
          if (0 == line[0])
            {
              connection->state = MHD_CONNECTION_FOOTERS_RECEIVED;
              if (connection->suspended)
                break;
              continue;
            }
          continue;
        case MHD_CONNECTION_FOOTERS_RECEIVED:
          call_connection_handler (connection); /* "final" call */
          if (connection->state == MHD_CONNECTION_CLOSED)
            continue;
          if (NULL == connection->response)
            break;              /* try again next time */
          if (MHD_NO == build_header_response (connection))
            {
              /* oops - close! */
	      CONNECTION_CLOSE_ERROR (connection,
				      _("Closing connection (failed to create response header)\n"));
              continue;
            }
          connection->state = MHD_CONNECTION_HEADERS_SENDING;
          if (MHD_NO != socket_flush_possible (connection))
            socket_start_extra_buffering (connection);
          else
            socket_start_no_buffering (connection);

          break;
        case MHD_CONNECTION_HEADERS_SENDING:
          /* no default action */
          break;
        case MHD_CONNECTION_HEADERS_SENT:
          /* Some clients may take some actions right after header receive */
          if (MHD_NO != socket_flush_possible (connection))
            socket_start_no_buffering_flush (connection);

#ifdef UPGRADE_SUPPORT
          if (NULL != connection->response->upgrade_handler)
            {
              socket_start_normal_buffering (connection);
              connection->state = MHD_CONNECTION_UPGRADE;
              /* This connection is "upgraded".  Pass socket to application. */
              if (MHD_YES !=
                  MHD_response_execute_upgrade_ (connection->response,
                                                 connection))
                {
                  /* upgrade failed, fail hard */
                  CONNECTION_CLOSE_ERROR (connection,
                                          NULL);
                  continue;
                }
              /* Response is not required anymore for this connection. */
              if (NULL != connection->response)
                {
                  struct MHD_Response * const resp = connection->response;
                  connection->response = NULL;
                  MHD_destroy_response (resp);
                }
              continue;
            }
#endif /* UPGRADE_SUPPORT */
          if (MHD_NO != socket_flush_possible (connection))
            socket_start_extra_buffering (connection);
          else
            socket_start_normal_buffering (connection);

          if (connection->have_chunked_upload)
            connection->state = MHD_CONNECTION_CHUNKED_BODY_UNREADY;
          else
            connection->state = MHD_CONNECTION_NORMAL_BODY_UNREADY;
          continue;
        case MHD_CONNECTION_NORMAL_BODY_READY:
          /* nothing to do here */
          break;
        case MHD_CONNECTION_NORMAL_BODY_UNREADY:
          if (NULL != connection->response->crc)
            MHD_mutex_lock_chk_ (&connection->response->mutex);
          if (0 == connection->response->total_size)
            {
              if (NULL != connection->response->crc)
                MHD_mutex_unlock_chk_ (&connection->response->mutex);
              connection->state = MHD_CONNECTION_BODY_SENT;
              continue;
            }
          if (try_ready_normal_body (connection))
            {
	      if (NULL != connection->response->crc)
	        MHD_mutex_unlock_chk_ (&connection->response->mutex);
              connection->state = MHD_CONNECTION_NORMAL_BODY_READY;
              /* Buffering for flushable socket was already enabled*/
              if (MHD_NO == socket_flush_possible (connection))
                socket_start_no_buffering (connection);
              break;
            }
          /* mutex was already unlocked by "try_ready_normal_body */
          /* not ready, no socket action */
          break;
        case MHD_CONNECTION_CHUNKED_BODY_READY:
          /* nothing to do here */
          break;
        case MHD_CONNECTION_CHUNKED_BODY_UNREADY:
          if (NULL != connection->response->crc)
            MHD_mutex_lock_chk_ (&connection->response->mutex);
          if ( (0 == connection->response->total_size) ||
               (connection->response_write_position ==
                connection->response->total_size) )
            {
              if (NULL != connection->response->crc)
                MHD_mutex_unlock_chk_ (&connection->response->mutex);
              connection->state = MHD_CONNECTION_BODY_SENT;
              continue;
            }
          if (try_ready_chunked_body (connection))
            {
              if (NULL != connection->response->crc)
                MHD_mutex_unlock_chk_ (&connection->response->mutex);
              connection->state = MHD_CONNECTION_CHUNKED_BODY_READY;
              /* Buffering for flushable socket was already enabled */
              if (MHD_NO == socket_flush_possible (connection))
                socket_start_no_buffering (connection);
              continue;
            }
          /* mutex was already unlocked by try_ready_chunked_body */
          break;
        case MHD_CONNECTION_BODY_SENT:
          if (MHD_NO == build_header_response (connection))
            {
              /* oops - close! */
	      CONNECTION_CLOSE_ERROR (connection,
				      _("Closing connection (failed to create response header)\n"));
              continue;
            }
          if ( (! connection->have_chunked_upload) ||
               (connection->write_buffer_send_offset ==
                connection->write_buffer_append_offset) )
            connection->state = MHD_CONNECTION_FOOTERS_SENT;
          else
            connection->state = MHD_CONNECTION_FOOTERS_SENDING;
          continue;
        case MHD_CONNECTION_FOOTERS_SENDING:
          /* no default action */
          break;
        case MHD_CONNECTION_FOOTERS_SENT:
	  if (MHD_HTTP_PROCESSING == connection->responseCode)
	  {
	    /* After this type of response, we allow sending another! */
	    connection->state = MHD_CONNECTION_HEADERS_PROCESSED;
	    MHD_destroy_response (connection->response);
	    connection->response = NULL;
	    /* FIXME: maybe partially reset memory pool? */
	    continue;
	  }
          if (MHD_NO != socket_flush_possible (connection))
            socket_start_no_buffering_flush (connection);
          else
            socket_start_normal_buffering (connection);

          MHD_destroy_response (connection->response);
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
          if ( (MHD_CONN_USE_KEEPALIVE != connection->keepalive) ||
               (connection->read_closed) )
            {
              /* have to close for some reason */
              MHD_connection_close_ (connection,
                                     MHD_REQUEST_TERMINATED_COMPLETED_OK);
              MHD_pool_destroy (connection->pool);
              connection->pool = NULL;
              connection->read_buffer = NULL;
              connection->read_buffer_size = 0;
              connection->read_buffer_offset = 0;
            }
          else
            {
              /* can try to keep-alive */
              if (MHD_NO != socket_flush_possible (connection))
                socket_start_normal_buffering (connection);
              connection->version = NULL;
              connection->state = MHD_CONNECTION_INIT;
              connection->last = NULL;
              connection->colon = NULL;
              connection->header_size = 0;
              connection->keepalive = MHD_CONN_KEEPALIVE_UNKOWN;
              /* Reset the read buffer to the starting size,
                 preserving the bytes we have already read. */
              connection->read_buffer
                = MHD_pool_reset (connection->pool,
                                  connection->read_buffer,
                                  connection->read_buffer_offset,
                                  connection->daemon->pool_size / 2);
              connection->read_buffer_size
                = connection->daemon->pool_size / 2;
            }
	  connection->client_aware = false;
          connection->client_context = NULL;
          connection->continue_message_write_offset = 0;
          connection->responseCode = 0;
          connection->headers_received = NULL;
	  connection->headers_received_tail = NULL;
          connection->response_write_position = 0;
          connection->have_chunked_upload = false;
          connection->current_chunk_size = 0;
          connection->current_chunk_offset = 0;
          connection->method = NULL;
          connection->url = NULL;
          connection->write_buffer = NULL;
          connection->write_buffer_size = 0;
          connection->write_buffer_send_offset = 0;
          connection->write_buffer_append_offset = 0;
          continue;
        case MHD_CONNECTION_CLOSED:
	  cleanup_connection (connection);
          connection->in_idle = false;
	  return MHD_NO;
#ifdef UPGRADE_SUPPORT
	case MHD_CONNECTION_UPGRADE:
          connection->in_idle = false;
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
          connection->in_idle = false;
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
  connection->in_idle = false;
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
