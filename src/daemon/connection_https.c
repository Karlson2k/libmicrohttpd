/*
     This file is part of libmicrohttpd
     (C) 2007, 2008 Daniel Pittman and Christian Grothoff

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
 * @brief  Methods for managing SSL/TLS connections. This file is only
 *         compiled if ENABLE_HTTPS is set.
 * @author Sagie Amir
 * @author Christian Grothoff
 */

#include "internal.h"
#include "connection.h"
#include "memorypool.h"
#include "response.h"
#include "reason_phrase.h"

/* get opaque type */
#include "gnutls_int.h"
#include "gnutls_record.h"

/* TODO #include rm "gnutls_errors.h" */
#include "gnutls_errors.h"

/* forward declarations used when setting secure connection callbacks */
int MHD_connection_handle_read (struct MHD_Connection *connection);
int MHD_connection_handle_write (struct MHD_Connection *connection);
int MHD_connection_handle_idle (struct MHD_Connection *connection);

/**
 * retrieve session info
 *
 * @param connection: from which to retrieve data
 * @return: an appropriate 'union MHD_SessionInfo' with the requested connection data or 'null_info' in an invalid request has been received.
 */
union MHD_SessionInfo
MHD_get_session_info ( struct MHD_Connection * connection, enum MHD_InfoType infoType)
{
  /* return NULL if this isn't a SSL/TLS type connection */
  if (connection->tls_session == NULL)
    {
      /* TODO clean */
      return (union MHD_SessionInfo) 0;
    }
  switch (infoType)
    {
#if HTTPS_SUPPORT
    case MHS_INFO_CIPHER_ALGO:
      return (union MHD_SessionInfo) connection->tls_session->security_parameters.
        read_bulk_cipher_algorithm;
    case MHD_INFO_KX_ALGO:
      return (union MHD_SessionInfo) connection->tls_session->security_parameters.
        kx_algorithm;
    case MHD_INFO_CREDENTIALS_TYPE:
      return (union MHD_SessionInfo) connection->tls_session->key->cred->algorithm;
    case MHD_INFO_MAC_ALGO:
      return (union MHD_SessionInfo) connection->tls_session->security_parameters.
        read_mac_algorithm;
    case MHD_INFO_COMPRESSION_METHOD:
      return (union MHD_SessionInfo) connection->tls_session->security_parameters.
        read_compression_algorithm;
    case MHD_INFO_PROTOCOL:
      return (union MHD_SessionInfo) connection->tls_session->security_parameters.
        version;
    case MHD_INFO_CERT_TYPE:
      return (union MHD_SessionInfo) connection->tls_session->security_parameters.
        cert_type;
#endif
    };
  return (union MHD_SessionInfo) 0;
}

/**
 * This function is called once a secure connection has been marked
 * for closure.
 *
 * @param connection: the connection to close
 */
static void
MHD_tls_connection_close (struct MHD_Connection * connection)
{
  MHD_gnutls_bye (connection->tls_session, GNUTLS_SHUT_WR);
  connection->tls_session->internals.read_eof = 1;

  SHUTDOWN (connection->socket_fd, SHUT_RDWR);
  CLOSE (connection->socket_fd);
  connection->socket_fd = -1;

  connection->state = MHD_CONNECTION_CLOSED;

  /* call notify_completed callback if one was registered */
  if (connection->daemon->notify_completed != NULL)
    connection->daemon->notify_completed (connection->daemon->
                                          notify_completed_cls, connection,
                                          &connection->client_context,
                                          MHD_TLS_REQUEST_TERMINATED_COMPLETED_OK);
}

/**
 * This function is called once a secure connection has been marked
 * for closure.
 *
 * @param connection: the connection to close
 * @param termination_code: the termination code with which the notify completed callback function is called.
 */
static void
MHD_tls_connection_close_err (struct MHD_Connection *connection,
                              enum MHD_RequestTerminationCode
                              termination_code)
{
  connection->tls_session->internals.read_eof = 1;
  SHUTDOWN (connection->socket_fd, SHUT_RDWR);
  CLOSE (connection->socket_fd);
  connection->socket_fd = -1;

  connection->state = MHD_CONNECTION_CLOSED;
  if (connection->daemon->notify_completed != NULL)
    connection->daemon->notify_completed (connection->daemon->
                                          notify_completed_cls, connection,
                                          &connection->client_context,
                                          termination_code);
}


/**
 * @name : MHDS_con_read
 *
 * reads data from the TLS record protocol
 * @param connection: is a %MHD_Connection structure.
 * @return: number of bytes received and zero on EOF.  A negative
 * error code is returned in case of an error.
 **/
static ssize_t
MHDS_con_read (struct MHD_Connection * connection)
{
  /* no special handling when GNUTLS_E_AGAIN is returned since this function is called from within a select loop */
  ssize_t size = MHD_gnutls_record_recv (connection->tls_session,
                                     &connection->read_buffer[connection->
                                                              read_buffer_offset],
                                     connection->read_buffer_size);
  return size;
}

static ssize_t
MHDS_con_write (struct MHD_Connection *connection)
{
  ssize_t sent = MHD_gnutls_record_send (connection->tls_session,
                                     &connection->write_buffer[connection->
                                                               write_buffer_send_offset],
                                     connection->write_buffer_append_offset
                                     - connection->write_buffer_send_offset);
  return sent;
}

/**
 * This function was created to handle per-connection processing that
 * has to happen even if the socket cannot be read or written to.  All
 * implementations (multithreaded, external select, internal select)
 * call this function.
 *
 * @param connection being handled
 * @return MHD_YES if we should continue to process the
 *         connection (not dead yet), MHD_NO if it died
 */
int
MHD_tls_connection_handle_idle (struct MHD_Connection *connection)
{
  unsigned int timeout;

#if DEBUG_STATES
  MHD_DLOG (connection->daemon, "%s: state: %s\n",
            __FUNCTION__, MHD_state_to_string (connection->state));
#endif

  timeout = connection->daemon->connection_timeout;
  if ((connection->socket_fd != -1) && (timeout != 0)
      && (time (NULL) - timeout > connection->last_activity))
    {
      MHD_tls_connection_close_err (connection,
                                    MHD_REQUEST_TERMINATED_TIMEOUT_REACHED);
      return MHD_NO;
    }

  switch (connection->state)
    {
    /* on newly created connections we might reach here before any reply has been received */
    case MHD_TLS_CONNECTION_INIT:
      return MHD_YES;
      /* close connection if necessary */
    case MHD_CONNECTION_CLOSED:
      MHD_tls_connection_close (connection);
      return MHD_NO;
    case MHD_TLS_HANDSHAKE_FAILED:
      MHD_tls_connection_close_err (connection,
                                    MHD_TLS_REQUEST_TERMINATED_WITH_ERROR);
      return MHD_NO;
      /* some HTTP state */
    default:
      return MHD_connection_handle_idle (connection);
    }
  return MHD_YES;
}

/**
 * This function handles a particular SSL/TLS connection when
 * it has been determined that there is data to be read off a
 * socket. Message processing is done by message type which is
 * determined by peeking into the first message type byte of the
 * stream.
 *
 * Error message handling : all fatal level messages cause the
 * connection to be terminated.
 *
 * Application data is forwarded to the underlying daemon for
 * processing.
 *
 * @param connection : the source connection
 * @return MHD_YES if we should continue to process the
 *         connection (not dead yet), MHD_NO if it died
 */
int
MHD_tls_connection_handle_read (struct MHD_Connection *connection)
{
  int ret;
  unsigned char msg_type;

  connection->last_activity = time (NULL);
  if (connection->state == MHD_CONNECTION_CLOSED ||
      connection->state == MHD_TLS_HANDSHAKE_FAILED)
    return MHD_NO;

#if DEBUG_STATES
  MHD_DLOG (connection->daemon, "%s: state: %s\n",
            __FUNCTION__, MHD_state_to_string (connection->state));
#endif

  /* discover content type */
  if (recv (connection->socket_fd, &msg_type, 1, MSG_PEEK) == -1)
    {
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon, "Failed to peek into TLS content type\n");
#endif
      return MHD_NO;
    }

  switch (msg_type)
    {
      /* check for handshake messages first */
    case GNUTLS_HANDSHAKE:
      /* negotiate handshake only while in INIT & HELLO_REQUEST states */
      if (connection->state == MHD_TLS_CONNECTION_INIT ||
          connection->state == MHD_TLS_HELLO_REQUEST)
        {
          ret = MHD_gnutls_handshake (connection->tls_session);
          if (ret == 0)
            {
              /* set connection state to enable HTTP processing */
              connection->state = MHD_CONNECTION_INIT;
            }
          /* set connection as closed */
          else
            {
#if HAVE_MESSAGES
              MHD_DLOG (connection->daemon,
                        "Error: Handshake has failed (%d)\n", ret);
#endif
              connection->state = MHD_TLS_HANDSHAKE_FAILED;
              return MHD_NO;
            }
          break;
        }
      /* a handshake message has been received out of bound */
      else
        {
#if HAVE_MESSAGES
          MHD_DLOG (connection->daemon,
                    "Error: received handshake message out of context\n");
#endif
          MHD_tls_connection_close_err (connection,
                                        MHD_TLS_REQUEST_TERMINATED_WITH_ERROR);
          return MHD_NO;
        }

      /* ignore any out of bound change chiper spec messages */
    case GNUTLS_CHANGE_CIPHER_SPEC:
      MHD_tls_connection_close_err (connection,
                                    MHD_TLS_REQUEST_TERMINATED_WITH_ERROR);
      return MHD_NO;

    case GNUTLS_ALERT:
      /*
       * this call of mhd_gtls_recv_int expects 0 bytes read.
       * done to decrypt alert message
       */
      mhd_gtls_recv_int (connection->tls_session, GNUTLS_ALERT,
                        GNUTLS_HANDSHAKE_FINISHED, 0, 0);

      /* CLOSE_NOTIFY */
      if (connection->tls_session->internals.last_alert ==
          GNUTLS_A_CLOSE_NOTIFY)
        {
          connection->state = MHD_CONNECTION_CLOSED;
          return MHD_YES;
        }
      /* non FATAL or WARNING */
      else if (connection->tls_session->internals.last_alert_level !=
               GNUTLS_AL_FATAL)
        {
#if HAVE_MESSAGES
          MHD_DLOG (connection->daemon,
                    "Received TLS alert: %s\n",
                    MHD_gnutls_alert_get_name ((int) connection->tls_session->
                                           internals.last_alert));
#endif
          return MHD_YES;
        }
      /* FATAL */
      else if (connection->tls_session->internals.last_alert_level ==
               GNUTLS_AL_FATAL)
        {
          MHD_tls_connection_close_err (connection,
                                        MHD_TLS_REQUEST_TERMINATED_WITH_FATAL_ALERT);
          return MHD_NO;
        }
      /* this should never execut */
      else
        {
#if HAVE_MESSAGES
          MHD_DLOG (connection->daemon,
                    "Received unrecognized alert: %d\n",
                    connection->tls_session->internals.last_alert);
#endif
          return MHD_NO;
        }


      /* forward application level content to MHD */
    case GNUTLS_APPLICATION_DATA:
      return MHD_connection_handle_read (connection);

    case GNUTLS_INNER_APPLICATION:
      break;
    default:
#if HAVE_MESSAGES
      MHD_DLOG (connection->daemon,
                "Error: unrecognized TLS read message. con-state: %d. l: %d, f: %s\n",
                connection->state, __LINE__, __FUNCTION__);
#endif
      return MHD_NO;
    }

  return MHD_YES;
}

/**
 * This function was created to handle writes to sockets when it has
 * been determined that the socket can be written to. This function
 * will forward all write requests to the underlying daemon unless
 * the connection has been marked for closing.
 *
 * @return MHD_connection_handle_write() if we should continue to
 *         process the connection (not dead yet), MHD_NO if it died
 */
int
MHD_tls_connection_handle_write (struct MHD_Connection *connection)
{
  connection->last_activity = time (NULL);

#if DEBUG_STATES
  MHD_DLOG (connection->daemon, "%s: state: %s\n",
            __FUNCTION__, MHD_state_to_string (connection->state));
#endif

  switch (connection->state)
    {
    case MHD_CONNECTION_CLOSED:
    case MHD_TLS_HANDSHAKE_FAILED:
      return MHD_NO;
      /* some HTTP connection state */
    default:
      return MHD_connection_handle_write (connection);
    }
  return MHD_NO;
}

/*
 * set connection callback function to be used through out
 * the processing of this secure connection.
 *
 */
void
MHD_set_https_calbacks (struct MHD_Connection *connection)
{
  connection->recv_cls = &MHDS_con_read;
  connection->send_cls = &MHDS_con_write;
  connection->read_handler = &MHD_tls_connection_handle_read;
  connection->write_handler = &MHD_tls_connection_handle_write;
  connection->idle_handler = &MHD_tls_connection_handle_idle;
}
