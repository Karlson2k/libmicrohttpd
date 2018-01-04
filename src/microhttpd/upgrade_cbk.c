/*
  This file is part of libmicrohttpd
  Copyright (C) 2017 Karlson2k (Evgeny Grin)

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
 * @file microhttpd/upgrade_cbk.c
 * @brief  Implementation of 'upgrade' functions with callbacks
 * @author Karlson2k (Evgeny Grin)
 */

#include "internal.h"
#include "connection.h"
#include "mhd_itc.h"
#include "mhd_threads.h"
#include "mhd_assert.h"

#ifndef UPGRADE_CBK_SUPPORT
#error 'upgrade' callcacks were not enabled by configure
#endif /* ! UPGRADE_CBK_SUPPORT */

bool
MHD_response_start_upgrade_cbk_ (struct MHD_Response *response,
                                 struct MHD_Connection *connection)
{
  const struct MHD_Daemon * const daemon = connection->daemon;
  struct MHD_UpgrHandleCbk *uh;

  mhd_assert (0 != (daemon->options & MHD_ALLOW_UPGRADE));

  if (NULL ==
      MHD_get_response_header (response,
                               MHD_HTTP_HEADER_UPGRADE))
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _("Invalid response for upgrade: 'Upgrade' header is not set!\n"));
#endif
      return false;
    }

  mhd_assert (NULL != response->upgr_cbk_start_handler);
  uh = MHD_calloc_ (1, sizeof (struct MHD_UpgrHandleCbk));
  if (NULL == uh)
    return false;

  uh->connection = connection;
  uh->has_recv_data_in_conn_buffer = (0 != connection->read_buffer_offset);

  if (MHD_mutex_init_ (&(uh->data_and_cbk_mutex)))
    {
      if (0 != (connection->daemon->options & MHD_USE_THREAD_PER_CONNECTION) ?
          (MHD_itc_init_(uh->itc)) : (MHD_itc_copy_(connection->daemon->itc, uh->itc), true))
        {
          if (MHD_NO != response->upgr_cbk_start_handler (connection,
                                                          connection->client_context,
                                                          uh,
                                                          response->upgr_cbk_start_handler_cls))
            {
              /* Normal HTTP processing is finished,
               * notify application. */
              if ( (NULL != daemon->notify_completed) &&
                   (connection->client_aware) )
                daemon->notify_completed (daemon->notify_completed_cls,
                                          connection,
                                          &(connection->client_context),
                                          MHD_REQUEST_TERMINATED_COMPLETED_OK);
              connection->client_aware = false;
              if (! uh->has_recv_data_in_conn_buffer)
                {
                  /* Destroy connection's memory pool as it will not be used any more. */
                  connection->read_buffer = NULL;
                  connection->write_buffer = NULL;
                  MHD_pool_destroy (connection->pool);
                  connection->pool = NULL;
                }
              return true;
            }

          if (0 != (connection->daemon->options & MHD_USE_THREAD_PER_CONNECTION))
            MHD_itc_destroy_chk_ (uh->itc);
        }
      else
        {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _("Failed to initialise connection's ITC.\n"));
#endif /* HAVE_MESSAGES */
        }
      MHD_mutex_destroy_chk_ (&(uh->data_and_cbk_mutex));
    }
  else
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _("Failed to initialise mutex.\n"));
#endif /* HAVE_MESSAGES */
    }
  free(uh);
  return false;
}


_MHD_EXTERN struct MHD_Response *
MHD_create_response_for_upgrade_cbk (MHD_UpgrStartCbk upgr_start_handler,
                                     void *upgr_start_handler_cls)
{
  struct MHD_Response *response;

  if (NULL == upgr_start_handler)
    return NULL; /* invalid request */
  response = MHD_calloc_ (1, sizeof (struct MHD_Response));
  if (NULL == response)
    return NULL;
  if (! MHD_mutex_init_ (&response->mutex))
    {
      free (response);
      return NULL;
    }
  response->upgr_cbk_start_handler = upgr_start_handler;
  response->upgr_cbk_start_handler_cls = upgr_start_handler_cls;
  response->total_size = MHD_SIZE_UNKNOWN;
  response->reference_count = 1;
  if (MHD_NO ==
      MHD_add_response_header (response,
                               MHD_HTTP_HEADER_CONNECTION,
                               "Upgrade"))
    {
      MHD_destroy_response (response);
      return NULL;
    }
  return response;
}


void
MHD_upgr_start_closing_ (struct MHD_UpgrHandleCbk *uh);


/**
 * @remark To be called only from connection's thread.
 * @note Mutex must locked before call.
 * @param uh
 */
static void
MHD_upgr_net_recv_ (struct MHD_UpgrHandleCbk *uh)
{
  struct MHD_Connection * const connection = uh->connection;
  mhd_assert (MHD_UPGR_STATE_CONNECTED <= uh->state);
  mhd_assert (MHD_UPGR_STATE_INVALID > uh->state);

  if (MHD_UPGR_STATE_TIMEOUT <= uh->state)
    return;

  mhd_assert (0 == (uh->state & MHD_UPGR_STATE_FLAG_NOTIFIED));

  if ( (NULL != uh->recv_buff) &&
       (! uh->peer_closed_write) )
    {
      ssize_t recv_res;
      mhd_assert (0 != uh->recv_buff_size);
      mhd_assert (uh->recv_buff_used < uh->recv_buff_size);

      MHD_mutex_unlock_chk_ (&(uh->data_and_cbk_mutex));
      /* Buffer data will not be modified in other threads
       * while buffer is not empty, so it is safe to release mutex. */
      recv_res = connection->send_cls (connection, uh->recv_buff + uh->recv_buff_used,
                                       uh->recv_buff_size - uh->recv_buff_used);
      MHD_mutex_lock_chk_ (&(uh->data_and_cbk_mutex));

      if (0 > recv_res)
        {
          if (MHD_ERR_AGAIN_ != recv_res)
            { /* Hard error. */
              uh->recv_needed = false;
              uh->state = MHD_UPGR_STATE_DISCONN;
            }
        }
      else if (0 == recv_res)
        {
          uh->recv_needed = false;
          uh->peer_closed_write = true;
        }
      else
        {
          mhd_assert (((size_t)recv_res) <= (uh->recv_buff_size - uh->recv_buff_used));
          uh->recv_buff_used += (size_t)recv_res;
          if (uh->recv_buff_used == uh->recv_buff_size)
            uh->recv_needed = false;
        }
    }
}

/**
 * @remark To be called only from connection's thread.
 * @note Mutex must locked before call.
 * @param uh
 */
static void
MHD_upgr_net_send_ (struct MHD_UpgrHandleCbk *uh)
{
  struct MHD_Connection * const connection = uh->connection;
  mhd_assert (MHD_UPGR_STATE_CONNECTED <= uh->state);
  mhd_assert (MHD_UPGR_STATE_INVALID > uh->state);

  if (MHD_UPGR_STATE_TIMEOUT <= uh->state)
    return;

  mhd_assert (0 == (uh->state & MHD_UPGR_STATE_FLAG_NOTIFIED));

  MHD_mutex_lock_chk_ (&(uh->data_and_cbk_mutex));
  if (NULL != uh->recv_buff)
    {
      ssize_t send_res;
      mhd_assert (0 != uh->send_buff_size);
      mhd_assert (uh->send_buff_sent < uh->send_buff_size);

      MHD_mutex_unlock_chk_ (&(uh->data_and_cbk_mutex));
      /* Buffer data will not be modified in other threads
       * while buffer is not empty, so it is safe to release mutex. */
      send_res = connection->send_cls (connection, uh->send_buff + uh->send_buff_sent,
                                       uh->send_buff_size - uh->send_buff_sent);
      MHD_mutex_lock_chk_ (&(uh->data_and_cbk_mutex));
      mhd_assert (0 != send_res);

      if (0 >= send_res)
        {
          if (MHD_ERR_AGAIN_ != send_res)
            { /* Hard error. */
              uh->send_needed = false;
              uh->state = MHD_UPGR_STATE_DISCONN;
            }
        }
      else
        {
          mhd_assert (((size_t)send_res) <= (uh->send_buff_size - uh->send_buff_sent));
          uh->send_buff_sent += (size_t)send_res;
          if (uh->send_buff_sent == uh->send_buff_size)
            uh->send_needed = false;
        }
    }
}

/* To be called after all other processing in connection thread. */
bool
MHD_upgr_check_termination_ (struct MHD_UpgrHandleCbk *uh)
{
  MHD_UpgrTerminationCbk term_callback;

  mhd_assert (MHD_UPGR_STATE_CONNECTED <= uh->state);
  mhd_assert (MHD_UPGR_STATE_INVALID > uh->state);

  if (MHD_UPGR_STATE_TIMEOUT > uh->state)
    return false;

  MHD_mutex_lock_chk_ (&(uh->data_and_cbk_mutex));
  mhd_assert (0 == (uh->state & MHD_UPGR_STATE_FLAG_NOTIFIED));
  term_callback = uh->termination_cbk;
  if (NULL != term_callback)
    {
      const void *callback_cls = uh->termintaion_cbk_cls;
      enum MHD_UpgrTerminationType term_type;
      const enum MHD_UpgrCbkState state = uh->state;
      switch (state)
        {
          case MHD_UPGR_STATE_TIMEOUT:
            term_type = MHD_UPGR_TERMINATION_BY_TIMEOUT; break;
          case MHD_UPGR_STATE_CLOSED_BY_APP:
            term_type = MHD_UPGR_TERMINATION_BY_APP; break;
          case MHD_UPGR_STATE_DISCONN:
            term_type = MHD_UPGR_TERMINATION_BY_DISCONN; break;
          default:
            mhd_assert(0); break;
        }
      MHD_mutex_unlock_chk_ (&(uh->data_and_cbk_mutex));
      term_callback (uh, term_type, callback_cls);
      MHD_mutex_lock_chk_ (&(uh->data_and_cbk_mutex));
      if (state == uh->state)
        uh->state = (enum MHD_UpgrCbkState) (uh->state | MHD_UPGR_STATE_FLAG_NOTIFIED);
    }
  else
    {
      uh->state = (enum MHD_UpgrCbkState) (uh->state | MHD_UPGR_STATE_FLAG_NOTIFIED);
    }

  MHD_mutex_unlock_chk_ (&(uh->data_and_cbk_mutex));
  return true;
}

_MHD_EXTERN int
MHD_upgr_recv_fill (struct MHD_UpgrHandleCbk *uh,
                    void *buffer,
                    size_t buffer_size,
                    MHD_UpgrTransferResultCbk result_cbk,
                    void *cls)
{
  const struct MHD_Daemon * const daemon = uh->connection->daemon;
  int ret = MHD_NO;

  mhd_assert (MHD_CONNECTION_UPGR_CBK == uh->connection->state);

  if ( (NULL == buffer) !=  (0 == buffer_size) )
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _("'buffer' is not null pointer but 'buffer_size' is zero or "
                  "'buffer' is null pointer but 'buffer_size' is not zero.\n"));
#endif /* HAVE_MESSAGES */
      return ret;
    }
  if ( (NULL == result_cbk) &&
       (NULL == buffer) )
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _("Both 'buffer' and 'result_cbk' are null pointers.\n"));
#endif /* HAVE_MESSAGES */
      return ret;
    }
  if ( (NULL == result_cbk) &&
       (NULL != cls) )
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _("'result_cbk' is null pointer but 'cls' is not null pointer.\n"));
#endif /* HAVE_MESSAGES */
      return ret;
    }

  if (MHD_mutex_lock_ (&(uh->data_and_cbk_mutex)))
    {
      bool need_notify_conn_thread = false;
      mhd_assert (MHD_UPGR_STATE_CONNECTED <= uh->state);
      mhd_assert (MHD_UPGR_STATE_INVALID > uh->state);
      if (MHD_UPGR_STATE_CLOSING < uh->state)
        {
#ifdef HAVE_MESSAGES
          MHD_DLOG (daemon,
                    _("Connection was disconnected.\n"));
#endif /* HAVE_MESSAGES */
          ret = MHD_NO;
        }
      else
        {
          if ( (NULL != uh->recv_buff) && (NULL != buffer) )
            {
#ifdef HAVE_MESSAGES
              MHD_DLOG (daemon,
                        _("Another buffer is already being used to receive data.\n"));
#endif /* HAVE_MESSAGES */
              ret = MHD_NO;
            }
          else if ( (NULL != uh->recv_result_cbk) && (NULL != result_cbk) )
            {
#ifdef HAVE_MESSAGES
              MHD_DLOG (daemon,
                        _("Another receive completion callback was already registered.\n"));
#endif /* HAVE_MESSAGES */
              ret = MHD_NO;
            }
          else if ( (NULL != uh->recv_buff) && (uh->recv_instant) )
            {
#ifdef HAVE_MESSAGES
              MHD_DLOG (daemon,
                        _("MHD_upgr_recv() is being processed.\n"));
#endif /* HAVE_MESSAGES */
              ret = MHD_NO;
            }
          else
            { /* Schedule data and/or callback. */
              if (NULL != data)
                {
                  uh->recv_buff = buffer;
                  uh->recv_buff_size = buffer_size;
                }
              if (NULL != result_cbk)
                {
                  uh->recv_result_cbk = result_cbk;
                  uh->recv_result_cbk_cls = cls;
                }
              uh->recv_needed = true;
              if (uh->has_recv_data_in_conn_buffer)
                { /* Instantly provide data and/or notify. */
                  uh->need_reloop = true;
                }
              else if (uh->peer_closed_write)
                { /* Handle instant re-loop and notify by callback. */
                  uh->need_reloop = true;
                }
              if (!MHD_thread_ID_match_current_ (uh->connection->pid.ID))
                need_notify_conn_thread = true;
              ret = MHD_YES;
            }
        }
      MHD_mutex_unlock_chk_ (&(uh->data_and_cbk_mutex));
      if (need_notify_conn_thread &&
          ! MHD_itc_activate_ (uh->itc, "d"))
        {
#ifdef HAVE_MESSAGES
          MHD_DLOG (daemon,
                    _("Failed to notify thread by ITC.\n"));
#endif /* HAVE_MESSAGES */
        }
    }
  return ret;
}

_MHD_EXTERN int
MHD_upgr_send_all (struct MHD_UpgrHandleCbk *uh,
                   const void *data,
                   size_t data_size,
                   MHD_UpgrTransferResultCbk result_cbk,
                   void *cls)
{
  const struct MHD_Daemon * const daemon = uh->connection->daemon;
  int ret = MHD_NO;

  mhd_assert (MHD_CONNECTION_UPGR_CBK == uh->connection->state);

  if ( (NULL == data) !=  (0 == data_size) )
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _("'data' is not null pointer but 'data_size' is zero or "
                  "'data' is null pointer but 'data_size' is not zero.\n"));
#endif /* HAVE_MESSAGES */
      return ret;
    }
  if ( (NULL == result_cbk) &&
       (NULL == data) )
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _("Both 'data' and 'result_cbk' are null pointers.\n"));
#endif /* HAVE_MESSAGES */
      return ret;
    }
  if ( (NULL == result_cbk) &&
       (NULL != cls) )
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _("'result_cbk' is null pointer but 'cls' is not null pointer.\n"));
#endif /* HAVE_MESSAGES */
      return ret;
    }

  if (MHD_mutex_lock_ (&(uh->data_and_cbk_mutex)))
    {
      bool need_notify_conn_thread = false;
      mhd_assert (MHD_UPGR_STATE_CONNECTED <= uh->state);
      mhd_assert (MHD_UPGR_STATE_INVALID > uh->state);
      if (MHD_UPGR_STATE_CLOSING <= uh->state)
        {
#ifdef HAVE_MESSAGES
          if (MHD_UPGR_STATE_CLOSING == uh->state)
            MHD_DLOG (daemon,
                      _("Connection is closing and cannot transmit more data.\n"));
          else
            MHD_DLOG (daemon,
                      _("Connection is disconnected.\n"));

#endif /* HAVE_MESSAGES */
          ret = MHD_NO;
        }
      else
        {
          if ( (NULL != uh->send_buff) && (NULL != data) )
            {
#ifdef HAVE_MESSAGES
          MHD_DLOG (daemon,
                    _("Another data is already being sent to remote.\n"));
#endif /* HAVE_MESSAGES */
              ret = MHD_NO;
            }
          else if ( (NULL != uh->send_result_cbk) && (NULL != result_cbk) )
            {
#ifdef HAVE_MESSAGES
              MHD_DLOG (daemon,
                        _("Another send completion callback was already registered.\n"));
#endif /* HAVE_MESSAGES */
              ret = MHD_NO;
            }
          else
            { /* Schedule data and/or callback. */
              const bool in_conn_thread = MHD_thread_ID_match_current_ (uh->connection->pid.ID);
              if (NULL != data)
                {
                  uh->send_buff = data;
                  uh->send_buff_size = data_size;
                }
              if (NULL != result_cbk)
                {
                  uh->send_result_cbk = result_cbk;
                  uh->send_result_cbk_cls = cls;
                }
              uh->send_needed = true;
              if (!MHD_thread_ID_match_current_ (uh->connection->pid.ID))
                need_notify_conn_thread = true;
              ret = MHD_YES;
            }
        }
      MHD_mutex_unlock_chk_ (&(uh->data_and_cbk_mutex));
      if (need_notify_conn_thread &&
          ! MHD_itc_activate_ (uh->itc, "d"))
        {
#ifdef HAVE_MESSAGES
          MHD_DLOG (daemon,
                    _("Failed to notify thread by ITC.\n"));
#endif /* HAVE_MESSAGES */
        }
    }
  return ret;
}

/**
 *
 * @param uh
 * @param buffer
 * @param buffer_size
 * @return -1 if no data available or in case of network error,
 *         -2 in case of any other error,
 *         0 if remote host performed shutdown of write side,
 *         or positive value for received data size
 */
_MHD_EXTERN ssize_t
MHD_upgr_recv (struct MHD_UpgrHandleCbk *uh,
               void *buffer,
               size_t buffer_size)
{
  const struct MHD_Daemon * const daemon = uh->connection->daemon;
  size_t ret = -2;

  mhd_assert (MHD_CONNECTION_UPGR_CBK == uh->connection->state);

  if (buffer_size > SSIZE_MAX)
    buffer_size = SSIZE_MAX;
  if (MHD_mutex_lock_ (&(uh->data_and_cbk_mutex)))
    {
      bool need_notify_conn_thread = false;

      mhd_assert (MHD_UPGR_STATE_CONNECTED <= uh->state);
      mhd_assert (MHD_UPGR_STATE_INVALID > uh->state);
      if (MHD_UPGR_STATE_CLOSING < uh->state)
        {
#ifdef HAVE_MESSAGES
          MHD_DLOG (daemon,
                    _("Connection was disconnected.\n"));
#endif /* HAVE_MESSAGES */
          ret = -2;
        }
      else
        {
          if (NULL != uh->recv_buff)
            {
#ifdef HAVE_MESSAGES
              MHD_DLOG (daemon,
                        _("Another buffer is already being used to receive data.\n"));
#endif /* HAVE_MESSAGES */
              ret = -2;
            }
          else
            {
              struct MHD_Connection * const connection = uh->connection;
              mhd_assert (!uh->recv_needed);
              if (uh->has_recv_data_in_conn_buffer)
                { /* Supply already received data. */
                  const size_t data_left = connection->read_buffer_offset - uh->conn_buffer_offset;
                  mhd_assert (uh->conn_buffer_offset < connection->read_buffer_offset);
                  if (buffer_size >= data_left)
                    {
                      memcpy (buffer, connection->read_buffer, data_left);
                      ret = data_left;
                      uh->has_recv_data_in_conn_buffer = false;
                      uh->conn_buffer_offset = 0;
                      MHD_pool_destroy (connection->pool);
                      connection->pool = NULL;
                    }
                  else
                    {
                      memcpy (buffer, connection->read_buffer, buffer_size);
                      ret = buffer_size;
                      uh->conn_buffer_offset += buffer_size;
                    }
                }
              else if (uh->peer_closed_write)
                {
                  ret = 0;
                }
              else if (uh->recv_instant)
                {
#ifdef HAVE_MESSAGES
                  MHD_DLOG (daemon,
                            _("Another MHD_upgr_recv() is already being processed.\n"));
#endif /* HAVE_MESSAGES */
                  ret = -2;
                }
              else
                {
                  ssize_t recv_res;
                  uh->recv_instant = true;
                  MHD_mutex_unlock_chk_ (&(uh->data_and_cbk_mutex));

                  recv_res = connection->recv_cls (connection, buffer, buffer_size);

                  MHD_mutex_lock_chk_ (&(uh->data_and_cbk_mutex));
                  uh->recv_instant = false;
                  if (0 < recv_res)
                    {
                      ret = recv_res;
                    }
                  else if (0 == recv_res)
                    { /* Remote host shut down writing on socket. */
                      uh->peer_closed_write = true;
                      if (!MHD_thread_ID_match_current_ (uh->connection->pid.ID))
                        need_notify_conn_thread = true;
                    }
                  else if (0 > recv_res)
                    { /* Any kind of error. */
                      uh->state = MHD_UPGR_STATE_DISCONN;
                      if (!MHD_thread_ID_match_current_ (uh->connection->pid.ID))
                        need_notify_conn_thread = true;
                    }
                }
            }
        }
      MHD_mutex_unlock_chk_ (&(uh->data_and_cbk_mutex));
      if (need_notify_conn_thread &&
          ! MHD_itc_activate_ (uh->itc, "d"))
        {
#ifdef HAVE_MESSAGES
          MHD_DLOG (daemon,
                    _("Failed to notify thread by ITC.\n"));
#endif /* HAVE_MESSAGES */
        }
    }
  return ret;
}


/**
 * @remark To be called only from connection's thread.
 * @note Mutex must locked before call.
 * @param uh
 */
static void
MHD_upgr_process_recieved_ (struct MHD_UpgrHandleCbk *uh)
{
  const struct MHD_connection * const connection = uh->connection;
  mhd_assert (MHD_CONNECTION_UPGR_CBK == connection->state);
  mhd_assert (MHD_UPGR_STATE_CONNECTED <= uh->state);
  mhd_assert (MHD_UPGR_STATE_INVALID > uh->state);
  mhd_assert ( (NULL == uh->recv_buff) == (0 == uh->recv_buff_size) );
  mhd_assert ( (uh->recv_needed) || ((NULL == uh->recv_buff) && (NULL == uh->recv_result_cbk)) );
  mhd_assert (uh->recv_buff_size >= uh->recv_buff_used);

  if ( (MHD_UPGR_STATE_CLOSING < uh->state) ||
       (uh->peer_closed_write) )
    { /* Any kind of disconnected state. */
      if ( (NULL != uh->recv_buff) ||
           (NULL != uh->recv_result_cbk) )
        { /* Some action is required. */
          /* Disconnect of connection was detected on last recv().
           * Cleanup internal recv-data and (optionally) notify
           * application. recv() on this connection will not be
           * allowed anymore. */
          void * const recv_buff = uh->recv_buff;
          const size_t recv_buff_size = uh->recv_buff_size;
          const size_t recv_buff_used = uh->recv_buff_used;
          const MHD_UpgrTransferResultCbk recv_result_cbk = uh->recv_result_cbk;
          void * const recv_finished_cbk_cls = uh->recv_result_cbk_cls;
          enum MHD_UpgrTransferResult tr_result;
          /* Receive completion callback must be called before
           * termination notification callback. */
          mhd_assert (0 == (uh->state & MHD_UPGR_STATE_FLAG_NOTIFIED));

          if (NULL != recv_result_cbk)
            {
              switch (uh->state)
                {
                case MHD_UPGR_STATE_CLOSING:
                  /* TODO: handle closure processing. */
                case MHD_UPGR_STATE_CONNECTED:
                  mhd_assert (uh->peer_closed_write);
                  tr_result = MHD_UPGR_TRNSF_RESULT_RECV_ABORTED_BY_REMOTE_SHUTDOWN; break;
                case MHD_UPGR_STATE_TIMEOUT:
                  tr_result = MHD_UPGR_TRNSF_RESULT_RECV_ABORTED_BY_TIMEOUT; break;
                case MHD_UPGR_STATE_CLOSED_BY_APP:
                  tr_result = MHD_UPGR_TRNSF_RESULT_RECV_ABORTED_BY_APP; break;
                case MHD_UPGR_STATE_DISCONN:
                  tr_result = MHD_UPGR_TRNSF_RESULT_RECV_ABORTED_BY_DISCONN; break;
                default:
                  mhd_assert (false); break;
                }
            }
          /* Cleanup internal data. */
          uh->recv_needed = false;
          uh->recv_buff = NULL;
          uh->recv_buff_size = 0;
          uh->recv_buff_used = 0;
          uh->recv_result_cbk = NULL;
          uh->recv_result_cbk_cls = NULL;

          if (NULL != recv_result_cbk)
            {
              /* Unlock mutex before calling callback. */
              MHD_mutex_unlock_chk_ (&(uh->data_and_cbk_mutex));
              recv_result_cbk (uh, tr_result, recv_buff_used, recv_buff, recv_buff_size, recv_finished_cbk_cls);
              MHD_mutex_lock_chk_ (&(uh->data_and_cbk_mutex));
            }
        }
    }
  else /* MHD_UPGR_STATE_CLOSING >= uh->state */
    {
      if ( ( (NULL != uh->recv_buff) && (uh->recv_buff_size == uh->recv_buff_used) ) ||
           ( (NULL == uh->recv_buff) && (NULL != uh->recv_result_cbk) && (uh->recv_ready) ) )
        { /* Some action is required. */
          /* # Data was fully received or
           * # Data was not scheduled to receive, but callback was registered
           *   and connection has become ready to receive.*/
          void * const recv_buff = uh->recv_buff;
          const size_t recv_buff_size = uh->recv_buff_size;
          const size_t recv_buff_used = uh->recv_buff_used;
          const MHD_UpgrTransferResultCbk recv_result_cbk = uh->recv_result_cbk;
          void * const recv_finished_cbk_cls = uh->recv_result_cbk_cls;

          /* Cleanup internal data. */
          uh->recv_buff = NULL;
          uh->recv_buff_size = 0;
          uh->recv_buff_used = 0;
          uh->recv_result_cbk = NULL;
          uh->recv_result_cbk_cls = NULL;
          if (MHD_UPGR_STATE_CLOSING != uh->state)
            uh->recv_needed = false;

          if (NULL != recv_result_cbk)
            {
              /* Unlock mutex before calling callback. */
              MHD_mutex_unlock_chk_ (&(uh->data_and_cbk_mutex));
              recv_result_cbk (uh, MHD_UPGR_TRNSF_RESULT_RECV_OK, recv_buff_used, recv_buff, recv_buff_size, recv_finished_cbk_cls);
              MHD_mutex_lock_chk_ (&(uh->data_and_cbk_mutex));
            }
        }
    }
}


/**
 * @remark To be called only from connection's thread.
 * @note Mutex must locked before call.
 * @param uh
 */
static void
MHD_upgr_process_sent_ (struct MHD_UpgrHandleCbk *uh)
{
  const struct MHD_connection * const connection = uh->connection;
  mhd_assert (MHD_CONNECTION_UPGR_CBK == connection->state);

  MHD_mutex_lock_chk_ (&(uh->data_and_cbk_mutex));
  mhd_assert (MHD_UPGR_STATE_CONNECTED <= uh->state);
  mhd_assert (MHD_UPGR_STATE_INVALID > uh->state);
  mhd_assert ( (NULL == uh->send_buff) == (0 == uh->send_buff_size) );
  mhd_assert ( (uh->send_needed) || ((NULL == uh->send_buff) && (NULL == uh->send_result_cbk)) );
  mhd_assert (uh->send_buff_size >= uh->send_buff_sent);

  if (MHD_UPGR_STATE_CLOSING < uh->state)
    { /* Any kind of disconnected state. */
      if ( (NULL != uh->send_buff) ||
           (NULL != uh->send_result_cbk) )
        { /* Some action is required. */
          /* Disconnect of connection was detected on last recv().
           * Cleanup internal recv-data and (optionally) notify
           * application. recv() on this connection will not be
           * allowed anymore. */
          void * const send_buff = uh->send_buff;
          const size_t send_buff_size = uh->send_buff_size;
          const size_t send_buff_sent = uh->send_buff_sent;
          const MHD_UpgrTransferResultCbk send_result_cbk = uh->send_result_cbk;
          void * const send_finished_cbk_cls = uh->send_result_cbk_cls;
          enum MHD_UpgrTransferResult tr_result;
          /* Receive completion callback must be called before
           * termination notification callback. */
          mhd_assert (0 == (uh->state & MHD_UPGR_STATE_FLAG_NOTIFIED));

          if (NULL != send_result_cbk)
            {
              switch (uh->state)
                {
                case MHD_UPGR_STATE_TIMEOUT:
                  tr_result = MHD_UPGR_TRNSF_RESULT_SEND_ABORTED_BY_TIMEOUT; break;
                case MHD_UPGR_STATE_CLOSED_BY_APP:
                  tr_result = MHD_UPGR_TRNSF_RESULT_SEND_ABORTED_BY_APP; break;
                case MHD_UPGR_STATE_DISCONN:
                  tr_result = MHD_UPGR_TRNSF_RESULT_SEND_ABORTED_BY_DISCONN; break;
                default:
                  mhd_assert (false); break;
                }
            }
          /* Cleanup internal data. */
          uh->send_needed = false;
          uh->send_buff = NULL;
          uh->send_buff_size = 0;
          uh->send_buff_sent = 0;
          uh->send_result_cbk = NULL;
          uh->send_result_cbk_cls = NULL;

          if (NULL != send_result_cbk)
            {
              /* Unlock mutex before calling callback. */
              MHD_mutex_unlock_chk_ (&(uh->data_and_cbk_mutex));
              send_result_cbk (uh, tr_result, send_buff_sent, send_buff, send_buff_size, send_finished_cbk_cls);
              return; /* Return right after calling callback. */
            }
        }
    }
  else /* MHD_UPGR_STATE_CLOSING >= uh->state */
    {
      if ( ( (NULL != uh->send_buff) && (uh->send_buff_size == uh->send_buff_sent) ) ||
           ( (NULL == uh->send_buff) && (NULL != uh->send_result_cbk) && (uh->send_ready) ) )
        { /* Some action is required. */
          /* # Data was fully sent or
           * # Data was not scheduled to send, but callback was registered
           *   and connection has become ready to send.*/
          void * const send_buff = uh->send_buff;
          const size_t send_buff_size = uh->send_buff_size;
          const size_t send_buff_sent = uh->send_buff_sent;
          const MHD_UpgrTransferResultCbk send_result_cbk = uh->send_result_cbk;
          void * const send_finished_cbk_cls = uh->send_result_cbk_cls;
          const bool start_closing = (MHD_UPGR_STATE_CLOSING == uh->state);

          /* Cleanup internal data. */
          uh->send_needed = false;
          uh->send_buff = NULL;
          uh->send_buff_size = 0;
          uh->send_buff_sent = 0;
          uh->send_result_cbk = NULL;
          uh->send_result_cbk_cls = NULL;

          if ( (NULL != send_result_cbk) ||
               start_closing)
            {
              /* Unlock mutex before calling callback. */
              MHD_mutex_unlock_chk_ (&(uh->data_and_cbk_mutex));
              if (NULL != send_result_cbk)
                send_result_cbk (uh, MHD_UPGR_TRNSF_RESULT_SENT_OK, send_buff_sent, send_buff, send_buff_size, send_finished_cbk_cls);
              if (start_closing)
                MHD_upgr_start_closing_ (uh);
              return; /* Return right after calling callback. */
            }
        }
    }
  MHD_mutex_unlock_chk_ (&(uh->data_and_cbk_mutex));
}


_MHD_EXTERN int
MHD_upgr_register_termination_cbk (struct MHD_UpgrHandleCbk *uh, MHD_UpgrTerminationCbk callback, void *cls)
{
  int ret = MHD_NO;
  if (NULL == uh)
    return ret;
  MHD_mutex_lock_chk_ (&(uh->data_and_cbk_mutex));
  mhd_assert (MHD_UPGR_STATE_CONNECTED <= uh->state);
  mhd_assert (MHD_UPGR_STATE_INVALID > uh->state);
  if (0 == (uh->state & MHD_UPGR_STATE_FLAG_NOTIFIED))
    {
      if (NULL != callback)
        {
          uh->termination_cbk = callback;
          uh->termintaion_cbk_cls = cls;
        }
      else
        {
          uh->termination_cbk = NULL;
          uh->termintaion_cbk_cls = NULL;
        }
      ret = MHD_YES;
    }
  else
    {
#ifdef HAVE_MESSAGES
      const struct MHD_Daemon * const daemon = uh->connection->daemon;
      MHD_DLOG (daemon,
                _("Connection was already disconnected.\n"));
#endif /* HAVE_MESSAGES */
    }
  MHD_mutex_unlock_chk_ (&(uh->data_and_cbk_mutex));
  return ret;
}

/**
 * @remark To be called only from connection's thread.
 * @note Mutex must locked before call.
 * @param uh
 */
static void
MHD_upgr_call_termination_cbk (struct MHD_UpgrHandleCbk *uh)
{
  mhd_assert (MHD_UPGR_STATE_CONNECTED <= uh->state);
  mhd_assert (MHD_UPGR_STATE_INVALID > uh->state);
  if ( (MHD_UPGR_STATE_TIMEOUT <= uh->state) &&
       (0 == (uh->state & MHD_UPGR_STATE_FLAG_NOTIFIED)) )
    {
      const MHD_UpgrTerminationCbk callback = uh->termination_cbk;
      void * const cls = uh->termintaion_cbk_cls;
      uh->termination_cbk = NULL;
      uh->termintaion_cbk_cls = NULL;
      uh->state = (enum MHD_UpgrCbkState) (uh->state | MHD_UPGR_STATE_FLAG_NOTIFIED);
      if (NULL != callback)
        {
          enum MHD_UpgrTerminationType term_type;
          if (MHD_UPGR_STATE_TIMEOUT == uh->state)
            term_type = MHD_UPGR_TERMINATION_BY_TIMEOUT;
          else if (MHD_UPGR_STATE_CLOSED_BY_APP == uh->state)
            term_type = MHD_UPGR_TERMINATION_BY_APP;
          else if (MHD_UPGR_STATE_DISCONN == uh->state)
            term_type = MHD_UPGR_TERMINATION_BY_DISCONN;
          else
            {
              mhd_assert (false);
            }
          MHD_mutex_unlock_chk_ (&(uh->data_and_cbk_mutex));
          callback (uh, term_type, cls);
          MHD_mutex_lock_chk_ (&(uh->data_and_cbk_mutex));
        }
    }
}

void
MHD_upgr_process_data_and_callbacks_ (struct MHD_UpgrHandleCbk *uh, bool read_ready, bool write_ready, bool net_err)
{
  struct MemoryPool *pool_to_destroy = NULL;
  MHD_mutex_lock_chk_ (&(uh->data_and_cbk_mutex));
  mhd_assert (MHD_UPGR_STATE_CONNECTED <= uh->state);
  mhd_assert (MHD_UPGR_STATE_CLOSING >= uh->state);
  if (net_err)
    { /* Try to read/write any pending data. */
      read_ready = true;
      write_ready = true;
    }
  uh->recv_ready = read_ready;
  uh->send_ready = write_ready;

  if (uh->recv_needed)
    {
      mhd_assert ((NULL != uh->recv_buff) || (NULL != uh->recv_result_cbk));
      if (NULL != uh->recv_buff)
        {
          if (uh->has_recv_data_in_conn_buffer)
            { /* Supply already received data. */
              struct MHD_Connection * const connection = uh->connection;
              const size_t data_left = connection->read_buffer_offset - uh->conn_buffer_offset;
              const size_t recv_buff_size = uh->recv_buff_size;
              mhd_assert (uh->conn_buffer_offset < connection->read_buffer_offset);
              mhd_assert (0 == uh->recv_buff_used);
              if (recv_buff_size >= data_left)
                {
                  memcpy (uh->recv_buff, connection->read_buffer, data_left);
                  uh->has_recv_data_in_conn_buffer = false;
                  uh->conn_buffer_offset = 0;
                  pool_to_destroy = connection->pool; /* Destroy pool without holding mutex. */
                  connection->pool = NULL;
                  uh->recv_buff_used = data_left;
                  if (data_left == recv_buff_size)
                    uh->recv_needed = false;
                }
              else
                {
                  memcpy (uh->recv_buff, connection->read_buffer, recv_buff_size);
                  ret = recv_buff_size;
                  uh->conn_buffer_offset += recv_buff_size;
                  uh->recv_buff_used = data_left;
                  uh->recv_needed = false;
                }
            }
          if ((read_ready) && (uh->recv_needed))
            {
              MHD_upgr_net_recv_ (uh);
            }
        }
    }
  if ((write_ready) && (uh->send_needed))
    {
      MHD_upgr_net_send_ (uh);
    }

  MHD_upgr_process_recieved_ (uh);
  MHD_upgr_process_send_ (uh);
  MHD_upgr_call_termination_cbk (uh);

  MHD_mutex_unlock_chk_ (&(uh->data_and_cbk_mutex));
  if (NULL != pool_to_destroy)
    MHD_pool_destroy (pool_to_destroy);
}
