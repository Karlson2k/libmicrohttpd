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

  if (MHD_mutex_init_ (&(uh->recv_mutex)))
    {
      if (MHD_mutex_init_ (&(uh->send_mutex)))
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
                  MHD_mutex_lock_chk_ (uh->recv_mutex);
                  /* Destroy connection's memory pool as it will not be used any more. */
                  connection->read_buffer = NULL;
                  connection->write_buffer = NULL;
                  MHD_pool_destroy (connection->pool);
                  connection->pool = NULL;
                  MHD_mutex_unlock_chk_ (uh->recv_mutex);
                }
              return true;
            }

          MHD_mutex_destroy_chk_ (&(uh->send_mutex));
        }
      else
        {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
                _("Failed to initialise mutex.\n"));
#endif /* HAVE_MESSAGES */
        }
      MHD_mutex_destroy_chk_ (&(uh->recv_mutex));
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

void
MHD_upgr_net_send_ (struct MHD_UpgrHandleCbk *uh)
{
  struct MHD_Connection * const connection = uh->connection;
  mhd_assert (MHD_UPGR_STATE_CONNECTED <= uh->state);
  mhd_assert (MHD_UPGR_STATE_INVALID > uh->state);

  /* Fast check without locking. */
  if (NULL == uh->recv_buff)
    return;

  MHD_mutex_lock_chk_ (uh->recv_mutex);
  /* Firm check under lock. */
  if (NULL != uh->recv_buff)
    {
      ssize_t send_res;
      mhd_assert (0 != uh->recv_buff_size);
      mhd_assert (uh->recv_buff_used < uh->recv_buff_size);

      send_res = connection->send_cls (connection, uh->recv_buff + uh->recv_buff_used,
                                       uh->recv_buff_size - uh->recv_buff_used);
      mhd_assert (0 != send_res);

      /* FIXME: remove flag clearing here or modify check in 'process_sent'. */
      if (0 >= send_res)
        {
          if (MHD_ERR_AGAIN_ != send_res)
            { /* Hard error. */
              uh->
            }
        }

    }
  MHD_mutex_unlock_chk_ (uh->recv_mutex);
}

void
MHD_upgr_net_recv_ (struct MHD_UpgrHandleCbk *uh)
{

}

_MHD_EXTERN int
MHD_upgr_send_all (struct MHD_UpgrHandleCbk *uh,
                   const void *data,
                   size_t data_size,
                   MHD_UpgrTransferFinishedCbk result_cbk,
                   void *cls)
{
  const struct MHD_Daemon * daemon;
  int ret = MHD_NO;

  if (NULL == uh)
    return ret;
  mhd_assert (MHD_CONNECTION_UPGR_CBK == uh->connection->state);
  daemon = uh->connection->daemon;

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

  if (MHD_mutex_lock_ (uh->send_mutex))
    {
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
        }
      else
        {
          if ( (NULL != uh->send_buff) && (NULL != data) )
            {
#ifdef HAVE_MESSAGES
          MHD_DLOG (daemon,
                    _("Another data is already being sent to remote.\n"));
#endif /* HAVE_MESSAGES */
            }
          else if ( (NULL != uh->send_finished_cbk) && (NULL != result_cbk) )
            {
#ifdef HAVE_MESSAGES
              MHD_DLOG (daemon,
                        _("Another send completion callback was already registered.\n"));
#endif /* HAVE_MESSAGES */
              ret = MHD_NO;
            }
          else
            { /* Schedule data and/or callback. */
              if (NULL != data)
                {
                  uh->send_buff = data;
                  uh->send_buff_size = data_size;
                }
              if (NULL != result_cbk)
                {
                  uh->send_finished_cbk = result_cbk;
                  uh->send_finished_cbk_cls = cls;
                }
              uh->send_needed = true;
              ret = MHD_YES;
            }
        }
      MHD_mutex_unlock_chk_ (uh->send_mutex);
    }
  return ret;
}

_MHD_EXTERN int
MHD_upgr_recv_fill (struct MHD_UpgrHandleCbk *uh,
                    void *buffer,
                    size_t buffer_size,
                    MHD_UpgrTransferFinishedCbk result_cbk,
                    void *cls)
{
  const struct MHD_Daemon * daemon;
  int ret = MHD_NO;

  if (NULL == uh)
    return ret;
  mhd_assert (MHD_CONNECTION_UPGR_CBK == uh->connection->state);
  daemon = uh->connection->daemon;

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

  if (MHD_mutex_lock_ (uh->recv_mutex))
    {
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
          else if ( (NULL != uh->recv_finished_cbk) && (NULL != result_cbk) )
            {
#ifdef HAVE_MESSAGES
              MHD_DLOG (daemon,
                        _("Another receive completion callback was already registered.\n"));
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
                  uh->recv_finished_cbk = result_cbk;
                  uh->recv_finished_cbk_cls = cls;
                }
              uh->recv_needed = true;
              if (uh->peer_closed_write)
                {
                  /* TODO: Handle instant re-loop and notify. */
                }
              ret = MHD_YES;
            }
        }
      MHD_mutex_unlock_chk_ (uh->recv_mutex);
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
  const struct MHD_Daemon * daemon;
  size_t ret = -2;
  if (NULL == uh)
    return ret;

  mhd_assert (MHD_CONNECTION_UPGR_CBK == uh->connection->state);
  daemon = uh->connection->daemon;

  if (buffer_size > SSIZE_MAX)
    buffer_size = SSIZE_MAX;
  if (MHD_mutex_lock_ (uh->recv_mutex))
    {
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
              else
                {
                  ssize_t recv_res;

                  recv_res = connection->recv_cls (connection, buffer, buffer_size);
                  if (0 < recv_res)
                    {
                      if ((size_t)recv_res < buffer_size)
                        uh->recv_ready = false;
                      /* Actually connection may be unready in other cases too,
                       * but this clear of flag results only in less processing
                       * after next MHD_upgr_recv_fill(). */
                    }
                  else if (0 == recv_res)
                    { /* Remote host shut down writing on socket. */
                      uh->peer_closed_write = true;
                    }
                  else if (0 > recv_res)
                    { /* Any kind of error. */
                      /* FIXME: main polling loop trigger on network error,
                       * so additional processing here is not required. */
                    }
                }
            }
          MHD_mutex_unlock_chk_ (uh->recv_mutex);
        }
    }
  return ret;
}


void
MHD_upgr_process_sent_ (struct MHD_UpgrHandleCbk *uh)
{
  const struct MHD_connection * const connection = uh->connection;
  mhd_assert (MHD_CONNECTION_UPGR_CBK == connection->state);

  MHD_mutex_lock_chk_ (uh->send_mutex);
  mhd_assert (MHD_UPGR_STATE_CONNECTED <= uh->state);
  mhd_assert (MHD_UPGR_STATE_INVALID > uh->state);
  mhd_assert ( (NULL == uh->send_buff) == (0 == uh->send_buff_size) );
  mhd_assert ( (uh->need_send) || ((NULL == uh->send_buff) && (NULL == uh->send_finished_cbk)) );
  mhd_assert (uh->send_buff_size >= uh->send_buff_used);

  if (MHD_UPGR_STATE_CLOSING < uh->state)
    { /* Any kind of disconnected state. */
      if ( (NULL != uh->send_buff) ||
           (NULL != uh->send_finished_cbk) )
        { /* Some action is required. */
          void * const send_buff = uh->send_buff;
          const size_t send_buff_size = uh->send_buff_size;
          const size_t send_buff_sent = uh->send_buff_sent;
          const MHD_UpgrTransferFinishedCbk send_finished_cbk = uh->send_finished_cbk;
          void * const send_finished_cbk_cls = uh->send_finished_cbk_cls;
          enum MHD_UpgrTransferResult tr_result;

          if (NULL != send_finished_cbk)
            {
              switch (uh->state)
                {
                case MHD_UPGR_STATE_TIMEOUT:
                  tr_result = MHD_UPGR_TRNSF_RESULT_SEND_ABORTED_BY_TIMEOUT; break;
                case MHD_UPGR_STATE_CLOSED_BY_APP:
                  tr_result = MHD_UPGR_TRNSF_RESULT_SEND_ABORTED_BY_APP; break;
                case MHD_UPGR_STATE_DISCONN_REMOTE:
                  tr_result = MHD_UPGR_TRNSF_RESULT_SEND_ABORTED_BY_REMOTE_DISCNT; break;
                case MHD_UPGR_STATE_DISCONN_ERR:
                  tr_result = MHD_UPGR_TRNSF_RESULT_SEND_ABORTED_BY_NET_ERR; break;
                default:
                  mhd_assert (false); break;
                }
            }
          /* Cleanup internal data. */
          uh->send_needed = false;
          uh->send_buff = NULL;
          uh->send_buff_size = 0;
          uh->send_buff_sent = 0;
          uh->send_finished_cbk = NULL;
          uh->send_finished_cbk_cls = NULL;

          if (NULL != send_finished_cbk)
            {
              /* Unlock mutex before calling callback. */
              MHD_mutex_unlock_chk_ (uh->send_mutex);
              send_finished_cbk (uh, tr_result, send_buff_sent, send_buff, send_buff_size, send_finished_cbk_cls);
              return; /* Return right after calling callback. */
            }
        }
    }
  else /* MHD_UPGR_STATE_CLOSING >= uh->state */
    {
      if ( ( (NULL != uh->send_buff) && (uh->send_buff_size == uh->send_buff_sent) ) ||
           ( (NULL == uh->send_buff) && (NULL != uh->send_finished_cbk) && (uh->send_ready) ) )
        { /* Some action is required. */
          void * const send_buff = uh->send_buff;
          const size_t send_buff_size = uh->send_buff_size;
          const size_t send_buff_sent = uh->send_buff_sent;
          const MHD_UpgrTransferFinishedCbk send_finished_cbk = uh->send_finished_cbk;
          void * const send_finished_cbk_cls = uh->send_finished_cbk_cls;
          const bool start_closing = (MHD_UPGR_STATE_CLOSING == uh->state);

          /* Cleanup internal data. */
          uh->send_needed = false;
          uh->send_buff = NULL;
          uh->send_buff_size = 0;
          uh->send_buff_sent = 0;
          uh->send_finished_cbk = NULL;
          uh->send_finished_cbk_cls = NULL;

          if ( (NULL != send_finished_cbk) ||
               start_closing)
            {
              /* Unlock mutex before calling callback. */
              MHD_mutex_unlock_chk_ (uh->send_mutex);
              if (NULL != send_finished_cbk)
                send_finished_cbk (uh, MHD_UPGR_TRNSF_RESULT_SENT_OK, send_buff_sent, send_buff, send_buff_size, send_finished_cbk_cls);
              if (start_closing)
                MHD_upgr_start_closing_ (uh);
              return; /* Return right after calling callback. */
            }
        }
    }
  MHD_mutex_unlock_chk_ (uh->send_mutex);
}


void
MHD_upgr_process_recieved_ (struct MHD_UpgrHandleCbk *uh)
{
  const struct MHD_connection * const connection = uh->connection;
  mhd_assert (MHD_CONNECTION_UPGR_CBK == connection->state);

  MHD_mutex_lock_chk_ (uh->recv_mutex);
  mhd_assert (MHD_UPGR_STATE_CONNECTED <= uh->state);
  mhd_assert (MHD_UPGR_STATE_INVALID > uh->state);
  mhd_assert ( (NULL == uh->recv_buff) == (0 == uh->recv_buff_size) );
  mhd_assert ( (uh->need_recv) || ((NULL == uh->recv_buff) && (NULL == uh->recv_finished_cbk)) );
  mhd_assert (uh->recv_buff_size >= uh->recv_buff_used);

  if ( (MHD_UPGR_STATE_CLOSING < uh->state) ||
       (uh->peer_closed_write) )
    { /* Any kind of disconnected state. */
      if ( (NULL != uh->recv_buff) ||
           (NULL != uh->recv_finished_cbk) )
        { /* Some action is required. */
          void * const recv_buff = uh->recv_buff;
          const size_t recv_buff_size = uh->recv_buff_size;
          const size_t recv_buff_used = uh->recv_buff_used;
          const MHD_UpgrTransferFinishedCbk recv_finished_cbk = uh->recv_finished_cbk;
          void * const recv_finished_cbk_cls = uh->recv_finished_cbk_cls;
          enum MHD_UpgrTransferResult tr_result;

          if (NULL != recv_finished_cbk)
            {
              switch (uh->state)
                {
                case MHD_UPGR_STATE_CLOSING:
                  /* TODO: handle closure processing. */
                case MHD_UPGR_STATE_CONNECTED:
                  mhd_assert (uh->peer_closed_write);
                  tr_result = MHD_UPGR_TRNSF_RESULT_RECV_ABORTED_BY_REMOTE_DISCNT; break;
                case MHD_UPGR_STATE_TIMEOUT:
                  tr_result = MHD_UPGR_TRNSF_RESULT_RECV_ABORTED_BY_TIMEOUT; break;
                case MHD_UPGR_STATE_CLOSED_BY_APP:
                  tr_result = MHD_UPGR_TRNSF_RESULT_RECV_ABORTED_BY_APP; break;
                case MHD_UPGR_STATE_DISCONN_REMOTE:
                  tr_result = MHD_UPGR_TRNSF_RESULT_RECV_ABORTED_BY_REMOTE_DISCNT; break;
                case MHD_UPGR_STATE_DISCONN_ERR:
                  tr_result = MHD_UPGR_TRNSF_RESULT_RECV_ABORTED_BY_NET_ERR; break;
                default:
                  mhd_assert (false); break;
                }
            }
          /* Cleanup internal data. */
          uh->recv_needed = false;
          uh->recv_buff = NULL;
          uh->recv_buff_size = 0;
          uh->recv_buff_used = 0;
          uh->recv_finished_cbk = NULL;
          uh->recv_finished_cbk_cls = NULL;

          if (NULL != recv_finished_cbk)
            {
              /* Unlock mutex before calling callback. */
              MHD_mutex_unlock_chk_ (uh->recv_mutex);
              recv_finished_cbk (uh, tr_result, recv_buff_used, recv_buff, recv_buff_size, recv_finished_cbk_cls);
              return; /* Return right after calling callback. */
            }
        }
    }
  else /* MHD_UPGR_STATE_CLOSING >= uh->state */
    {
      if ( ( (NULL != uh->recv_buff) && (uh->recv_buff_size == uh->recv_buff_used) ) ||
           ( (NULL == uh->recv_buff) && (NULL != uh->recv_finished_cbk) && (uh->recv_ready) ) )
        { /* Some action is required. */
          void * const recv_buff = uh->recv_buff;
          const size_t recv_buff_size = uh->recv_buff_size;
          const size_t recv_buff_used = uh->recv_buff_used;
          const MHD_UpgrTransferFinishedCbk recv_finished_cbk = uh->recv_finished_cbk;
          void * const recv_finished_cbk_cls = uh->recv_finished_cbk_cls;

          /* Cleanup internal data. */
          uh->recv_buff = NULL;
          uh->recv_buff_size = 0;
          uh->recv_buff_used = 0;
          uh->recv_finished_cbk = NULL;
          uh->recv_finished_cbk_cls = NULL;
          if (MHD_UPGR_STATE_CLOSING != uh->state)
            uh->recv_needed = false;

          if (NULL != recv_finished_cbk)
            {
              /* Unlock mutex before calling callback. */
              MHD_mutex_unlock_chk_ (uh->recv_mutex);
              recv_finished_cbk (uh, MHD_UPGR_TRNSF_RESULT_RECV_OK, recv_buff_used, recv_buff, recv_buff_size, recv_finished_cbk_cls);
              return; /* Return right after calling callback. */
            }
        }
    }

  MHD_mutex_unlock_chk_ (uh->recv_mutex);
}
