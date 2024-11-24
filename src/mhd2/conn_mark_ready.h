/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/conn_mark_ready.h
 * @brief  The definition of static functions to mark/unmark connection as
 *         "process ready".
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_CONN_MARK_READY_H
#define MHD_CONN_MARK_READY_H 1

#include "mhd_sys_options.h"

#include "sys_null_macro.h"

#include "mhd_assert.h"

#include "mhd_connection.h"
#include "mhd_daemon.h"
#include "mhd_dlinked_list.h"

/**
 * Mark connection as "ready to process" and add it to the end of the
 * "process ready" list if connection is not in the list.
 * @param c the connection to mark
 * @param d the daemon for the connection
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_ void
mhd_conn_mark_ready (struct MHD_Connection *restrict c,
                     struct MHD_Daemon *restrict d)
{
  mhd_assert (d == c->daemon);
  if (c->in_proc_ready)
  {
    mhd_assert ((NULL != mhd_DLINKEDL_GET_NEXT (c, proc_ready)) || \
                (NULL != mhd_DLINKEDL_GET_PREV (c, proc_ready)) || \
                (c == mhd_DLINKEDL_GET_FIRST (&(d->events), proc_ready)));
    return; /* Already marked and in the list */
  }
  mhd_assert (NULL == mhd_DLINKEDL_GET_NEXT (c, proc_ready));
  mhd_assert (NULL == mhd_DLINKEDL_GET_PREV (c, proc_ready));
  mhd_assert (c != mhd_DLINKEDL_GET_FIRST (&(d->events), proc_ready));
  mhd_assert (c != mhd_DLINKEDL_GET_LAST (&(d->events), proc_ready));

  mhd_DLINKEDL_INS_LAST (&(d->events), c, proc_ready);
  c->in_proc_ready = true;
}


/**
 * Mark connection as "not ready to process" and remove it from the "process
 * ready" list if connection is in the list.
 * @param c the connection to mark
 * @param d the daemon for the connection
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_ void
mhd_conn_mark_unready (struct MHD_Connection *restrict c,
                       struct MHD_Daemon *restrict d)
{
  mhd_assert (d == c->daemon);
  if (! c->in_proc_ready)
  {
    mhd_assert (NULL == mhd_DLINKEDL_GET_NEXT (c, proc_ready));
    mhd_assert (NULL == mhd_DLINKEDL_GET_PREV (c, proc_ready));
    mhd_assert (c != mhd_DLINKEDL_GET_FIRST (&(d->events), proc_ready));
    mhd_assert (c != mhd_DLINKEDL_GET_LAST (&(d->events), proc_ready));
    return; /* Already unmarked and not in the list */
  }
  mhd_assert ((NULL != mhd_DLINKEDL_GET_NEXT (c, proc_ready)) || \
              (NULL != mhd_DLINKEDL_GET_PREV (c, proc_ready)) || \
              (c == mhd_DLINKEDL_GET_FIRST (&(d->events), proc_ready)));

  mhd_DLINKEDL_DEL (&(d->events), c, proc_ready);
  c->in_proc_ready = false;
}


/**
 * Update "ready" mark on the connection, remove or add connection to
 * the "process ready" list if necessary.
 * @param c the connection to update
 * @param force_ready ignore network states and mark the connection as "ready"
 * @param d the daemon for the connection
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_ void
mhd_conn_mark_ready_update3 (struct MHD_Connection *restrict c,
                             unsigned int force_ready,
                             struct MHD_Daemon *restrict d)
{
  if (force_ready ||
      (0 !=
       ((((unsigned int) c->sk.ready) | mhd_C_HAS_TLS_DATA_IN (c))
        & ((unsigned int) c->event_loop_info)
        & (MHD_EVENT_LOOP_INFO_RECV | MHD_EVENT_LOOP_INFO_SEND))))
    mhd_conn_mark_ready (c, d);
  else
    mhd_conn_mark_unready (c, d);
}


/**
 * Update "ready" mark on the connection, remove or add connection to
 * the "process ready" list if necessary.
 * This function could be used if the "daemon" handle is already extracted
 * from the connection.
 * @param c the connection to update
 * @param d the daemon for the connection
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_ void
mhd_conn_mark_ready_update2 (struct MHD_Connection *restrict c,
                             struct MHD_Daemon *restrict d)
{
  mhd_conn_mark_ready_update3 (c, 0, d);
}


/**
 * Update "ready" mark on the connection, remove or add connection to
 * the "process ready" list if necessary.
 * This function could be used if the "daemon" handle has not been extracted
 * from the connection.
 * @param c the connection to update
 * @param d the daemon for the connection
 */
MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_ void
mhd_conn_mark_ready_update (struct MHD_Connection *restrict c)
{
  mhd_conn_mark_ready_update2 (c,
                               c->daemon);
}


#endif /* ! MHD_CONN_MARK_READY_H */
