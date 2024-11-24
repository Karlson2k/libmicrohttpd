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
 * @file src/mhd2/upgrade_proc.c
 * @brief  The implementation of functions for processing data for HTTP Upgrade
 * @author Karlson2k (Evgeny Grin)
 */


#include "mhd_sys_options.h"

#include "upgrade_proc.h"

#include "sys_base_types.h"

#include "mhd_locks.h"

#include "mhd_action.h"
#include "mhd_connection.h"
#include "mhd_daemon.h"
#include "mhd_upgrade.h"

#include "daemon_funcs.h"
#include "stream_funcs.h"
#include "daemon_logger.h"

#include "mhd_public_api.h"


MHD_INTERNAL
MHD_FN_PAR_NONNULL_ (1) bool
mhd_upgrade_try_start_upgrading (struct MHD_Connection *restrict c)
{
  mhd_assert (mhd_HTTP_STAGE_UPGRADE_HEADERS_SENDING == c->stage);
  mhd_assert ((mhd_ACTION_UPGRADE == c->rq.app_act.head_act.act) ||
              (mhd_UPLOAD_ACTION_UPGRADE == c->rq.app_act.upl_act.act));
  mhd_assert (NULL != c->write_buffer);
  mhd_assert ((0 != c->read_buffer_offset) || (NULL == c->read_buffer));
  mhd_assert (NULL == c->upgr.c);

  if (c->write_buffer_append_offset != c->write_buffer_send_offset)
    return false;

  c->stage = mhd_HTTP_STAGE_UPGRADING;

  return true;
}


MHD_INTERNAL
MHD_FN_PAR_NONNULL_ (1) bool
mhd_upgrade_finish_switch_to_upgraded (struct MHD_Connection *restrict c)
{
  struct mhd_UpgradeActionData *pupgr_data;
  mhd_assert (mhd_HTTP_STAGE_UPGRADING == c->stage);
  mhd_assert (NULL != c->write_buffer);
  mhd_assert ((0 != c->read_buffer_offset) || (NULL == c->read_buffer));
  mhd_assert (NULL == c->upgr.c);

  pupgr_data = (mhd_ACTION_UPGRADE == c->rq.app_act.head_act.act) ?
               &(c->rq.app_act.head_act.data.upgrd) :
               &(c->rq.app_act.upl_act.data.upgrd);

  // TODO: Support thread-per-connection

  c->upgr.c = c;
  if (! mhd_mutex_init (&(c->upgr.lock)))
  {
    c->upgr.c = NULL;
    mhd_LOG_MSG (c->daemon,
                 MHD_SC_MUTEX_INIT_FAILURE,
                 "Failed to initialise mutex for HTTP-Upgraded operations");
    mhd_conn_start_closing_no_sys_res (c);
    return false;
  }
  mhd_DLINKEDL_INIT_LINKS (c, upgr_cleanup);
  mhd_stream_release_write_buffer (c);
  mhd_conn_pre_upgrade (c);

  mhd_conn_pre_clean_part1 (c);

  c->stage = mhd_HTTP_STAGE_UPGRADED;

  mhd_assert (! c->in_proc_ready);
  mhd_assert (NULL == mhd_DLINKEDL_GET_PREV (c, by_timeout));
  mhd_assert (NULL == mhd_DLINKEDL_GET_NEXT (c, by_timeout));
  mhd_assert (c != mhd_DLINKEDL_GET_FIRST (&(c->daemon->conns), def_timeout));
  mhd_assert (c != mhd_DLINKEDL_GET_LAST (&(c->daemon->conns), def_timeout));
  mhd_assert (c != mhd_DLINKEDL_GET_FIRST (&(c->daemon->conns), cust_timeout));
  mhd_assert (c != mhd_DLINKEDL_GET_LAST (&(c->daemon->conns), cust_timeout));

  pupgr_data->cb (pupgr_data->cb_cls,
                  &(c->rq),
                  &(c->upgr));
  return true;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1) enum MHD_StatusCode
MHD_upgraded_close (struct MHD_UpgradedHandle *urh)
{
  struct MHD_Connection *const restrict c = urh->c;
  struct MHD_Daemon *const restrict d = c->daemon;

  if (mhd_HTTP_STAGE_UPGRADED != c->stage) /* Probably, assert would be better here */
    return MHD_SC_TOO_LATE;

  c->stage = mhd_HTTP_STAGE_UPGRADED_CLEANING;
  mhd_mutex_lock_chk (&(d->conns.upgr.ucu_lock));
  mhd_DLINKEDL_INS_LAST (&(d->conns.upgr), c, upgr_cleanup);
  mhd_mutex_unlock_chk (&(d->conns.upgr.ucu_lock));
  (void) mhd_daemon_trigger_itc (d); /* Ignore result, the connection has been placed in cleanup list already */

  return MHD_SC_OK;
}


MHD_INTERNAL
MHD_FN_PAR_NONNULL_ (1) void
mhd_upgraded_deinit (struct MHD_Connection *restrict c)
{
  mhd_assert ((mhd_HTTP_STAGE_UPGRADED_CLEANING == c->stage) || \
              (mhd_HTTP_STAGE_UPGRADED == c->stage));
  mhd_assert (c == c->upgr.c);

  mhd_mutex_destroy_chk (&(c->upgr.lock));
}
