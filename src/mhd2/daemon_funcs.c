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
 * @file src/mhd2/daemon_funcs.c
 * @brief  The implementation of internal daemon-related functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "daemon_funcs.h"

#include "sys_base_types.h"
#include "sys_malloc.h"

#include "mhd_assert.h"
#include "mhd_itc.h"
#include "mhd_daemon.h"
#include "daemon_logger.h"


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_MUST_CHECK_RESULT_ struct MHD_Daemon *
mhd_daemon_get_master_daemon (struct MHD_Daemon *restrict d)
{
#ifdef MHD_USE_THREADS
  if (mhd_D_HAS_MASTER (d))
    return d->threading.hier.master;
#endif /* MHD_USE_THREADS */
  return d;
}


#ifdef MHD_USE_THREADS

MHD_INTERNAL bool
mhd_daemon_trigger_itc (struct MHD_Daemon *restrict d)
{
  mhd_assert (mhd_ITC_IS_VALID (d->threading.itc));
  if (! mhd_itc_activate (d->threading.itc))
  {
    mhd_LOG_MSG (d, MHD_SC_ITC_USE_FAILED, \
                 "Failed to communicate by ITC with the daemon thread.");
    return false;
  }
  return true;
}


#endif /* MHD_USE_THREADS */


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_daemon_resume_conns (struct MHD_Daemon *restrict d)
{
  (void) d;
  mhd_assert (0 && "Not implemented yet");
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_MUST_CHECK_RESULT_ bool
mhd_daemon_claim_lbuf (struct MHD_Daemon *d,
                       size_t requested_size)
{
  bool ret;
  struct MHD_Daemon *const masterd = mhd_daemon_get_master_daemon (d);
  mhd_assert (0 != requested_size);
  if (0 == masterd->req_cfg.large_buf.space_left)
    return false; /* Shortcut for typical use without large buffer */

  ret = false;
  mhd_mutex_lock_chk (&(masterd->req_cfg.large_buf.lock));
  if (masterd->req_cfg.large_buf.space_left >= requested_size)
  {
    masterd->req_cfg.large_buf.space_left -= requested_size;
    ret = true;
  }
  mhd_mutex_unlock_chk (&(masterd->req_cfg.large_buf.lock));
  return ret;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_daemon_reclaim_lbuf (struct MHD_Daemon *d,
                         size_t reclaimed_size)
{
  struct MHD_Daemon *const masterd = mhd_daemon_get_master_daemon (d);
  mhd_assert (0 != reclaimed_size);
  mhd_mutex_lock_chk (&(masterd->req_cfg.large_buf.lock));
  masterd->req_cfg.large_buf.space_left += reclaimed_size;
  mhd_mutex_unlock_chk (&(masterd->req_cfg.large_buf.lock));
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_
MHD_FN_PAR_OUT_ (3) bool
mhd_daemon_get_lbuf (struct MHD_Daemon *restrict d,
                     size_t requested_size,
                     struct mhd_Buffer *restrict buf)
{
  if (! mhd_daemon_claim_lbuf (d, requested_size))
  {
    buf->size = 0;
    buf->buf = NULL;
    return false;
  }
  buf->buf = (char *) malloc (requested_size);
  if (NULL == buf->buf)
  {
    buf->size = 0;
    mhd_daemon_reclaim_lbuf (d, requested_size);
    return false;
  }
  buf->size = requested_size;
  return true;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ MHD_FN_MUST_CHECK_RESULT_
MHD_FN_PAR_INOUT_ (3) bool
mhd_daemon_grow_lbuf (struct MHD_Daemon *restrict d,
                      size_t grow_size,
                      struct mhd_Buffer *restrict buf)
{
  void *new_alloc;
  mhd_assert (NULL != buf->buf || 0 == buf->size);
  mhd_assert (0 != buf->size || NULL == buf->buf);

  if (! mhd_daemon_claim_lbuf (d, grow_size))
    return false;

  if (NULL == buf->buf)
    new_alloc = malloc (grow_size);
  else
    new_alloc = realloc (buf->buf, buf->size + grow_size);
  if (NULL == new_alloc)
  {
    mhd_daemon_reclaim_lbuf (d, grow_size);
    return false;
  }

  buf->buf = (char *) new_alloc;
  buf->size += grow_size;

  return true;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_INOUT_ (2) void
mhd_daemon_free_lbuf (struct MHD_Daemon *restrict d,
                      struct mhd_Buffer *restrict buf)
{
  if (0 == buf->size)
  {
    mhd_assert (NULL == buf->buf);
    return;
  }
  free (buf->buf);
  buf->buf = NULL;
  mhd_daemon_reclaim_lbuf (d, buf->size);
  buf->size = 0;
}
