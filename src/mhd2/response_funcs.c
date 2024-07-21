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
 * @file src/mhd2/response_funcs.с
 * @brief  The definition of the internal response helper functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "sys_malloc.h"

#include "sys_null_macro.h"
#include "mhd_response.h"
#include "response_funcs.h"
#include "mhd_locks.h"
#include "response_options.h"


#include "mhd_atomic_counter.h"


MHD_INTERNAL
MHD_FN_PAR_NONNULL_ (1) bool
response_make_reusable (struct MHD_Response *restrict r)
{
  mhd_assert (! r->reuse.reusable);
  mhd_assert (! r->frozen);
  mhd_assert (NULL != r->settings);

  if (mhd_mutex_init (&(r->reuse.settings_lock)))
  {
    if (mhd_atomic_counter_init (&(r->reuse.counter), 1))
    {
      r->reuse.reusable = true;
      return true;
    }
    (void) mhd_mutex_destroy (&(r->reuse.settings_lock));
  }
  return false;
}


MHD_INTERNAL
MHD_FN_PAR_NONNULL_ (1) void
mhd_response_deinit_reusable (struct MHD_Response *restrict r)
{
  mhd_assert (r->reuse.reusable);
  mhd_assert (0 == mhd_atomic_counter_get (&(r->reuse.counter)));

  mhd_atomic_counter_deinit (&(r->reuse.counter));
  mhd_mutex_destroy_chk (&(r->reuse.settings_lock));
}


static void
response_set_properties (struct MHD_Response *restrict r)
{
  struct ResponseOptions *restrict const s = r->settings;
  mhd_assert (NULL != s);

  r->cfg.head_only = s->head_only_response;
  if (s->http_1_0_compatible_strict)
  {
    r->cfg.close_forced = true;
    r->cfg.chunked = false;
    r->cfg.mode_1_0 = s->http_1_0_server;
  }
  else if (s->http_1_0_server)
  {
    r->cfg.close_forced = s->conn_close || (MHD_SIZE_UNKNOWN == r->cntn_size);
    r->cfg.chunked = false;
    r->cfg.mode_1_0 = true;
  }
  else
  {
    r->cfg.close_forced = s->conn_close;
    r->cfg.chunked = s->chunked_enc || (MHD_SIZE_UNKNOWN == r->cntn_size);
    r->cfg.mode_1_0 = false;
  }

  r->cfg.cnt_len_by_app = s->insanity_header_content_length; // TODO: set only if "content-lengh" header is used

  // TODO: calculate size of the headers and the "Connection:" header

  r->frozen = true;

  r->settings = NULL;
  free (s);
}


/**
 * Check whether response is "frozen" (modifications blocked) and "freeze"
 * it if it was not frozen before
 * @param response the response to manipulate
 */
MHD_INTERNAL void
mhd_response_check_frozen_freeze (struct MHD_Response *restrict response)
{
  bool need_unlock;
  if (response->frozen)
    return;

  if (response->reuse.reusable)
  {
    need_unlock = true;
    mhd_mutex_lock_chk (&(response->reuse.settings_lock));
    mhd_assert (1 == mhd_atomic_counter_get (&(response->reuse.counter)));
  }
  else
    need_unlock = false;

  if (! response->frozen)/* Re-check under the lock */
    response_set_properties (response);

  if (need_unlock)
    mhd_mutex_unlock_chk (&(response->reuse.settings_lock));
}
