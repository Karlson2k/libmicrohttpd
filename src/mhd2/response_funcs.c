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

#include "sys_null_macro.h"
#include "mhd_response.h"
#include "response_funcs.h"
#include "mhd_locks.h"

static void
response_set_properties (struct MHD_Response *restrict r)
{
  struct ResponseOptions *restrict const s = r->settings;
  mhd_assert (NULL != s);
  r->frozen = true;

  r->cfg.head_only = s->head_only_response;
  if (s->http_1_0_compatible_strict)
  {
    r->cfg.conn_close = true;
    r->cfg.chunked = false;
  }
  else
  {
    r->cfg.conn_close = s->conn_close;
    r->cfg.chunked = s->chunked_enc || (MHD_SIZE_UNKNOWN == r->size);
  }
  r->cfg.mode_1_0 = s->http_1_0_server;
  r->cfg.cnt_len_by_app = s->insanity_header_content_length; // TODO: set only if "content-lengh" header is used

  r->settings = NULL;
}


/**
 * Check whether response is "frozen" (modifications blocked) and "freeze"
 * it if it was not frozen before
 * @param response the response to manipulate
 */
MHD_INTERNAL void
mhd_response_check_frozen_freeze (struct MHD_Response *restrict response)
{
  bool need_lock;
  if (response->frozen)
    return;

  if (response->reuse.reusable)
  {
    need_lock = true;
    mhd_mutex_lock_chk (&(response->reuse.settings_lock));
    mhd_assert (1 == response->reuse.counter);
  }
  else
    need_lock = false;

  if (! response->frozen)/* Re-check under the lock */
    response_set_properties (response);

  if (need_lock)
    mhd_mutex_unlock_chk (&(response->reuse.settings_lock));
}
