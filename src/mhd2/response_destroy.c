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
 * @file src/mhd2/response_destroy.c
 * @brief  The declarations of internal functions for response deletion
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"
#include "response_destroy.h"
#include "mhd_response.h"

#include "mhd_assert.h"
#include "mhd_atomic_counter.h"

#include "sys_malloc.h"

#include "mhd_public_api.h"

#include "response_add_header.h"
#include "response_funcs.h"
#include "response_from.h"

/**
 * Perform full response de-initialisation, with cleaning-up / freeing
 * all content data and headers.
 * The response settings (if any) must be already freed.
 * @param r the response to free
 */
static MHD_FN_PAR_NONNULL_ (1) void
response_full_detinit (struct MHD_Response *restrict r)
{
  mhd_response_remove_all_headers (r);
  if (NULL != r->special_resp.spec_hdr)
    free (r->special_resp.spec_hdr);
  if (r->reuse.reusable)
    mhd_response_deinit_reusable (r);
  mhd_response_deinit_content_data (r);
  free (r);
}


MHD_INTERNAL void
mhd_response_dec_use_count (struct MHD_Response *restrict r)
{
  mhd_assert (r->frozen);

  if (r->reuse.reusable)
  {
    if (0 != mhd_atomic_counter_dec_get (&(r->reuse.counter)))
      return; /* The response is still used somewhere */
  }

  response_full_detinit (r);
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1) void
MHD_response_destroy (struct MHD_Response *response)
{
  if (! response->frozen)
  {
    /* This response has been never used for actions */
    mhd_assert (NULL != response->settings);
    free (response->settings);
#ifndef NDEBUG
    /* Decrement counter to avoid triggering assert in deinit function */
    mhd_assert (0 == mhd_atomic_counter_dec_get (&(response->reuse.counter)));
#endif
    response_full_detinit (response);
    return;
  }

  mhd_response_dec_use_count (response);
}
