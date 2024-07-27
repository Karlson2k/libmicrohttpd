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
 * @file src/mhd2/dcc_action.c
 * @brief  The definition of the MHD_DCC_action_*()
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include <string.h>

#include "mhd_dcc_action.h"
#include "mhd_response.h"
#include "mhd_reply.h"
#include "mhd_connection.h"

#include "mhd_public_api.h"

MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_CSTR_ (4) const struct MHD_DynamicContentCreatorAction *
MHD_DCC_action_continue_zc (
  struct MHD_DynamicContentCreatorContext *ctx,
  size_t data_size,
  const struct MHD_DynContentZCIoVec *iov_data,
  const char *MHD_RESTRICT chunk_ext)
{
  struct MHD_DynamicContentCreatorAction *ret;

  ret = NULL;
  do
  {
    if ((&(ctx->connection->rp.app_act_ctx)) != ctx)
      break;
    if (mhd_DCC_ACTION_NO_ACTION != ctx->connection->rp.app_act.act)
      break; /* The action already has been created */
    if (NULL != iov_data)
    {
      mhd_assert (0 && "Not implemented yet");
      break;
    }
    if (0 == data_size)
    { /* The total size must be non-zero */
      if (NULL == iov_data)
        break;
      mhd_assert (0 && "Not implemented yet");
      (void) iov_data->iov_count;
      // TODO: add check for iov data total size
      break;
    }
    if (NULL != chunk_ext)
    {
      if (ctx->connection->rp.props.chunked)
      {
        mhd_assert (0 && "Not implemented yet");
        // TODO: copy 'chunk_ext' directly to the output buffer
        break;
      }
    }
    ret = &(ctx->connection->rp.app_act);
    ret->act = mhd_DCC_ACTION_CONTINUE;
    ret->data.cntnue.buf_data_size = data_size;
    ret->data.cntnue.iov_data = iov_data;
  } while (0);

  if (NULL == ret)
  {
    /* Call application clean-up */
    if ((NULL != iov_data) && (NULL != iov_data->iov_fcb))
      iov_data->iov_fcb (iov_data->iov_fcb_cls);
  }

  return ret;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1)
const struct MHD_DynamicContentCreatorAction *
MHD_DCC_action_finish_with_footer (
  struct MHD_DynamicContentCreatorContext *ctx,
  size_t num_footers,
  const struct MHD_NameValueCStr *MHD_RESTRICT footers)
{
  struct MHD_DynamicContentCreatorAction *ret;

  if ((&(ctx->connection->rp.app_act_ctx)) != ctx)
    return NULL;
  if (mhd_DCC_ACTION_NO_ACTION != ctx->connection->rp.app_act.act)
    return NULL; /* The action already has been created */
  if ((0 != num_footers) && (NULL == footers))
    return NULL;

  if (MHD_SIZE_UNKNOWN != ctx->connection->rp.response->cntn_size)
  {
    mhd_assert (ctx->connection->rp.rsp_cntn_read_pos <
                ctx->connection->rp.response->cntn_size);
    return NULL;
  }

  if (0 != num_footers)
  {
    mhd_assert (0 && "Not implemented yet");
    // TODO: build response footer and use footers directly
    return NULL;
  }

  ret = &(ctx->connection->rp.app_act);
  ret->act = mhd_DCC_ACTION_FINISH;

  return ret;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_RETURNS_NONNULL_ const struct MHD_DynamicContentCreatorAction *
MHD_DCC_action_suspend (struct MHD_DynamicContentCreatorContext *ctx)
{
  struct MHD_DynamicContentCreatorAction *ret;

  if ((&(ctx->connection->rp.app_act_ctx)) != ctx)
    return NULL;
  if (mhd_DCC_ACTION_NO_ACTION != ctx->connection->rp.app_act.act)
    return NULL; /* The action already has been created */

  ret = &(ctx->connection->rp.app_act);
  ret->act = mhd_DCC_ACTION_SUSPEND;

  return ret;
}
