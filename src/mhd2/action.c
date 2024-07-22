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
 * @file src/mhd2/action.c
 * @brief  The definition of the MHD_action_*() and MHD_upload_action_*()
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "mhd_action.h"
#include "mhd_request.h"

#include "daemon_logger.h"

#include "response_funcs.h"

#include "mhd_public_api.h"


MHD_EXTERN_ MHD_FN_PAR_NONNULL_ALL_
const struct MHD_Action *
MHD_action_suspend (struct MHD_Request *request)
{
  struct MHD_Action *const restrict head_act = &(request->app_act.head_act);
  if (mhd_ACTION_NO_ACTION != head_act->act)
    return (const struct MHD_Action *) NULL;

  head_act->act = mhd_ACTION_SUSPEND;
  return head_act;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1) const struct MHD_Action *
MHD_action_from_response (struct MHD_Request *request,
                          struct MHD_Response *response)
{
  struct MHD_Action *const restrict head_act = &(request->app_act.head_act);
  if (mhd_ACTION_NO_ACTION != head_act->act)
    return (const struct MHD_Action *) NULL;
  if (NULL == response)
    return (const struct MHD_Action *) NULL;

  mhd_response_check_frozen_freeze (response);

  head_act->act = mhd_ACTION_RESPONSE;
  head_act->data.response = response;

  return head_act;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1) const struct MHD_Action *
MHD_action_process_upload (struct MHD_Request *request,
                           size_t large_buffer_size,
                           MHD_UploadCallback uc_full,
                           void *uc_full_cls,
                           MHD_UploadCallback uc_inc,
                           void *uc_inc_cls)
{
  struct MHD_Action *const restrict head_act = &(request->app_act.head_act);
  if (mhd_ACTION_NO_ACTION != head_act->act)
    return (const struct MHD_Action *) NULL;
  if (0 == large_buffer_size)
  {
    if (NULL != uc_full)
      return (const struct MHD_Action *) NULL;
    if (NULL == uc_inc)
      return (const struct MHD_Action *) NULL;
  }
  else
  {
    if (NULL == uc_full)
      return (const struct MHD_Action *) NULL;
  }

  head_act->act = mhd_ACTION_UPLOAD;
  head_act->data.upload.large_buffer_size = large_buffer_size;
  head_act->data.upload.full.cb = uc_full;
  head_act->data.upload.full.cls = uc_full_cls;
  head_act->data.upload.inc.cb = uc_inc;
  head_act->data.upload.inc.cls = uc_inc_cls;

  return head_act;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1) const struct MHD_Action *
MHD_action_post_processor (struct MHD_Request *request,
                           size_t pp_buffer_size,
                           size_t pp_stream_limit,
                           enum MHD_HTTP_PostEncoding enc,
                           MHD_PostDataReader reader,
                           void *reader_cls,
                           MHD_PostDataFinished done_cb,
                           void *done_cb_cls)
{
  struct MHD_Action *const restrict head_act =
    &(request->app_act.head_act);
  if (mhd_ACTION_NO_ACTION != head_act->act)
    return (const struct MHD_Action *) NULL;
  if (NULL == done_cb)
    return (const struct MHD_Action *) NULL;

  head_act->act = mhd_ACTION_POST_PROCESS;
  head_act->data.post_process.pp_buffer_size = pp_buffer_size;
  head_act->data.post_process.pp_stream_limit = pp_stream_limit;
  head_act->data.post_process.enc = enc;
  head_act->data.post_process.reader = reader;
  head_act->data.post_process.reader_cls = reader_cls;
  head_act->data.post_process.done_cb = done_cb;
  head_act->data.post_process.done_cb_cls = done_cb_cls;

  return head_act;
}


MHD_EXTERN_ MHD_FN_RETURNS_NONNULL_ MHD_FN_PAR_NONNULL_ALL_
const struct MHD_UploadAction *
MHD_upload_action_suspend (struct MHD_Request *request)
{
  struct MHD_UploadAction *const restrict upl_act =
    &(request->app_act.upl_act);
  if (mhd_UPLOAD_ACTION_NO_ACTION != upl_act->act)
    return (const struct MHD_UploadAction *) NULL;

  upl_act->act = mhd_UPLOAD_ACTION_SUSPEND;

  return upl_act;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1) const struct MHD_UploadAction *
MHD_upload_action_from_response (struct MHD_Request *request,
                                 struct MHD_Response *response)
{
  struct MHD_UploadAction *const restrict upl_act =
    &(request->app_act.upl_act);
  if (mhd_UPLOAD_ACTION_NO_ACTION != upl_act->act)
    return (const struct MHD_UploadAction *) NULL;

  mhd_response_check_frozen_freeze (response);

  upl_act->act = mhd_UPLOAD_ACTION_RESPONSE;
  upl_act->data.response = response;

  return upl_act;
}


MHD_EXTERN_ MHD_FN_RETURNS_NONNULL_ const struct MHD_UploadAction *
MHD_upload_action_continue (struct MHD_Request *request)
{
  struct MHD_UploadAction *const restrict upl_act =
    &(request->app_act.upl_act);
  if (mhd_UPLOAD_ACTION_NO_ACTION != upl_act->act)
    return (const struct MHD_UploadAction *) NULL;

  upl_act->act = mhd_UPLOAD_ACTION_CONTINUE;

  return upl_act;
}
