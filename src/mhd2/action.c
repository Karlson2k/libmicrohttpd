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
#include "response_destroy.h"

#ifdef MHD_UPGRADE_SUPPORT
#  include "upgrade_prep.h"
#endif

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
  if (NULL == response)
    return (const struct MHD_Action *) NULL;

  mhd_response_check_frozen_freeze (response);
  mhd_response_inc_use_count (response);

  if (mhd_ACTION_NO_ACTION != head_act->act)
  {
    mhd_response_dec_use_count (response);
    return (const struct MHD_Action *) NULL;
  }

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
MHD_action_parse_post (struct MHD_Request *request,
                       size_t buffer_size,
                       size_t max_nonstream_size,
                       enum MHD_HTTP_PostEncoding enc,
                       MHD_PostDataReader stream_reader,
                       void *reader_cls,
                       MHD_PostDataFinished done_cb,
                       void *done_cb_cls)
{
#ifdef HAVE_POST_PARSER
  struct MHD_Action *const restrict head_act =
    &(request->app_act.head_act);
  if (mhd_ACTION_NO_ACTION != head_act->act)
    return (const struct MHD_Action *) NULL;
  if (NULL == done_cb)
    return (const struct MHD_Action *) NULL;

  head_act->act = mhd_ACTION_POST_PARSE;
  head_act->data.post_parse.buffer_size = buffer_size;
  head_act->data.post_parse.max_nonstream_size = max_nonstream_size;
  head_act->data.post_parse.enc = enc;
  head_act->data.post_parse.stream_reader = stream_reader;
  head_act->data.post_parse.reader_cls = reader_cls;
  head_act->data.post_parse.done_cb = done_cb;
  head_act->data.post_parse.done_cb_cls = done_cb_cls;

  return head_act;
#else  /* ! HAVE_POST_PARSER */
  (void) request; (void) buffer_size; (void) max_nonstream_size;
  (void) enc; (void) stream_reader; (void) reader_cls;
  (void) done_cb; (void) done_cb_cls;
  return NULL;
#endif /* ! HAVE_POST_PARSER */
}


#ifdef MHD_UPGRADE_SUPPORT

MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_IN_SIZE_ (6,5) const struct MHD_Action *
MHD_action_upgrade (struct MHD_Request *MHD_RESTRICT request,
                    const char *MHD_RESTRICT upgrade_hdr_value,
                    MHD_UpgradeHandler upgrade_handler,
                    void *upgrade_handler_cls,
                    size_t num_headers,
                    const struct MHD_NameValueCStr *MHD_RESTRICT headers)
{
  struct MHD_Action *const restrict head_act =
    &(request->app_act.head_act);
  if (mhd_ACTION_NO_ACTION != head_act->act)
    return (const struct MHD_Action *) NULL;
  if (NULL == upgrade_handler)
    return (const struct MHD_Action *) NULL;
  if (request->cntn.cntn_size != request->cntn.recv_size)
    return (const struct MHD_Action *) NULL; /* Cannot start "Upgrade" if any content upload is pending */

  if (! mhd_upgrade_prep_for_action (request,
                                     upgrade_hdr_value,
                                     num_headers,
                                     headers,
                                     false))
    return (const struct MHD_Action *) NULL;

  head_act->act = mhd_ACTION_UPGRADE;
  head_act->data.upgrd.cb = upgrade_handler;
  head_act->data.upgrd.cb_cls = upgrade_handler_cls;

  return head_act;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1)
MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_IN_SIZE_ (6,5) const struct MHD_UploadAction *
MHD_upload_action_upgrade (
  struct MHD_Request *MHD_RESTRICT request,
  const char *MHD_RESTRICT upgrade_hdr_value,
  MHD_UpgradeHandler upgrade_handler,
  void *upgrade_handler_cls,
  size_t num_headers,
  const struct MHD_NameValueCStr *MHD_RESTRICT headers)
{
  struct MHD_UploadAction *const restrict upl_act =
    &(request->app_act.upl_act);
  if (mhd_UPLOAD_ACTION_NO_ACTION != upl_act->act)
    return (const struct MHD_UploadAction *) NULL;
  if (NULL == upgrade_handler)
    return (const struct MHD_UploadAction *) NULL;
  if (request->cntn.cntn_size != request->cntn.recv_size)
    return (const struct MHD_UploadAction *) NULL; /* Cannot start "Upgrade" if any content upload is pending */

  if (! mhd_upgrade_prep_for_action (request,
                                     upgrade_hdr_value,
                                     num_headers,
                                     headers,
                                     true))
    return (const struct MHD_UploadAction *) NULL;

  upl_act->act = mhd_UPLOAD_ACTION_UPGRADE;
  upl_act->data.upgrd.cb = upgrade_handler;
  upl_act->data.upgrd.cb_cls = upgrade_handler_cls;

  return upl_act;
}


#endif /* MHD_UPGRADE_SUPPORT */


MHD_EXTERN_ MHD_FN_PAR_NONNULL_ALL_
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
  if (NULL == response)
    return (const struct MHD_UploadAction *) NULL;

  mhd_response_check_frozen_freeze (response);
  mhd_response_inc_use_count (response);

  if (mhd_UPLOAD_ACTION_NO_ACTION != upl_act->act)
  {
    mhd_response_dec_use_count (response);
    return (const struct MHD_UploadAction *) NULL;
  }

  upl_act->act = mhd_UPLOAD_ACTION_RESPONSE;
  upl_act->data.response = response;

  return upl_act;
}


MHD_EXTERN_
MHD_FN_PAR_NONNULL_ (1) const struct MHD_UploadAction *
MHD_upload_action_continue (struct MHD_Request *request)
{
  struct MHD_UploadAction *const restrict upl_act =
    &(request->app_act.upl_act);
  if (mhd_UPLOAD_ACTION_NO_ACTION != upl_act->act)
    return (const struct MHD_UploadAction *) NULL;

  upl_act->act = mhd_UPLOAD_ACTION_CONTINUE;

  return upl_act;
}
