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
 * @file src/mhd2/mhd_action.h
 * @brief  The definition of the MHD_Action and MHD_UploadAction structures
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_ACTION_H
#define MHD_ACTION_H 1

#include "mhd_sys_options.h"

#include "sys_base_types.h"

#include "mhd_str_types.h"


/**
 * The type of the action requested by application
 */
enum mhd_ActionType
{
  /**
   * Action has not been set yet.
   */
  mhd_ACTION_NO_ACTION = 0
  ,
  /**
   * Start replying with the response
   */
  mhd_ACTION_RESPONSE
  ,
  /**
   * Process clients upload by application callback
   */
  mhd_ACTION_UPLOAD
  ,
  /**
   * Process clients upload by POST processor
   */
  mhd_ACTION_POST_PROCESS
  ,
  /**
   * Suspend requests (connection)
   */
  mhd_ACTION_SUSPEND
  ,
  /**
   * Hard close request with no response
   */
  mhd_ACTION_ABORT
};

/**
 * Check whether provided mhd_ActionType value is valid
 */
#define mhd_ACTION_IS_VALID(act) \
        ((mhd_ACTION_RESPONSE <= (act)) && (mhd_ACTION_ABORT >= (act)))


struct MHD_Response; /* forward declaration */
struct MHD_Request;  /* forward declaration */

#ifndef MHD_UPLOADCALLBACK_DEFINED

typedef const struct MHD_UploadAction *
(MHD_FN_PAR_NONNULL_ (2)  MHD_FN_PAR_INOUT_SIZE_ (4,3)
 *MHD_UploadCallback)(void *upload_cls,
                      struct MHD_Request *request,
                      size_t content_data_size,
                      void *content_data);

#define MHD_UPLOADCALLBACK_DEFINED 1
#endif /* ! MHD_UPLOADCALLBACK_DEFINED */

/**
 * Upload callback data
 */
struct mhd_UploadCallbackData
{
  /**
   * The callback
   */
  MHD_UploadCallback cb;

  /**
   * The closure for @a cb
   */
  void *cls;
};

/**
 * The data for upload callbacks
 */
struct mhd_UploadCallbacks
{
  /**
   * The size of the buffer for the @a full upload callback
   */
  size_t large_buffer_size;

  /**
   * The data for the callback that processes only complete upload
   */
  struct mhd_UploadCallbackData full;

  /**
   * The data for the callback that processes only incremental uploads
   */
  struct mhd_UploadCallbackData inc;
};

#ifndef MHD_POST_DATA_READER_DEFINED

typedef const struct MHD_UploadAction *
(*MHD_PostDataReader) (void *cls,
                       const struct MHD_String *name,
                       const struct MHD_String *filename,
                       const struct MHD_String *content_type,
                       const struct MHD_String *encoding,
                       const void *data,
                       uint_fast64_t off,
                       size_t size);


typedef const struct MHD_UploadAction *
(*MHD_PostDataFinished) (struct MHD_Request *req,
                         void *cls);

#define MHD_POST_DATA_READER_DEFINED 1
#endif /* ! MHD_POST_DATA_READER_DEFINED */

#ifndef MHD_HTTP_POSTENCODING_DEFINED

enum MHD_FIXED_ENUM_MHD_APP_SET_ MHD_HTTP_PostEncoding
{
  /**
   * No post encoding / broken data / unknown encoding
   */
  MHD_HTTP_POST_ENCODING_OTHER = 0
  ,
  /**
   * "application/x-www-form-urlencoded"
   * See https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#url-encoded-form-data
   * See https://url.spec.whatwg.org/#application/x-www-form-urlencoded
   * See https://datatracker.ietf.org/doc/html/rfc3986#section-2
   */
  MHD_HTTP_POST_ENCODING_FORM_URLENCODED = 1
  ,
  /**
   * "multipart/form-data"
   * See https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#multipart-form-data
   * See https://www.rfc-editor.org/rfc/rfc7578.html
   */
  MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA = 2
  ,
  /**
   * "text/plain"
   * Introduced by HTML5
   * See https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#plain-text-form-data
   * @warning Format is ambiguous. Do not use unless there is a very strong reason.
   */
  MHD_HTTP_POST_ENCODING_TEXT_PLAIN = 3
};


/** @} */ /* end of group postenc */

#define MHD_HTTP_POSTENCODING_DEFINED 1
#endif /* ! MHD_HTTP_POSTENCODING_DEFINED */


// TODO: correct and describe
struct mhd_PostProcessorActionData
{
  size_t pp_buffer_size;
  size_t pp_stream_limit; // FIXME: Remove? Duplicated with pp_buffer_size
  enum MHD_HTTP_PostEncoding enc;
  MHD_PostDataReader reader;
  void *reader_cls;
  MHD_PostDataFinished done_cb;
  void *done_cb_cls;
};

/**
 * The data for the application action
 */
union mhd_ActionData
{
  /**
   * The data for the action #mhd_ACTION_RESPONSE
   */
  struct MHD_Response *response;

  /**
   * The data for the action #mhd_ACTION_UPLOAD
   */
  struct mhd_UploadCallbacks upload;

  /**
   * The data for the action #mhd_ACTION_POST_PROCESS
   */
  struct mhd_PostProcessorActionData post_process;
};


/**
 * The action provided after reporting all headers to application
 */
struct MHD_Action
{
  /**
   * The action
   */
  enum mhd_ActionType act;

  /**
   * The data for the @a act action
   */
  union mhd_ActionData data;
};

/**
 * The type of the action requested by application
 */
enum mhd_UploadActionType
{
  /**
   * Action has not been set yet.
   */
  mhd_UPLOAD_ACTION_NO_ACTION = 0
  ,
  /**
   * Continue processing the upload
   */
  mhd_UPLOAD_ACTION_CONTINUE
  ,
  /**
   * Start replying with the response
   */
  mhd_UPLOAD_ACTION_RESPONSE
  ,
  /**
   * Suspend requests (connection)
   */
  mhd_UPLOAD_ACTION_SUSPEND
  ,
  /**
   * Hard close request with no response
   */
  mhd_UPLOAD_ACTION_ABORT
};

/**
 * Check whether provided mhd_UploadActionType value is valid
 */
#define mhd_UPLOAD_ACTION_IS_VALID(act) \
        ((mhd_UPLOAD_ACTION_CONTINUE <= (act)) && \
         (mhd_UPLOAD_ACTION_ABORT >= (act)))


/**
 * The data for the application action
 */
union mhd_UploadActionData
{
  /**
   * The data for the action #mhd_ACTION_RESPONSE
   */
  struct MHD_Response *response;
};

/**
 * The action provided when consuming client's upload
 */
struct MHD_UploadAction
{
  /**
   * The action
   */
  enum mhd_UploadActionType act;

  /**
   * The data for the @a act action
   */
  union mhd_UploadActionData data;
};

#endif /* ! MHD_ACTION_H */
