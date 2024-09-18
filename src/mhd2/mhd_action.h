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

#ifdef HAVE_POST_PARSER
#  include "http_post_enc.h"
#  include "mhd_bool.h"
#  include "mhd_post_result.h"
#endif


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
#ifdef HAVE_POST_PARSER
  ,
  /**
   * Process POST data clients upload by POST parser
   */
  mhd_ACTION_POST_PARSE
#endif /* HAVE_POST_PARSER */
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

#ifdef HAVE_POST_PARSER
#ifndef MHD_POST_DATA_READER_DEFINED

typedef const struct MHD_UploadAction *
(MHD_FN_PAR_NONNULL_ (1) MHD_FN_PAR_NONNULL_ (3) MHD_FN_PAR_NONNULL_ (4)
 MHD_FN_PAR_NONNULL_ (5) MHD_FN_PAR_NONNULL_ (6)
 *MHD_PostDataReader) (struct MHD_Request *req,
                       void *cls,
                       const struct MHD_String *name,
                       const struct MHD_StringNullable *filename,
                       const struct MHD_StringNullable *content_type,
                       const struct MHD_StringNullable *encoding,
                       size_t size,
                       const void *data,
                       uint_fast64_t off,
                       enum MHD_Bool final_data);

typedef const struct MHD_UploadAction *
(MHD_FN_PAR_NONNULL_ (1)
 *MHD_PostDataFinished) (struct MHD_Request *req,
                         void *cls,
                         enum MHD_PostParseResult parsing_result);

#define MHD_POST_DATA_READER_DEFINED 1
#endif /* ! MHD_POST_DATA_READER_DEFINED */


/**
 * The data for performing POST action
 */
struct mhd_PostParseActionData
{
  /**
   * The maximum size allowed for the buffers to parse the POST data.
   */
  size_t buffer_size;
  /**
   * The size of the field (in encoded form) above which values are not
   * buffered and incrementally "streamed"
   */
  size_t max_nonstream_size;
  /**
   * The data encoding to use,
   * #MHD_HTTP_POST_ENCODING_OTHER indicates automatic detection
   */
  enum MHD_HTTP_PostEncoding enc;
  /**
   * The callback function which process values in "streaming" way.
   * Can be NULL.
   */
  MHD_PostDataReader stream_reader;
  /**
   * The closure for the @a stream_reader
   */
  void *reader_cls;
  /**
   * The "final" callback, called after all POST data has been parsed.
   */
  MHD_PostDataFinished done_cb;
  /**
   * The closure for the @a done_cb
   */
  void *done_cb_cls;
};

#endif /* HAVE_POST_PARSER */

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

#ifdef HAVE_POST_PARSER
  /**
   * The data for the action #mhd_ACTION_POST_PARSE
   */
  struct mhd_PostParseActionData post_parse;
#endif /* HAVE_POST_PARSER */
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
