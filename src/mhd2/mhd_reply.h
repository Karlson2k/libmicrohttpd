/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2021-2024 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/mhd_reply.h
 * @brief  The definition of the working reply data
 * @author Karlson2k (Evgeny Grin)
 *
 * Data structures in this header are used when responding to client's request.
 * Do not be confused with terms "response" and "reply" using in MHD code.
 * The "MHD_Response" is an connection-independent object that have all
 * data required to form a respond.
 * The "MHD_Reply" is working connection-specific data used to format
 * the respond based on provided data in "MHD_Response".
 */

#ifndef MHD_REPLY_H
#define MHD_REPLY_H 1

#include "mhd_sys_options.h"

#include "sys_bool_type.h"

#include "mhd_dcc_action.h"

#include "mhd_iovec.h"

struct MHD_Response; /* forward declaration */

/**
 * Reply-specific properties.
 */
struct MHD_Reply_Properties
{
#ifdef _DEBUG
  bool set; /**< Indicates that other members are set and valid */
#endif /* _DEBUG */
  bool use_reply_body_headers; /**< Use reply body-specific headers */
  bool send_reply_body; /**< Send reply body (can be zero-sized) */
  bool chunked; /**< Use chunked encoding for reply */
  bool end_by_closing; /**< Signal end of content (only) by closing connection */
};

/**
 * The location of the reply content
 */
enum MHD_FIXED_ENUM_ mhd_ReplyContentLocation
{
  /**
   * Reply content is absent
   */
  mhd_REPLY_CNTN_LOC_NOWHERE = 0
  ,
  /**
   * Reply content is in the response buffer
   */
  mhd_REPLY_CNTN_LOC_RESP_BUF
  ,
  /**
   * Reply content is in the connection buffer
   */
  mhd_REPLY_CNTN_LOC_CONN_BUF
  ,
  /**
   * Reply content is in the vector data
   */
  mhd_REPLY_CNTN_LOC_IOV
  ,
  /**
   * Reply content is in the file, to be used with sendfile() function
   */
  mhd_REPLY_CNTN_LOC_FILE
};


/**
 * Reply-specific values.
 *
 * Meaningful for the current reply only.
 */
struct MHD_Reply
{
  /**
   * The action provided by application when content is dynamically created.
   * Used only when mhd_RESPONSE_CONTENT_DATA_CALLBACK == response->cntn_dtype
   */
  struct MHD_DynamicContentCreatorAction app_act;

  /**
   * The context provided for application callback for dynamic content.
   * Used only when mhd_RESPONSE_CONTENT_DATA_CALLBACK == response->cntn_dtype
   */
  struct MHD_DynamicContentCreatorContext app_act_ctx;

  /**
   * Response to transmit (initially NULL).
   */
  struct MHD_Response *response;

  /**
   * The "ICY" response.
   * Reply begins with the SHOUTcast "ICY" line instead of "HTTP".
   */
  bool responseIcy;

  /**
   * Current rest position in the actual content (should be 0 while
   * sending headers).
   * When sending buffers located in the connection buffers, it is updated
   * when the data copied to the buffers. In other cases it is updated when
   * data is actually sent.
   */
  uint_fast64_t rsp_cntn_read_pos;

  /**
   * The copy of iov response.
   * Valid if iovec response is used.
   * Updated during send.
   * Members are allocated in the pool.
   */
  struct mhd_iovec_track resp_iov;

  /**
   * The location of the reply content
   */
  enum mhd_ReplyContentLocation cntn_loc;

  /**
   * Reply-specific properties
   */
  struct MHD_Reply_Properties props;
};

#endif /* ! MHD_REPLY_H */
