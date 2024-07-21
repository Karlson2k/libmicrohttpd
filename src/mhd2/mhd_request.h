/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2022-2024 Evgeny Grin (Karlson2k)

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
 * @file src/mhd2/mhd_request.h
 * @brief  The definition of the request data structures
 * @author Karlson2k (Evgeny Grin)
 *
 * Data structures in this header are used when parsing client's request
 */

#ifndef MHD_REQUEST_H
#define MHD_REQUEST_H 1

#include "mhd_sys_options.h"
#include "sys_base_types.h"
#include "sys_bool_type.h"
#include "mhd_public_api.h"

#include "mhd_dlinked_list.h"

#include "http_prot_ver.h"
#include "http_method.h"
#include "mhd_action.h"
#include "mhd_buffer.h"


/**
 * The action set by the application
 */
struct mhd_ApplicationAction
{
  /**
   * The action after header reporting
   */
  struct MHD_Action head_act;
  /**
   * The action during upload processing
   */
  struct MHD_UploadAction upl_act;
};

/**
 * The request line processing data
 */
struct MHD_RequestLineProcessing
{
  /**
   * The position of the next character to be processed
   */
  size_t proc_pos;
  /**
   * The number of empty lines skipped
   */
  unsigned int skipped_empty_lines;
  /**
   * The position of the start of the current/last found whitespace block,
   * zero if not found yet.
   */
  size_t last_ws_start;
  /**
   * The position of the next character after the last known whitespace
   * character in the current/last found whitespace block,
   * zero if not found yet.
   */
  size_t last_ws_end;
  /**
   * The pointer to the request target.
   * The request URI will be formed based on it.
   */
  char *rq_tgt;
  /**
   * The pointer to the first question mark in the @a rq_tgt.
   */
  char *rq_tgt_qmark;
  /**
   * The number of whitespace characters in the request URI
   */
  size_t num_ws_in_uri;
};

/**
 * The request header processing data
 */
struct MHD_HeaderProcessing
{
  /**
   * The position of the last processed character
   */
  size_t proc_pos;

  /**
   * The position of the first whitespace character in current contiguous
   * whitespace block.
   * Zero when no whitespace found or found non-whitespace character after
   * whitespace.
   * Must be zero, if the current character is not whitespace.
   */
  size_t ws_start;

  /**
   * Indicates that end of the header (field) name found.
   * Must be false until the first colon in line is found.
   */
  bool name_end_found;

  /**
   * The length of the header name.
   * Must be zero until the first colon in line is found.
   * Name always starts at zero position.
   */
  size_t name_len;

  /**
   * The position of the first character of the header value.
   * Zero when the first character has not been found yet.
   */
  size_t value_start;

  /**
   * Line starts with whitespace.
   * It's meaningful only for the first line, as other lines should be handled
   * as "folded".
   */
  bool starts_with_ws;
};

/**
 * The union of request line and header processing data
 */
union MHD_HeadersProcessing
{
  /**
   * The request line processing data
   */
  struct MHD_RequestLineProcessing rq_line;

  /**
   * The request header processing data
   */
  struct MHD_HeaderProcessing hdr;
};


/**
 * The union of text staring point and the size of the text
 */
union MHD_StartOrSize
{
  /**
   * The starting point of the text.
   * Valid when the text is being processed and the end of the text
   * is not yet determined.
   */
  const char *start;
  /**
   * The size of the text.
   * Valid when the text has been processed and the end of the text
   * is known.
   */
  size_t size;
};

struct mhd_RequestField; /* forward declarations */

mhd_DLINKEDL_LINKS_DEF (mhd_RequestField);

/**
 * Header, footer, or cookie for HTTP request.
 */
struct mhd_RequestField
{
  /**
   * The field data
   */
  struct MHD_NameValueKind field;

  /**
   * Headers are kept in a double-linked list.
   */
  mhd_DLNKDL_LINKS (mhd_RequestField,fields);
};

mhd_DLINKEDL_LIST_DEF (mhd_RequestField);


/**
 * The request content data
 */
struct mhd_ReqContentData
{
  /**
   * The pointer to the large buffer
   * Must be NULL if large buffer is not allocated.
   */
  struct mhd_Buffer lbuf;

  /**
   * The total size of the request content.
   * #MHD_SIZE_UNKNOWN if the size is not yet known (chunked upload).
   */
  uint_fast64_t cntn_size;

  /**
   * The size of the received content
   */
  uint_fast64_t recv_size;

  /**
   * The size of the processed content
   */
  uint_fast64_t proc_size;
};


/**
 * Request-specific values.
 *
 * Meaningful for the current request only.
 */
struct MHD_Request
{
  /**
   * Linked list of parsed headers.
   */
  mhd_DLNKDL_LIST (mhd_RequestField,fields);

  /**
   * The action set by the application
   */
  struct mhd_ApplicationAction app_act;

  /**
   * The request content data
   */
  struct mhd_ReqContentData cntn;

  /**
   * Set to true if request is too large to be handled
   */
  bool too_large;

  /**
   * HTTP version string (i.e. http/1.1).  Allocated
   * in pool.
   */
  const char *version;

  /**
   * HTTP protocol version as enum.
   */
  enum MHD_HTTP_ProtocolVersion http_ver;

  /**
   * Request method.  Should be GET/POST/etc.  Allocated in pool.
   */
  const char *method;

  /**
   * The request method as enum.
   */
  enum mhd_HTTP_Method http_mthd;

  /**
   * Requested URL, the part before '?' (excluding parameters).  Allocated
   * in pool.
   */
  const char *url;

  /**
   * The length of the @a url in characters, not including the terminating zero.
   */
  size_t url_len;

  /**
   * The original length of the request target.
   */
  size_t req_target_len;

  /**
   * Number of bytes we had in the HTTP header, set once we
   * pass #MHD_CONNECTION_HEADERS_RECEIVED.
   * This includes the request line, all request headers, the header section
   * terminating empty line, with all CRLF (or LF) characters.
   */
  size_t header_size;

  /**
   * The union of the size of all request field lines (headers) and
   * the starting point of the first request field line (the first header).
   * Until #MHD_CONNECTION_HEADERS_RECEIVED the @a start member is valid,
   * staring with #MHD_CONNECTION_HEADERS_RECEIVED the @a size member is valid.
   * The size includes CRLF (or LR) characters, but does not include
   * the terminating empty line.
   */
  union MHD_StartOrSize field_lines;

  /**
   * Are we receiving with chunked encoding?
   * This will be set to #MHD_YES after we parse the headers and
   * are processing the body with chunks.
   * After we are done with the body and we are processing the footers;
   * once the footers are also done, this will be set to #MHD_NO again
   * (before the final call to the handler).
   * It is used only for requests, chunked encoding for response is
   * indicated by @a rp_props.
   */
  bool have_chunked_upload;

  /**
   * If we are receiving with chunked encoding, where are we right
   * now?
   * Set to 0 if we are waiting to receive the chunk size;
   * otherwise, this is the size of the current chunk.
   * A value of zero is also used when we're at the end of the chunks.
   */
  uint_fast64_t current_chunk_size;

  /**
   * If we are receiving with chunked encoding, where are we currently
   * with respect to the current chunk (at what offset / position)?
   */
  uint_fast64_t current_chunk_offset;

  /**
   * We allow the main application to associate some pointer with the
   * HTTP request, which is passed to each #MHD_AccessHandlerCallback
   * and some other API calls.  Here is where we store it.  (MHD does
   * not know or care what it is).
   */
  void *app_context;

  /**
   * Did we ever call the "default_handler" on this request?
   * This flag determines if we have called the #MHD_OPTION_NOTIFY_COMPLETED
   * handler when the request finishes.
   */
  bool app_aware;

  /**
   * Number of bare CR characters that were replaced with space characters
   * in the request line or in the headers (field lines).
   */
  size_t num_cr_sp_replaced;

  /**
   * The number of header lines skipped because they have no colon
   */
  size_t skipped_broken_lines;

  /**
   * The data of the request line / request headers processing
   */
  union MHD_HeadersProcessing hdrs;
};


#endif /* ! MHD_REQUEST_H */
