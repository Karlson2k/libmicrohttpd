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
 * @file src/mhd2/mhd_response.h
 * @brief  The definition of the MHD_Response type and related structures
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_RESPONSE_H
#define MHD_RESPONSE_H 1

#include "mhd_sys_options.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include "mhd_public_api.h"

#include "mhd_dlinked_list.h"
#include "mhd_str_types.h"

#include "mhd_iovec.h"

#ifdef MHD_USE_THREADS
#  include "mhd_locks.h"
#endif

#include "mhd_atomic_counter.h"


struct ResponseOptions; /* forward declaration */

struct mhd_ResponseHeader; /* forward declaration */

mhd_DLINKEDL_LINKS_DEF (mhd_ResponseHeader);

/**
 * Response header / field
 */
struct mhd_ResponseHeader
{
  /**
   * The name of the header / field
   */
  struct MHD_String name;

  /**
   * The value of the header / field
   */
  struct MHD_String value;

  /**
   * The links to other headers
   */
  mhd_DLNKDL_LINKS (mhd_ResponseHeader,headers);
};

/**
 * The type of content
 */
enum mhd_ResponseContentDataType
{
  mhd_RESPONSE_CONTENT_DATA_INVALID = 0
  ,
  mhd_RESPONSE_CONTENT_DATA_BUFFER
  ,
  mhd_RESPONSE_CONTENT_DATA_IOVEC
  ,
  mhd_RESPONSE_CONTENT_DATA_FILE
  ,
  mhd_RESPONSE_CONTENT_DATA_CALLBACK
};

/**
 * I/O vector response data
 */
struct mhd_ResponseIoVec
{
  /**
   * The copy of array of iovec elements.
   * Must be freed!
   */
  mhd_iovec *iov;

  /**
   * The number of elements in the @a iov array
   */
  size_t cnt;
};

/**
 * The file data for the the response
 */
struct mhd_ResponseFD
{
  /**
   * The file description of the response
   */
  int fd;

  /**
   * The offset in the file of the response content
   */
  uint_fast64_t offset;

  /**
   * Indicate that @a fd is a pipe
   */
  bool is_pipe;

#ifdef MHD_USE_SENDFILE
  /**
   * Use 'sendfile()' function for the @a FD
   * Initially 'true' (except for pipes) but can be flipped to 'false' if
   * sendfile() cannot handle this file.
   */
  volatile bool use_sf;
#endif
};

/**
 * Dynamic response data
 */
struct mhd_ResponseDynamic
{
  /**
   * The callback for the content data
   */
  MHD_DynamicContentCreator cb;
  /**
   * The closure for the @a cb
   */
  void *cls;
};

/**
 * The response content data
 */
union mhd_ResponseContent
{
  /**
   * The fixed unmodifiable data.
   * 'unsigned char' pointer is used to simplify individual ranges addressing.
   */
  const unsigned char *restrict buf;

  /**
   * The I/O vector data
   */
  struct mhd_ResponseIoVec iovec;

  /**
   * The file data for the the response
   */
  struct mhd_ResponseFD file;

  /**
   * Dynamic response data
   */
  struct mhd_ResponseDynamic dyn;
};

/**
 * The data of the free/cleanup callback
 */
struct mhd_FreeCbData
{
  /**
   * The Free/Cleanup callback
   */
  MHD_FreeCallback cb;

  /**
   * The closure for the @a cb
   */
  void *cls;
};


struct mhd_ResponseReuseData
{
  /**
   * Indicate that response could be used more than one time
   */
  volatile bool reusable;

  /**
   * The number of active uses of the response.
   * Used only when @a reusable is 'true'.
   * When number reached zero, the response is destroyed.
   */
  struct mhd_AtomicCounter counter;

#ifdef MHD_USE_THREADS
  /**
   * The mutex for @a settings access.
   * Used only when @a reusable is 'true'.
   */
  mhd_mutex settings_lock;
#endif /* MHD_USE_THREADS */
};

struct mhd_ResponseConfiguration
{
  /**
   * Response have undefined content
   * Must be used only when response content (even zero-size) is not allowed.
   */
  bool head_only;

  /**
   * If set to 'true' then the chunked encoding must be used (if allowed
   * by HTTP version).
   * If 'false' then chunked encoding must not be used.
   */
  bool chunked;

  /**
   * If 'true', "Connection: close" header must be always used
   */
  bool close_forced;

  /**
   * Use "HTTP/1.0" in the reply header
   * @a chunked is 'false' if this flag set.
   * @a close_forced is 'true' is this flag set.
   */
  bool mode_1_0;

  /**
   * The (possible incorrect) content length is provided by application
   */
  bool cnt_len_by_app;

  /**
   * Response has "Date:" header
   */
  bool has_hdr_date; // TODO: set the member

  /**
   * Response has "Connection:" header
   */
  bool has_hdr_conn; // TODO: set the member

  /**
   * Response is internal-only error response
   */
  bool int_err_resp;
};

/**
 * Special data for internal error responses
 */
struct mhd_ResponseInternalErrData
{
  /**
   * The length of the @a spec_hdr
   */
  size_t spec_hdr_len;
  /**
   * The special header string.
   * The final CRLF is not included.
   * Must be deallocated if not NULL.
   */
  char *spec_hdr;
};

#ifndef NDEBUG
struct mhd_ResponseDebug
{
  bool is_internal;
};
#endif

mhd_DLINKEDL_LIST_DEF (mhd_ResponseHeader);

// TODO: Group members in structs

struct MHD_Response
{
  /**
   * The response HTTP status code
   */
  enum MHD_HTTP_StatusCode sc;

  /**
   * The size of the response.
   * #MHD_SIZE_UNKNOWN if size is undefined
   */
  uint_fast64_t cntn_size;

  /**
   * The type of the content data
   */
  enum mhd_ResponseContentDataType cntn_dtype;

  /**
   * The data of the content of the response
   */
  union mhd_ResponseContent cntn;

  /**
   * The data of the free/cleanup callback
   */
  struct mhd_FreeCbData free;

  /**
   * Configuration data of the response
   */
  struct mhd_ResponseConfiguration cfg;

  /**
   * If response is "frozen" then response data cannot be changed.
   * The use counter for re-usable responses is the exception and can be
   * changed when "frozen".
   */
  volatile bool frozen;

  /**
   * The re-use parameters
   */
  struct mhd_ResponseReuseData reuse;

  /**
   * The settings, before the response is @a frozen
   */
  struct ResponseOptions *restrict settings;

  /**
   * The double linked list of the response headers
   */
  mhd_DLNKDL_LIST (mhd_ResponseHeader,headers);

  /**
   * Special data for internal error responses
   */
  struct mhd_ResponseInternalErrData special_resp;

  #ifndef NDEBUG
  struct mhd_ResponseDebug dbg;
#endif
};

#endif /* ! MHD_RESPONSE_H */
