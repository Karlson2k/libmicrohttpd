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
 * @file src/mhd2/post_parser_funcs.c
 * @brief  The implementation of internal POST parser functions
 * @author Karlson2k (Evgeny Grin)
 */


#include "mhd_sys_options.h"

#include "post_parser_funcs.h"

#include "mhd_post_parser.h"

#include <string.h>

#include "mhd_action.h"
#include "mhd_request.h"
#include "mhd_connection.h"
#include "mhd_daemon.h"

#include "mhd_str_macros.h"

#include "mhd_str.h"
#include "daemon_logger.h"
#include "stream_funcs.h"
#include "stream_process_request.h"

#include "daemon_funcs.h"
#include "request_get_value.h"

/**
 * The result of 'multipart/form-data' processing
 */
enum MHD_FIXED_ENUM_ mhd_MPartDetectResult
{
  /**
   * Sting processed successfully, boundary detected
   */
  mhd_MPART_DET_OK = 0
  ,
  /**
   * Error processing string, the error result is set
   */
  mhd_MPART_DET_ERROR_SET
  ,
  /**
   * The string is not 'multipart/form-data' header
   */
  mhd_MPART_DET_NO_MPART
};


/**
 * Process 'Content-Type:' header value as 'multipart/form-data' data to
 * prepare POST parsing data, including setting correct 'boundary' value
 * @param c the stream to use
 * @param h_cnt_tp the 'Content-Type:' header value string
 * @return 'mhd_MPART_DET_OK' if processed successfully and boundary has been
 *                             detected and set,
 *         'mhd_MPART_DET_ERROR_SET' is has some error in processing which
 *                                    resulted in specific error set in
 *                                    the stream,
 *         'mhd_MPART_DET_NO_MPART' is string is not 'multipart/form-data' data
 */
static MHD_FN_PAR_NONNULL_ALL_ enum mhd_MPartDetectResult
process_mpart_header (struct MHD_Connection *restrict c,
                      const struct MHD_String *restrict h_cnt_tp)
{
  static const struct MHD_String mpart_token =
    mhd_MSTR_INIT ("multipart/form-data");
  static const struct MHD_String mpart_bound_par =
    mhd_MSTR_INIT ("boundary");
  struct mhd_BufferConst mpart_bound;
  bool mpart_bound_quoted;
  enum mhd_StingStartsWithTokenResult res;

  mhd_assert (NULL != h_cnt_tp->cstr);

  res = mhd_str_starts_with_token_req_param (h_cnt_tp,
                                             &mpart_token,
                                             &mpart_bound_par,
                                             &mpart_bound,
                                             &mpart_bound_quoted);

  if (mhd_STR_STARTS_W_TOKEN_NO_TOKEN == res)
    return mhd_MPART_DET_NO_MPART;

  if (mhd_STR_STARTS_W_TOKEN_HAS_TOKEN_BAD_FORMAT == res)
  {
    mhd_LOG_PRINT (c->daemon, \
                   MHD_SC_REQ_POST_PARSE_FAILED_HEADER_MISFORMED, \
                   mhd_LOG_FMT ("The request POST data cannot be parsed " \
                                "because 'Content-Type: " \
                                "multipart/form-data' header is " \
                                "misformed: %.*s%s"), \
                   (int) ((h_cnt_tp->len <= 127) ? h_cnt_tp->len : 127),
                   h_cnt_tp->cstr,
                   (h_cnt_tp->len <= 127) ? "" : "...");
    c->rq.u_proc.post.parse_result =
      MHD_POST_PARSE_RES_FAILED_HEADER_MISFORMED;
    return mhd_MPART_DET_ERROR_SET;
  }

  mhd_assert (mhd_STR_STARTS_W_TOKEN_HAS_TOKEN == res);

  if (0 == mpart_bound.size)
  {
    mhd_LOG_MSG (c->daemon, \
                 MHD_SC_REQ_POST_PARSE_FAILED_HEADER_NO_BOUNDARY, \
                 "The request POST data cannot be parsed because " \
                 "'Content-Type: multipart/form-data' header has " \
                 "no 'boundary' parameter value.");
    c->rq.u_proc.post.parse_result =
      MHD_POST_PARSE_RES_FAILED_HEADER_NO_BOUNDARY;
    return mhd_MPART_DET_ERROR_SET;
  }

  mhd_assert (NULL != mpart_bound.data);

  if (! mpart_bound_quoted)
  {
    c->rq.u_proc.post.enc = MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA;
    c->rq.u_proc.post.e_d.m_form.bound = mpart_bound;
  }
  else
  {
    char *buf;

    mhd_assert (2 <= mpart_bound.size); /* At least one char and at least one '\' */

    buf = mhd_stream_alloc_memory (c, mpart_bound.size);
    if (NULL == buf)
    {
      /* It is very low probability that pool would not have memory just
       * to held the small boundary string. While it could be possible
       * to allocate memory from "large buffer", it would over-complicate
       * code here and at freeing part. */
      mhd_LOG_MSG (c->daemon, MHD_SC_REQ_POST_PARSE_FAILED_NO_POOL_MEM, \
                   "The request POST data cannot be parsed because " \
                   "there is not enough pool memory.");
      c->rq.u_proc.post.parse_result = MHD_POST_PARSE_RES_FAILED_NO_POOL_MEM;
      return mhd_MPART_DET_ERROR_SET;
    }
    c->rq.u_proc.post.enc = MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA;
    c->rq.u_proc.post.e_d.m_form.bound.size =
      mhd_str_unquote (mpart_bound.data,
                       mpart_bound.size,
                       buf);
    mhd_assert (0 != c->rq.u_proc.post.e_d.m_form.bound.size);
  }
  return mhd_MPART_DET_OK;
}


/**
 * Detect used POST encoding and 'boundary' for 'multipart/form-data'.
 * @param c the stream to use
 * @return 'true' if detected successfully,
 *         'false' if POST encoding cannot be detected
 */
static MHD_FN_PAR_NONNULL_ (1) bool
detect_post_enc (struct MHD_Connection *restrict c)
{
  const struct MHD_StringNullable *h_cnt_tp;

  mhd_assert (MHD_CONNECTION_BODY_RECEIVING > c->state);

  h_cnt_tp = mhd_request_get_value_st (&(c->rq),
                                       MHD_VK_HEADER,
                                       MHD_HTTP_HEADER_CONTENT_TYPE);
  if (NULL == h_cnt_tp)
  {
    mhd_LOG_MSG (c->daemon, MHD_SC_REQ_POST_PARSE_FAILED_NO_CNTN_TYPE, \
                 "The request POST data cannot be parsed because " \
                 "the request has no 'Content-Type:' header and no " \
                 "explicit POST encoding is set.");
    c->rq.u_proc.post.parse_result = MHD_POST_PARSE_RES_FAILED_NO_CNTN_TYPE;
    return false;  /* The "Content-Type:" is not defined by the client */
  }

  mhd_assert (NULL != h_cnt_tp->cstr);

  if (mhd_str_equal_caseless_n_st ("application/x-www-form-urlencoded",
                                   h_cnt_tp->cstr,
                                   h_cnt_tp->len))
  {
    c->rq.u_proc.post.enc = MHD_HTTP_POST_ENCODING_FORM_URLENCODED;
    return true;
  }

  if (1)
  {
    enum mhd_MPartDetectResult res;

    res = process_mpart_header (c,
                                (const struct MHD_String *) (const void *)
                                h_cnt_tp);

    if (mhd_MPART_DET_OK == res)
      return true;

    if (mhd_MPART_DET_ERROR_SET == res)
      return false;

    mhd_assert (mhd_MPART_DET_NO_MPART == res);
  }

  if (1)
  {
    static const struct MHD_String txt_tkn = mhd_MSTR_INIT ("text/plain");
    struct MHD_String h_cnt_tp_copy = {h_cnt_tp->len, h_cnt_tp->cstr};
    mhd_assert (NULL != h_cnt_tp->cstr);

    if (mhd_str_starts_with_token_opt_param (&h_cnt_tp_copy,
                                             &txt_tkn))
    {
      c->rq.u_proc.post.enc = MHD_HTTP_POST_ENCODING_TEXT_PLAIN;
      return true;
    }
  }
  mhd_LOG_MSG (c->daemon, \
               MHD_SC_REQ_POST_PARSE_FAILED_UNKNOWN_CNTN_TYPE, \
               "The request POST data cannot be parsed because " \
               "'Content-Type' header value is unknown or unsupported.");
  c->rq.u_proc.post.parse_result =
    MHD_POST_PARSE_RES_FAILED_UNKNOWN_CNTN_TYPE;
  return false;
}


/**
 * Detect 'boundary' for 'multipart/form-data' POST encoding.
 * @param c the stream to use
 * @return 'true' if succeed,
 *         'false' if failed and error result is set
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
detect_mpart_boundary_from_the_header (struct MHD_Connection *restrict c)
{
  const struct MHD_StringNullable *h_cnt_tp;
  enum mhd_MPartDetectResult res;

  mhd_assert (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA == \
              c->rq.app_act.head_act.data.post_parse.enc);

  h_cnt_tp = mhd_request_get_value_st (&(c->rq),
                                       MHD_VK_HEADER,
                                       MHD_HTTP_HEADER_CONTENT_TYPE);
  if (NULL == h_cnt_tp)
  {
    mhd_LOG_MSG (c->daemon, MHD_SC_REQ_POST_PARSE_FAILED_NO_CNTN_TYPE, \
                 "The request POST data cannot be parsed because " \
                 "'multipart/form-data' requires 'boundary' parameter, but " \
                 "the request has no 'Content-Type:' header.");
    c->rq.u_proc.post.parse_result = MHD_POST_PARSE_RES_FAILED_NO_CNTN_TYPE;
    return false;
  }

  mhd_assert (NULL != h_cnt_tp->cstr);

  res = process_mpart_header (c,
                              (const struct MHD_String *) (const void *)
                              h_cnt_tp);

  if (mhd_MPART_DET_OK == res)
    return true;

  if (mhd_MPART_DET_NO_MPART == res)
  {
    mhd_LOG_MSG (c->daemon, MHD_SC_REQ_POST_PARSE_FAILED_HEADER_NOT_MPART, \
                 "The request POST data cannot be parsed because " \
                 "'multipart/form-data' requires 'boundary' parameter, but " \
                 "the request has no 'Content-Type: multipart/form-data' " \
                 "header.");
    c->rq.u_proc.post.parse_result = MHD_POST_PARSE_RES_FAILED_HEADER_NOT_MPART;
    return false;
  }

  mhd_assert (mhd_MPART_DET_ERROR_SET == res);
  return false;
}


/**
 * Reset field parsing data for "application/x-www-form-urlencoded"
 * @param pdata the parsing data
 */
static MHD_FN_PAR_NONNULL_ (1) void
reset_parse_field_data_urlenc (struct mhd_PostParserData *pdata)
{
  mhd_assert (MHD_HTTP_POST_ENCODING_FORM_URLENCODED == pdata->enc);
  memset (&(pdata->e_d.u_enc), 0, sizeof(pdata->e_d.u_enc));
  pdata->field_start = 0;
}


/**
 * Initial reset field parsing data for "multipart/form-data"
 * @param pdata the parsing data
 */
static MHD_FN_PAR_NONNULL_ (1) void
reset_parse_field_data_mpart_init (struct mhd_PostParserData *pdata)
{
  mhd_assert (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA == pdata->enc);
  memset (&(pdata->e_d.m_form.f), 0, sizeof(pdata->e_d.m_form.f));
  pdata->e_d.m_form.st = mhd_POST_MPART_ST_NOT_STARTED;
  pdata->e_d.m_form.line_start = mhd_POST_INVALID_POS;
  pdata->e_d.m_form.delim_check_start = mhd_POST_INVALID_POS;
  mhd_assert (NULL != pdata->e_d.m_form.bound.data);
  mhd_assert (0 != pdata->e_d.m_form.bound.size);
  mhd_assert (NULL == memchr (pdata->e_d.m_form.bound.data, '\r', \
                              pdata->e_d.m_form.bound.size));
  mhd_assert (NULL == memchr (pdata->e_d.m_form.bound.data, '\n', \
                              pdata->e_d.m_form.bound.size));
  pdata->field_start = 0;
}


/**
 * Reset field parsing data for "multipart/form-data" after processing
 * previous field
 * @param pdata the parsing data
 * @param final 'true' if last field was "closed" by the "final" delimiter
 */
static MHD_FN_PAR_NONNULL_ (1) void
reset_parse_field_data_mpart_cont (struct mhd_PostParserData *pdata,
                                   bool final)
{
  mhd_assert (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA == pdata->enc);
  memset (&(pdata->e_d.m_form.f), 0, sizeof(pdata->e_d.m_form.f));
  pdata->e_d.m_form.st = final ?
                         mhd_POST_MPART_ST_EPILOGUE :
                         mhd_POST_MPART_ST_PART_START;
  pdata->field_start = 0;
}


/**
 * Reset field parsing data for "text/plain"
 * @param pdata the parsing data
 */
static MHD_FN_PAR_NONNULL_ (1) void
reset_parse_field_data_text (struct mhd_PostParserData *pdata)
{
  mhd_assert (MHD_HTTP_POST_ENCODING_TEXT_PLAIN == pdata->enc);
  memset (&(pdata->e_d.text), 0, sizeof(pdata->e_d.text));
  pdata->field_start = 0;
}


/**
 * Finish initialisation of data for POST parsing
 * @param c the stream to use
 */
static MHD_FN_PAR_NONNULL_ (1) void
init_post_parse_data (struct MHD_Connection *restrict c)
{
  struct mhd_PostParserData *const pdata =
    &(c->rq.u_proc.post);

  mhd_assert (mhd_ACTION_POST_PARSE == c->rq.app_act.head_act.act);
  mhd_assert (MHD_HTTP_POST_ENCODING_OTHER != \
              c->rq.u_proc.post.enc);
  mhd_assert (0 == pdata->lbuf_used);

  pdata->lbuf_limit = c->rq.app_act.head_act.data.post_parse.buffer_size;

  switch (pdata->enc)
  {
  case MHD_HTTP_POST_ENCODING_FORM_URLENCODED:
    reset_parse_field_data_urlenc (pdata);
    break;
  case MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA:
    reset_parse_field_data_mpart_init (pdata);
    break;
  case MHD_HTTP_POST_ENCODING_TEXT_PLAIN:
    reset_parse_field_data_text (pdata);
    break;
  case MHD_HTTP_POST_ENCODING_OTHER:
  default:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
  }
}


MHD_INTERNAL
MHD_FN_PAR_NONNULL_ (1) bool
mhd_stream_prepare_for_post_parse (struct MHD_Connection *restrict c)
{
  mhd_assert (mhd_ACTION_POST_PARSE == c->rq.app_act.head_act.act);
  if (MHD_HTTP_POST_ENCODING_OTHER ==
      c->rq.app_act.head_act.data.post_parse.enc)
  {
    if (! detect_post_enc (c))
    {
      mhd_assert (MHD_POST_PARSE_RES_OK != c->rq.u_proc.post.parse_result);
      c->discard_request = true;
      c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
      return false;
    }
  }
  else if (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA ==
           c->rq.app_act.head_act.data.post_parse.enc)
  {
    if (! detect_mpart_boundary_from_the_header (c))
    {
      mhd_assert (MHD_POST_PARSE_RES_OK != c->rq.u_proc.post.parse_result);
      c->discard_request = true;
      c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
      return false;
    }
  }
  else
    c->rq.u_proc.post.enc = c->rq.app_act.head_act.data.post_parse.enc;

  mhd_assert (MHD_HTTP_POST_ENCODING_OTHER != \
              c->rq.u_proc.post.enc);
  mhd_assert ((MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA != \
               c->rq.u_proc.post.enc) || \
              (0 != c->rq.u_proc.post.e_d.m_form.bound.size));

  init_post_parse_data (c);

  return true;
}


/**
 * Allocate memory from "large shared buffer" for POST parsing
 * @param c the stream to use
 * @param alloc_size the size to allocate
 * @param[out] buf the buffer to allocate
 * @return 'true' if succeed,
 *         'false' otherwise
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_INOUT_ (3) bool
get_lbuf_fixed_size (struct MHD_Connection *restrict c,
                     size_t alloc_size,
                     struct mhd_Buffer *restrict buf)
{
  mhd_assert (mhd_ACTION_POST_PARSE == c->rq.app_act.head_act.act);
  mhd_assert (0 == buf->size);
  mhd_assert (NULL == buf->data);

  if (alloc_size > c->rq.u_proc.post.lbuf_limit)
    return false;

  return mhd_daemon_get_lbuf (c->daemon,
                              alloc_size,
                              buf);
}


/**
 * Grow the allocated memory from "large shared buffer" for POST parsing
 * @param c the stream to use
 * @param grow_size the size to grow
 * @param[in,out] buf the buffer to grow
 * @return 'true' if succeed,
 *         'false' otherwise
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_INOUT_ (3) bool
grow_lbuf_fixed_size (struct MHD_Connection *restrict c,
                      size_t grow_size,
                      struct mhd_Buffer *restrict buf)
{
  mhd_assert (mhd_ACTION_POST_PARSE == c->rq.app_act.head_act.act);
  mhd_assert (0 != buf->size);
  mhd_assert (NULL != buf->data);
  mhd_assert (c->rq.u_proc.post.lbuf_limit >= buf->size);

  if (buf->size + grow_size > c->rq.u_proc.post.lbuf_limit)
    return false;

  return mhd_daemon_grow_lbuf (c->daemon,
                               grow_size,
                               buf);
}


/**
 * Test whether current incomplete value must be provided to the "stream"
 * reader.
 * @param c the connection to use
 * @param field_cur_size the current size of the current field
 * @return 'true' if the value must be provided via the "stream" reader,
 *         'false' otherwise.
 */
MHD_static_inline_ MHD_FN_PURE_ MHD_FN_PAR_NONNULL_ALL_ bool
is_value_streaming_needed (struct MHD_Connection *restrict c,
                           size_t field_cur_size)
{
  struct mhd_PostParseActionData *const p_par =
    &(c->rq.app_act.head_act.data.post_parse);
  struct mhd_PostParserData *const p_data = &(c->rq.u_proc.post);

  if (NULL == p_par->stream_reader)
  {
    mhd_assert (0 == p_data->value_off);
    return false; /* No value streaming possible */
  }

  if (0 != p_data->value_off)
    return true; /* Part of the value has been already provided to "stream"
                    reader, the rest of the value should be provided
                    in the same way */

  return (p_par->max_nonstream_size < field_cur_size);
}


/**
 * Add parsed POST field to the list of request's fields
 * @param c the stream to use
 * @param name the name of the field
 * @param filename the filename of the field
 * @param content_type the "Content-Type:" of the field
 * @param transfer_encoding the "Transfer-Encoding:" of the field
 * @param value the value of the field
 * @return 'true' if succeed,
 *         'false' if memory allocation failed (no pool memory in the stream)
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
add_parsed_post_field (struct MHD_Connection *restrict c,
                       struct mhd_PositionAndLength *restrict name,
                       struct mhd_PositionAndLength *restrict filename,
                       struct mhd_PositionAndLength *restrict content_type,
                       struct mhd_PositionAndLength *restrict transfer_encoding,
                       struct mhd_PositionAndLength *restrict value)
{
  struct mhd_RequestPostField *pfield;

  mhd_assert ((0 != filename->pos) || (0 == filename->len));
  mhd_assert ((0 != content_type->pos) || (0 == content_type->len));
  mhd_assert ((0 != transfer_encoding->pos) || \
              (0 == transfer_encoding->len));
  mhd_assert ((0 != value->pos) || (0 == value->len));

  pfield = (struct mhd_RequestPostField *)
           mhd_stream_alloc_memory (c,
                                    sizeof (struct mhd_RequestPostField));
  if (NULL == pfield)
    return false;

  pfield->field.name = *name;
  pfield->field.value = *value;
  pfield->field.filename = *filename;
  pfield->field.content_type = *content_type;
  pfield->field.transfer_encoding = *transfer_encoding;

  mhd_DLINKEDL_INIT_LINKS (pfield, post_fields);

  mhd_DLINKEDL_INS_LAST (&(c->rq), pfield, post_fields);

  return true;
}


MHD_static_inline_ MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_IN_ (1)
MHD_FN_PAR_OUT_ (10) MHD_FN_PAR_OUT_ (11)
MHD_FN_PAR_OUT_ (12) MHD_FN_PAR_OUT_ (13) void
make_post_strings_from_buf_and_indices (const char *restrict buf,
                                        size_t name_start,
                                        size_t name_len,
                                        size_t filename_start,
                                        size_t filename_len,
                                        size_t cntn_type_start,
                                        size_t cntn_type_len,
                                        size_t enc_start,
                                        size_t enc_len,
                                        struct MHD_String *name,
                                        struct MHD_StringNullable *filename,
                                        struct MHD_StringNullable *content_type,
                                        struct MHD_StringNullable *encoding)
{
  name->len = name_len;
  name->cstr = buf + name_start;

  if (0 != filename_start)
  {
    filename->len = filename_len;
    filename->cstr = buf + filename_start;
  }
  else
  {
    filename->len = 0;
    filename->cstr = NULL;
  }
  if (0 != cntn_type_start)
  {
    content_type->len = cntn_type_len;
    content_type->cstr = buf + cntn_type_start;
  }
  else
  {
    content_type->len = 0;
    content_type->cstr = NULL;
  }
  if (0 != enc_start)
  {
    encoding->len = enc_len;
    encoding->cstr = buf + enc_start;
  }
  else
  {
    encoding->len = 0;
    encoding->cstr = NULL;
  }
}


/**
 * Process new full parsed POST field
 * @param c the stream to use
 * @param buf the buffer, where the data is
 * @param pfield_next_pos the pointer to variable holding index of
 *                        the next field to be parsed
 * @param pdata_size the pointer to variable holding the size of the data
 * @param field_start the start of the current field in the @a buf
 * @param name_start the start of the name of the field in the @a buf
 * @param name_len the length of the name, not including mandatory terminating
 *                 zero
 * @param filename_start the start of the filename of the field in the @a buf,
 *                       zero if no filename is provided
 * @param filename_len the length of the filename, not including mandatory
 *                     terminating zero
 * @param cntn_type_start the start of the Content-Type value of the field in
 *                        the @a buf, zero if no Content-Type is provided
 * @param cntn_type_len the length of the Content-Type value, not including
 *                      mandatory terminating zero
 * @param enc_start the start of the Content-Encoding value of the field in
 *                  the @a buf, zero if no Content-Encoding is provided
 * @param enc_len the length of the Content-Encoding value, not including
 *                    mandatory terminating zero
 * @param value_start the start of the field value in the @a buf, zero if
 *                    no value is provided
 * @param value_len the length of the field value, not including mandatory
 *                  terminating zero
 * @return 'true' if stream state has been changed,
 *         'false' to continue parsing
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
process_complete_field_all (struct MHD_Connection *restrict c,
                            char *restrict buf,
                            size_t *restrict pfield_next_pos,
                            size_t *restrict pdata_size,
                            size_t field_start,
                            size_t name_start,
                            size_t name_len,
                            size_t filename_start,
                            size_t filename_len,
                            size_t cntn_type_start,
                            size_t cntn_type_len,
                            size_t enc_start,
                            size_t enc_len,
                            size_t value_start,
                            size_t value_len)
{
  struct mhd_PostParseActionData *const p_par =
    &(c->rq.app_act.head_act.data.post_parse);
  struct mhd_PostParserData *const p_data = &(c->rq.u_proc.post);

  mhd_assert (mhd_ACTION_POST_PARSE == c->rq.app_act.head_act.act);

  mhd_assert ((0 == filename_start) || \
              (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA == p_data->enc));
  mhd_assert ((0 == cntn_type_start) || \
              (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA == p_data->enc));
  mhd_assert ((0 == enc_start) || \
              (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA == p_data->enc));

  mhd_assert (MHD_CONNECTION_REQ_RECV_FINISHED >= c->state);
  mhd_assert (value_start + value_len <= *pfield_next_pos);
  mhd_assert ((MHD_CONNECTION_FULL_REQ_RECEIVED <= c->state) || \
              (value_start + value_len < *pfield_next_pos));
  mhd_assert (*pfield_next_pos <= *pdata_size);
  mhd_assert ((name_start + name_len < value_start) || \
              (0 == value_start));
  mhd_assert (value_start + value_len <= *pfield_next_pos);
  mhd_assert ((MHD_CONNECTION_FULL_REQ_RECEIVED <= c->state) || \
              (name_start + name_len < *pfield_next_pos));
  mhd_assert ((filename_start + filename_len < value_start) || \
              (0 == value_start));
  mhd_assert (filename_start + filename_len <= *pfield_next_pos);
  mhd_assert ((cntn_type_start + cntn_type_len < value_start) || \
              (0 == value_start));
  mhd_assert (cntn_type_start + cntn_type_len <= *pfield_next_pos);
  mhd_assert ((enc_start + enc_len < value_start) || \
              (0 == value_start));
  mhd_assert (enc_start + enc_len <= *pfield_next_pos);
  mhd_assert (field_start <= name_start);
  mhd_assert ((field_start <= filename_start) || (0 == filename_start));
  mhd_assert ((field_start <= cntn_type_start) || (0 == cntn_type_start));
  mhd_assert ((field_start <= enc_start) || (0 == enc_start));
  mhd_assert ((field_start <= value_start) || (0 == value_start));
  mhd_assert ((0 != filename_start) || (0 == filename_len));
  mhd_assert ((0 != cntn_type_start) || (0 == cntn_type_len));
  mhd_assert ((0 != enc_start) || (0 == enc_len));
  mhd_assert ((0 != value_start) || (0 == value_len));

  p_data->some_data_provided = true;

  if (is_value_streaming_needed (c, (*pfield_next_pos - field_start)))
  {
    bool res;
    const struct MHD_UploadAction *act;
    const size_t field_size = *pfield_next_pos - field_start;
    struct MHD_String name;
    struct MHD_StringNullable filename;
    struct MHD_StringNullable content_type;
    struct MHD_StringNullable encoding;

    make_post_strings_from_buf_and_indices (buf,
                                            name_start,
                                            name_len,
                                            filename_start,
                                            filename_len,
                                            cntn_type_start,
                                            cntn_type_len,
                                            enc_start,
                                            enc_len,
                                            &name,
                                            &filename,
                                            &content_type,
                                            &encoding);

    act = p_par->stream_reader (&(c->rq),
                                p_par->reader_cls,
                                &name,
                                &filename,
                                &content_type,
                                &encoding,
                                value_len,
                                buf + value_start,
                                p_data->value_off,
                                MHD_YES);
    p_data->some_data_provided = true;
    res = mhd_stream_process_upload_action (c, act, false);
    if (c->suspended)
      return true;
    p_data->value_off = 0;
    if (*pdata_size > *pfield_next_pos)
    {
      memmove (buf + field_start,
               buf + *pfield_next_pos,
               *pdata_size - *pfield_next_pos);
    }
    *pfield_next_pos -= field_size;
    *pdata_size -= field_size;
    return res;
  }
  else
  {
    struct mhd_PositionAndLength name_i;
    struct mhd_PositionAndLength filename_i;
    struct mhd_PositionAndLength content_type_i;
    struct mhd_PositionAndLength encoding_i;
    struct mhd_PositionAndLength value_i;

    name_i.pos = name_start;
    name_i.len = name_len;
    filename_i.pos = filename_start;
    filename_i.len = filename_len;
    content_type_i.pos = cntn_type_start;
    content_type_i.len = cntn_type_len;
    encoding_i.pos = enc_start;
    encoding_i.len = enc_len;
    value_i.pos = value_start;
    value_i.len = value_len;

    if (! add_parsed_post_field (c,
                                 &name_i,
                                 &filename_i,
                                 &content_type_i,
                                 &encoding_i,
                                 &value_i))
    {
      c->discard_request = true;
      c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
      mhd_LOG_MSG (c->daemon, MHD_SC_REQ_POST_PARSE_FAILED_NO_POOL_MEM, \
                   "The request POST data cannot be parsed completely " \
                   "because there is not enough pool memory.");
      p_data->parse_result = MHD_POST_PARSE_RES_FAILED_NO_POOL_MEM;
      return true;
    }

    p_data->some_data_provided = true;
  }

  return false; /* Continue parsing */
}


/**
 * Process new full parsed POST field
 * @param c the stream to use
 * @param buf the buffer, where the data is
 * @param pfield_next_pos the pointer to variable holding index of
 *                        the next field to be parsed
 * @param pdata_size the pointer to variable holding the size of the data
 * @param field_start the start of the current field in the @a buf
 * @param name_start the start of the name of the field in the @a buf
 * @param name_len the length of the name, not including mandatory terminating
 *                 zero
 * @param value_start the start of the field value in the @a buf, zero if
 *                    no value is provided
 * @param value_len the length of the field value, not including mandatory
 *                  terminating zero
 * @return 'true' if stream state has been changed,
 *         'false' to continue parsing
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
process_complete_field (struct MHD_Connection *restrict c,
                        char *restrict buf,
                        size_t *restrict pfield_next_pos,
                        size_t *restrict pdata_size,
                        size_t field_start,
                        size_t name_start,
                        size_t name_len,
                        size_t value_start,
                        size_t value_len)
{
  mhd_assert (MHD_CONNECTION_REQ_RECV_FINISHED >= c->state);
  mhd_assert (value_start + value_len <= *pfield_next_pos);
  mhd_assert ((MHD_CONNECTION_FULL_REQ_RECEIVED <= c->state) || \
              (value_start + value_len < *pfield_next_pos));
  mhd_assert ((name_start + name_len < value_start) || \
              (0 == value_start));
  mhd_assert (name_start + name_len <= *pfield_next_pos);
  mhd_assert ((MHD_CONNECTION_FULL_REQ_RECEIVED <= c->state) || \
              (name_start + name_len < *pfield_next_pos));
  mhd_assert (field_start <= name_start);
  mhd_assert ((field_start <= value_start) || (0 == value_start));

  mhd_assert (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA != \
              c->rq.u_proc.post.enc);

  return process_complete_field_all (c,
                                     buf,
                                     pfield_next_pos,
                                     pdata_size,
                                     field_start,
                                     name_start,
                                     name_len,
                                     0, 0, 0, 0, 0, 0,
                                     value_start,
                                     value_len);
}


/**
 * Process the part of the POST value.
 *
 * The part of the value are be provided for "streaming" processing by
 * the application callback and removed from the buffer (the remaining of
 * the data in the buffer is shifted backward).
 * The function must be called only when streaming is the partial value is
 * needed.
 *
 * @param c the connection to use
 * @param buf the pointer to the buffer
 * @param pnext_pos the position of the next character to be processed
 *                  in the buffer
 * @param pdata_size the size of the data in the buffer
 * @param name_start the position of the "name", must be zero-terminated
 * @param name_len the length of the "name", not including zero-termination
 * @param filename_start the position of the filename, zero if not
 *                       provided / set
 * @param filename_len the length of the filename
 * @param cntn_type_start the position of field "Content-Type" value, zero
 *                        if not provided / set
 * @param cntn_type_len the length of the field "Content-Type" value
 * @param enc_start the position of the field "Content-Encoding" value, zero
 *                        if not provided / set
 * @param enc_len the length of  the field "Content-Encoding" value
 * @param part_value_start the position of partial value data, does not
 *                         need to be zero-terminated
 * @param part_value_len the length of the partial value data
 * @return 'true' if connection/stream state has been changed,
 *         'false' indicates the need to continuation of POST data parsing
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
process_partial_value_all (struct MHD_Connection *restrict c,
                           char *restrict buf,
                           size_t *restrict pnext_pos,
                           size_t *restrict pdata_size,
                           size_t name_start,
                           size_t name_len,
                           size_t filename_start,
                           size_t filename_len,
                           size_t cntn_type_start,
                           size_t cntn_type_len,
                           size_t enc_start,
                           size_t enc_len,
                           size_t part_value_start,
                           size_t part_value_len)
{
  struct mhd_PostParseActionData *const p_par =
    &(c->rq.app_act.head_act.data.post_parse);
  struct mhd_PostParserData *const p_data = &(c->rq.u_proc.post);
  struct MHD_String name;
  struct MHD_StringNullable filename;
  struct MHD_StringNullable content_type;
  struct MHD_StringNullable encoding;
  const struct MHD_UploadAction *act;
  bool res;

  mhd_assert (MHD_CONNECTION_REQ_RECV_FINISHED >= c->state);
  mhd_assert (part_value_start + part_value_len <= *pnext_pos);
  mhd_assert (0 != part_value_start);
  mhd_assert (0 != part_value_len);
  mhd_assert (name_start + name_len < *pnext_pos);
  mhd_assert (filename_start + filename_len < part_value_start);
  mhd_assert (filename_start + filename_len < *pnext_pos);
  mhd_assert (cntn_type_start + cntn_type_len < part_value_start);
  mhd_assert (cntn_type_start + cntn_type_len < *pnext_pos);
  mhd_assert (enc_start + enc_len < part_value_start);
  mhd_assert (enc_start + enc_len < *pnext_pos);
  mhd_assert ((0 != filename_start) || (0 == filename_len));
  mhd_assert ((0 != cntn_type_start) || (0 == cntn_type_len));
  mhd_assert ((0 != enc_start) || (0 == enc_len));
  mhd_assert (NULL != p_par->stream_reader);

  make_post_strings_from_buf_and_indices (buf,
                                          name_start,
                                          name_len,
                                          filename_start,
                                          filename_len,
                                          cntn_type_start,
                                          cntn_type_len,
                                          enc_start,
                                          enc_len,
                                          &name,
                                          &filename,
                                          &content_type,
                                          &encoding);

  act = p_par->stream_reader (&(c->rq),
                              p_par->reader_cls,
                              &name,
                              &filename,
                              &content_type,
                              &encoding,
                              part_value_len,
                              buf + part_value_start,
                              p_data->value_off,
                              MHD_NO);

  p_data->some_data_provided = true;

  res = mhd_stream_process_upload_action (c, act, false);
  if (c->suspended)
    return true;

  p_data->value_off += part_value_len;
  if (*pdata_size > *pnext_pos)
  {
    memmove (buf + part_value_start,
             buf + part_value_start + part_value_len,
             part_value_len);
  }
  *pnext_pos -= part_value_len;
  *pdata_size -= part_value_len;
  return res;
}


/**
 * Process the part of the POST value.
 * The part of the value are be provided for "streaming" processing by
 * the application callback and removed from the buffer (the remaining of
 * the data in the buffer is shifted backward).
 * The function must be called only when streaming is the partial value is
 * needed.
 * @param c the connection to use
 * @param buf the pointer to the buffer
 * @param pnext_pos the position of the next character to be processed
 *                  in the buffer
 * @param pdata_size the size of the data in the buffer
 * @param name_start the position of the "name", must be zero-terminated
 * @param name_len the length of the "name", not including zero-termination
 * @param part_value_start the position of partial value data, does not
 *                         need to be zero-terminated
 * @param part_value_len the length of the partial value data
 * @return 'true' if connection/stream state has been changed,
 *         'false' indicates the need to continuation of POST data parsing
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
process_partial_value (struct MHD_Connection *restrict c,
                       char *restrict buf,
                       size_t *restrict pnext_pos,
                       size_t *restrict pdata_size,
                       size_t name_start,
                       size_t name_len,
                       size_t part_value_start,
                       size_t part_value_len)
{
  mhd_assert (MHD_CONNECTION_REQ_RECV_FINISHED >= c->state);
  mhd_assert (part_value_start + part_value_len <= *pnext_pos);
  mhd_assert (name_start + name_len < part_value_start);
  mhd_assert (0 != part_value_start);
  mhd_assert (0 != part_value_len);
  mhd_assert (name_start + name_len < *pnext_pos);


  mhd_assert (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA != \
              c->rq.u_proc.post.enc);

  return process_partial_value_all (c,
                                    buf,
                                    pnext_pos,
                                    pdata_size,
                                    name_start,
                                    name_len,
                                    0, 0, 0, 0, 0, 0,
                                    part_value_start,
                                    part_value_len);
}


/**
 * Parse "application/x-www-form-urlencoded" data
 * @param c the stream to use
 * @param pdata_size the pointer to variable holding the size of the data in
 *                   the @a buf
 * @param buf the buffer with the data
 * @return 'true' if stream state changed,
 *         'false' to continue parsing
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_INOUT_ (2) MHD_FN_PAR_INOUT_ (3) bool
parse_post_urlenc (struct MHD_Connection *restrict c,
                   size_t *restrict pdata_size,
                   char *restrict buf)
{
  struct mhd_PostParserData *const p_data = &(c->rq.u_proc.post);
  struct mhd_PostParserUrlEncData *const uf = &(p_data->e_d.u_enc); /**< the current "url-enc" field */
  size_t i;

  mhd_assert (MHD_HTTP_POST_ENCODING_FORM_URLENCODED == c->rq.u_proc.post.enc);
  mhd_assert (MHD_POST_PARSE_RES_OK == p_data->parse_result);
  mhd_assert (! c->discard_request);
  mhd_assert (p_data->next_parse_pos < *pdata_size);

  if ((mhd_POST_UENC_ST_VALUE == uf->st) &&
      (0 != uf->value_len))
  {
    /* The 'value' was partially decoded, but not processed because application
     * asked for 'suspend' action */
    mhd_assert (NULL != c->rq.app_act.head_act.data.post_parse.stream_reader);
    if (process_partial_value (c,
                               buf,
                               &p_data->next_parse_pos,
                               pdata_size,
                               uf->name_idx,
                               uf->name_len,
                               uf->value_idx,
                               uf->value_len))
      return true;
    uf->value_len = 0;
  }

  i = p_data->next_parse_pos;
  while (*pdata_size > i)
  {
    switch (uf->st)
    {
    case mhd_POST_UENC_ST_NOT_STARTED:
      mhd_assert (0 == p_data->field_start);
      mhd_assert (0 == p_data->value_off);
      p_data->field_start = i;
      uf->name_idx = i;
      uf->last_pct_idx = mhd_POST_INVALID_POS;
      uf->st = mhd_POST_UENC_ST_NAME;
    /* Intentional fall-through */
    case mhd_POST_UENC_ST_NAME:
      do /* Fast local loop */
      {
        if ('+' == buf[i])
          buf[i] = ' ';
        else if ('%' == buf[i])
          uf->last_pct_idx = i;
        else if ('=' == buf[i])
        {
          uf->st = mhd_POST_UENC_ST_AT_EQ;
          break;
        }
        else if ('&' == buf[i])
        {
          uf->st = mhd_POST_UENC_ST_AT_AMPRSND;
          break;
        }
      } while (*pdata_size > ++i);
      mhd_assert ((*pdata_size == i) || \
                  (mhd_POST_UENC_ST_AT_EQ == uf->st) || \
                  (mhd_POST_UENC_ST_AT_AMPRSND == uf->st) );
      continue;
    case mhd_POST_UENC_ST_AT_EQ:
      mhd_assert (i > uf->name_idx);
      mhd_assert (0 == uf->name_len);
      mhd_assert (uf->last_pct_idx >= p_data->field_start);
      mhd_assert (uf->last_pct_idx >= uf->name_idx);
      mhd_assert ((uf->last_pct_idx == mhd_POST_INVALID_POS) || \
                  (uf->last_pct_idx < i));
      mhd_assert (0 == uf->value_len);
      if (uf->last_pct_idx != mhd_POST_INVALID_POS)
        uf->name_len = mhd_str_pct_decode_lenient_n (buf + uf->name_idx,
                                                     i - uf->name_idx,
                                                     buf + uf->name_idx,
                                                     i - uf->name_idx,
                                                     NULL);
      else
        uf->name_len = i - uf->name_idx;
      buf[uf->name_idx + uf->name_len] = 0; /* Zero-terminate the name */

      uf->st = mhd_POST_UENC_ST_EQ_FOUND;
      ++i; /* Process the next char */
      continue; /* Check whether the next char is available */
    case mhd_POST_UENC_ST_EQ_FOUND:
      mhd_assert (0 == p_data->value_off);
      mhd_assert (0 == uf->value_idx);
      mhd_assert (0 == uf->value_len);
      mhd_assert (0 != i && "the 'value' should follow the 'name'");
      uf->last_pct_idx = mhd_POST_INVALID_POS;
      uf->value_idx = i;
      uf->st = mhd_POST_UENC_ST_VALUE;
    /* Intentional fall-through */
    case mhd_POST_UENC_ST_VALUE:
      do /* Fast local loop */
      {
        if ('+' == buf[i])
          buf[i] = ' ';
        else if ('%' == buf[i])
          uf->last_pct_idx = i;
        else if ('&' == buf[i])
        {
          uf->st = mhd_POST_UENC_ST_AT_AMPRSND;
          break;
        }
      } while (*pdata_size > ++i);
      mhd_assert ((*pdata_size == i) || \
                  (mhd_POST_UENC_ST_AT_AMPRSND == uf->st));
      continue;
    case mhd_POST_UENC_ST_AT_AMPRSND:
      mhd_assert (0 == uf->value_len);
      mhd_assert ((uf->last_pct_idx == mhd_POST_INVALID_POS) || \
                  (uf->last_pct_idx < i));
      mhd_assert ((uf->last_pct_idx == mhd_POST_INVALID_POS) || \
                  ((uf->name_idx + uf->name_len) < i));
      if (0 != uf->value_idx)
      {
        /* Have 'name' and 'value' */
        if (uf->last_pct_idx != mhd_POST_INVALID_POS)
          uf->value_len = mhd_str_pct_decode_lenient_n (buf + uf->value_idx,
                                                        i - uf->value_idx,
                                                        buf + uf->value_idx,
                                                        i - uf->value_idx,
                                                        NULL);
        else
          uf->value_len = i - uf->value_idx;
        buf[uf->value_idx + uf->value_len] = 0; /* Zero-terminate the value */
      }
      else
      {
        /* Have 'name' only (without any 'value') */
        if (uf->last_pct_idx != mhd_POST_INVALID_POS)
          uf->name_len = mhd_str_pct_decode_lenient_n (buf + uf->name_idx,
                                                       i - uf->name_idx,
                                                       buf + uf->name_idx,
                                                       i - uf->name_idx,
                                                       NULL);
        else
          uf->name_len = i - uf->name_idx;
        buf[uf->name_idx + uf->name_len] = 0; /* Zero-terminate the name */
      }
      uf->st = mhd_POST_UENC_ST_FULL_FIELD_FOUND;
    /* Intentional fall-through */
    case mhd_POST_UENC_ST_FULL_FIELD_FOUND:
      ++i; /* Consume current character,
              advance to the next char to be checked */
      if (process_complete_field (c,
                                  buf,
                                  &i,
                                  pdata_size,
                                  p_data->field_start,
                                  uf->name_idx,
                                  uf->name_len,
                                  uf->value_idx,
                                  uf->value_len))
      {
        if (c->suspended)
          --i; /* Go back to the same position */
        else
          reset_parse_field_data_urlenc (p_data);
        p_data->next_parse_pos = i;
        return true;
      }
      mhd_assert (*pdata_size >= i);
      reset_parse_field_data_urlenc (p_data);
      continue; /* Process the next char */
    default:
      mhd_assert (0 && "Impossible value");
      MHD_UNREACHABLE_;
      break;
    }
    mhd_assert (0 && "Should be unreachable");
    MHD_UNREACHABLE_;
    break;
  }

  mhd_assert (*pdata_size == i);

  mhd_assert (mhd_POST_UENC_ST_AT_EQ != uf->st);
  mhd_assert (mhd_POST_UENC_ST_AT_AMPRSND != uf->st);
  mhd_assert (mhd_POST_UENC_ST_FULL_FIELD_FOUND != uf->st);
  mhd_assert ((mhd_POST_UENC_ST_VALUE != uf->st) || \
              (0 == uf->value_len));

  mhd_assert (*pdata_size == i);

  if ((mhd_POST_UENC_ST_VALUE == uf->st) &&
      (i != uf->value_idx) && /* Encoded value position must be larger then zero */
      is_value_streaming_needed (c, i - p_data->field_start))
  {
    size_t len_of_value_part;
    if (uf->last_pct_idx != mhd_POST_INVALID_POS)
    {
      mhd_assert (uf->last_pct_idx < i);
      mhd_assert (uf->last_pct_idx >= uf->value_idx);

      if (2 >= (i - uf->last_pct_idx))
        i = uf->last_pct_idx;  /* The last percent-encoded character is incomplete */

      len_of_value_part =
        mhd_str_pct_decode_lenient_n (buf + uf->value_idx,
                                      i - uf->value_idx,
                                      buf + uf->value_idx,
                                      i - uf->value_idx,
                                      NULL);
    }
    else
      len_of_value_part = i - uf->value_idx;

    if (0 != len_of_value_part)
    {
      bool proc_res;

      proc_res =
        process_partial_value (c,
                               buf,
                               &i,
                               pdata_size,
                               uf->name_idx,
                               uf->name_len,
                               uf->value_idx,
                               len_of_value_part);

      /* Reset position of last '%' char: it was already decoded or
       * 'i' points to it and it will be processed again next time */
      uf->last_pct_idx = mhd_POST_INVALID_POS;

      if (proc_res)
      {
        if (c->suspended)
          uf->value_len = len_of_value_part; /* Indicate that value has been
                                                partially decoded and needs
                                                to be "streamed" again */
        p_data->next_parse_pos = i;
        return true;
      }
    }
  }

  p_data->next_parse_pos = i;
  return false; /* Continue parsing */
}


/**
 * Parse "multipart/form-data" data
 * @param c the stream to use
 * @param pdata_size the pointer to variable holding the size of the data in
 *                   the @a buf
 * @param buf the buffer with the data
 * @return 'true' if stream state changed,
 *         'false' to continue parsing
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_INOUT_ (2) MHD_FN_PAR_INOUT_ (3) bool
parse_post_mpart (struct MHD_Connection *restrict c,
                  size_t *restrict pdata_size,
                  char *restrict buf)
{
  const int discp_lvl = c->daemon->req_cfg.strictnees;
  const bool bare_lf_as_crlf = (-2 >= discp_lvl); /* Bare LF termination is dangerous when used in "multipart/form-data" */
  struct mhd_PostParserData *const p_data = &(c->rq.u_proc.post);
  struct mhd_PostParserMPartFormData *const mf = &(p_data->e_d.m_form); /**< the current "form-data" parsing details */
  size_t i;

  mhd_assert (NULL != mf->bound.data);
  mhd_assert (NULL == memchr (mf->bound.data, '\r', mf->bound.size));
  mhd_assert (NULL == memchr (mf->bound.data, '\n', mf->bound.size));
  mhd_assert (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA == \
              c->rq.u_proc.post.enc);
  mhd_assert (MHD_POST_PARSE_RES_OK == p_data->parse_result);
  mhd_assert (mhd_POST_MPART_ST_FORMAT_ERROR != mf->st);
  mhd_assert (! c->discard_request);
  mhd_assert (p_data->next_parse_pos < *pdata_size);

  i = p_data->next_parse_pos;
  while (*pdata_size > i)
  {
    switch (mf->st)
    {
    case mhd_POST_MPART_ST_BACK_TO_PREAMBL:
      mhd_assert (mhd_POST_INVALID_POS != mf->delim_check_start);
      mf->delim_check_start = mhd_POST_INVALID_POS;
      mf->line_start = mhd_POST_INVALID_POS;
      mf->st = mhd_POST_MPART_ST_PREAMBL;
    /* Intentional fall-through */
    case mhd_POST_MPART_ST_PREAMBL:
      mhd_assert (0 == p_data->field_start);
      mhd_assert (0 == p_data->value_off);
      mhd_assert (mhd_POST_INVALID_POS == mf->delim_check_start);
      mhd_assert (mhd_POST_INVALID_POS == mf->line_start);
      do /* Fast local loop */
      {
        if ('\r' == buf[i])
        {
          mf->st = mhd_POST_MPART_ST_PREAMBL_CR_FOUND;
          ++i; /* Go to the next char */
          break;
        }
        else if ('\n' == buf[i] && bare_lf_as_crlf)
        {
          mf->st = mhd_POST_MPART_ST_PREAMBL_LINE_START;
          ++i; /* Go to the next char */
          break;
        }
      } while (*pdata_size > ++i);
      mhd_assert ((*pdata_size == i) || \
                  (mhd_POST_MPART_ST_PREAMBL_CR_FOUND == mf->st) || \
                  (mhd_POST_MPART_ST_PREAMBL_LINE_START == mf->st) );
      continue;
    case mhd_POST_MPART_ST_PREAMBL_CR_FOUND:
      mhd_assert (mhd_POST_INVALID_POS != mf->delim_check_start);
      mhd_assert (mhd_POST_INVALID_POS == mf->line_start);
      if ('\n' == buf[i])
      {
        mf->st = mhd_POST_MPART_ST_PREAMBL_LINE_START;
        ++i;
      }
      else
      {
        mf->delim_check_start = mhd_POST_INVALID_POS;
        mf->st = mhd_POST_MPART_ST_PREAMBL;
      }
      continue;
    case mhd_POST_MPART_ST_NOT_STARTED:
      mhd_assert (0 == p_data->field_start);
      mhd_assert (0 == p_data->value_off);
      mf->delim_check_start = i;
    /* Intentional fall-through */
    case mhd_POST_MPART_ST_PREAMBL_LINE_START:
      mhd_assert (mhd_POST_INVALID_POS != mf->delim_check_start);
      mhd_assert (mhd_POST_INVALID_POS == mf->line_start);
      mf->line_start = i;
      mf->st = mhd_POST_MPART_ST_PREAMBL_CHECKING_FOR_DELIM;
    /* Intentional fall-through */
    case mhd_POST_MPART_ST_PREAMBL_CHECKING_FOR_DELIM:
      mhd_assert (i >= mf->line_start);
      do /* Fast local loop */
      {
        mhd_assert (i - mf->line_start < mf->bound.size + 2);
        if (i < mf->line_start + 2)
        {
          if ('-' != buf[i])
          {
            mf->st = mhd_POST_MPART_ST_BACK_TO_PREAMBL;
            break;
          }
        }
        else if (i <= mf->line_start + mf->bound.size + 1)
        {
          if (mf->bound.data[i - (mf->line_start + 2)] != buf[i])
          {
            mf->st = mhd_POST_MPART_ST_BACK_TO_PREAMBL;
            break;
          }
          else if (i == mf->line_start + mf->bound.size + 1)
          {
            mf->st = mhd_POST_MPART_ST_FIRST_DELIM_FOUND;
            ++i;
            break;
          }
        }
      } while (*pdata_size > ++i);
      mhd_assert ((*pdata_size == i) || \
                  (mhd_POST_MPART_ST_FIRST_DELIM_FOUND == mf->st) || \
                  (mhd_POST_MPART_ST_BACK_TO_PREAMBL == mf->st));
      continue;
    case mhd_POST_MPART_ST_FIRST_DELIM_FOUND:
      mhd_assert (mhd_POST_INVALID_POS != mf->delim_check_start);
      mhd_assert (mhd_POST_INVALID_POS != mf->line_start);
      mhd_assert (i >= mf->line_start + mf->bound.size + 2);
      do /* Fast local loop */
      {
        if ('\n' == buf[i])
        {
          if (bare_lf_as_crlf ||
              ('\r' == buf [i - 1]))
          {
            mf->st = mhd_POST_MPART_ST_FIRST_PART_START;
            ++i;
          }
          else
            mf->st = mhd_POST_MPART_ST_FORMAT_ERROR;

          break;
        }
        else if ('\r' == buf [i - 1])
        {
          mf->st = mhd_POST_MPART_ST_FORMAT_ERROR;
          break;
        }
        else if ((i == mf->line_start + mf->bound.size + 3) &&
                 ('-' == buf [i - 1]) &&
                 ('-' == buf [i]))
        {
          mf->st = mhd_POST_MPART_ST_EPILOGUE;
          break;
        }
      } while (*pdata_size > ++i);
      mhd_assert ((*pdata_size == i) || \
                  (mhd_POST_MPART_ST_FIRST_PART_START == mf->st) || \
                  (mhd_POST_MPART_ST_FORMAT_ERROR == mf->st) || \
                  (mhd_POST_MPART_ST_EPILOGUE == mf->st));
      continue;
    case mhd_POST_MPART_ST_FIRST_PART_START:
      mhd_assert (i > p_data->field_start);
      mhd_assert (*pdata_size > i);
      if ((c->rq.app_act.head_act.data.post_parse.max_nonstream_size <
           i - p_data->field_start) ||
          (*pdata_size - i < i - p_data->field_start))
      {
        /* Discard unused data */
        const size_t discard_size = i - p_data->field_start;
        memmove (buf + p_data->field_start,
                 buf + i,
                 discard_size);
        i -= discard_size;
        *pdata_size -= discard_size;
        mf->delim_check_start = i;
      }
    /* Intentional fall-through */
    case mhd_POST_MPART_ST_PART_START:
      mhd_assert (0 == mf->f.name_len);
      mhd_assert (0 == p_data->value_off);
      p_data->field_start = mf->delim_check_start;
      mf->delim_check_start = mhd_POST_INVALID_POS;
    /* Intentional fall-through */
    case mhd_POST_MPART_ST_HEADER_LINE_START:
      mf->line_start = i;
      mf->st = mhd_POST_MPART_ST_HEADER_LINE;
    /* Intentional fall-through */
    case mhd_POST_MPART_ST_HEADER_LINE:
      mhd_assert (i >= mf->line_start);
      mhd_assert (mhd_POST_INVALID_POS != mf->line_start);
      do /* Fast local loop */
      {
        if ('\r' == buf[i])
        {
          mf->st = mhd_POST_MPART_ST_HEADER_LINE_CR_FOUND;
          ++i;
          break;
        }
        else if ('\n' == buf[i])
        {
          if (bare_lf_as_crlf)
            mf->st = mhd_POST_MPART_ST_HEADER_LINE_END;
          else
            mf->st = mhd_POST_MPART_ST_FORMAT_ERROR;
          break;
        }
        else if (mf->line_start + mf->bound.size + 1 == i)
        {
          if (('-' == buf[mf->line_start]) &&
              ('-' == buf[mf->line_start + 1]) &&
              (0 == memcmp (buf + mf->line_start + 1,
                            mf->bound.data,
                            mf->bound.size)))
          {
            /* The delimiter before the end of the header */
            if (! bare_lf_as_crlf)
              mf->delim_check_start = mf->line_start - 2;
            else
              mf->delim_check_start = mf->line_start - 1; /* Actually can be one char earlier */
            mf->st = mhd_POST_MPART_ST_DELIM_FOUND;
            break;
          }
        }
      } while (*pdata_size > ++i);
      mhd_assert ((*pdata_size == i) || \
                  (mhd_POST_MPART_ST_HEADER_LINE_CR_FOUND == mf->st) || \
                  (mhd_POST_MPART_ST_HEADER_LINE_END == mf->st) || \
                  (mhd_POST_MPART_ST_DELIM_FOUND == mf->st) || \
                  (mhd_POST_MPART_ST_FORMAT_ERROR == mf->st) );
      continue;
    case mhd_POST_MPART_ST_HEADER_LINE_CR_FOUND:
      if ('\n' != buf[i])
      {
        mf->st = mhd_POST_MPART_ST_FORMAT_ERROR;
        continue;
      }
      mf->st = mhd_POST_MPART_ST_HEADER_LINE_END;
    /* Intentional fall-through */
    case mhd_POST_MPART_ST_HEADER_LINE_END:
      mhd_assert (i >= mf->line_start);
      mhd_assert (mhd_POST_INVALID_POS != mf->line_start);
      if (1)
      {
        size_t line_len;
        if (i == mf->line_start)
          line_len = 0;
        else if ('\r' == buf[i - 1])
          line_len = i - mf->line_start - 1;
        else
          line_len = i - mf->line_start;

        if (0 == line_len)
        {
          ++i;
          mf->st = mhd_POST_MPART_ST_VALUE_START;
          continue;
        }
        else
        {
          static const struct MHD_String hdr =
            mhd_MSTR_INIT ("Content-Disposition:");
          static const struct MHD_String tkn = mhd_MSTR_INIT ("form-data");
          static const struct MHD_String n_par = mhd_MSTR_INIT ("name");

          if ((hdr.len + tkn.len + n_par.len + 2 <= line_len) &&
              mhd_str_equal_caseless_bin_n (hdr.cstr,
                                            buf + mf->line_start,
                                            hdr.len))
          {
            size_t hdr_val_start;
            struct MHD_String hdr_val;
            enum mhd_StingStartsWithTokenResult res;
            struct mhd_BufferConst name_buf;
            bool hdr_has_name;
            bool name_needs_unq;

            buf [mf->line_start + line_len] = 0; /* Zero-terminate the header line */
            hdr_val_start = mf->line_start + hdr.len;
            /* Skip all whitespace chars */
            while ((' ' == buf[hdr_val_start]) || ('\t' == buf[hdr_val_start]))
              ++hdr_val_start;

            mhd_assert (hdr_val_start <= i);

            hdr_val.cstr = buf + hdr_val_start;
            hdr_val.len = mf->line_start + line_len - hdr_val_start;

            res = mhd_str_starts_with_token_req_param (&hdr_val,
                                                       &tkn,
                                                       &n_par,
                                                       &name_buf,
                                                       &name_needs_unq);
            if (mhd_STR_STARTS_W_TOKEN_HAS_TOKEN_BAD_FORMAT == res)
            {
              /* Found two names for one field */
              mf->st = mhd_POST_MPART_ST_FORMAT_ERROR;
              continue;
            }
            else if (mhd_STR_STARTS_W_TOKEN_HAS_TOKEN == res)
            {
              static const struct MHD_String fn_par =
                mhd_MSTR_INIT ("filename");
              struct mhd_BufferConst fname_buf;
              bool fname_needs_unq;

              if (NULL != name_buf.data)
              {
                mhd_assert (buf < name_buf.data);
                if (0 != mf->f.name_idx)
                {
                  /* Found two names for one field */
                  mf->st = mhd_POST_MPART_ST_FORMAT_ERROR;
                  continue;
                }
                mf->f.name_idx = (size_t) (name_buf.data - buf);
                mf->f.name_len = name_buf.size;
                hdr_has_name = true;

                /* Do not process (unquote, url-decode, zero-terminate) here yet
                 * as it may break the header format */
              }
              else
                hdr_has_name = false;

              res = mhd_str_starts_with_token_req_param (&hdr_val,
                                                         &tkn,
                                                         &fn_par,
                                                         &fname_buf,
                                                         &fname_needs_unq);
              if (mhd_STR_STARTS_W_TOKEN_HAS_TOKEN_BAD_FORMAT == res)
              {
                mf->st = mhd_POST_MPART_ST_FORMAT_ERROR;
                continue;
              }
              else if (mhd_STR_STARTS_W_TOKEN_HAS_TOKEN == res)
              {
                if (NULL != fname_buf.data)
                {
                  mhd_assert (buf < fname_buf.data);
                  if (0 != mf->f.filename_idx)
                  {
                    /* Found two filenames for one field */
                    mf->st = mhd_POST_MPART_ST_FORMAT_ERROR;
                    continue;
                  }
                  mf->f.filename_idx = (size_t) (fname_buf.data - buf);
                  if (! fname_needs_unq)
                    mf->f.filename_len = fname_buf.size;
                  else
                  {
                    mf->f.filename_len =
                      mhd_str_unquote (fname_buf.data,
                                       fname_buf.size,
                                       buf + mf->f.filename_idx);
                    if ((0 == mf->f.filename_len) && (0 != fname_buf.size))
                    {
                      mhd_assert (0 && "broken quoting must be detected " \
                                  "earlier by " \
                                  "mhd_str_starts_with_token_req_param()");
                      MHD_UNREACHABLE_;
                      mf->st = mhd_POST_MPART_ST_FORMAT_ERROR;
                      continue;
                    }
                  }
                  mhd_assert (mf->f.filename_idx + mf->f.filename_len <= i);
                  mf->f.filename_len =
                    mhd_str_pct_decode_lenient_n (buf + mf->f.filename_idx,
                                                  mf->f.filename_len,
                                                  buf + mf->f.filename_idx,
                                                  mf->f.filename_len,
                                                  NULL);
                  mhd_assert (mf->f.filename_idx + mf->f.filename_len <= i);

                  buf[mf->f.filename_idx + mf->f.filename_len] = 0; /* Zero-terminate the filename */
                }
              }
              else
              {
                mhd_assert (mhd_STR_STARTS_W_TOKEN_NO_TOKEN == res);
                mhd_assert (0 && "The presence of the token was "
                            "checked earlier");
                MHD_UNREACHABLE_;
              }

              if (hdr_has_name)
              {
                if (name_needs_unq)
                {
                  mf->f.name_len = mhd_str_unquote (buf + mf->f.name_idx,
                                                    mf->f.name_len,
                                                    buf + mf->f.name_idx);
                  if ((0 == mf->f.name_len) && (0 != name_buf.size))
                  {
                    mhd_assert (0 && "broken quoting must be detected " \
                                "earlier by " \
                                "mhd_str_starts_with_token_req_param()");
                    MHD_UNREACHABLE_;
                    mf->st = mhd_POST_MPART_ST_FORMAT_ERROR;
                    continue;
                  }
                }
                mhd_assert (mf->f.name_idx + mf->f.name_len <= i);
                mf->f.name_len =
                  mhd_str_pct_decode_lenient_n (buf + mf->f.name_idx,
                                                mf->f.name_len,
                                                buf + mf->f.name_idx,
                                                mf->f.name_len,
                                                NULL);
                mhd_assert (mf->f.name_idx + mf->f.name_len <= i);

                buf[mf->f.name_idx + mf->f.name_len] = 0; /* Zero-terminate the name */
              }
            }
          }
        }
      }
      ++i;
      mf->st = mhd_POST_MPART_ST_HEADER_LINE_START;
      continue;
    case mhd_POST_MPART_ST_VALUE_START:
      mhd_assert (mhd_POST_INVALID_POS == mf->delim_check_start);
      mhd_assert (0 == p_data->value_off);
      mhd_assert (0 == mf->f.value_idx);
      mhd_assert (0 == mf->f.value_len);
      mhd_assert (0 != i && "the 'value' should follow the 'name'");
      if (0 == mf->f.name_idx)
      {
        mhd_LOG_MSG (c->daemon, \
                     p_data->some_data_provided ? \
                     MHD_SC_REQ_POST_PARSE_PARTIAL_INVALID_POST_FORMAT : \
                     MHD_SC_REQ_POST_PARSE_FAILED_INVALID_POST_FORMAT, \
                     "The request 'multipart/form-data' POST field has no " \
                     "name of the field.");
        p_data->parse_result =
          p_data->some_data_provided ?
          MHD_POST_PARSE_RES_PARTIAL_INVALID_POST_FORMAT :
          MHD_POST_PARSE_RES_FAILED_INVALID_POST_FORMAT;
        mf->st = mhd_POST_MPART_ST_EPILOGUE; /* Avoid processing buffer data */
        c->discard_request = true;
        c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
        return true; /* Stop parsing the upload */
      }
      mhd_assert (0 != mf->f.name_len);
      mhd_assert (i > mf->f.name_idx);
      mf->f.value_idx = i;
      mf->line_start = mhd_POST_INVALID_POS;
    /* Intentional fall-through */
    case mhd_POST_MPART_ST_BACK_TO_VALUE:
      mf->delim_check_start = mhd_POST_INVALID_POS;
      mf->st = mhd_POST_MPART_ST_VALUE;
    /* Intentional fall-through */
    case mhd_POST_MPART_ST_VALUE:
      mhd_assert (mhd_POST_INVALID_POS == mf->delim_check_start);
      mhd_assert (mhd_POST_INVALID_POS == mf->line_start);
      do /* Fast local loop */
      {
        if ('\r' == buf[i])
        {
          mf->delim_check_start = i;
          mf->st = mhd_POST_MPART_ST_VALUE_CR_FOUND;
          ++i;
          break;
        }
        else if (bare_lf_as_crlf && '\n' == buf[i])
        {
          mf->delim_check_start = i;
          mf->st = mhd_POST_MPART_ST_VALUE_LINE_START;
          ++i;
          break;
        }
      } while (*pdata_size > ++i);
      mhd_assert ((*pdata_size == i) || \
                  (mhd_POST_MPART_ST_VALUE_CR_FOUND == mf->st) || \
                  (mhd_POST_MPART_ST_VALUE_LINE_START == mf->st));
      continue;
    case mhd_POST_MPART_ST_VALUE_CR_FOUND:
      if ('\n' != buf[i])
      {
        mf->st = mhd_POST_MPART_ST_BACK_TO_VALUE;
        continue;
      }
      mf->st = mhd_POST_MPART_ST_VALUE_LINE_START;
      ++i;
      continue;
    case mhd_POST_MPART_ST_VALUE_LINE_START:
      mhd_assert (mhd_POST_INVALID_POS != mf->delim_check_start);
      mf->line_start = i;
      mf->st = mhd_POST_MPART_ST_VALUE_CHECKING_FOR_DELIM;
    /* Intentional fall-through */
    case mhd_POST_MPART_ST_VALUE_CHECKING_FOR_DELIM:
      mhd_assert (i >= mf->line_start);
      do /* Fast local loop */
      {
        mhd_assert (i - mf->line_start < mf->bound.size + 2);
        if (i < mf->line_start + 2)
        {
          if ('-' != buf[i])
          {
            mf->st = mhd_POST_MPART_ST_BACK_TO_VALUE;
            break;
          }
        }
        else if (i <= mf->line_start + mf->bound.size + 1)
        {
          if (mf->bound.data[i - (mf->line_start + 2)] != buf[i])
          {
            mf->st = mhd_POST_MPART_ST_BACK_TO_VALUE;
            break;
          }
          if (i == mf->line_start + mf->bound.size + 1)
          {
            mf->st = mhd_POST_MPART_ST_DELIM_FOUND;
            ++i;
            break;
          }
        }
      } while (*pdata_size > ++i);
      mhd_assert ((*pdata_size == i) || \
                  (mhd_POST_MPART_ST_BACK_TO_VALUE == mf->st) || \
                  (mhd_POST_MPART_ST_DELIM_FOUND == mf->st));
      continue;
    case mhd_POST_MPART_ST_DELIM_FOUND:
      mhd_assert (mhd_POST_INVALID_POS != mf->delim_check_start);
      mhd_assert (mhd_POST_INVALID_POS != mf->line_start);
      mhd_assert (i >= mf->line_start + mf->bound.size + 2);
      do /* Fast local loop */
      {
        if ('\n' == buf[i])
        {
          if (bare_lf_as_crlf ||
              ('\r' == buf [i - 1]))
            mf->st = mhd_POST_MPART_ST_VALUE_END_FOUND;
          else
            mf->st = mhd_POST_MPART_ST_FORMAT_ERROR;

          break;
        }
        else if ('\r' == buf [i - 1])
        {
          mf->st = mhd_POST_MPART_ST_FORMAT_ERROR;
          break;
        }
        else if ((i == mf->line_start + mf->bound.size + 3) &&
                 ('-' == buf [i - 1]) &&
                 ('-' == buf [i]))
        {
          mf->st = mhd_POST_MPART_ST_VALUE_END_FOUND_FINAL;
          break;
        }
      } while (*pdata_size > ++i);
      mhd_assert ((*pdata_size == i) || \
                  (mhd_POST_MPART_ST_VALUE_END_FOUND == mf->st) || \
                  (mhd_POST_MPART_ST_VALUE_END_FOUND_FINAL == mf->st) || \
                  (mhd_POST_MPART_ST_FORMAT_ERROR == mf->st));
      continue;
    case mhd_POST_MPART_ST_VALUE_END_FOUND:
    case mhd_POST_MPART_ST_VALUE_END_FOUND_FINAL:
      mhd_assert (mhd_POST_INVALID_POS != mf->delim_check_start);
      mhd_assert (mf->f.value_idx <= mf->delim_check_start);
      mhd_assert (0 == mf->f.value_len);
      mhd_assert (0 != mf->f.name_len);
      mhd_assert (i > mf->f.name_idx);
      mhd_assert (i > mf->delim_check_start);
      if (0 != mf->f.value_idx)
      {
        mf->f.value_len = mf->delim_check_start - mf->f.value_idx;
        buf[mf->f.value_idx + mf->f.value_len] = 0; /* Zero-terminate the value */
        ++mf->delim_check_start; /* Shift start of the delimiter to keep zero-termination */
      }
      if (mhd_POST_MPART_ST_VALUE_END_FOUND == mf->st)
        mf->st = mhd_POST_MPART_ST_FULL_FIELD_FOUND;
      else
        mf->st = mhd_POST_MPART_ST_FULL_FIELD_FOUND_FINAL;
    /* Intentional fall-through */
    case mhd_POST_MPART_ST_FULL_FIELD_FOUND:
    case mhd_POST_MPART_ST_FULL_FIELD_FOUND_FINAL:
      mhd_assert (mhd_POST_INVALID_POS != mf->delim_check_start);
      if (1)
      {
        size_t new_delim_check_start;
        bool state_changed;

        ++i; /* Consume current character */
        new_delim_check_start = mf->delim_check_start;
        state_changed =
          process_complete_field_all (c,
                                      buf,
                                      &new_delim_check_start,
                                      pdata_size,
                                      p_data->field_start,
                                      mf->f.name_idx,
                                      mf->f.name_len,
                                      mf->f.filename_idx,
                                      mf->f.filename_len,
                                      mf->f.cntn_type_idx,
                                      mf->f.cntn_type_len,
                                      mf->f.enc_idx,
                                      mf->f.enc_len,
                                      mf->f.value_idx,
                                      mf->f.value_len);
        if (c->suspended)
        {
          mhd_assert (mf->delim_check_start == new_delim_check_start);
          mhd_assert (state_changed);
          p_data->next_parse_pos = --i; /* Restore position */
          return true;
        }

        if (mf->delim_check_start != new_delim_check_start)
        {
          size_t shift_size;
          mhd_assert (mf->delim_check_start > new_delim_check_start);

          shift_size = new_delim_check_start - mf->delim_check_start;
          mf->delim_check_start = new_delim_check_start;
          i -= shift_size;
        }

        mhd_assert (*pdata_size >= i);

        reset_parse_field_data_mpart_cont (
          p_data,
          mhd_POST_MPART_ST_FULL_FIELD_FOUND_FINAL == mf->st);

        if (state_changed)
        {
          p_data->next_parse_pos = i;
          return true;
        }
      }
      continue; /* Process the next char */
    case mhd_POST_MPART_ST_EPILOGUE:
      /* Discard the rest of the content data */
      *pdata_size = i;
      p_data->next_parse_pos = i;
      return false;
    case mhd_POST_MPART_ST_FORMAT_ERROR:
      if (p_data->some_data_provided)
      {
        mhd_LOG_MSG (c->daemon, \
                     MHD_SC_REQ_POST_PARSE_PARTIAL_INVALID_POST_FORMAT, \
                     "The request POST has broken encoding or format and " \
                     "was parsed only partially.");
        p_data->parse_result =
          MHD_POST_PARSE_RES_PARTIAL_INVALID_POST_FORMAT;
      }
      else
      {
        mhd_LOG_MSG (c->daemon, \
                     MHD_SC_REQ_POST_PARSE_FAILED_INVALID_POST_FORMAT, \
                     "The request POST has broken encoding or format and " \
                     "cannot be parsed.");
        p_data->parse_result =
          MHD_POST_PARSE_RES_FAILED_INVALID_POST_FORMAT;
      }
      c->discard_request = true;
      c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
      return true;
    default:
      mhd_assert (0 && "Impossible value");
      MHD_UNREACHABLE_;
      break;
    }
    mhd_assert (0 && "Should be unreachable");
    MHD_UNREACHABLE_;
    break;
  }

  mhd_assert (*pdata_size == i);

  mhd_assert (mhd_POST_MPART_ST_NOT_STARTED != mf->st);
  mhd_assert (mhd_POST_MPART_ST_BACK_TO_PREAMBL != mf->st);
  mhd_assert (mhd_POST_MPART_ST_PREAMBL_LINE_START != mf->st);
  mhd_assert (mhd_POST_MPART_ST_HEADER_LINE_END != mf->st);
  mhd_assert (mhd_POST_MPART_ST_BACK_TO_VALUE != mf->st);
  mhd_assert (mhd_POST_MPART_ST_VALUE_END_FOUND != mf->st);
  mhd_assert (mhd_POST_MPART_ST_VALUE_END_FOUND_FINAL != mf->st);
  mhd_assert ((mhd_POST_MPART_ST_VALUE != mf->st) || \
              (0 == mf->f.value_len));

  mhd_assert (*pdata_size == i);

  if ((0 != mf->f.value_idx) &&
      (((mhd_POST_MPART_ST_VALUE == mf->st) &&
        (i != mf->f.value_idx) &&
        is_value_streaming_needed (c, i - p_data->field_start)) ||
       (((mhd_POST_MPART_ST_VALUE_CR_FOUND == mf->st) ||
         (mhd_POST_MPART_ST_VALUE_LINE_START == mf->st) ||
         (mhd_POST_MPART_ST_VALUE_CHECKING_FOR_DELIM == mf->st)) &&
        (i != mf->delim_check_start) &&
        is_value_streaming_needed (c, i - mf->delim_check_start))))
  {
    bool proc_res;

    mhd_assert ((mhd_POST_MPART_ST_VALUE == mf->st) || \
                (i >= mf->delim_check_start));
    mhd_assert ((mhd_POST_MPART_ST_VALUE == mf->st) || \
                (mhd_POST_INVALID_POS != mf->delim_check_start));
    if (mhd_POST_MPART_ST_VALUE != mf->st)
    {
      i = mf->delim_check_start; /* Reset position */
      mf->delim_check_start = mhd_POST_INVALID_POS;
      mf->line_start = mhd_POST_INVALID_POS;
      mf->st = mhd_POST_MPART_ST_VALUE;
    }

    proc_res =
      process_partial_value_all (c,
                                 buf,
                                 &i,
                                 pdata_size,
                                 mf->f.name_idx,
                                 mf->f.name_len,
                                 mf->f.filename_idx,
                                 mf->f.filename_len,
                                 mf->f.cntn_type_idx,
                                 mf->f.cntn_type_len,
                                 mf->f.enc_idx,
                                 mf->f.enc_len,
                                 mf->f.value_idx,
                                 i - mf->f.value_idx);

    p_data->next_parse_pos = i;

    return proc_res;
  }

  p_data->next_parse_pos = i;
  return false; /* Continue parsing */
}


static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_INOUT_ (2) MHD_FN_PAR_INOUT_ (3) bool
parse_post_text (struct MHD_Connection *restrict c,
                 size_t *restrict pdata_size,
                 char *restrict buf)
{
  const int discp_lvl = c->daemon->req_cfg.strictnees;
  /* Treat bare LF as the end of the line.
     The same logic used here as for parsing HTTP headers.
     Bare LF is processed as the end of the line or rejected as broken
     request. */
  const bool bare_lf_as_crlf = mhd_ALLOW_BARE_LF_AS_CRLF (discp_lvl);
  struct mhd_PostParserData *const p_data = &(c->rq.u_proc.post);
  struct mhd_PostParserTextData *const tf = &(p_data->e_d.text); /**< the current "text" field */
  size_t i;
  bool enc_broken;

  mhd_assert (MHD_HTTP_POST_ENCODING_TEXT_PLAIN == c->rq.u_proc.post.enc);
  mhd_assert (MHD_POST_PARSE_RES_OK == p_data->parse_result);
  mhd_assert (! c->discard_request);
  mhd_assert (p_data->next_parse_pos < *pdata_size);

  enc_broken = false;
  i = p_data->next_parse_pos;
  while (*pdata_size > i)
  {
    switch (tf->st)
    {
    case mhd_POST_TEXT_ST_NOT_STARTED:
      mhd_assert (0 == p_data->field_start);
      mhd_assert (0 == p_data->value_off);
      p_data->field_start = i;
      tf->name_idx = i;
      tf->st = mhd_POST_TEXT_ST_NAME;
    /* Intentional fall-through */
    case mhd_POST_TEXT_ST_NAME:
      do /* Fast local loop */
      {
        if ('=' == buf[i])
        {
          tf->st = mhd_POST_TEXT_ST_AT_EQ;
          break;
        }
        else if ('\r' == buf[i])
        {
          tf->st = mhd_POST_TEXT_ST_AT_CR;
          break;
        }
        else if ('\n' == buf[i])
        {
          tf->st = mhd_POST_TEXT_ST_AT_LF_BARE;
          break;
        }
      } while (*pdata_size > ++i);
      mhd_assert ((*pdata_size == i) || \
                  (mhd_POST_TEXT_ST_NAME != tf->st));
      continue;
    case mhd_POST_TEXT_ST_AT_EQ:
      mhd_assert (i > tf->name_idx);
      mhd_assert (0 == tf->name_len);
      mhd_assert (0 == tf->value_len);
      buf[i] = 0; /* Zero-terminate the name */
      tf->name_len = i - tf->name_idx;
      tf->st = mhd_POST_TEXT_ST_EQ_FOUND;
      ++i; /* Process the next char */
      continue;
    case mhd_POST_TEXT_ST_EQ_FOUND:
      mhd_assert (0 == p_data->value_off);
      mhd_assert (0 == tf->value_idx);
      mhd_assert (0 == tf->value_len);
      mhd_assert (0 != i && "the 'value' should follow the 'name'");
      tf->value_idx = i;
      tf->st = mhd_POST_TEXT_ST_VALUE;
    /* Intentional fall-through */
    case mhd_POST_TEXT_ST_VALUE:
      do /* Fast local loop */
      {
        if ('\r' == buf[i])
        {
          tf->st = mhd_POST_TEXT_ST_AT_CR;
          break;
        }
        else if ('\n' == buf[i])
        {
          tf->st = mhd_POST_TEXT_ST_AT_LF_BARE;
          break;
        }
      } while (*pdata_size > ++i);
      mhd_assert ((*pdata_size == i) || \
                  (mhd_POST_TEXT_ST_AT_CR == tf->st) || \
                  (mhd_POST_TEXT_ST_AT_LF_BARE == tf->st));
      continue;
    case mhd_POST_TEXT_ST_AT_LF_BARE:
      if (! bare_lf_as_crlf)
      {
        enc_broken = true;
        break;
      }
    /* Intentional fall-through */
    case mhd_POST_TEXT_ST_AT_CR:
      mhd_assert (0 == tf->value_len);
      buf[i] = 0; /* Zero-terminate the value (or the name) */
      if (0 != tf->value_idx)
        tf->value_len = i - tf->value_idx;
      else
        tf->name_len = i - tf->name_idx;
      if ((0 == tf->name_len) && (0 == tf->value_len))
      { /* Empty line */
        ++i; /* Advance to the next char to be checked */
        reset_parse_field_data_text (p_data);
        tf->st = mhd_POST_TEXT_ST_NOT_STARTED;
      }
      else if (mhd_POST_TEXT_ST_AT_LF_BARE == tf->st)
        tf->st = mhd_POST_TEXT_ST_FULL_LINE_FOUND;
      else
      {
        tf->st = mhd_POST_TEXT_ST_CR_FOUND;
        ++i; /* Process the next char */
      }
      continue;
    case mhd_POST_TEXT_ST_CR_FOUND:
      if ('\n' != buf[i])
      {
        enc_broken = true;
        break;
      }
      tf->st = mhd_POST_TEXT_ST_FULL_LINE_FOUND;
    /* Intentional fall-through */
    case mhd_POST_TEXT_ST_FULL_LINE_FOUND:
      ++i; /* Advance to the next char to be checked */
      if (process_complete_field (c,
                                  buf,
                                  &i,
                                  pdata_size,
                                  p_data->field_start,
                                  tf->name_idx,
                                  tf->name_len,
                                  tf->value_idx,
                                  tf->value_len))
      {
        if (c->suspended)
          --i; /* Go back to the same position */
        else
          reset_parse_field_data_text (p_data);
        p_data->next_parse_pos = i;
        return true;
      }
      mhd_assert (*pdata_size >= i);
      reset_parse_field_data_text (p_data);
      continue; /* Process the next char */
    default:
      mhd_assert (0 && "Impossible value");
      MHD_UNREACHABLE_;
      enc_broken = true;
      break;
    }
    mhd_assert (enc_broken);
    break;
  }

  mhd_assert ((*pdata_size == i) || enc_broken);

  if (enc_broken)
  {
    if (p_data->some_data_provided)
    {
      mhd_LOG_MSG (c->daemon, \
                   MHD_SC_REQ_POST_PARSE_PARTIAL_INVALID_POST_FORMAT, \
                   "The request POST has broken encoding or format and " \
                   "was parsed only partially.");
      p_data->parse_result =
        MHD_POST_PARSE_RES_PARTIAL_INVALID_POST_FORMAT;
    }
    else
    {
      mhd_LOG_MSG (c->daemon, \
                   MHD_SC_REQ_POST_PARSE_FAILED_INVALID_POST_FORMAT, \
                   "The request POST has broken encoding or format and " \
                   "cannot be parsed.");
      p_data->parse_result =
        MHD_POST_PARSE_RES_FAILED_INVALID_POST_FORMAT;
    }
    tf->st = mhd_POST_TEXT_ST_NOT_STARTED;
    c->discard_request = true;
    c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
    return true;
  }

  mhd_assert (mhd_POST_TEXT_ST_AT_EQ != tf->st);
  mhd_assert (mhd_POST_TEXT_ST_AT_CR != tf->st);
  mhd_assert (mhd_POST_TEXT_ST_AT_LF_BARE != tf->st);
  mhd_assert (mhd_POST_TEXT_ST_FULL_LINE_FOUND != tf->st);

  mhd_assert (*pdata_size == i);

  if ((mhd_POST_TEXT_ST_VALUE == tf->st) &&
      (i != tf->value_idx) &&
      is_value_streaming_needed (c, i - p_data->field_start))
  {
    if (process_partial_value (c,
                               buf,
                               &i,
                               pdata_size,
                               tf->name_idx,
                               tf->name_len,
                               tf->value_idx,
                               i - tf->value_idx))
    {
      p_data->next_parse_pos = i;
      return true;
    }
  }

  p_data->next_parse_pos = i;
  return false; /* Continue parsing */
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_INOUT_ (3) bool
mhd_stream_post_parse (struct MHD_Connection *restrict c,
                       size_t *restrict pdata_size,
                       char *restrict buf)
{
  struct mhd_PostParserData *const p_data = &(c->rq.u_proc.post);
  bool alloc_failed;

  mhd_assert (MHD_HTTP_POST_ENCODING_OTHER != p_data->enc);
  mhd_assert (c->rq.cntn.lbuf.size <= p_data->lbuf_limit);

  if ((MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA == p_data->enc) &&
      (mhd_POST_MPART_ST_EPILOGUE == p_data->e_d.m_form.st))
  {
    /* No need to process the data */
    *pdata_size = 0; /* All data has been moved */
    return false; /* Continue normal processing */
  }

  // TODO: support process in the connection buffer
  if (NULL == c->rq.cntn.lbuf.data)
  {
    alloc_failed = ! get_lbuf_fixed_size (c,
                                          *pdata_size + 1,
                                          &(c->rq.cntn.lbuf));
  }
  else
  {
    size_t space_left;

    mhd_assert (c->rq.cntn.lbuf.size >= p_data->lbuf_used);
    space_left = c->rq.cntn.lbuf.size - p_data->lbuf_used;

    if (*pdata_size > space_left)
      alloc_failed = ! grow_lbuf_fixed_size (c,
                                             *pdata_size - space_left + 1,
                                             &(c->rq.cntn.lbuf));
    else
      alloc_failed = false;

  }
  if (alloc_failed)
  {
    mhd_LOG_MSG (c->daemon, \
                 MHD_SC_REQ_POST_PARSE_FAILED_NO_LARGE_BUF_MEM, \
                 "Not enough large shared buffer memory to " \
                 "parse POST request.");
    p_data->parse_result =
      MHD_POST_PARSE_RES_FAILED_NO_LARGE_BUF_MEM;
    c->discard_request = true;
    c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
    return true;
  }
  memcpy (c->rq.cntn.lbuf.data + p_data->lbuf_used,
          buf,
          *pdata_size);
  p_data->lbuf_used += *pdata_size;
  *pdata_size = 0; /* All data has been moved */

  switch (p_data->enc)
  {
  case MHD_HTTP_POST_ENCODING_FORM_URLENCODED:
    return parse_post_urlenc (c,
                              &(p_data->lbuf_used),
                              c->rq.cntn.lbuf.data);
  case MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA:
    return parse_post_mpart (c,
                             &(p_data->lbuf_used),
                             c->rq.cntn.lbuf.data);
  case MHD_HTTP_POST_ENCODING_TEXT_PLAIN:
    return parse_post_text (c,
                            &(p_data->lbuf_used),
                            c->rq.cntn.lbuf.data);
  case MHD_HTTP_POST_ENCODING_OTHER:
  default:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    p_data->parse_result =
      MHD_POST_PARSE_RES_PARTIAL_INVALID_POST_FORMAT;
    c->discard_request = true;
    c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
    break;
  }
  return true;
}


/**
 * Check whether some unprocessed or partially processed data left in buffers
 * for urlencoding POST encoding.
 * @param c the stream to use
 * @param pdata_size the pointer to the size of the data in the buffer
 * @param buf the buffer with the data
 * @return 'true' if stream state was changed,
 *         'false' to continue normal processing
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_INOUT_ (2) MHD_FN_PAR_INOUT_ (3) bool
check_post_leftovers_urlenc (struct MHD_Connection *restrict c,
                             size_t *restrict pdata_size,
                             char *restrict buf)
{
  struct mhd_PostParserData *const p_data = &(c->rq.u_proc.post);
  struct mhd_PostParserUrlEncData *const uf = &(p_data->e_d.u_enc); /**< the current "text" field */
  size_t pos;
  size_t name_start;
  size_t name_len;
  size_t value_start;
  size_t value_len;

  pos = p_data->next_parse_pos;  /* Points to the char AFTER the data, valid location as buffer is always at least one byte larger */
  mhd_assert (pos == p_data->next_parse_pos);
  mhd_assert (pos < c->rq.cntn.lbuf.size); // TODO: support processing in connection buffer
  mhd_assert (*pdata_size >= pos);
  switch (uf->st)
  {
  case mhd_POST_UENC_ST_NOT_STARTED:
    mhd_assert (pos == *pdata_size);
    return false; /* Continue processing */
  case mhd_POST_UENC_ST_NAME:
    mhd_assert (pos == *pdata_size);
    /* Unfinished name */
    name_start = uf->name_idx;
    if (uf->last_pct_idx != mhd_POST_INVALID_POS)
      name_len = mhd_str_pct_decode_lenient_n (buf + uf->name_idx,
                                               pos - uf->name_idx,
                                               buf + uf->name_idx,
                                               pos - uf->name_idx,
                                               NULL);
    else
      name_len = pos - uf->name_idx;
    buf[name_start + name_len] = 0; /* Zero-terminate the result, an extra byte is always available in the buffer */
    value_start = 0;
    value_len = 0;
    break;
  case mhd_POST_UENC_ST_EQ_FOUND:
    mhd_assert (pos == *pdata_size);
    name_start = uf->name_idx;
    name_len = uf->name_len;
    value_start = pos;
    value_len = 0;
    buf[value_start] = 0; /* Zero-terminate the result, an extra byte is always available */
    break;
  case mhd_POST_UENC_ST_VALUE:
    mhd_assert (0 != uf->value_idx);
    name_start = uf->name_idx;
    name_len = uf->name_len;
    mhd_assert (0 == buf[name_start + name_len]);
    if (0 != uf->value_len)
    {
      /* The value was partially decoded and then application requested stream
       * suspending. */
      mhd_assert (pos < *pdata_size);
      mhd_assert (2 >= *pdata_size - pos);
      value_start = uf->value_idx;
      if (uf->value_idx + uf->value_len != pos)
        memmove (buf + uf->value_idx + uf->value_len,
                 buf + pos,
                 *pdata_size - pos);
      value_len = uf->value_len + *pdata_size - pos;
    }
    else
    {
      /* The value has not been decoded yet */
      mhd_assert (pos == *pdata_size);
      value_start = uf->value_idx;
      if (uf->last_pct_idx != mhd_POST_INVALID_POS)
        value_len = mhd_str_pct_decode_lenient_n (buf + uf->value_idx,
                                                  pos - uf->value_idx,
                                                  buf + uf->value_idx,
                                                  pos - uf->value_idx,
                                                  NULL);
      else
        value_len = pos - uf->value_idx;
    }
    buf[value_start + value_len] = 0; /* Zero-terminate the result, an extra byte is always available in the buffer */
    break;
  case mhd_POST_UENC_ST_FULL_FIELD_FOUND:
    /* Full value was found, but the stream has been suspended by
     * the application */
    mhd_assert (pos + 1 == *pdata_size);
    mhd_assert (0 != uf->value_idx);
    mhd_assert (pos != uf->value_idx);
    name_start = uf->name_idx;
    name_len = uf->name_len;
    value_start = uf->value_idx;
    value_len = uf->value_len;
    mhd_assert (0 == buf[name_start + name_len]);
    mhd_assert (0 == buf[value_start + value_len]);
    ++pos;
    mhd_assert (pos == *pdata_size);
    break;
  case mhd_POST_UENC_ST_AT_EQ:
  case mhd_POST_UENC_ST_AT_AMPRSND:
  default:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    p_data->parse_result = MHD_POST_PARSE_RES_FAILED_INVALID_POST_FORMAT;
    return false;
  }

  if (process_complete_field (c,
                              buf,
                              &pos,
                              pdata_size,
                              p_data->field_start,
                              name_start,
                              name_len,
                              value_start,
                              value_len))
    return true;

  reset_parse_field_data_urlenc (p_data);

  return false; /* Continue normal processing */
}


/**
 * Check whether some unprocessed or partially processed data left in buffers
 * for "multipart/form-data" POST encoding.
 * @param c the stream to use
 * @param pdata_size the pointer to the size of the data in the buffer
 * @param buf the buffer with the data
 * @return 'true' if stream state was changed,
 *         'false' to continue normal processing
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_INOUT_ (2) MHD_FN_PAR_INOUT_ (3) bool
check_post_leftovers_mpart (struct MHD_Connection *restrict c,
                            size_t *restrict pdata_size,
                            char *restrict buf)
{
  struct mhd_PostParserData *const p_data = &(c->rq.u_proc.post);
  struct mhd_PostParserMPartFormData *const mf = &(p_data->e_d.m_form); /**< the current "form-data" parsing details */
  size_t pos;
  bool not_terminated;
  bool add_field;
  size_t field_pos;
  size_t field_len;

  pos = p_data->next_parse_pos;  /* Points to the char AFTER the data, valid location as buffer is always at least one byte larger */
  mhd_assert (pos == p_data->next_parse_pos);
  mhd_assert (pos < c->rq.cntn.lbuf.size); // TODO: support processing in connection buffer
  mhd_assert (*pdata_size >= pos);

  not_terminated = false;
  add_field = false;
  field_pos = 0;
  field_len = 0;

  switch (mf->st)
  {
  case mhd_POST_MPART_ST_NOT_STARTED:
  case mhd_POST_MPART_ST_PREAMBL:
  case mhd_POST_MPART_ST_PREAMBL_CR_FOUND:
  case mhd_POST_MPART_ST_PREAMBL_CHECKING_FOR_DELIM:
    mhd_assert (pos == *pdata_size);
    return false; /* Continue processing */
  case mhd_POST_MPART_ST_FIRST_DELIM_FOUND:
  case mhd_POST_MPART_ST_FIRST_PART_START:
  case mhd_POST_MPART_ST_PART_START:
    mhd_assert (pos == *pdata_size);
    not_terminated = true;
    break;
  case mhd_POST_MPART_ST_HEADER_LINE_START:
  case mhd_POST_MPART_ST_HEADER_LINE:
  case mhd_POST_MPART_ST_HEADER_LINE_CR_FOUND:
  case mhd_POST_MPART_ST_VALUE_START:
    mhd_assert (pos == *pdata_size);
    not_terminated = true;
    add_field = (0 != mf->f.name_idx);
    break;
  case mhd_POST_MPART_ST_VALUE:
  case mhd_POST_MPART_ST_VALUE_CR_FOUND:
  case mhd_POST_MPART_ST_VALUE_LINE_START:
  case mhd_POST_MPART_ST_VALUE_CHECKING_FOR_DELIM:
    mhd_assert (0 != mf->f.name_idx);
    mhd_assert (0 != mf->f.value_idx);
    not_terminated = true;
    add_field = true;
    field_pos = mf->f.value_idx;
    field_len = pos - field_len;
    break;
  case mhd_POST_MPART_ST_DELIM_FOUND:
    mhd_assert (0 != mf->f.name_idx);
    mhd_assert (mhd_POST_INVALID_POS != mf->delim_check_start);
    mhd_assert (pos > mf->delim_check_start);
    not_terminated = true;
    add_field = true;
    if (0 != mf->f.value_idx)
    {
      field_pos = mf->f.value_idx;
      field_len = pos -  mf->delim_check_start;
    }
    break;
  case mhd_POST_MPART_ST_FULL_FIELD_FOUND:
    not_terminated = true;
  /* Intentional fall-through */
  case mhd_POST_MPART_ST_FULL_FIELD_FOUND_FINAL:
    mhd_assert (0 != mf->f.name_idx);
    add_field = true;
    if (0 != mf->f.value_idx)
    {
      field_pos = mf->f.value_idx;
      field_len = mf->f.value_len;
    }
    break;
  case mhd_POST_MPART_ST_EPILOGUE:
  case mhd_POST_MPART_ST_FORMAT_ERROR:
    return false; /* Continue processing */
  case mhd_POST_MPART_ST_BACK_TO_PREAMBL:
  case mhd_POST_MPART_ST_PREAMBL_LINE_START:
  case mhd_POST_MPART_ST_HEADER_LINE_END:
  case mhd_POST_MPART_ST_BACK_TO_VALUE:
  case mhd_POST_MPART_ST_VALUE_END_FOUND:
  case mhd_POST_MPART_ST_VALUE_END_FOUND_FINAL:
  default:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    p_data->parse_result = MHD_POST_PARSE_RES_FAILED_INVALID_POST_FORMAT;
    return false;
  }

  if (not_terminated)
  {
    /* The "closing" delimiter is missing */
    mhd_LOG_MSG (c->daemon, \
                 MHD_SC_REQ_POST_PARSE_OK_BAD_TERMINATION, \
                 "The request POST has invalid termination / ending. " \
                 "The last parsed field may be incorrect.");
    p_data->parse_result = MHD_POST_PARSE_RES_OK_BAD_TERMINATION;
  }

  if (add_field)
  {
    if (process_complete_field_all (c,
                                    buf,
                                    &pos,
                                    pdata_size,
                                    p_data->field_start,
                                    mf->f.name_idx,
                                    mf->f.name_len,
                                    mf->f.filename_idx,
                                    mf->f.filename_len,
                                    mf->f.cntn_type_idx,
                                    mf->f.cntn_type_len,
                                    mf->f.enc_idx,
                                    mf->f.enc_len,
                                    field_pos,
                                    field_len))
      return true;
  }

  reset_parse_field_data_mpart_cont (p_data,
                                     ! not_terminated);

  return false; /* Continue normal processing */
}


/**
 * Check whether some unprocessed or partially processed data left in buffers
 * for "text" POST encoding.
 * @param c the stream to use
 * @param pdata_size the pointer to the size of the data in the buffer
 * @param buf the buffer with the data
 * @return 'true' if stream state was changed,
 *         'false' to continue normal processing
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_INOUT_ (2) MHD_FN_PAR_INOUT_ (3) bool
check_post_leftovers_text (struct MHD_Connection *restrict c,
                           size_t *restrict pdata_size,
                           char *restrict buf)
{
  struct mhd_PostParserData *const p_data = &(c->rq.u_proc.post);
  struct mhd_PostParserTextData *const tf = &(p_data->e_d.text); /**< the current "text" field */
  size_t pos;
  size_t name_start;
  size_t name_len;
  size_t value_start;
  size_t value_len;

  pos = p_data->next_parse_pos;  /* Points to the char AFTER the data, valid location as buffer is always at least one byte larger */
  mhd_assert (pos == p_data->next_parse_pos);
  mhd_assert (pos < c->rq.cntn.lbuf.size); // TODO: support processing in connection buffer
  switch (tf->st)
  {
  case mhd_POST_TEXT_ST_NOT_STARTED:
    mhd_assert (pos == *pdata_size);
    return false; /* Continue processing */
  case mhd_POST_TEXT_ST_NAME:
    /* Unfinished name */
    mhd_assert (pos == *pdata_size);
    name_start = tf->name_idx;
    name_len = pos - name_start;
    buf[pos] = 0; /* Zero-terminate the result, an extra byte is always available */
    value_start = 0;
    value_len = 0;
    break;
  case mhd_POST_TEXT_ST_EQ_FOUND:
    mhd_assert (pos == *pdata_size);
    name_start = tf->name_idx;
    name_len = tf->name_len;
    value_start = pos;
    value_len = 0;
    buf[pos] = 0; /* Zero-terminate the result, an extra byte is always available */
    break;
  case mhd_POST_TEXT_ST_VALUE:
    mhd_assert (pos == *pdata_size);
    mhd_assert (0 != tf->value_idx);
    mhd_assert (pos != tf->value_idx);
    name_start = tf->name_idx;
    name_len = tf->name_len;
    value_start = tf->value_idx;
    value_len = pos - value_start;
    buf[pos] = 0; /* Zero-terminate the result, an extra byte space is always available */
    break;
  case mhd_POST_TEXT_ST_CR_FOUND:
    mhd_assert (pos == *pdata_size);
    mhd_assert (0 != tf->value_idx);
    mhd_assert (pos != tf->value_idx);
    name_start = tf->name_idx;
    name_len = tf->name_len;
    value_start = tf->value_idx;
    value_len = tf->value_len;
    mhd_assert (value_start + value_len + 1 == pos);
    mhd_assert (0 == buf[value_start + value_len]);
    break;
  case mhd_POST_TEXT_ST_FULL_LINE_FOUND:
    /* Full value was found, but the stream has been suspended by
     * the application */
    mhd_assert (pos + 1 == *pdata_size);
    mhd_assert (0 != tf->value_idx);
    name_start = tf->name_idx;
    name_len = tf->name_len;
    value_start = tf->value_idx;
    value_len = tf->value_len;
    mhd_assert ((value_start + value_len + 1 == pos) || \
                (value_start + value_len + 2 == pos));
    mhd_assert (0 == buf[value_start + value_len]);
    ++pos;
    mhd_assert (pos == *pdata_size);
    break;
  case mhd_POST_TEXT_ST_AT_EQ:
  case mhd_POST_TEXT_ST_AT_LF_BARE:
  case mhd_POST_TEXT_ST_AT_CR:
  default:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    p_data->parse_result = MHD_POST_PARSE_RES_FAILED_INVALID_POST_FORMAT;
    return false;
  }

  if (tf->st != mhd_POST_TEXT_ST_FULL_LINE_FOUND)
  {
    /* The line must be terminated by CRLF, but it is not */
    mhd_LOG_MSG (c->daemon, \
                 MHD_SC_REQ_POST_PARSE_OK_BAD_TERMINATION, \
                 "The request POST has invalid termination / ending. " \
                 "The last parsed field may be incorrect.");
    p_data->parse_result = MHD_POST_PARSE_RES_OK_BAD_TERMINATION;
  }

  if (process_complete_field (c,
                              buf,
                              &pos,
                              pdata_size,
                              p_data->field_start,
                              name_start,
                              name_len,
                              value_start,
                              value_len))
    return true;

  reset_parse_field_data_text (p_data);

  return false; /* Continue normal processing */
}


/**
 * Check in leftover POST data in the buffers
 * @param c the stream to use
 * @return 'true' if stream state is changed,
 *         'false' to continue
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
check_post_leftovers (struct MHD_Connection *restrict c)
{
  struct mhd_PostParserData *const p_data = &(c->rq.u_proc.post);
  switch (p_data->enc)
  {
  case MHD_HTTP_POST_ENCODING_FORM_URLENCODED:
    return check_post_leftovers_urlenc (c,
                                        &(p_data->lbuf_used),
                                        c->rq.cntn.lbuf.data);
  case MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA:
    return check_post_leftovers_mpart (c,
                                       &(p_data->lbuf_used),
                                       c->rq.cntn.lbuf.data);
  case MHD_HTTP_POST_ENCODING_TEXT_PLAIN:
    return check_post_leftovers_text (c,
                                      &(p_data->lbuf_used),
                                      c->rq.cntn.lbuf.data);
  case MHD_HTTP_POST_ENCODING_OTHER:
  default:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    p_data->parse_result =
      MHD_POST_PARSE_RES_PARTIAL_INVALID_POST_FORMAT;
    c->discard_request = true;
    c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
    break;
  }
  return true;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_stream_process_post_finish (struct MHD_Connection *restrict c)
{
  struct mhd_PostParserData *const p_data = &(c->rq.u_proc.post);
  const struct MHD_UploadAction *act;
  bool state_changed;

  if (MHD_POST_PARSE_RES_OK == p_data->parse_result)
  {
    // TODO: implement processing in the connection buffer
    if (check_post_leftovers (c))
      return true;
  }

  act = c->rq.app_act.head_act.data.post_parse.done_cb (
    &(c->rq),
    c->rq.app_act.head_act.data.post_parse.done_cb_cls,
    p_data->parse_result);

  state_changed = mhd_stream_process_upload_action (c, act, true);
  if (! c->suspended)
    mhd_daemon_free_lbuf (c->daemon, &(c->rq.cntn.lbuf));
  return state_changed;
}
