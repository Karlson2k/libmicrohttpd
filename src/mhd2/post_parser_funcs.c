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

  if (0 != mpart_bound.size)
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


static MHD_FN_PAR_NONNULL_ (1) void
reset_text_parse_field_data (struct mhd_PostParserData *pdata)
{
  mhd_assert (MHD_HTTP_POST_ENCODING_TEXT_PLAIN == pdata->enc);
  memset (&(pdata->e_d.text), 0, sizeof(pdata->e_d.text));
#ifndef HAVE_NULL_PTR_ALL_ZEROS
  pdata->e_d.text.name_ptr = NULL;
  pdata->e_d.text.value_ptr = NULL;
#endif
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

  pdata->lbuf_left = c->rq.app_act.head_act.data.post_parse.buffer_size;

  switch (pdata->enc)
  {
  case MHD_HTTP_POST_ENCODING_FORM_URLENCODED:
    // TODO:
    break;
  case MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA:
    // TODO
    break;
  case MHD_HTTP_POST_ENCODING_TEXT_PLAIN:
    reset_text_parse_field_data (pdata);
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
MHD_FN_PAR_OUT_ (3) bool
get_lbuf_fixed_size (struct MHD_Connection *restrict c,
                     size_t alloc_size,
                     struct mhd_Buffer *restrict buf)
{
  mhd_assert (mhd_ACTION_POST_PARSE == c->rq.app_act.head_act.act);

  if (alloc_size > c->rq.u_proc.post.lbuf_left)
    return NULL;

  if (! mhd_daemon_get_lbuf (c->daemon,
                             alloc_size,
                             buf))
    return false;

  c->rq.u_proc.post.lbuf_left -= alloc_size;
  return true;
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

  if (grow_size > c->rq.u_proc.post.lbuf_left)
    return NULL;

  if (! mhd_daemon_grow_lbuf (c->daemon,
                              grow_size,
                              buf))
    return false;

  c->rq.u_proc.post.lbuf_left -= grow_size;
  return true;
}


/**
 * Add parsed POST field to the list of request's fields
 * @param c the stream to use
 * @param name the name of the field
 * @param filename the filename of the filed
 * @param content_type the "Content-Type:" of the field
 * @param transfer_encoding the "Transfer-Encoding:" of the field
 * @param value the value of the field
 * @return 'true' if succeed,
 *         'false' if memory allocation failed (no pool memory in the stream)
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
add_parsed_post_field (struct MHD_Connection *restrict c,
                       struct MHD_String *restrict name,
                       struct MHD_StringNullable *restrict filename,
                       struct MHD_StringNullable *restrict content_type,
                       struct MHD_StringNullable *restrict transfer_encoding,
                       struct MHD_StringNullable *restrict value)
{
  struct mhd_RequestPostField *pfield;

  mhd_assert (NULL != name->cstr);
  mhd_assert ((NULL != filename->cstr) || (0 == filename->len));
  mhd_assert ((NULL != content_type->cstr) || (0 == content_type->len));
  mhd_assert ((NULL != transfer_encoding->cstr) || \
              (0 == transfer_encoding->len));
  mhd_assert ((NULL != value->cstr) || (0 == value->len));

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
 * Process new full parsed POST filed
 * @param c the stream to use
 * @param buf the buffer, where the data is
 * @param pnext_pos the pointer to variable holding index on the next position
 *                  to be parsed
 * @param pdata_size the pointer to variable holding the size of the data
 * @param field_start the start of the current field in the @a buf
 * @param name_start the start of the name of the filed in the @a buf
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
                            size_t *restrict pnext_pos,
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

  struct MHD_String name;
  struct MHD_StringNullable filename;
  struct MHD_StringNullable content_type;
  struct MHD_StringNullable encoding;
  struct MHD_StringNullable value;

  mhd_assert (mhd_ACTION_POST_PARSE == c->rq.app_act.head_act.act);

  mhd_assert ((0 == filename_start) || \
              (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA == p_data->enc));
  mhd_assert ((0 == cntn_type_start) || \
              (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA == p_data->enc));
  mhd_assert ((0 == enc_start) || \
              (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA == p_data->enc));

  mhd_assert (*pnext_pos <= *pdata_size);
  mhd_assert (value_start + value_len < *pnext_pos);
  mhd_assert ((name_start + name_len < value_start) || \
              (0 == value_start));
  mhd_assert (name_start + name_len < *pnext_pos);
  mhd_assert ((filename_start + filename_len < value_start) || \
              (0 == value_start));
  mhd_assert (filename_start + filename_len < *pnext_pos);
  mhd_assert ((cntn_type_start + cntn_type_len < value_start) || \
              (0 == value_start));
  mhd_assert (cntn_type_start + cntn_type_len < *pnext_pos);
  mhd_assert ((enc_start + enc_len < value_start) || \
              (0 == value_start));
  mhd_assert (enc_start + enc_len < *pnext_pos);
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

  if (NULL != p_par->stream_reader)
  {
    if ((p_par->auto_stream_size < (*pnext_pos - field_start))
        || (0 != p_data->value_off))
    {
      bool res;
      const struct MHD_UploadAction *act;
      const size_t field_size = *pnext_pos - field_start;

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
      res = mhd_stream_process_upload_action (c, act, false);
      if (c->suspended)
        return true;
      p_data->value_off = 0;
      if (*pdata_size > *pnext_pos)
      {
        memmove (buf + field_start,
                 buf + *pnext_pos,
                 *pdata_size - *pnext_pos);
      }
      *pnext_pos -= field_size;
      *pdata_size -= field_size;
      return res;
    }
  }

  if (0 != value_start)
  {
    value.len = value_len;
    value.cstr = buf + value_start;
  }
  else
  {
    value.len = 0;
    value.cstr = NULL;
  }

  if (! add_parsed_post_field (c,
                               &name,
                               &filename,
                               &content_type,
                               &encoding,
                               &value))
  {
    c->discard_request = true;
    c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
    mhd_LOG_MSG (c->daemon, MHD_SC_REQ_POST_PARSE_FAILED_NO_POOL_MEM, \
                 "The request POST data cannot be parsed completely " \
                 "because there is not enough pool memory.");
    c->rq.u_proc.post.parse_result = MHD_POST_PARSE_RES_FAILED_NO_POOL_MEM;
    return true;
  }

  return false; /* Continue parsing */
}


/**
 * Process new full parsed POST filed
 * @param c the stream to use
 * @param buf the buffer, where the data is
 * @param pnext_pos the pointer to variable holding index on the next position
 *                  to be parsed
 * @param pdata_size the pointer to variable holding the size of the data
 * @param field_start the start of the current field in the @a buf
 * @param name_start the start of the name of the filed in the @a buf
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
                        size_t *restrict pnext_pos,
                        size_t *restrict pdata_size,
                        size_t field_start,
                        size_t name_start,
                        size_t name_len,
                        size_t value_start,
                        size_t value_len)
{
  mhd_assert (value_start + value_len < *pnext_pos);
  mhd_assert ((name_start + name_len < value_start) || \
              (0 == value_start));
  mhd_assert (name_start + name_len < *pnext_pos);
  mhd_assert (field_start <= name_start);
  mhd_assert ((field_start <= value_start) || (0 == value_start));

  mhd_assert (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA != \
              c->rq.u_proc.post.enc);

  return process_complete_field_all (c,
                                     buf,
                                     pnext_pos,
                                     pdata_size,
                                     field_start,
                                     name_start,
                                     name_len,
                                     0, 0, 0, 0, 0, 0,
                                     value_start,
                                     value_len);
}


static MHD_FN_PAR_NONNULL_ALL_ bool
process_partial_value_all (struct MHD_Connection *restrict c,
                           char *restrict buf,
                           size_t *restrict pnext_pos,
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
                           size_t part_value_start,
                           size_t part_value_len)
{
  struct mhd_PostParseActionData *const p_par =
    &(c->rq.app_act.head_act.data.post_parse);
  struct mhd_PostParserData *const p_data = &(c->rq.u_proc.post);

  mhd_assert (*pnext_pos < *pdata_size);
  mhd_assert (part_value_start + part_value_len == *pnext_pos);
  mhd_assert (0 != part_value_start);
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

  p_data->some_data_provided = true;

  if (NULL == p_par->stream_reader)
    return false; /* Continue parsing */

  if ((p_par->auto_stream_size < (*pnext_pos - field_start))
      || (0 != p_data->value_off))
  {
    struct MHD_String name;
    struct MHD_StringNullable filename;
    struct MHD_StringNullable content_type;
    struct MHD_StringNullable encoding;
    const struct MHD_UploadAction *act;
    bool res;

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
  return false; /* Continue parsing */
}


static MHD_FN_PAR_NONNULL_ALL_ bool
process_partial_value (struct MHD_Connection *restrict c,
                       char *restrict buf,
                       size_t *restrict pnext_pos,
                       size_t *restrict pdata_size,
                       size_t field_start,
                       size_t name_start,
                       size_t name_len,
                       size_t part_value_start,
                       size_t part_value_len)
{
  mhd_assert (part_value_start + part_value_len < *pnext_pos);
  mhd_assert (name_start + name_len < part_value_start);
  mhd_assert (0 != part_value_start);
  mhd_assert (name_start + name_len < *pnext_pos);

  mhd_assert (MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA != \
              c->rq.u_proc.post.enc);

  return process_partial_value_all (c,
                                    buf,
                                    pnext_pos,
                                    pdata_size,
                                    field_start,
                                    name_start,
                                    name_len,
                                    0, 0, 0, 0, 0, 0,
                                    part_value_start,
                                    part_value_len);
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

  mhd_assert (MHD_POST_PARSE_RES_OK == c->rq.u_proc.post.parse_result);
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
                  (mhd_POST_TEXT_ST_VALUE != tf->st));
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
      if (mhd_POST_TEXT_ST_AT_LF_BARE == tf->st)
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
        p_data->next_parse_pos = i;
        return true;
      }
      mhd_assert (*pdata_size >= i);
      reset_text_parse_field_data (&(c->rq.u_proc.post));
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
      c->rq.u_proc.post.parse_result =
        MHD_POST_PARSE_RES_PARTIAL_INVALID_POST_FORMAT;
    }
    else
    {
      mhd_LOG_MSG (c->daemon, \
                   MHD_SC_REQ_POST_PARSE_FAILED_INVALID_POST_FORMAT, \
                   "The request POST has broken encoding or format and " \
                   "cannot be parsed.");
      c->rq.u_proc.post.parse_result =
        MHD_POST_PARSE_RES_FAILED_INVALID_POST_FORMAT;
    }
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
      (i != tf->value_idx))
  {
    if (process_partial_value (c,
                               buf,
                               &i,
                               pdata_size,
                               p_data->field_start,
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
  mhd_assert (p_data->lbuf.size >= p_data->lbuf_used);

  // TODO: support process in the connection buffer
  if (NULL == p_data->lbuf.data)
  {
    alloc_failed = ! get_lbuf_fixed_size (c,
                                          *pdata_size + 1,
                                          &(p_data->lbuf));
  }
  else
  {
    size_t space_left;

    mhd_assert (p_data->lbuf.size >= p_data->lbuf_used);
    space_left = p_data->lbuf.size - p_data->lbuf_used;

    if (*pdata_size > space_left)
      alloc_failed = ! grow_lbuf_fixed_size (c,
                                             *pdata_size - space_left + 1,
                                             &(p_data->lbuf));
    else
      alloc_failed = false;

  }
  if (alloc_failed)
  {
    mhd_LOG_MSG (c->daemon, \
                 MHD_SC_REQ_POST_PARSE_FAILED_NO_LARGE_BUF_MEM, \
                 "Not enough large shared buffer memory to " \
                 "parse POST request.");
    c->rq.u_proc.post.parse_result =
      MHD_POST_PARSE_RES_FAILED_NO_LARGE_BUF_MEM;
    c->discard_request = true;
    c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
    return true;
  }
  memcpy (p_data->lbuf.data + p_data->lbuf_used,
          buf,
          *pdata_size);
  p_data->lbuf_used += *pdata_size;
  *pdata_size = 0; /* All data has been moved */

  switch (p_data->enc)
  {
  case MHD_HTTP_POST_ENCODING_FORM_URLENCODED:
    // TODO: finish
    c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
    return true;
  case MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA:
    // TODO: finish
    c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
    return true;
  case MHD_HTTP_POST_ENCODING_TEXT_PLAIN:
    return parse_post_text (c,
                            &(p_data->lbuf_used),
                            p_data->lbuf.data);
  case MHD_HTTP_POST_ENCODING_OTHER:
  default:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    c->rq.u_proc.post.parse_result =
      MHD_POST_PARSE_RES_PARTIAL_INVALID_POST_FORMAT;
    c->discard_request = true;
    c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
    break;
  }
  return true;
}


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

  pos = *pdata_size; /* Points to the char AFTER the data, valid location as buffer is always at least one byte larger */
  mhd_assert (pos == p_data->next_parse_pos);
  mhd_assert (pos < p_data->lbuf.size); // TODO: support processing in connection buffer
  switch (tf->st)
  {
  case mhd_POST_TEXT_ST_NOT_STARTED:
    return false; /* Continue processing */
  case mhd_POST_TEXT_ST_NAME:
    /* Unfinished name */
    name_start = tf->name_idx;
    name_len = pos - name_start;
    buf[pos] = 0; /* Zero-terminate the result, an extra byte is always available */
    value_start = 0;
    value_len = 0;
    break;
  case mhd_POST_TEXT_ST_EQ_FOUND:
    name_start = tf->name_idx;
    name_len = tf->name_len;
    value_start = pos;
    value_len = 0;
    buf[pos] = 0; /* Zero-terminate the result, an extra byte is always available */
    break;
  case mhd_POST_TEXT_ST_VALUE:
    mhd_assert (0 != tf->value_idx);
    mhd_assert (pos != tf->value_idx);
    name_start = tf->name_idx;
    name_len = tf->name_len;
    value_start = tf->value_idx;
    value_len = pos - value_start;
    buf[pos] = 0; /* Zero-terminate the result, an extra byte is always available */
    break;
  case mhd_POST_TEXT_ST_CR_FOUND:
    mhd_assert (0 != tf->value_idx);
    mhd_assert (pos != tf->value_idx);
    name_start = tf->name_idx;
    name_len = tf->name_len;
    value_start = tf->value_idx;
    value_len = tf->value_len;
    mhd_assert (value_start + value_len + 1 == pos);
    mhd_assert (0 == buf[value_start + value_len]);
    break;
  case mhd_POST_TEXT_ST_AT_EQ:
  case mhd_POST_TEXT_ST_AT_LF_BARE:
  case mhd_POST_TEXT_ST_AT_CR:
  case mhd_POST_TEXT_ST_FULL_LINE_FOUND:
  default:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    p_data->parse_result = MHD_POST_PARSE_RES_FAILED_INVALID_POST_FORMAT;
    return false;
  }

  mhd_LOG_MSG (c->daemon, \
               MHD_SC_REQ_POST_PARSE_OK_BAD_TERMINATION, \
               "The request POST has invalid termination / ending. " \
               "The last parsed filed may be incorrect.");
  p_data->parse_result = MHD_POST_PARSE_RES_OK_BAD_TERMINATION;

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

  reset_text_parse_field_data (&(c->rq.u_proc.post));

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
    // TODO: finish
    c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
    return true;
  case MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA:
    // TODO: finish
    c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
    return true;
  case MHD_HTTP_POST_ENCODING_TEXT_PLAIN:
    return check_post_leftovers_text (c,
                                      &(p_data->lbuf_used),
                                      p_data->lbuf.data);
  case MHD_HTTP_POST_ENCODING_OTHER:
  default:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    c->rq.u_proc.post.parse_result =
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

  // TODO: implement processing in the connection buffer
  if (check_post_leftovers (c))
    return true;

  act = c->rq.app_act.head_act.data.post_parse.done_cb (
    &(c->rq),
    c->rq.app_act.head_act.data.post_parse.done_cb_cls,
    p_data->parse_result);

  return mhd_stream_process_upload_action (c, act, true);
}
