/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Christian Grothoff

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
 * @file libtest_convenience_server_reply.c
 * @brief convenience functions that generate
 *   replies from the server for libtest users
 * @author Christian Grothoff
 */
#include <pthread.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "microhttpd2.h"
#include "libtest.h"
#include <curl/curl.h>


const struct MHD_Action *
MHDT_server_reply_text (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size)
{
  const char *text = cls;

  return MHD_action_from_response (
    request,
    MHD_response_from_buffer_static (MHD_HTTP_STATUS_OK,
                                     strlen (text),
                                     text));
}


const struct MHD_Action *
MHDT_server_reply_file (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size)
{
  const char *text = cls;
  size_t tlen = strlen (text);
  char fn[] = "/tmp/mhd-test-XXXXXX";
  int fd;

  fd = mkstemp (fn);
  if (-1 == fd)
  {
    fprintf (stderr,
             "Failed to mkstemp() temporary file\n");
    return NULL;
  }
  if (tlen != write (fd, text, tlen))
  {
    fprintf (stderr,
             "Failed to write() temporary file in one go: %s\n",
             strerror (errno));
    return NULL;
  }
  fsync (fd);
  if (0 != remove (fn))
  {
    fprintf (stderr,
             "Failed to remove() temporary file %s: %s\n",
             fn,
             strerror (errno));
  }
  return MHD_action_from_response (
    request,
    MHD_response_from_fd (MHD_HTTP_STATUS_OK,
                          fd,
                          0 /* offset */,
                          tlen));
}


const struct MHD_Action *
MHDT_server_reply_with_header (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size)
{
  const char *header = cls;
  size_t hlen = strlen (header) + 1;
  char name[hlen];
  const char *colon = strchr (header, ':');
  const char *value;
  struct MHD_Response *resp;

  memcpy (name,
          header,
          hlen);
  name[colon - header] = '\0';
  value = &name[colon - header + 1];

  resp = MHD_response_from_empty (MHD_HTTP_STATUS_NO_CONTENT);
  if (MHD_SC_OK !=
      MHD_response_add_header (resp,
                               name,
                               value))
    return NULL;
  return MHD_action_from_response (
    request,
    resp);
}


const struct MHD_Action *
MHDT_server_reply_check_query (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size)
{
  const char *equery = cls;
  size_t qlen = strlen (equery) + 1;
  char qc[qlen];

  memcpy (qc,
          equery,
          qlen);
  for (const char *tok = strtok (qc, "&");
       NULL != tok;
       tok = strtok (NULL, "&"))
  {
    const char *end;
    const struct MHD_StringNullable *sn;
    const char *val;

    end = strchr (tok, '=');
    if (NULL == end)
    {
      end = &tok[strlen (tok)];
      val = NULL;
    }
    else
    {
      val = end + 1;
    }
    {
      size_t alen = end - tok;
      char arg[alen + 1];

      memcpy (arg,
              tok,
              alen);
      arg[alen] = '\0';
      sn = MHD_request_get_value (request,
                                  MHD_VK_GET_ARGUMENT,
                                  arg);
      if (NULL == sn)
      {
        fprintf (stderr,
                 "NULL returned for query key %s\n",
                 arg);
        return NULL;
      }
      if (NULL == val)
      {
        if (NULL != sn->cstr)
        {
          fprintf (stderr,
                   "NULL expected for value for query key %s, got %s\n",
                   arg,
                   sn->cstr);
          return NULL;
        }
      }
      else
      {
        if (NULL == sn->cstr)
        {
          fprintf (stderr,
                   "%s expected for value for query key %s, got NULL\n",
                   val,
                   arg);
          return NULL;
        }
        if (0 != strcmp (val,
                         sn->cstr))
        {
          fprintf (stderr,
                   "%s expected for value for query key %s, got %s\n",
                   val,
                   arg,
                   sn->cstr);
          return NULL;
        }
      }
    }
  }

  return MHD_action_from_response (
    request,
    MHD_response_from_empty (
      MHD_HTTP_STATUS_NO_CONTENT));
}


const struct MHD_Action *
MHDT_server_reply_check_header (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size)
{
  const char *want = cls;
  size_t wlen = strlen (want) + 1;
  char key[wlen];
  const char *colon = strchr (want, ':');
  const struct MHD_StringNullable *have;
  const char *value;

  memcpy (key,
          want,
          wlen);
  if (NULL != colon)
  {
    key[colon - want] = '\0';
    value = &key[colon - want + 1];
  }
  else
  {
    value = NULL;
  }
  have = MHD_request_get_value (request,
                                MHD_VK_HEADER,
                                key);
  if (NULL == have)
  {
    fprintf (stderr,
             "Missing client header `%s'\n",
             want);
    return NULL;
  }
  if (NULL == value)
  {
    if (NULL != have->cstr)
    {
      fprintf (stderr,
               "Have unexpected client header `%s': `%s'\n",
               key,
               have->cstr);
      return NULL;
    }
  }
  else
  {
    if (NULL == have->cstr)
    {
      fprintf (stderr,
               "Missing value for client header `%s'\n",
               want);
      return NULL;
    }
    if (0 != strcmp (have->cstr,
                     value))
    {
      fprintf (stderr,
               "Client HTTP header `%s' was expected to be `%s' but is `%s'\n",
               key,
               value,
               have->cstr);
      return NULL;
    }
  }
  return MHD_action_from_response (
    request,
    MHD_response_from_empty (
      MHD_HTTP_STATUS_NO_CONTENT));
}


/**
 * Function to process data uploaded by a client.
 *
 * @param cls the payload we expect to be uploaded as a 0-terminated string
 * @param request the request is being processed
 * @param content_data_size the size of the @a content_data,
 *                          zero when all data have been processed
 * @param[in] content_data the uploaded content data,
 *                         may be modified in the callback,
 *                         valid only until return from the callback,
 *                         NULL when all data have been processed
 * @return action specifying how to proceed:
 *         #MHD_upload_action_continue() to continue upload (for incremental
 *         upload processing only),
 *         #MHD_upload_action_suspend() to stop reading the upload until
 *         the request is resumed,
 *         #MHD_upload_action_abort_request() to close the socket,
 *         or a response to discard the rest of the upload and transmit
 *         the response
 * @ingroup action
 */
static const struct MHD_UploadAction *
check_upload_cb (void *cls,
                 struct MHD_Request *request,
                 size_t content_data_size,
                 void *content_data)
{
  const char *want = cls;
  size_t wlen = strlen (want);

  if (content_data_size != wlen)
  {
    fprintf (stderr,
             "Invalid body size given to full upload callback\n");
    return NULL;
  }
  if (0 != memcmp (want,
                   content_data,
                   wlen))
  {
    fprintf (stderr,
             "Invalid body data given to full upload callback\n");
    return NULL;
  }
  /* success! */
  return MHD_upload_action_from_response (
    request,
    MHD_response_from_empty (
      MHD_HTTP_STATUS_NO_CONTENT));
}


const struct MHD_Action *
MHDT_server_reply_check_upload (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size)
{
  const char *want = cls;
  size_t wlen = strlen (want);

  return MHD_action_process_upload_full (request,
                                         wlen,
                                         &check_upload_cb,
                                         (void *) want);
}


/**
 * Closure for #chunk_return.
 */
struct ChunkContext
{
  /**
   * Where we are in the buffer.
   */
  const char *pos;
};


/**
 * Function that returns a string in chunks.
 *
 * @param dyn_cont_cls must be a `struct ChunkContext`
 * @param ctx the context to produce the action to return,
 *            the pointer is only valid until the callback returns
 * @param pos position in the datastream to access;
 *        note that if a `struct MHD_Response` object is re-used,
 *        it is possible for the same content reader to
 *        be queried multiple times for the same data;
 *        however, if a `struct MHD_Response` is not re-used,
 *        libmicrohttpd guarantees that "pos" will be
 *        the sum of all data sizes provided by this callback
 * @param[out] buf where to copy the data
 * @param max maximum number of bytes to copy to @a buf (size of @a buf)
 * @return action to use,
 *         NULL in case of any error (the response will be aborted)
 */
static const struct MHD_DynamicContentCreatorAction *
chunk_return (void *cls,
              struct MHD_DynamicContentCreatorContext *ctx,
              uint_fast64_t pos,
              void *buf,
              size_t max)
{
  struct ChunkContext *cc = cls;
  size_t imax = strlen (cc->pos);
  const char *space = strchr (cc->pos, ' ');

  if (0 == imax)
    return MHD_DCC_action_finish (ctx);
  if (NULL != space)
    imax = space - cc->pos + 1;
  if (imax > max)
    imax = max;
  memcpy (buf,
          cc->pos,
          imax);
  cc->pos += imax;
  return MHD_DCC_action_continue (ctx,
                                  imax);
}


const struct MHD_Action *
MHDT_server_reply_chunked_text (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size)
{
  const char *text = cls;
  struct ChunkContext *cc;

  cc = malloc (sizeof (struct ChunkContext));
  if (NULL == cc)
    return NULL;
  cc->pos = text;

  return MHD_action_from_response (
    request,
    MHD_response_from_callback (MHD_HTTP_STATUS_OK,
                                MHD_SIZE_UNKNOWN,
                                &chunk_return,
                                cc,
                                &free));
}
