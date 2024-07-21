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
      if (NULL == val)
      {
        if (NULL != sn->cstr)
        {
          fprintf (stderr,
                   "NULL expected for query key %s, got %s\n",
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
                   "%s expected for query key %s, got NULL\n",
                   val,
                   arg);
          return NULL;
        }
        if (0 != strcmp (val,
                         sn->cstr))
        {
          fprintf (stderr,
                   "%s expected for query key %s, got %s\n",
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
               "Missing expected client header `%s'\n",
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
