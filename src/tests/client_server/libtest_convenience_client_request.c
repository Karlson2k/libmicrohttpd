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
 * @file libtest_convenience.c
 * @brief convenience functions implementing clients making requests for libtest users
 * @author Christian Grothoff
 */
#include <pthread.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "libtest.h"
#include <curl/curl.h>


#ifndef CURL_VERSION_BITS
#  define CURL_VERSION_BITS(x,y,z) ((x) << 16 | (y) << 8 | (z))
#endif
#ifndef CURL_AT_LEAST_VERSION
#  define CURL_AT_LEAST_VERSION(x,y,z) \
        (LIBCURL_VERSION_NUM >= CURL_VERSION_BITS (x, y, z))
#endif

#if CURL_AT_LEAST_VERSION (7,83,0)
#  define HAVE_LIBCRUL_NEW_HDR_API 1
#endif


/**
 * Closure for the write_cb().
 */
struct WriteBuffer
{
  /**
   * Where to store the response.
   */
  char *buf;

  /**
   * Number of bytes in @e buf.
   */
  size_t len;

  /**
   * Current write offset in @e buf.
   */
  size_t pos;

  /**
   * Set to non-zero on errors (buffer full).
   */
  int err;
};


/**
 * Callback for CURLOPT_WRITEFUNCTION processing
 * data downloaded from the HTTP server.
 *
 * @param ptr data uploaded
 * @param size size of a member
 * @param nmemb number of members
 * @param stream must be a `struct WriteBuffer`
 * @return bytes processed (size*nmemb) or error
 */
static size_t
write_cb (void *ptr,
          size_t size,
          size_t nmemb,
          void *stream)
{
  struct WriteBuffer *wb = stream;
  size_t prod = size * nmemb;

  if ( (prod / size != nmemb) ||
       (wb->pos + prod < wb->pos) ||
       (wb->pos + prod > wb->len) )
  {
    wb->err = 1;
    return CURLE_WRITE_ERROR;
  }
  memcpy (wb->buf + wb->pos,
          ptr,
          prod);
  wb->pos += prod;
  return prod;
}


/**
 * Declare variables needed to check a download.
 *
 * @param text text data we expect to receive
 */
#define DECLARE_WB(text) \
        size_t wb_tlen = strlen (text); \
        char wb_buf[wb_tlen];           \
        struct WriteBuffer wb = {       \
          .buf = wb_buf,                \
          .len = wb_tlen                \
        }


/**
 * Set CURL options to the write_cb() and wb buffer
 * to check a download.
 *
 * @param c CURL handle
 */
#define SETUP_WB(c) do {                       \
          if (CURLE_OK !=                              \
              curl_easy_setopt (c,                     \
                                CURLOPT_WRITEFUNCTION, \
                                &write_cb))            \
          {                                            \
            curl_easy_cleanup (c);                     \
            return "Failed to set write callback for curl request"; \
          }                                            \
          if (CURLE_OK !=                              \
              curl_easy_setopt (c,                     \
                                CURLOPT_WRITEDATA,     \
                                &wb))                  \
          {                                            \
            curl_easy_cleanup (c);                     \
            return "Failed to set write buffer for curl request"; \
          }                                                      \
} while (0)

/**
 * Check that we received the expected text.
 *
 * @param text text we expect to have downloaded
 */
#define CHECK_WB(text) do {      \
          if ( (wb_tlen != wb.pos) ||    \
               (0 != wb.err) ||          \
               (0 != memcmp (text,       \
                             wb_buf,     \
                             wb_tlen)) ) \
          return "Downloaded data does not match expectations"; \
} while (0)


/**
 * Perform the curl request @a c and cleanup and
 * return an error if the request failed.
 *
 * @param c request to perform
 */
#define PERFORM_REQUEST(c) do {                  \
          CURLcode res;                          \
          res = curl_easy_perform (c);           \
          if (CURLE_OK != res)                   \
          {                                      \
            curl_easy_cleanup (c);               \
            return "Failed to fetch URL";        \
          }                                      \
} while (0)

/**
 * Check that the curl request @a c completed
 * with the @a want status code.
 * Return an error if the status does not match.
 *
 * @param c request to check
 * @param want desired HTTP status code
 */
#define CHECK_STATUS(c,want) do {                \
          if (! check_status (c, want))          \
          {                                      \
            curl_easy_cleanup (c);               \
            return "Unexpected HTTP status";     \
          }                                      \
} while (0)

/**
 * Chec that the HTTP status of @a c matches @a expected_status
 *
 * @param a completed CURL request
 * @param expected_status the expected HTTP response code
 * @return true if the status matches
 */
static bool
check_status (CURL *c,
              unsigned int expected_status)
{
  long status;

  if (CURLE_OK !=
      curl_easy_getinfo (c,
                         CURLINFO_RESPONSE_CODE,
                         &status))
  {
    fprintf (stderr,
             "Failed to get HTTP status");
    return false;
  }
  if (((unsigned int) status) != expected_status)
  {
    fprintf (stderr,
             "Expected HTTP status %u, got %ld\n",
             expected_status,
             status);
    return false;
  }
  return true;
}


/**
 * Set the @a base_url for the @a c handle.
 *
 * @param[in,out] c curl handle to manipulate
 * @param base_url base URL to set
 * @return true on success, false on failure (@a c will be cleaned up in this case)
 */
static bool
set_url (CURL *c,
         const char *base_url)
{
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_URL,
                        base_url))
  {
    curl_easy_cleanup (c);
    return false;
  }
  if (0 == strncasecmp (base_url,
                        "https://",
                        strlen ("https://")))
  {
    /* disable certificate checking */
    if ( (CURLE_OK !=
          curl_easy_setopt (c,
                            CURLOPT_SSL_VERIFYPEER,
                            0L)) ||
         (CURLE_OK !=
          curl_easy_setopt (c,
                            CURLOPT_SSL_VERIFYHOST,
                            0L)) )
    {
      curl_easy_cleanup (c);
      return false;
    }
  }
  return true;
}


const char *
MHDT_client_get_root (
  const void *cls,
  const struct MHDT_PhaseContext *pc)
{
  const char *text = cls;
  CURL *c;
  DECLARE_WB (text);

  c = curl_easy_init ();
  if (NULL == c)
    return "Failed to initialize Curl handle";
  if (! set_url (c,
                 pc->base_url))
    return "Failed to set URL for curl request";
  SETUP_WB (c);
  PERFORM_REQUEST (c);
  CHECK_STATUS (c, MHD_HTTP_STATUS_OK);
  curl_easy_cleanup (c);
  CHECK_WB (text);
  return NULL;
}


const char *
MHDT_client_get_with_query (
  const void *cls,
  const struct MHDT_PhaseContext *pc)
{
  const char *args = cls;
  size_t alen = strlen (args);
  CURL *c;
  size_t blen = strlen (pc->base_url);
  char u[alen + blen + 1];

  memcpy (u,
          pc->base_url,
          blen);
  memcpy (u + blen,
          args,
          alen);
  u[alen + blen] = '\0';
  c = curl_easy_init ();
  if (NULL == c)
    return "Failed to initialize Curl handle";
  if (! set_url (c,
                 u))
    return "Failed to set URL for curl request";
  PERFORM_REQUEST (c);
  CHECK_STATUS (c,
                MHD_HTTP_STATUS_NO_CONTENT);
  curl_easy_cleanup (c);
  return NULL;
}


const char *
MHDT_client_set_header (
  const void *cls,
  const struct MHDT_PhaseContext *pc)
{
  const char *hdr = cls;
  CURL *c;
  CURLcode res;
  struct curl_slist *slist;

  c = curl_easy_init ();
  if (NULL == c)
    return "Failed to initialize Curl handle";
  if (! set_url (c,
                 pc->base_url))
    return "Failed to set URL for curl request";
  slist = curl_slist_append (NULL,
                             hdr);
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_HTTPHEADER,
                        slist))
  {
    curl_easy_cleanup (c);
    curl_slist_free_all (slist);
    return "Failed to set custom header for curl request";
  }
  res = curl_easy_perform (c);
  curl_slist_free_all (slist);
  if (CURLE_OK != res)
  {
    curl_easy_cleanup (c);
    return "Failed to fetch URL";
  }
  CHECK_STATUS (c,
                MHD_HTTP_STATUS_NO_CONTENT);
  curl_easy_cleanup (c);
  return NULL;
}


const char *
MHDT_client_expect_header (const void *cls,
                           const struct MHDT_PhaseContext *pc)
{
#ifdef HAVE_LIBCRUL_NEW_HDR_API
  const char *hdr = cls;
  size_t hlen = strlen (hdr) + 1;
  char key[hlen];
  const char *colon = strchr (hdr, ':');
  const char *value;
  CURL *c;
  bool found = false;

  if (NULL == colon)
    return "Invalid expected header passed";
  memcpy (key,
          hdr,
          hlen);
  key[colon - hdr] = '\0';
  value = &key[colon - hdr + 1];
  c = curl_easy_init ();
  if (NULL == c)
    return "Failed to initialize Curl handle";
  if (! set_url (c,
                 pc->base_url))
    return "Failed to set URL for curl request";
  PERFORM_REQUEST (c);
  CHECK_STATUS (c,
                MHD_HTTP_STATUS_NO_CONTENT);
  for (size_t index = 0; ! found; index++)
  {
    CURLHcode rval;
    struct curl_header *hout;

    rval = curl_easy_header (c,
                             key,
                             index,
                             CURLH_HEADER,
                             -1 /* last request */,
                             &hout);
    if (CURLHE_BADINDEX == rval)
      break;
    found = (0 == strcmp (value,
                          hout->value));
  }
  if (! found)
  {
    curl_easy_cleanup (c);
    return "Expected HTTP response header not found";
  }
  curl_easy_cleanup (c);
  return NULL;
#else  /* ! HAVE_LIBCRUL_NEW_HDR_API */
  (void) cls; (void) pc;
  return NULL;
#endif /* ! HAVE_LIBCRUL_NEW_HDR_API */
}


/**
 * Closure for the read_cb().
 */
struct ReadBuffer
{
  /**
   * Origin of data to upload.
   */
  const char *buf;

  /**
   * Number of bytes in @e buf.
   */
  size_t len;

  /**
   * Current read offset in @e buf.
   */
  size_t pos;

  /**
   * Number of chunks to user when sending.
   */
  unsigned int chunks;

};


/**
 * Callback for CURLOPT_READFUNCTION for uploading
 * data to the HTTP server.
 *
 * @param ptr data uploaded
 * @param size size of a member
 * @param nmemb number of members
 * @param stream must be a `struct ReadBuffer`
 * @return bytes processed (size*nmemb) or error
 */
static size_t
read_cb (void *ptr,
         size_t size,
         size_t nmemb,
         void *stream)
{
  struct ReadBuffer *rb = stream;
  size_t limit = size * nmemb;

  if (limit / size != nmemb)
    return CURLE_WRITE_ERROR;
  if (limit > rb->len - rb->pos)
    limit = rb->len - rb->pos;
  if ( (rb->chunks > 1) &&
       (limit > 1) )
  {
    limit /= rb->chunks;
    rb->chunks--;
  }
  memcpy (ptr,
          rb->buf + rb->pos,
          limit);
  rb->pos += limit;
  return limit;
}


const char *
MHDT_client_put_data (
  const void *cls,
  const struct MHDT_PhaseContext *pc)
{
  const char *text = cls;
  struct ReadBuffer rb = {
    .buf = text,
    .len = strlen (text)
  };
  CURL *c;

  c = curl_easy_init ();
  if (NULL == c)
    return "Failed to initialize Curl handle";
  if (! set_url (c,
                 pc->base_url))
    return "Failed to set URL for curl request";
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_UPLOAD,
                        1L))
  {
    curl_easy_cleanup (c);
    return "Failed to set PUT method for curl request";
  }
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_READFUNCTION,
                        &read_cb))
  {
    curl_easy_cleanup (c);
    return "Failed to set READFUNCTION for curl request";
  }
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_READDATA,
                        &rb))
  {
    curl_easy_cleanup (c);
    return "Failed to set READFUNCTION for curl request";
  }
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_INFILESIZE_LARGE,
                        (curl_off_t) rb.len))
  {
    curl_easy_cleanup (c);
    return "Failed to set INFILESIZE_LARGE for curl request";
  }
  PERFORM_REQUEST (c);
  CHECK_STATUS (c,
                MHD_HTTP_STATUS_NO_CONTENT);
  curl_easy_cleanup (c);
  return NULL;
}


const char *
MHDT_client_chunk_data (
  const void *cls,
  const struct MHDT_PhaseContext *pc)
{
  const char *text = cls;
  struct ReadBuffer rb = {
    .buf = text,
    .len = strlen (text),
    .chunks = 2
  };
  CURL *c;

  c = curl_easy_init ();
  if (NULL == c)
    return "Failed to initialize Curl handle";
  if (! set_url (c,
                 pc->base_url))
    return "Failed to set URL for curl request";
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_UPLOAD,
                        1L))
  {
    curl_easy_cleanup (c);
    return "Failed to set PUT method for curl request";
  }
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_READFUNCTION,
                        &read_cb))
  {
    curl_easy_cleanup (c);
    return "Failed to set READFUNCTION for curl request";
  }
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_READDATA,
                        &rb))
  {
    curl_easy_cleanup (c);
    return "Failed to set READFUNCTION for curl request";
  }
  PERFORM_REQUEST (c);
  CHECK_STATUS (c,
                MHD_HTTP_STATUS_NO_CONTENT);
  curl_easy_cleanup (c);
  return NULL;
}


const char *
MHDT_client_do_post (
  const void *cls,
  const struct MHDT_PhaseContext *pc)
{
  const struct MHDT_PostInstructions *pi = cls;
  CURL *c;
  struct curl_slist *request_hdr = NULL;

  /* reset wants in case we re-use the array */
  if (NULL != pi->wants)
  {
    for (unsigned int i = 0; NULL != pi->wants[i].key; i++)
    {
      pi->wants[i].value_off = 0;
      pi->wants[i].satisfied = false;
    }
  }
  c = curl_easy_init ();
  if (NULL == c)
    return "Failed to initialize Curl handle";
  if (! set_url (c,
                 pc->base_url))
    return "Failed to set URL for curl request";
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_POST,
                        1L))
  {
    curl_easy_cleanup (c);
    return "Failed to set POST method for curl request";
  }
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_POSTFIELDS,
                        pi->postdata))
  {
    curl_easy_cleanup (c);
    return "Failed to set POSTFIELDS for curl request";
  }
  if (0 != pi->postdata_size)
  {
    if (CURLE_OK !=
        curl_easy_setopt (c,
                          CURLOPT_POSTFIELDSIZE_LARGE,
                          (curl_off_t) pi->postdata_size))
    {
      curl_easy_cleanup (c);
      return "Failed to set POSTFIELDS for curl request";
    }
  }
  if (NULL != pi->postheader)
  {
    request_hdr = curl_slist_append (request_hdr,
                                     pi->postheader);
  }
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_HTTPHEADER,
                        request_hdr))
  {
    curl_easy_cleanup (c);
    curl_slist_free_all (request_hdr);
    return "Failed to set HTTPHEADER for curl request";
  }
  PERFORM_REQUEST (c);
  CHECK_STATUS (c,
                MHD_HTTP_STATUS_NO_CONTENT);
  curl_easy_cleanup (c);
  curl_slist_free_all (request_hdr);
  if (NULL != pi->wants)
  {
    for (unsigned int i = 0; NULL != pi->wants[i].key; i++)
    {
      if (! pi->wants[i].satisfied)
      {
        fprintf (stderr,
                 "Server did not correctly detect key '%s'\n",
                 pi->wants[i].key);
        return "key-value data not matched by server";
      }
    }
  }
  return NULL;
}
