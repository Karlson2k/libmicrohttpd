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
#include "microhttpd2.h"
#include "libtest.h"
#include <curl/curl.h>

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
  if (status != expected_status)
  {
    fprintf (stderr,
             "Expected HTTP status %u, got %ld\n",
             expected_status,
             status);
    return false;
  }
  return true;
}


const char *
MHDT_client_get_root (
  void *cls,
  const struct MHDT_PhaseContext *pc)
{
  const char *text = cls;
  CURL *c;
  DECLARE_WB (text);

  c = curl_easy_init ();
  if (NULL == c)
    return "Failed to initialize Curl handle";
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_URL,
                        pc->base_url))
  {
    curl_easy_cleanup (c);
    return "Failed to set URL for curl request";
  }
  SETUP_WB (c);
  PERFORM_REQUEST (c);
  CHECK_STATUS (c, MHD_HTTP_STATUS_OK);
  curl_easy_cleanup (c);
  CHECK_WB (text);
  return NULL;
}


const char *
MHDT_client_get_with_query (
  void *cls,
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

  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_URL,
                        u))
  {
    curl_easy_cleanup (c);
    return "Failed to set URL for curl request";
  }
  PERFORM_REQUEST (c);
  CHECK_STATUS (c,
                MHD_HTTP_STATUS_NO_CONTENT);
  curl_easy_cleanup (c);
  return NULL;
}


const char *
MHDT_client_set_header (void *cls,
                        const struct MHDT_PhaseContext *pc)
{
  const char *hdr = cls;
  CURL *c;
  CURLcode res;
  struct curl_slist *slist;

  c = curl_easy_init ();
  if (NULL == c)
    return "Failed to initialize Curl handle";
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_URL,
                        pc->base_url))
  {
    curl_easy_cleanup (c);
    return "Failed to set URL for curl request";
  }
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
MHDT_client_expect_header (void *cls,
                           const struct MHDT_PhaseContext *pc)
{
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
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_URL,
                        pc->base_url))
  {
    curl_easy_cleanup (c);
    return "Failed to set URL for curl request";
  }
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
  void *cls,
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
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_URL,
                        pc->base_url))
  {
    curl_easy_cleanup (c);
    return "Failed to set URL for curl request";
  }
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
  void *cls,
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
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_URL,
                        pc->base_url))
  {
    curl_easy_cleanup (c);
    return "Failed to set URL for curl request";
  }
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
