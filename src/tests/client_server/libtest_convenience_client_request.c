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
 * @file libtest_convenience_client_request.c
 * @brief convenience functions implementing clients making requests for libtest users
 * @author Christian Grothoff
 */
#include "libtest.h"
#include <pthread.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
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
 * @param[in,out] pc phase context with further options
 * @return NULL on success, error message on failure (@a c will be cleaned up in this case)
 */
static const char *
set_url (CURL *c,
         const char *base_url,
         struct MHDT_PhaseContext *pc)
{
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_URL,
                        base_url))
  {
    curl_easy_cleanup (c);
    return "Failed to set URL";
  }
  if (CURLE_OK !=
      curl_easy_setopt (c,
                        CURLOPT_VERBOSE,
                        1))
  {
    curl_easy_cleanup (c);
    return "Failed to set verbosity";
  }
  {
    /* Force curl to do the request to 127.0.0.1 regardless of
       hostname */
    const char *host;
    const char *end;
    char ri[1024];

    if (0 == strncasecmp (base_url,
                          "https://",
                          strlen ("https://")))
      host = &base_url[strlen ("https://")];
    else
      host = &base_url[strlen ("http://")];
    end = strchr (host, '/');
    if (NULL == end)
      end = host + strlen (host);
    snprintf (ri,
              sizeof (ri),
              "%.*s:127.0.0.1",
              (int) (end - host),
              host);
    pc->hosts = curl_slist_append (NULL,
                                   ri);
    if (CURLE_OK !=
        curl_easy_setopt (c,
                          CURLOPT_RESOLVE,
                          pc->hosts))
    {
      curl_easy_cleanup (c);
      return "Failed to override DNS";
    }
  }
  if (0 == strncasecmp (base_url,
                        "https://",
                        strlen ("https://")))
  {
    struct MHDT_Phase *phase = pc->phase;

    if (phase->check_server_cert)
    {
      if (CURLE_OK !=
          curl_easy_setopt (c,
                            CURLOPT_CAINFO,
                            "data/root-ca.crt"))
      {
        curl_easy_cleanup (c);
        return "Failed to override root CA";
      }
    }
    else
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
        return "Failed to disable X509 server certificate checks";
      }
    }
    if (NULL != phase->client_cert)
    {
      if (CURLE_OK !=
          curl_easy_setopt (c,
                            CURLOPT_SSLCERT,
                            phase->client_cert))
      {
        curl_easy_cleanup (c);
        return "Failed to set client certificate";
      }
    }
  }
  return NULL;
}


const char *
MHDT_client_get_host (const void *cls,
                      struct MHDT_PhaseContext *pc)
{
  const char *host = cls;
  const char *err;
  size_t alen = strlen (host);
  CURL *c;
  size_t blen = strlen (pc->base_url);
  char u[alen + blen + 1];
  const char *slash = strchr (pc->base_url,
                              '/');
  const char *colon;

  if (NULL == slash)
    return "'/' missing in base URL";
  colon = strchr (slash,
                  ':');
  if (NULL == colon)
    return "':' missing in base URL";
  snprintf (u,
            sizeof (u),
            "https://%s%s",
            host,
            colon);
  c = curl_easy_init ();
  if (NULL == c)
    return "Failed to initialize Curl handle";
  err = set_url (c,
                 u,
                 pc);
  if (NULL != err)
    return err;
  PERFORM_REQUEST (c);
  CHECK_STATUS (c,
                MHD_HTTP_STATUS_OK);
  curl_easy_cleanup (c);
  return NULL;
}


const char *
MHDT_client_get_root (
  const void *cls,
  struct MHDT_PhaseContext *pc)
{
  const char *text = cls;
  CURL *c;
  const char *err;
  DECLARE_WB (text);

  c = curl_easy_init ();
  if (NULL == c)
    return "Failed to initialize Curl handle";
  err = set_url (c,
                 pc->base_url,
                 pc);
  if (NULL != err)
    return err;
  SETUP_WB (c);
  PERFORM_REQUEST (c);
  CHECK_STATUS (c,
                MHD_HTTP_STATUS_OK);
  curl_easy_cleanup (c);
  CHECK_WB (text);
  return NULL;
}


const char *
MHDT_client_get_with_query (
  const void *cls,
  struct MHDT_PhaseContext *pc)
{
  const char *args = cls;
  const char *err;
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
  err = set_url (c,
                 u,
                 pc);
  if (NULL != err)
    return err;
  PERFORM_REQUEST (c);
  CHECK_STATUS (c,
                MHD_HTTP_STATUS_NO_CONTENT);
  curl_easy_cleanup (c);
  return NULL;
}


const char *
MHDT_client_set_header (
  const void *cls,
  struct MHDT_PhaseContext *pc)
{
  const char *hdr = cls;
  const char *err;
  CURL *c;
  CURLcode res;
  struct curl_slist *slist;

  c = curl_easy_init ();
  if (NULL == c)
    return "Failed to initialize Curl handle";
  err = set_url (c,
                 pc->base_url,
                 pc);
  if (NULL != err)
    return err;
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
                           struct MHDT_PhaseContext *pc)
{
#ifdef HAVE_LIBCRUL_NEW_HDR_API
  const char *hdr = cls;
  const char *err;
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
  err = set_url (c,
                 pc->base_url,
                 pc);
  if (NULL != err)
    return err;
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
  struct MHDT_PhaseContext *pc)
{
  const char *text = cls;
  const char *err;
  struct ReadBuffer rb = {
    .buf = text,
    .len = strlen (text)
  };
  CURL *c;

  c = curl_easy_init ();
  if (NULL == c)
    return "Failed to initialize Curl handle";
  err = set_url (c,
                 pc->base_url,
                 pc);
  if (NULL != err)
    return err;
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
  struct MHDT_PhaseContext *pc)
{
  const char *text = cls;
  const char *err;
  struct ReadBuffer rb = {
    .buf = text,
    .len = strlen (text),
    .chunks = 2
  };
  CURL *c;

  c = curl_easy_init ();
  if (NULL == c)
    return "Failed to initialize Curl handle";
  err = set_url (c,
                 pc->base_url,
                 pc);
  if (NULL != err)
    return err;
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
  struct MHDT_PhaseContext *pc)
{
  const struct MHDT_PostInstructions *pi = cls;
  const char *err;
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
  err = set_url (c,
                 pc->base_url,
                 pc);
  if (NULL != err)
    return err;
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


/**
 * Send HTTP request with basic authentication.
 *
 * @param cred $USERNAME:$PASSWORD to use
 * @param[in,out] phase context
 * @param[out] http_status set to HTTP status
 * @return error message, NULL on success
 */
static const char *
send_basic_auth (const char *cred,
                 struct MHDT_PhaseContext *pc,
                 unsigned int *http_status)
{
  CURL *c;
  const char *err;
  long status;
  char *pass = strchr (cred, ':');
  char *user;

  if (NULL == pass)
    return "invalid credential given";
  user = strndup (cred,
                  pass - cred);
  pass++;
  c = curl_easy_init ();
  if (NULL == c)
  {
    free (user);
    return "Failed to initialize Curl handle";
  }
  err = set_url (c,
                 pc->base_url,
                 pc);
  if (NULL != err)
  {
    free (user);
    curl_easy_cleanup (c);
    return err;
  }
  if ( (CURLE_OK !=
        curl_easy_setopt (c,
                          CURLOPT_HTTPAUTH,
                          (long) CURLAUTH_BASIC)) ||
       (CURLE_OK !=
        curl_easy_setopt (c,
                          CURLOPT_USERNAME,
                          user)) ||
       (CURLE_OK !=
        curl_easy_setopt (c,
                          CURLOPT_PASSWORD,
                          pass)) )
  {
    curl_easy_cleanup (c);
    free (user);
    return "Failed to set basic authentication header for curl request";
  }
  free (user);
  PERFORM_REQUEST (c);
  if (CURLE_OK !=
      curl_easy_getinfo (c,
                         CURLINFO_RESPONSE_CODE,
                         &status))
  {
    return "Failed to get HTTP status";
  }
  *http_status = (unsigned int) status;
  curl_easy_cleanup (c);
  return NULL;
}


const char *
MHDT_client_send_basic_auth (
  const void *cls,
  struct MHDT_PhaseContext *pc)
{
  const char *cred = cls;
  const char *ret;
  unsigned int status;

  ret = send_basic_auth (cred,
                         pc,
                         &status);
  if (NULL != ret)
    return ret;
  if (MHD_HTTP_STATUS_NO_CONTENT != status)
    return "invalid HTTP response code";
  return NULL;
}


const char *
MHDT_client_fail_basic_auth (
  const void *cls,
  struct MHDT_PhaseContext *pc)
{
  const char *cred = cls;
  const char *ret;
  unsigned int status;

  ret = send_basic_auth (cred,
                         pc,
                         &status);
  if (NULL != ret)
    return ret;
  if (MHD_HTTP_STATUS_UNAUTHORIZED != status)
    return "invalid HTTP response code";
  return NULL;
}


/**
 * Send HTTP request with digest authentication.
 *
 * @param cred $USERNAME:$PASSWORD to use
 * @param[in,out] phase context
 * @param[out] http_status set to HTTP status
 * @return error message, NULL on success
 */
static const char *
send_digest_auth (const char *cred,
                  struct MHDT_PhaseContext *pc,
                  unsigned int *http_status)
{
  CURL *c;
  const char *err;
  long status;
  char *pass = strchr (cred, ':');
  char *user;

  if (NULL == pass)
    return "invalid credential given";
  user = strndup (cred,
                  pass - cred);
  pass++;
  c = curl_easy_init ();
  if (NULL == c)
  {
    free (user);
    return "Failed to initialize Curl handle";
  }
  err = set_url (c,
                 pc->base_url,
                 pc);
  if (NULL != err)
  {
    free (user);
    curl_easy_cleanup (c);
    return err;
  }
  if ( (CURLE_OK !=
        curl_easy_setopt (c,
                          CURLOPT_HTTPAUTH,
                          (long) CURLAUTH_DIGEST)) ||
       (CURLE_OK !=
        curl_easy_setopt (c,
                          CURLOPT_USERNAME,
                          user)) ||
       (CURLE_OK !=
        curl_easy_setopt (c,
                          CURLOPT_PASSWORD,
                          pass)) )
  {
    curl_easy_cleanup (c);
    free (user);
    return "Failed to set digest authentication header for curl request";
  }
  free (user);
  PERFORM_REQUEST (c);
  if (CURLE_OK !=
      curl_easy_getinfo (c,
                         CURLINFO_RESPONSE_CODE,
                         &status))
  {
    return "Failed to get HTTP status";
  }
  *http_status = (unsigned int) status;
  curl_easy_cleanup (c);
  return NULL;
}


const char *
MHDT_client_send_digest_auth (
  const void *cls,
  struct MHDT_PhaseContext *pc)
{
  const char *cred = cls;
  const char *ret;
  unsigned int status;

  ret = send_digest_auth (cred,
                          pc,
                          &status);
  if (NULL != ret)
    return ret;
  if (MHD_HTTP_STATUS_NO_CONTENT != status)
    return "invalid HTTP response code";
  return NULL;
}


const char *
MHDT_client_fail_digest_auth (
  const void *cls,
  struct MHDT_PhaseContext *pc)
{
  const char *cred = cls;
  const char *ret;
  unsigned int status;

  ret = send_digest_auth (cred,
                          pc,
                          &status);
  if (NULL != ret)
    return ret;
  if (MHD_HTTP_STATUS_UNAUTHORIZED != status)
    return "invalid HTTP response code";
  return NULL;
}
