/*
 This file is part of libmicrohttpd
 (C) 2007 Christian Grothoff

 libmicrohttpd is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published
 by the Free Software Foundation; either version 2, or (at your
 option) any later version.

 libmicrohttpd is distributed in the hope that it will be useful, but
 WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with libmicrohttpd; see the file COPYING.  If not, write to the
 Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 Boston, MA 02111-1307, USA.
 */

/**
 * @file mhds_multi_daemon_test.c
 * @brief  Testcase for libmicrohttpd multiple HTTPS daemon scenario
 * @author Sagie Amir
 */

#include "config.h"
#include "plibc.h"
#include "microhttpsd.h"
#include <errno.h>

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define PAGE_NOT_FOUND "<html><head><title>File not found</title></head><body>File not found</body></html>"

#define MHD_E_SERVER_INIT "Error: failed to start server\n"
#define MHD_E_TEST_FILE_CREAT "Error: failed to setup test file\n"

#include "tls_test_keys.h"

const char *test_file_name = "https_test_file";
const char test_file_data[] = "Hello World\n";

struct CBC
{
  char *buf;
  size_t pos;
  size_t size;
};

static size_t
copyBuffer (void *ptr, size_t size, size_t nmemb, void *ctx)
{
  struct CBC *cbc = ctx;

  if (cbc->pos + size * nmemb > cbc->size)
    return 0;                   /* overflow */
  memcpy (&cbc->buf[cbc->pos], ptr, size * nmemb);
  cbc->pos += size * nmemb;
  return size * nmemb;
}

static int
file_reader (void *cls, size_t pos, char *buf, int max)
{
  FILE *file = cls;
  fseek (file, pos, SEEK_SET);
  return fread (buf, 1, max, file);
}

/* HTTP access handler call back */
static int
http_ahc (void *cls, struct MHD_Connection *connection,
          const char *url, const char *method, const char *upload_data,
          const char *version, unsigned int *upload_data_size, void **ptr)
{
  static int aptr;
  struct MHD_Response *response;
  int ret;
  FILE *file;
  struct stat buf;

  /* TODO never respond on first call */
  if (0 != strcmp (method, MHD_HTTP_METHOD_GET))
    return MHD_NO;              /* unexpected method */
  if (&aptr != *ptr)
    {
      /* do never respond on first call */
      *ptr = &aptr;
      return MHD_YES;
    }
  *ptr = NULL;                  /* reset when done */

  file = fopen (url, "r");
  if (file == NULL)
    {
      response = MHD_create_response_from_data (strlen (PAGE_NOT_FOUND),
                                                (void *) PAGE_NOT_FOUND,
                                                MHD_NO, MHD_NO);
      ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
      MHD_destroy_response (response);
    }
  else
    {
      stat (url, &buf);
      response = MHD_create_response_from_callback (buf.st_size, 32 * 1024,     /* 32k PAGE_NOT_FOUND size */
                                                    &file_reader, file,
                                                    (MHD_ContentReaderFreeCallback)
                                                    & fclose);
      ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
      MHD_destroy_response (response);
    }
  return ret;
}

/*
 * perform cURL request for file
 * @param test_fd: file to attempt transferring
 */
static int
test_daemon_get (FILE * test_fd, char *cipher_suite, int proto_version,
                 int port)
{
  CURL *c;
  struct CBC cbc;
  CURLcode errornum;
  char *doc_path;
  char url[255];
  size_t len;
  struct stat file_stat;

  stat (test_file_name, &file_stat);
  len = file_stat.st_size;

  /* used to memcmp local copy & deamon supplied copy */
  unsigned char *mem_test_file_local;

  /* setup test file path, url */
  doc_path = get_current_dir_name ();

  mem_test_file_local = malloc (len);
  fseek (test_fd, 0, SEEK_SET);
  if (fread (mem_test_file_local, sizeof (char), len, test_fd) != len)
    {
      fclose (test_fd);
      fprintf (stderr, "Error: failed to read test file. %s\n",
               strerror (errno));
      return -1;
    }

  if (NULL == (cbc.buf = malloc (sizeof (char) * len)))
    {
      fclose (test_fd);
      fprintf (stderr, "Error: failed to read test file. %s\n",
               strerror (errno));
      return -1;
    }
  cbc.size = len;
  cbc.pos = 0;

  /* construct url */
  sprintf (url, "%s:%d%s/%s", "https://localhost", port, doc_path,
           test_file_name);

  c = curl_easy_init ();
#ifdef DEBUG
  curl_easy_setopt (c, CURLOPT_VERBOSE, 1);
#endif
  curl_easy_setopt (c, CURLOPT_URL, url);
  curl_easy_setopt (c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
  curl_easy_setopt (c, CURLOPT_TIMEOUT, 10L);
  curl_easy_setopt (c, CURLOPT_CONNECTTIMEOUT, 10L);
  curl_easy_setopt (c, CURLOPT_WRITEFUNCTION, &copyBuffer);
  curl_easy_setopt (c, CURLOPT_FILE, &cbc);

  /* TLS options */
  curl_easy_setopt (c, CURLOPT_SSLVERSION, proto_version);
  curl_easy_setopt (c, CURLOPT_SSL_CIPHER_LIST, cipher_suite);

  /* currently skip any peer authentication */
  curl_easy_setopt (c, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt (c, CURLOPT_SSL_VERIFYHOST, 0);

  curl_easy_setopt (c, CURLOPT_FAILONERROR, 1);

  // NOTE: use of CONNECTTIMEOUT without also
  //   setting NOSIGNAL results in really weird
  //   crashes on my system!
  curl_easy_setopt (c, CURLOPT_NOSIGNAL, 1);
  if (CURLE_OK != (errornum = curl_easy_perform (c)))
    {
      fprintf (stderr, "curl_easy_perform failed: `%s'\n",
               curl_easy_strerror (errornum));
      curl_easy_cleanup (c);
      return errornum;
    }

  curl_easy_cleanup (c);

  /* compare received file and local reference */
  if (memcmp (cbc.buf, mem_test_file_local, len) != 0)
    {
      fprintf (stderr, "Error: local file & received file differ.\n");
      free (mem_test_file_local);
      free (cbc.buf);
      free (doc_path);
      return -1;
    }

  free (mem_test_file_local);
  free (cbc.buf);
  free (doc_path);
  return 0;
}

/*
 * assert initiating two separate daemons and having one shut down
 * doesn't affect the other
 */
int
test_concurent_daemon_pair (FILE * test_fd, char *cipher_suite,
                            int proto_version)
{

  int ret;
  struct MHD_Daemon *d1;
  struct MHD_Daemon *d2;
  d1 = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION | MHD_USE_SSL |
                         MHD_USE_DEBUG, 42433,
                         NULL, NULL, &http_ahc, NULL,
                         MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
                         MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
                         MHD_OPTION_END);

  if (d1 == NULL)
    {
      fprintf (stderr, MHD_E_SERVER_INIT);
      return -1;
    }

  d2 = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION | MHD_USE_SSL |
                         MHD_USE_DEBUG, 42434,
                         NULL, NULL, &http_ahc, NULL,
                         MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
                         MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
                         MHD_OPTION_END);

  if (d2 == NULL)
    {
      fprintf (stderr, MHD_E_SERVER_INIT);
      return -1;
    }

  ret = test_daemon_get (test_fd, cipher_suite, proto_version, 42433);
  ret += test_daemon_get (test_fd, cipher_suite, proto_version, 42434);

  MHD_stop_daemon (d2);
  ret += test_daemon_get (test_fd, cipher_suite, proto_version, 42433);
  MHD_stop_daemon (d1);
  return ret;
}

FILE *
setupTestFile ()
{
  FILE *test_fd;

  if (NULL == (test_fd = fopen (test_file_name, "w+")))
    {
      fprintf (stderr, "Error: failed to open `%s': %s\n",
               test_file_name, strerror (errno));
      return NULL;
    }
  if (fwrite (test_file_data, sizeof (char), strlen (test_file_data), test_fd)
      != strlen (test_file_data))
    {
      fprintf (stderr, "Error: failed to write `%s. %s'\n",
               test_file_name, strerror (errno));
      return NULL;
    }
  if (fflush (test_fd))
    {
      fprintf (stderr, "Error: failed to flush test file stream. %s\n",
               strerror (errno));
      return NULL;
    }

  return test_fd;
}

int
main (int argc, char *const *argv)
{
  FILE *test_fd;
  unsigned int errorCount = 0;

  if ((test_fd = setupTestFile ()) == NULL)
    {
      fprintf (stderr, MHD_E_TEST_FILE_CREAT);
      return -1;
    }

  if (0 != curl_global_init (CURL_GLOBAL_ALL))
    {
      fprintf (stderr, "Error (code: %u)\n", errorCount);
      return -1;
    }

  errorCount +=
    test_concurent_daemon_pair (test_fd, "AES256-SHA", CURL_SSLVERSION_TLSv1);

  if (errorCount != 0)
    fprintf (stderr, "Error (code: %u)\n", errorCount);

  curl_global_cleanup ();
  fclose (test_fd);

  remove (test_file_name);
  return errorCount != 0;
}
