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
 * @file mhds_get_test.c
 * @brief  Testcase for libmicrohttpd HTTPS GET operations
 * @author Sagie Amir
 */

#include "platform.h"
#include "microhttpd.h"
#include <curl/curl.h>
#include <limits.h>
#include <sys/stat.h>

#define DEBUG_CURL_VERBOSE 0
#define PAGE_NOT_FOUND "<html><head><title>File not found</title></head><body>File not found</body></html>"

#define MHD_E_MEM "Error: memory error\n"
#define MHD_E_SERVER_INIT "Error: failed to start server\n"
#define MHD_E_TEST_FILE_CREAT "Error: failed to setup test file\n"

#include "tls_test_keys.h"

extern int curl_check_version (const char *req_version, ...);

const int DEBUG_GNUTLS_LOG_LEVEL = 6;
const char *ca_cert_file_name = "ca_cert_pem";
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
 * test HTTPS transfer
 * @param test_fd: file to attempt transfering
 */
static int
test_daemon_get (FILE * test_fd, char *cipher_suite, int proto_version)
{
  CURL *c;
  struct CBC cbc;
  CURLcode errornum;
  char *doc_path;
  size_t doc_path_len;
  char url[255];
  struct stat statb;

  stat (test_file_name, &statb);

  int len = statb.st_size;

  /* used to memcmp local copy & deamon supplied copy */
  unsigned char *mem_test_file_local;

  /* setup test file path, url */
  doc_path_len = PATH_MAX > 4096 ? 4096 : PATH_MAX;
  if (NULL == (doc_path = malloc (doc_path_len)))
    {
      fprintf (stderr, MHD_E_MEM);
      return -1;
    }
  if (getcwd (doc_path, doc_path_len) == NULL)
    {
      fprintf (stderr, "Error: failed to get working directory. %s\n",
               strerror (errno));
      free (doc_path);
      return -1;
    }

  if (NULL == (mem_test_file_local = malloc (len)))
    {
      fprintf (stderr, MHD_E_MEM);
      free (doc_path);
      return -1;
    }

  fseek (test_fd, 0, SEEK_SET);
  if (fread (mem_test_file_local, sizeof (char), len, test_fd) != len)
    {
      fprintf (stderr, "Error: failed to read test file. %s\n",
               strerror (errno));
      free (doc_path);
      free (mem_test_file_local);
      return -1;
    }

  if (NULL == (cbc.buf = malloc (sizeof (char) * len)))
    {
      fprintf (stderr, MHD_E_MEM);
      free (doc_path);
      free (mem_test_file_local);
      return -1;
    }
  cbc.size = len;
  cbc.pos = 0;

  /* construct url - this might use doc_path */
  sprintf (url, "%s%s/%s", "https://localhost:42433",
           doc_path, test_file_name);

  c = curl_easy_init ();
#if DEBUG_CURL_VERBOSE
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

  /* perform peer authentication */
  curl_easy_setopt (c, CURLOPT_SSL_VERIFYPEER, 1);
  curl_easy_setopt (c, CURLOPT_CAINFO, ca_cert_file_name);

  curl_easy_setopt (c, CURLOPT_SSL_VERIFYHOST, 0);

  curl_easy_setopt (c, CURLOPT_FAILONERROR, 1);

  /* NOTE: use of CONNECTTIMEOUT without also
     setting NOSIGNAL results in really weird
     crashes on my system! */
  curl_easy_setopt (c, CURLOPT_NOSIGNAL, 1);
  if (CURLE_OK != (errornum = curl_easy_perform (c)))
    {
      fprintf (stderr, "curl_easy_perform failed: `%s'\n",
               curl_easy_strerror (errornum));
      curl_easy_cleanup (c);
      free (cbc.buf);
      free (doc_path);
      free (mem_test_file_local);
      return errornum;
    }

  curl_easy_cleanup (c);

  if (memcmp (cbc.buf, mem_test_file_local, len) != 0)
    {
      fprintf (stderr, "Error: local file & received file differ.\n");
      free (cbc.buf);
      free (mem_test_file_local);
      free (doc_path);
      return -1;
    }

  free (mem_test_file_local);
  free (cbc.buf);
  free (doc_path);
  return 0;
}

/* perform a HTTP GET request via SSL/TLS */
static int
test_secure_get (FILE * test_fd, char *cipher_suite, int proto_version)
{
  int ret;
  struct MHD_Daemon *d;

  d = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION | MHD_USE_SSL |
                        MHD_USE_DEBUG, 42433,
                        NULL, NULL, &http_ahc, NULL,
                        MHD_OPTION_HTTPS_MEM_KEY, srv_signed_key_pem,
                        MHD_OPTION_HTTPS_MEM_CERT, srv_signed_cert_pem,
                        MHD_OPTION_END);

  if (d == NULL)
    {
      fprintf (stderr, MHD_E_SERVER_INIT);
      return -1;
    }

  ret = test_daemon_get (test_fd, cipher_suite, proto_version);

  MHD_stop_daemon (d);
  return ret;
}

/* setup a temporary transfer test file */
static FILE *
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
      fclose (test_fd);
      return NULL;
    }
  if (fflush (test_fd))
    {
      fprintf (stderr, "Error: failed to flush test file stream. %s\n",
               strerror (errno));
      fclose (test_fd);
      return NULL;
    }

  return test_fd;
}

static FILE *
setup_ca_cert ()
{
  FILE *fd;

  if (NULL == (fd = fopen (ca_cert_file_name, "w+")))
    {
      fprintf (stderr, "Error: failed to open `%s': %s\n",
               ca_cert_file_name, strerror (errno));
      return NULL;
    }
  if (fwrite (ca_cert_pem, sizeof (char), strlen (ca_cert_pem), fd)
      != strlen (ca_cert_pem))
    {
      fprintf (stderr, "Error: failed to write `%s. %s'\n",
               ca_cert_file_name, strerror (errno));
      fclose (fd);
      return NULL;
    }
  if (fflush (fd))
    {
      fprintf (stderr, "Error: failed to flush ca cert file stream. %s\n",
               strerror (errno));
      fclose (fd);
      return NULL;
    }

  return fd;
}

int
main (int argc, char *const *argv)
{
  FILE *test_fd;
  unsigned int errorCount = 0;

  if (curl_check_version (MHD_REQ_CURL_VERSION))
    {
      return -1;
    }

  if ((test_fd = setupTestFile ()) == NULL)
    {
      fprintf (stderr, MHD_E_TEST_FILE_CREAT);
      return -1;
    }

  setup_ca_cert ();

  if (0 != curl_global_init (CURL_GLOBAL_ALL))
    {
      fprintf (stderr, "Error (code: %u)\n", errorCount);
      fclose (test_fd);
      return -1;
    }

  errorCount +=
    test_secure_get (test_fd, "AES256-SHA", CURL_SSLVERSION_TLSv1);

  if (errorCount != 0)
    fprintf (stderr, "Failed test: %s.\n", argv[0]);

  curl_global_cleanup ();
  fclose (test_fd);

  remove (test_file_name);
  remove (ca_cert_file_name);
  return errorCount != 0;
}
