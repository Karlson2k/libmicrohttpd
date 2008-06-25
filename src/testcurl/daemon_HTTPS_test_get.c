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
 * @file daemon_HTTPS_test_get.c
 * @brief  Testcase for libmicrohttpd GET operations
 * @author lv-426
 */

#include "config.h"
#include "plibc.h"
#include "microhttpd.h"
#include <errno.h>

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define BUF_SIZE 1024
#define MAX_URL_LEN 255

/* Test Certificate */
const char cert_pem[] =
  "-----BEGIN CERTIFICATE-----\n"
  "MIIB5zCCAVKgAwIBAgIERiYdJzALBgkqhkiG9w0BAQUwGTEXMBUGA1UEAxMOR251\n"
  "VExTIHRlc3QgQ0EwHhcNMDcwNDE4MTMyOTExWhcNMDgwNDE3MTMyOTExWjAZMRcw\n"
  "FQYDVQQDEw5HbnVUTFMgdGVzdCBDQTCBnDALBgkqhkiG9w0BAQEDgYwAMIGIAoGA\n"
  "vuyYeh1vfmslnuggeEKgZAVmQ5ltSdUY7H25WGSygKMUYZ0KT74v8C780qtcNt9T\n"
  "7EPH/N6RvB4BprdssgcQLsthR3XKA84jbjjxNCcaGs33lvOz8A1nf8p3hD+cKfRi\n"
  "kfYSW2JazLrtCC4yRCas/SPOUxu78of+3HiTfFm/oXUCAwEAAaNDMEEwDwYDVR0T\n"
  "AQH/BAUwAwEB/zAPBgNVHQ8BAf8EBQMDBwQAMB0GA1UdDgQWBBTpPBz7rZJu5gak\n"
  "Viyi4cBTJ8jylTALBgkqhkiG9w0BAQUDgYEAiaIRqGfp1jPpNeVhABK60SU0KIAy\n"
  "njuu7kHq5peUgYn8Jd9zNzExBOEp1VOipGsf6G66oQAhDFp2o8zkz7ZH71zR4HEW\n"
  "KoX6n5Emn6DvcEH/9pAhnGxNHJAoS7czTKv/JDZJhkqHxyrE1fuLsg5Qv25DTw7+\n"
  "PfqUpIhz5Bbm7J4=\n" "-----END CERTIFICATE-----\n";

const char key_pem[] =
  "-----BEGIN RSA PRIVATE KEY-----\n"
  "MIICXAIBAAKBgQC7ZkP18sXXtozMxd/1iDuxyUtqDqGtIFBACIChT1yj0Phsz+Y8\n"
  "9+wEdhMXi2SJIlvA3VN8O+18BLuAuSi+jpvGjqClEsv1Vx6i57u3M0mf47tKrmpN\n"
  "aP/JEeIyjc49gAuNde/YAIGPKAQDoCKNYQQH+rY3fSEHSdIJYWmYkKNYqQIDAQAB\n"
  "AoGADpmARG5CQxS+AesNkGmpauepiCz1JBF/JwnyiX6vEzUh0Ypd39SZztwrDxvF\n"
  "PJjQaKVljml1zkJpIDVsqvHdyVdse8M+Qn6hw4x2p5rogdvhhIL1mdWo7jWeVJTF\n"
  "RKB7zLdMPs3ySdtcIQaF9nUAQ2KJEvldkO3m/bRJFEp54k0CQQDYy+RlTmwRD6hy\n"
  "7UtMjR0H3CSZJeQ8svMCxHLmOluG9H1UKk55ZBYfRTsXniqUkJBZ5wuV1L+pR9EK\n"
  "ca89a+1VAkEA3UmBelwEv2u9cAU1QjKjmwju1JgXbrjEohK+3B5y0ESEXPAwNQT9\n"
  "TrDM1m9AyxYTWLxX93dI5QwNFJtmbtjeBQJARSCWXhsoaDRG8QZrCSjBxfzTCqZD\n"
  "ZXtl807ymCipgJm60LiAt0JLr4LiucAsMZz6+j+quQbSakbFCACB8SLV1QJBAKZQ\n"
  "YKf+EPNtnmta/rRKKvySsi3GQZZN+Dt3q0r094XgeTsAqrqujVNfPhTMeP4qEVBX\n"
  "/iVX2cmMTSh3w3z8MaECQEp0XJWDVKOwcTW6Ajp9SowtmiZ3YDYo1LF9igb4iaLv\n"
  "sWZGfbnU3ryjvkb6YuFjgtzbZDZHWQCo8/cOtOBmPdk=\n"
  "-----END RSA PRIVATE KEY-----\n";

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
http_ahc (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *upload_data,
          const char *version, unsigned int *upload_data_size, void **ptr)
{
  static int aptr;
  static char full_url[MAX_URL_LEN];
  struct MHD_Response *response;
  int ret;
  FILE *file;
  struct stat buf;

  // TODO never respond on first call
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
      return 1;
    }
  else
    {
      stat (&url[1], &buf);
      response = MHD_create_response_from_callback (buf.st_size, 32 * 1024,     /* 32k PAGE_NOT_FOUND size */
                                                    &file_reader, file,
                                                    (MHD_ContentReaderFreeCallback)
                                                    & fclose);
      ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
      MHD_destroy_response (response);
    }
  return ret;
}

static int
test_HTTPS_Get ()
{
  struct MHD_Daemon *d;
  CURL *c;
  struct CBC cbc;
  CURLcode errornum;
  char *doc_path;
  char *url;
  /* currently use self as test file - consider better alternatives */
  char *test_file_name = "daemon_HTTPS_test_get";
  struct stat test_file_stat;
  FILE *key_file, *cert_file, *test_file;

  /* used to memcmp local copy & deamon supplied copy */
  unsigned char *mem_test_file_local;
  unsigned char *mem_test_file_recv;

  /* setup test file path, url */
  doc_path = get_current_dir_name ();

  /* construct url - this might use doc_path */ 
  url =
    (char *) malloc (sizeof (char) *
                     (strlen (test_file_name) +
                      strlen ("https://127.0.0.1:42433/")));
  strncat (url, "https://127.0.0.1:42433/", strlen ("https://127.0.0.1:42433/"));
  strncat (url, test_file_name, strlen (test_file_name));

  /* look for test file used for testing */
  key_file = fopen ("key_file", "w");
  cert_file = fopen ("cert_file", "w");
  test_file = fopen (test_file_name, "r");
  if ( key_file == NULL)
    {
      fprintf (stderr, "Error : failed to open key_file. errno:%d\n", errno);
      return 1;
    }
  if (!cert_file)
    {
      fprintf (stderr, "Error : failed to open cert_file. errno:%d\n", errno);
      return 1;
    }
  if (!test_file)
    {
      fprintf (stderr, "Error : failed to open test_file. errno:%d\n", errno);
      return 1;
    }
  if (stat (test_file_name, &test_file_stat) == -1)
    return 1;

  /* create test cert & key */
  fwrite (key_pem, 1, sizeof (key_pem), key_file);
  fwrite (cert_pem, 1, sizeof (cert_pem), cert_file);
  mem_test_file_local = malloc (test_file_stat.st_size);
  mem_test_file_recv = malloc (test_file_stat.st_size);
  fread (mem_test_file_local, 1, test_file_stat.st_size, test_file);

  fclose (key_file);
  fclose (cert_file);
  fclose (test_file);

  cbc.buf = mem_test_file_recv;
  cbc.size = test_file_stat.st_size;
  cbc.pos = 0;

  /* setup test */
  d = MHD_start_daemon (MHD_USE_SELECT_INTERNALLY | MHD_USE_DEBUG,
                        42433, NULL, NULL, &http_ahc, NULL,
                        MHD_OPTION_DOC_ROOT, doc_path, MHD_OPTION_END);
  if (d == NULL)
    return 1;

  c = curl_easy_init ();
  curl_easy_setopt (c, CURLOPT_URL, url);
  curl_easy_setopt (c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  curl_easy_setopt (c, CURLOPT_TIMEOUT, 150L);
  curl_easy_setopt (c, CURLOPT_CONNECTTIMEOUT, 15L);
  curl_easy_setopt (c, CURLOPT_WRITEFUNCTION, &copyBuffer);
  curl_easy_setopt (c, CURLOPT_WRITEDATA, &cbc);
  /* TLS options */
  curl_easy_setopt (c, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
  curl_easy_setopt (c, CURLOPT_SSL_CIPHER_LIST, "AES256-SHA");
  /* currently skip peer authentication */
  curl_easy_setopt (c, CURLOPT_SSL_VERIFYPEER, 0);
  // curl_easy_setopt (c, CURLOPT_FAILONERROR, 1);

  // NOTE: use of CONNECTTIMEOUT without also
  //   setting NOSIGNAL results in really weird
  //   crashes on my system!
  curl_easy_setopt (c, CURLOPT_NOSIGNAL, 1);
  if (CURLE_OK != (errornum = curl_easy_perform (c)))
    {
      fprintf (stderr,
               "curl_easy_perform failed: `%s'\n",
               curl_easy_strerror (errornum));
      curl_easy_cleanup (c);
      MHD_stop_daemon (d);
      return 2;
    }
  curl_easy_cleanup (c);
  MHD_stop_daemon (d);
  if (remove ("key_file") != 0)
    fprintf (stderr, "Error : failed to remove key_file.\n");
  if (remove ("cert_file") != 0)
    fprintf (stderr, "Error : failed to remove cert_file.\n");

  fprintf (stderr, "file = %s.\n" , mem_test_file_recv );
  if (memcmp (cbc.buf, mem_test_file_local, test_file_stat.st_size) == 0)
    {
      // TODO find proper error code
      return 1;
    }
  return 0;
}

int
main (int argc, char *const *argv)
{

  unsigned int errorCount = 0;

  if (0 != curl_global_init (CURL_GLOBAL_WIN32))
    return 2;
  errorCount += test_HTTPS_Get ();
  if (errorCount != 0)
    fprintf (stderr, "Error (code: %u)\n", errorCount);
  curl_global_cleanup ();
  return errorCount == 0;       /* 0 == pass */
}
