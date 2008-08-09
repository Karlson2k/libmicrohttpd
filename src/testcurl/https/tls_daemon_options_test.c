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

#include <sys/stat.h>

#include "gnutls.h"
#include <curl/curl.h>

#define DEBUG_CURL_VERBOSE 0
#define PAGE_NOT_FOUND "<html><head><title>File not found</title></head><body>File not found</body></html>"

#define MHD_E_MEM "Error: memory error\n"
#define MHD_E_SERVER_INIT "Error: failed to start server\n"
#define MHD_E_TEST_FILE_CREAT "Error: failed to setup test file\n"
#define MHD_E_CERT_FILE_CREAT "Error: failed to setup test certificate\n"
#define MHD_E_KEY_FILE_CREAT "Error: failed to setup test certificate\n"

#include "tls_test_keys.h"

const int DEBUG_GNUTLS_LOG_LEVEL = 0;
const char *test_file_name = "https_test_file";
const char test_file_data[] = "Hello World\n";

int curl_check_version (const char *req_version, ...);

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
test_https_transfer (FILE * test_fd, char *cipher_suite, int proto_version)
{
  CURL *c;
  CURLcode errornum;
  struct CBC cbc;
  char *doc_path;
  char url[255];
  struct stat statb;

  stat (test_file_name, &statb);

  int len = statb.st_size;

  /* used to memcmp local copy & deamon supplied copy */
  unsigned char *mem_test_file_local;

  /* setup test file path, url */
  doc_path = get_current_dir_name ();

  if (NULL == (mem_test_file_local = malloc (len)))
    {
      fclose (test_fd);
      fprintf (stderr, MHD_E_MEM);
      return -1;
    }

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
      fprintf (stderr, MHD_E_MEM);
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
  curl_easy_setopt (c, CURLOPT_TIMEOUT, 5L);
  curl_easy_setopt (c, CURLOPT_CONNECTTIMEOUT, 5L);
  curl_easy_setopt (c, CURLOPT_WRITEFUNCTION, &copyBuffer);
  curl_easy_setopt (c, CURLOPT_FILE, &cbc);

  /* TLS options */
  curl_easy_setopt (c, CURLOPT_SSLVERSION, proto_version);
  curl_easy_setopt (c, CURLOPT_SSL_CIPHER_LIST, cipher_suite);

  /* currently skip any peer authentication */
  curl_easy_setopt (c, CURLOPT_SSL_VERIFYPEER, 0);
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
      return errornum;
    }

  curl_easy_cleanup (c);

  if (memcmp (cbc.buf, mem_test_file_local, len) != 0)
    {
      fprintf (stderr, "Error: local file & received file differ.\n");
      free (cbc.buf);
      free (mem_test_file_local);
      return -1;
    }

  free (mem_test_file_local);
  free (cbc.buf);
  free (doc_path);
  return 0;
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

static int
setup (struct MHD_Daemon **d, va_list arg_list)
{
  *d = MHD_start_daemon_va (MHD_USE_THREAD_PER_CONNECTION | MHD_USE_SSL |
                            MHD_USE_DEBUG, 42433, "127.0.0.1",
                            NULL, NULL, &http_ahc, NULL, arg_list);

  if (*d == NULL)
    {
      fprintf (stderr, MHD_E_SERVER_INIT);
      return -1;
    }

  return 0;
}

static void
teardown (struct MHD_Daemon *d)
{
  MHD_stop_daemon (d);
}

/* TODO test_wrap: change sig to (setup_func, test, va_list test_arg) & move to test_util.c */
int
test_wrap (char *test_name, int
           (*test) (FILE * test_fd, char *cipher_suite, int proto_version),
           FILE * test_fd, char *cipher_suite, int proto_version, ...)
{
  int ret;
  va_list arg_list;
  struct MHD_Daemon *d;

  va_start (arg_list, proto_version);
  if (setup (&d, arg_list) != 0)
    {
      va_end (arg_list);
      return -1;
    }

  fprintf (stdout, "running test: %s ", test_name);
  ret = test (test_fd, cipher_suite, proto_version);

  if (ret == 0)
    {
      fprintf (stdout, "[pass]\n");
    }
  else
    {
      fprintf (stdout, "[fail]\n");
    }

  teardown (d);
  va_end (arg_list);
  return ret;
}

/* perform a HTTP GET request via SSL/TLS */

/* test loading of key & certificate files */
int
test_file_certificates (FILE * test_fd, char *cipher_suite, int proto_version)
{
  int ret;
  struct MHD_Daemon *d;
  FILE *cert_fd, *key_fd;
  char cert_path[255], key_path[255], *cur_dir;

  cur_dir = get_current_dir_name ();

  sprintf (cert_path, "%s/%s", cur_dir, "cert.pem");
  sprintf (key_path, "%s/%s", cur_dir, "key.pem");

  if (NULL == (key_fd = fopen (key_path, "w+")))
    {
      fprintf (stderr, MHD_E_KEY_FILE_CREAT);
      return -1;
    }
  if (NULL == (cert_fd = fopen (cert_path, "w+")))
    {
      fprintf (stderr, MHD_E_CERT_FILE_CREAT);
      return -1;
    }

  fwrite (srv_key_pem, strlen (srv_key_pem), sizeof (char), key_fd);
  fwrite (srv_self_signed_cert_pem, strlen (srv_self_signed_cert_pem),
          sizeof (char), cert_fd);
  fclose (key_fd);
  fclose (cert_fd);

  if (d == NULL)
    {
      fprintf (stderr, MHD_E_SERVER_INIT);
      return -1;
    }

  ret = test_https_transfer (test_fd, cipher_suite, proto_version);

  free (cur_dir);
  remove (cert_path);
  remove (key_path);
  return ret;
}

/*
 * test server refuses to negotiate connections with unsupported protocol versions
 */
int
test_protocol_version (FILE * test_fd, char *cipher_suite,
                       int curl_proto_version)
{
  CURL *c;
  CURLcode errornum;

  c = curl_easy_init ();
#if DEBUG_CURL_VERBOSE
  curl_easy_setopt (c, CURLOPT_VERBOSE, 1);
#endif
  curl_easy_setopt (c, CURLOPT_URL, "https://localhost:42433/");
  curl_easy_setopt (c, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
  curl_easy_setopt (c, CURLOPT_TIMEOUT, 5L);
  curl_easy_setopt (c, CURLOPT_CONNECTTIMEOUT, 5L);

  /* TLS options */
  curl_easy_setopt (c, CURLOPT_SSLVERSION, curl_proto_version);
  curl_easy_setopt (c, CURLOPT_SSL_CIPHER_LIST, cipher_suite);

  curl_easy_setopt (c, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt (c, CURLOPT_SSL_VERIFYHOST, 0);
  curl_easy_setopt (c, CURLOPT_FAILONERROR, 1);

  /* NOTE: use of CONNECTTIMEOUT without also
     setting NOSIGNAL results in really weird
     crashes on my system! */
  curl_easy_setopt (c, CURLOPT_NOSIGNAL, 1);

  /* assert daemon rejected request */
  if (CURLE_OK == (errornum = curl_easy_perform (c)))
    {
      fprintf (stderr, "curl_easy_perform failed: `%s'\n",
               curl_easy_strerror (errornum));
      curl_easy_cleanup (c);
      return -1;
    }

  return 0;
}

/* setup a temporary transfer test file */
int
main (int argc, char *const *argv)
{
  FILE *test_fd;
  unsigned int errorCount = 0;

  gnutls_global_set_log_level (DEBUG_GNUTLS_LOG_LEVEL);

  if (curl_check_version (MHD_REQ_CURL_VERSION))
    {
      return -1;
    }

  if ((test_fd = setupTestFile ()) == NULL)
    {
      fprintf (stderr, MHD_E_TEST_FILE_CREAT);
      return -1;
    }

  if (0 != curl_global_init (CURL_GLOBAL_ALL))
    {
      fprintf (stderr, "Error: %s\n", strerror (errno));
      return -1;
    }

  int mac[] = { MHD_GNUTLS_MAC_SHA1, 0 };
  int p[] = { MHD_GNUTLS_SSL3, 0 };
  int cipher[] = { MHD_GNUTLS_CIPHER_3DES_CBC, 0 };
  int kx[] = { MHD_GNUTLS_KX_ANON_DH, 0 };

  errorCount +=
    test_wrap ("https_transfer", &test_https_transfer, test_fd, "AES256-SHA",
               CURL_SSLVERSION_TLSv1,
               MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
               MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
               MHD_OPTION_END);
  errorCount +=
    test_wrap ("file certificates", &test_file_certificates, test_fd,
               "AES256-SHA", CURL_SSLVERSION_TLSv1, MHD_OPTION_HTTPS_MEM_KEY,
               srv_key_pem, MHD_OPTION_HTTPS_MEM_CERT,
               srv_self_signed_cert_pem, MHD_OPTION_END);
  errorCount +=
    test_wrap ("protocol_version", &test_protocol_version, test_fd,
               "AES256-SHA", CURL_SSLVERSION_TLSv1, MHD_OPTION_HTTPS_MEM_KEY,
               srv_key_pem, MHD_OPTION_HTTPS_MEM_CERT,
               srv_self_signed_cert_pem, MHD_OPTION_PROTOCOL_VERSION, p,
               MHD_OPTION_END);
  errorCount +=
    test_wrap ("cipher DES-CBC3-SHA", &test_https_transfer, test_fd,
               "DES-CBC3-SHA", CURL_SSLVERSION_TLSv1,
               MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
               MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
               MHD_OPTION_CIPHER_ALGORITHM, cipher, MHD_OPTION_END);
  errorCount +=
    test_wrap ("mac SH1", &test_https_transfer, test_fd, "AES256-SHA",
               CURL_SSLVERSION_TLSv1, MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
               MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
               MHD_OPTION_MAC_ALGO, mac, MHD_OPTION_END);
  errorCount +=
    test_wrap ("kx ANON_DH", &test_https_transfer, test_fd,
               "ADH-DES-CBC3-SHA", CURL_SSLVERSION_TLSv1,
               MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
               MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
               MHD_OPTION_CRED_TYPE, MHD_GNUTLS_CRD_ANON,
               MHD_OPTION_CIPHER_ALGORITHM, cipher, MHD_OPTION_KX_PRIORITY,
               kx, MHD_OPTION_END);

  /*gnutls_mac_algorithm_t mac[] = {
     {MHD_GNUTLS_MAC_MD5, 0}, 0};
     gnutls_mac_algorithm_t * cur_mac;

     for ( cur_mac = &mac[0]; (*cur_mac) != 0; cur_mac++ ){
     option[0] = MHD_GNUTLS_MAC_SHA1;
     errorCount +=
     test_wrap (&test_https_transfer, test_fd, "AES256-SHA",
     CURL_SSLVERSION_TLSv1, MHD_OPTION_MAC_ALGO, option);
     } */

  if (errorCount != 0)
    fprintf (stderr, "Failed test: %s.\n", argv[0]);

  curl_global_cleanup ();
  fclose (test_fd);

  remove (test_file_name);

  return errorCount != 0;
}
