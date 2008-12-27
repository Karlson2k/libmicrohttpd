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
 * @file tls_thread_mode_test.c
 * @brief  Testcase for libmicrohttpd HTTPS GET operations
 * @author Sagie Amir
 * @author Christian Grothoff
 * 
 * TODO: add test for external select! 
 */

#include "platform.h"
#include "microhttpd.h"

#include <sys/stat.h>
#include <limits.h>
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

const char *test_file_name = "https_test_file";
const char test_file_data[] = "Hello World\n";

int curl_check_version (const char *req_version, ...);

struct CBC
{
  char *buf;
  size_t pos;
  size_t size;
};

struct https_test_data
{
  FILE *test_fd;
  char *cipher_suite;
  int proto_version;
};

struct CipherDef
{
  int options[2];
  char *curlname;
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



/**
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
      fclose (test_fd);
      fprintf (stderr, MHD_E_MEM);
      return -1;
    }
  if (getcwd (doc_path, doc_path_len) == NULL)
    {
      fclose (test_fd);
      free (doc_path);
      fprintf (stderr, "Error: failed to get working directory. %s\n",
               strerror (errno));
      return -1;
    }

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
  curl_easy_setopt (c, CURLOPT_TIMEOUT, 60L);
  curl_easy_setopt (c, CURLOPT_CONNECTTIMEOUT, 60L);
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

/**
 * used when spawning multiple threads executing curl server requests
 *
 */
static void *
https_transfer_thread_adapter (void *args)
{
  static int nonnull;
  struct https_test_data *cargs = args;
  int ret;

  /* time spread incomming requests */
  usleep ((useconds_t) 10.0 * ((double) rand ()) / ((double) RAND_MAX));
  ret = test_https_transfer (cargs->test_fd,
			     cargs->cipher_suite, cargs->proto_version);
  if (ret == 0)
    return NULL;
  return &nonnull;
}

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
setup (struct MHD_Daemon **d, int daemon_flags, va_list arg_list)
{
  *d = MHD_start_daemon_va (daemon_flags, 42433,
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
static int
test_wrap (char *test_name, int
           (*test_function) (FILE * test_fd, char *cipher_suite, int proto_version),
           FILE * test_fd, int daemon_flags, char *cipher_suite,
           int proto_version, ...)
{
  int ret;
  va_list arg_list;
  struct MHD_Daemon *d;

  va_start (arg_list, proto_version);
  if (setup (&d, daemon_flags, arg_list) != 0)
    {
      va_end (arg_list);
      return -1;
    }

  fprintf (stdout, "running test: %s ", test_name);
  ret = test_function (test_fd, cipher_suite, proto_version);

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

/**
 * Test non-parallel requests.
 *
 * @return: 0 upon all client requests returning '0', -1 otherwise.
 *
 * TODO : make client_count a parameter - numver of curl client threads to spawn
 */
static int
test_single_client (FILE * test_fd, char *cipher_suite,
		    int curl_proto_version)
{
  void *client_thread_ret;
  struct https_test_data client_args = {test_fd, cipher_suite, curl_proto_version};

  client_thread_ret = https_transfer_thread_adapter (&client_args);
  if (client_thread_ret != NULL)
    return -1;    
  return 0;
}


/**
 * Test parallel request handling.
 *
 * @return: 0 upon all client requests returning '0', -1 otherwise.
 *
 * TODO : make client_count a parameter - numver of curl client threads to spawn
 */
static int
test_parallel_clients (FILE * test_fd, char *cipher_suite,
		       int curl_proto_version)
{
  int i;
  int client_count = 3;
  void *client_thread_ret;
  pthread_t client_arr[client_count];
  struct https_test_data client_args = {test_fd, cipher_suite, curl_proto_version};

  for (i = 0; i < client_count; ++i)
    {
      if (pthread_create (&client_arr[i], NULL,
                          (void * ) &https_transfer_thread_adapter, &client_args) != 0)
        {
          fprintf (stderr, "Error: failed to spawn test client threads.\n");
          return -1;
        }
    }

  /* check all client requests fulfilled correctly */
  for (i = 0; i < client_count; ++i)
    {
      if ((pthread_join (client_arr[i], &client_thread_ret) != 0) ||
          (client_thread_ret != NULL) )        
	return -1;    
    }

  return 0;
}


int
main (int argc, char *const *argv)
{
  FILE *test_fd;
  unsigned int errorCount = 0;

  /* initialize random seed used by curl clients */
  unsigned int iseed = (unsigned int) time (NULL);
  srand (iseed);

  if (curl_check_version (MHD_REQ_CURL_VERSION))
    return -1;    

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

  errorCount +=
    test_wrap ("multi threaded daemon, single client",  &test_single_client, test_fd,
               MHD_USE_SSL | MHD_USE_DEBUG, "AES256-SHA",
               CURL_SSLVERSION_TLSv1, MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
               MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
               MHD_OPTION_END);

  errorCount +=
    test_wrap ("single threaded daemon, single client", &test_single_client, test_fd,
               MHD_USE_SELECT_INTERNALLY |
	       MHD_USE_SSL | MHD_USE_DEBUG, "AES256-SHA",
               CURL_SSLVERSION_TLSv1, MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
               MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
               MHD_OPTION_END);

  errorCount +=
    test_wrap ("multi threaded daemon, parallel client",   &test_parallel_clients, test_fd,
               MHD_USE_SSL | MHD_USE_DEBUG, "AES256-SHA",
               CURL_SSLVERSION_TLSv1, MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
               MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
               MHD_OPTION_END);

  errorCount +=
    test_wrap ("single threaded daemon, parallel clients", &test_parallel_clients, test_fd,
               MHD_USE_SELECT_INTERNALLY | 
	       MHD_USE_SSL | MHD_USE_DEBUG, "AES256-SHA",
               CURL_SSLVERSION_TLSv1, MHD_OPTION_HTTPS_MEM_KEY, srv_key_pem,
               MHD_OPTION_HTTPS_MEM_CERT, srv_self_signed_cert_pem,
               MHD_OPTION_END);

  if (errorCount != 0)
    fprintf (stderr, "Failed test: %s.\n", argv[0]);

  curl_global_cleanup ();
  fclose (test_fd);

  remove (test_file_name);

  return errorCount != 0;
}
