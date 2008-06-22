/*
 * Copyright (C) 2000,2001,2002,2003,2006,2007 Nikos Mavrogiannopoulos
 * Copyright (C) 2004,2005 Free Software Foundation
 *
 * This file is part of GNUTLS.
 *
 * GNUTLS is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *               
 * GNUTLS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *                               
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <config.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <gnutls.h>
#include <extra.h>
#include <sys/time.h>
#include <tests.h>
#include <common.h>
#include <tls_test-gaa.h>

#ifndef SHUT_WR
# define SHUT_WR 1
#endif

#ifndef SHUT_RDWR
# define SHUT_RDWR 2
#endif

#define SA struct sockaddr
#define ERR(err,s) if (err==-1) {perror(s);return(1);}
#define MAX_BUF 4096

/* global stuff here */
int resume;
char *hostname = NULL;
int port;
int record_max_size;
int fingerprint;
static int debug;

gnutls_srp_client_credentials_t srp_cred;
gnutls_anon_client_credentials_t anon_cred;
gnutls_certificate_credentials_t xcred;

/* end of global stuff */


int verbose = 0;

extern int tls1_ok;
extern int tls1_1_ok;
extern int ssl3_ok;

static void
tls_log_func (int level, const char *str)
{
  fprintf (stderr, "|<%d>| %s", level, str);
}

typedef test_code_t (*TEST_FUNC) (gnutls_session_t);

typedef struct
{
  char *test_name;
  TEST_FUNC func;
  char *suc_str;
  char *fail_str;
  char *unsure_str;
} TLS_TEST;

static const TLS_TEST tls_tests[] = {
  {"for TLS 1.1 support", test_tls1_1, "yes", "no", "dunno"},
  {"fallback from TLS 1.1 to", test_tls1_1_fallback, "TLS 1.0", "failed",
   "SSL 3.0"},
  {"for TLS 1.0 support", test_tls1, "yes", "no", "dunno"},
  {"for SSL 3.0 support", test_ssl3, "yes", "no", "dunno"},
  {"for HTTPS server name", test_server, "", "failed", "not checked"},
  {"for version rollback bug in RSA PMS", test_rsa_pms, "no", "yes",
   "dunno"},
  {"for version rollback bug in Client Hello", test_version_rollback,
   "no", "yes", "dunno"},

  /* this test will disable TLS 1.0 if the server is 
   * buggy */
  {"whether we need to disable TLS 1.0", test_tls_disable, "no", "yes",
   "dunno"},

  {"whether the server ignores the RSA PMS version",
   test_rsa_pms_version_check, "yes", "no", "dunno"},
  {"whether the server can accept Hello Extensions",
   test_hello_extension, "yes", "no", "dunno"},
  {"whether the server can accept cipher suites not in SSL 3.0 spec",
   test_unknown_ciphersuites, "yes", "no", "dunno"},
  {"whether the server can accept a bogus TLS record version in the client hello", test_version_oob, "yes", "no", "dunno"},
  {"for certificate information", test_certificate, "", "", ""},
  {"for trusted CAs", test_server_cas, "", "", ""},
  {"whether the server understands TLS closure alerts", test_bye, "yes",
   "no", "partially"},
  /* the fact that is after the closure alert test does matter.
   */
  {"whether the server supports session resumption",
   test_session_resume2, "yes", "no", "dunno"},
  {"for export-grade ciphersuite support", test_export, "yes", "no",
   "dunno"},
  {"RSA-export ciphersuite info", test_export_info, "", "N/A", "N/A"},
#ifdef ENABLE_ANON
  {"for anonymous authentication support", test_anonymous, "yes", "no",
   "dunno"},
  {"anonymous Diffie Hellman group info", test_dhe_group, "", "N/A",
   "N/A"},
#endif
  {"for ephemeral Diffie Hellman support", test_dhe, "yes", "no",
   "dunno"},
  {"ephemeral Diffie Hellman group info", test_dhe_group, "", "N/A",
   "N/A"},
  {"for AES cipher support (TLS extension)", test_aes, "yes", "no",
   "dunno"},
#ifdef	ENABLE_CAMELLIA
  {"for CAMELLIA cipher support (TLS extension)", test_camellia, "yes", "no",
   "dunno"},
#endif
  {"for 3DES cipher support", test_3des, "yes", "no", "dunno"},
  {"for ARCFOUR 128 cipher support", test_arcfour, "yes", "no", "dunno"},
  {"for ARCFOUR 40 cipher support", test_arcfour_40, "yes", "no",
   "dunno"},
  {"for MD5 MAC support", test_md5, "yes", "no", "dunno"},
  {"for SHA1 MAC support", test_sha, "yes", "no", "dunno"},
#ifdef HAVE_LIBZ
  {"for ZLIB compression support (TLS extension)", test_zlib, "yes",
   "no", "dunno"},
#endif
  {"for LZO compression support (GnuTLS extension)", test_lzo, "yes",
   "no", "dunno"},
  {"for max record size (TLS extension)", test_max_record_size, "yes",
   "no", "dunno"},
#ifdef ENABLE_SRP
  {"for SRP authentication support (TLS extension)", test_srp, "yes",
   "no", "dunno"},
#endif
  {"for OpenPGP authentication support (TLS extension)", test_openpgp1,
   "yes", "no", "dunno"},
  {NULL, NULL, NULL, NULL, NULL}
};

static int tt = 0;
const char *ip;

static void gaa_parser (int argc, char **argv);

int
main (int argc, char **argv)
{
  int err, ret;
  int sd, i;
  gnutls_session_t state;
  char buffer[MAX_BUF + 1];
  char portname[6];
  struct addrinfo hints, *res, *ptr;

  gaa_parser (argc, argv);

#ifndef _WIN32
  signal (SIGPIPE, SIG_IGN);
#endif

  sockets_init ();

  if (gnutls_global_init () < 0)
    {
      fprintf (stderr, "global state initialization error\n");
      exit (1);
    }

  gnutls_global_set_log_function (tls_log_func);
  gnutls_global_set_log_level (debug);

  if (gnutls_global_init_extra () < 0)
    {
      fprintf (stderr, "global state initialization error\n");
      exit (1);
    }

  printf ("Resolving '%s'...\n", hostname);
  /* get server name */
  memset (&hints, 0, sizeof (hints));
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = 0;
  snprintf (portname, sizeof (portname), "%d", port);
  if ((err = getaddrinfo (hostname, portname, &hints, &res)) != 0)
    {
      fprintf (stderr, "Cannot resolve %s: %s\n", hostname,
               gai_strerror (err));
      exit (1);
    }

  /* X509 stuff */
  if (gnutls_certificate_allocate_credentials (&xcred) < 0)
    {                           /* space for 2 certificates */
      fprintf (stderr, "memory error\n");
      exit (1);
    }

  /* SRP stuff */
#ifdef ENABLE_SRP
  if (gnutls_srp_allocate_client_credentials (&srp_cred) < 0)
    {
      fprintf (stderr, "memory error\n");
      exit (1);
    }
#endif

#ifdef ENABLE_ANON
  /* ANON stuff */
  if (gnutls_anon_allocate_client_credentials (&anon_cred) < 0)
    {
      fprintf (stderr, "memory error\n");
      exit (1);
    }
#endif

  i = 0;

  do
    {

      if (tls_tests[i].test_name == NULL)
        break;                  /* finished */

      /* if neither of SSL3 and TLSv1 are supported, exit
       */
      if (i > 3 && tls1_1_ok == 0 && tls1_ok == 0 && ssl3_ok == 0)
        {
          fprintf (stderr,
                   "\nServer does not support any of SSL 3.0, TLS 1.0 and TLS 1.1\n");
          break;
        }

      sd = -1;
      for (ptr = res; ptr != NULL; ptr = ptr->ai_next)
        {
          sd = socket (ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
          if (sd == -1)
            {
              continue;
            }

          getnameinfo (ptr->ai_addr, ptr->ai_addrlen, buffer, MAX_BUF,
                       NULL, 0, NI_NUMERICHOST);
          if (tt++ == 0)
            printf ("Connecting to '%s:%d'...\n", buffer, port);
          if ((err = connect (sd, ptr->ai_addr, ptr->ai_addrlen)) != 0)
            {
              close (sd);
              sd = -1;
              continue;
            }
        }
      ERR (err, "connect") gnutls_init (&state, GNUTLS_CLIENT);
      gnutls_transport_set_ptr (state, (gnutls_transport_ptr_t) sd);

      do
        {
          printf ("Checking %s...", tls_tests[i].test_name);

          ret = tls_tests[i].func (state);

          if (ret == TEST_SUCCEED)
            printf (" %s\n", tls_tests[i].suc_str);
          else if (ret == TEST_FAILED)
            printf (" %s\n", tls_tests[i].fail_str);
          else if (ret == TEST_UNSURE)
            printf (" %s\n", tls_tests[i].unsure_str);
          else if (ret == TEST_IGNORE)
            {
              printf (" N/A\n");
              i++;
            }
        }
      while (ret == TEST_IGNORE && tls_tests[i].test_name != NULL);

      gnutls_deinit (state);

      shutdown (sd, SHUT_RDWR); /* no more receptions */
      close (sd);

      i++;
    }
  while (1);

  freeaddrinfo (res);

#ifdef ENABLE_SRP
  gnutls_srp_free_client_credentials (srp_cred);
#endif
  gnutls_certificate_free_credentials (xcred);
#ifdef ENABLE_ANON
  gnutls_anon_free_client_credentials (anon_cred);
#endif
  gnutls_global_deinit ();

  return 0;
}

static gaainfo info;
void
gaa_parser (int argc, char **argv)
{
  if (gaa (argc, argv, &info) != -1)
    {
      fprintf (stderr,
               "Error in the arguments. Use the -h or --help parameters to get more info.\n");
      exit (1);
    }

  port = info.pp;
  if (info.rest_args == NULL)
    hostname = "localhost";
  else
    hostname = info.rest_args;

  debug = info.debug;

  verbose = info.more_info;

}

void
tls_test_version (void)
{
  const char *v = gnutls_check_version (NULL);

  printf ("gnutls-cli-debug (GnuTLS) %s\n", LIBGNUTLS_VERSION);
  if (strcmp (v, LIBGNUTLS_VERSION) != 0)
    printf ("libgnutls %s\n", v);
}
