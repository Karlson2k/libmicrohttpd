/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2016, 2024 Christian Grothoff & Evgeny Grin (Karlson2k)

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
 * @file test_tls.c
 * @brief  test with client against TLS server
 * @author Christian Grothoff
 */
#include "libtest.h"


int
main (int argc, char *argv[])
{
  char *srv_certs_chain
    = MHDT_load_pem ("chain.crt");
  char *srv_cert_key
    = MHDT_load_pem ("test-server-key.pem");
  struct MHD_DaemonOptionAndValue rca_options[] = {
    MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_AUTO),
    MHD_D_OPTION_WM_WORKER_THREADS (1),
    MHD_D_OPTION_TLS (MHD_TLS_BACKEND_ANY),
    MHD_D_OPTION_TLS_CERT_KEY (srv_certs_chain,
                               srv_cert_key,
                               NULL),
    MHD_D_OPTION_TERMINATE ()
  };
#ifdef MHD_SUPPORT_GNUTLS
  struct MHD_DaemonOptionAndValue rca_options_gnu[] = {
    MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_AUTO),
    MHD_D_OPTION_WM_WORKER_THREADS (1),
    MHD_D_OPTION_TLS (MHD_TLS_BACKEND_GNUTLS),
    MHD_D_OPTION_TLS_CERT_KEY (srv_certs_chain,
                               srv_cert_key,
                               NULL),
    MHD_D_OPTION_TERMINATE ()
  };
#endif
#ifdef MHD_SUPPORT_OPENSSL
  struct MHD_DaemonOptionAndValue rca_options_open[] = {
    MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_AUTO),
    MHD_D_OPTION_WM_WORKER_THREADS (1),
    MHD_D_OPTION_TLS (MHD_TLS_BACKEND_OPENSSL),
    MHD_D_OPTION_TLS_CERT_KEY (srv_certs_chain,
                               srv_cert_key,
                               NULL),
    MHD_D_OPTION_TERMINATE ()
  };
#endif
  struct ServerType
  {
    const char *label;
    MHDT_ServerSetup server_setup;
    void *server_setup_cls;
    MHDT_ServerRunner server_runner;
    void *server_runner_cls;
    struct MHDT_Phase phase;
  } configs[] = {
    {
      .label = "certs_chain",
      .server_setup = &MHDT_server_setup_minimal,
      .server_setup_cls = rca_options,
      .server_runner = &MHDT_server_run_minimal,
      .phase = {
        .label = "simple RCA get",
        .server_cb = &MHDT_server_reply_text,
        .server_cb_cls = (void *) "Hello world",
        .client_cb = &MHDT_client_get_host,
        .client_cb_cls = "localhost",
        .timeout_ms = 2500,
        .use_tls = true,
        .check_server_cert = true
      }


    },
#ifdef MHD_SUPPORT_GNUTLS
    {
      .label = "certs_chain",
      .server_setup = &MHDT_server_setup_minimal,
      .server_setup_cls = rca_options_gnu,
      .server_runner = &MHDT_server_run_minimal,
      .phase = {
        .label = "simple RCA get",
        .server_cb = &MHDT_server_reply_text,
        .server_cb_cls = (void *) "Hello world",
        .client_cb = &MHDT_client_get_host,
        .client_cb_cls = "localhost",
        .timeout_ms = 2500,
        .use_tls = true,
        .check_server_cert = true
      }


    },
#endif
#ifdef MHD_SUPPORT_OPENSSL
    {
      .label = "certs_chain",
      .server_setup = &MHDT_server_setup_minimal,
      .server_setup_cls = rca_options_open,
      .server_runner = &MHDT_server_run_minimal,
      .phase = {
        .label = "simple RCA get",
        .server_cb = &MHDT_server_reply_text,
        .server_cb_cls = (void *) "Hello world",
        .client_cb = &MHDT_client_get_host,
        .client_cb_cls = "localhost",
        .timeout_ms = 2500,
        .use_tls = true,
        .check_server_cert = true
      }


    },
#endif
    {
      .label = "END"
    }
  };
  unsigned int i;
  int ret = 0;

  (void) argc; /* Unused. Silence compiler warning. */
  (void) argv; /* Unused. Silence compiler warning. */

  for (i = 0; NULL != configs[i].server_setup; i++)
  {
    struct ServerType *st = &configs[i];
    struct MHDT_Phase phases[2] = {
      st->phase
    };
    fprintf (stderr,
             "Running TLS tests with server setup '%s'\n",
             st->label);
    ret = MHDT_test (st->server_setup,
                     st->server_setup_cls,
                     st->server_runner,
                     st->server_runner_cls,
                     phases);
    if (0 != ret)
    {
      fprintf (stderr,
               "Test failed with server of type '%s' (%u)\n",
               st->label,
               i);
      break;
    }
  }
  free (srv_cert_key);
  free (srv_certs_chain);
  return ret;
}
