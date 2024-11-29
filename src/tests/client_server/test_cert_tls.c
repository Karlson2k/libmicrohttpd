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
  char *client_of_rca_private_key
    = MHDT_load_pem ("client-of-rca-private-key");
  char *client_of_rca_signed_cert
    = MHDT_load_pem ("client-of-rca-signed-cert");
  char *client_of_ica_private_key
    = MHDT_load_pem ("client-of-ica-private-key");
  char *client_of_ica_signed_cert
    = MHDT_load_pem ("client-of-ica-signed-cert");
  char *client_of_ica_chain
    = MHDT_load_pem ("client-of-ica-chain");
  struct MHD_DaemonOptionAndValue rca_options[] = {
    MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_AUTO),
    MHD_D_OPTION_WM_WORKER_THREADS (1),
    MHD_D_OPTION_TLS (MHD_TLS_BACKEND_ANY),
    MHD_D_OPTION_TLS_CERT_KEY (client_of_rca_signed_cert,
                               client_of_rca_private_key,
                               "clientword"),
    MHD_D_OPTION_TERMINATE ()
  };
  struct MHD_DaemonOptionAndValue ica_options[] = {
    MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_AUTO),
    MHD_D_OPTION_WM_WORKER_THREADS (1),
    MHD_D_OPTION_TLS (MHD_TLS_BACKEND_ANY),
    MHD_D_OPTION_TLS_CERT_KEY (client_of_ica_chain,
                               client_of_ica_private_key,
                               "iclientword"),
    MHD_D_OPTION_TERMINATE ()
  };
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
      .label = "rca_server",
      .server_setup = &MHDT_server_setup_minimal,
      .server_setup_cls = rca_options,
      .server_runner = &MHDT_server_run_minimal,
      .phase = {
        .label = "simple RCA get",
        .server_cb = &MHDT_server_reply_text,
        .server_cb_cls = (void *) "Hello world",
        .client_cb = &MHDT_client_get_host,
        .client_cb_cls = "client.ca.gnu",
        .timeout_ms = 2500,
        .use_tls = true,
        .check_server_cert = true
      }


    },
    {
      .label = "ica_server",
      .server_setup = &MHDT_server_setup_minimal,
      .server_setup_cls = ica_options,
      .server_runner = &MHDT_server_run_minimal,
      .phase = {
        .label = "simple ICA get",
        .server_cb = &MHDT_server_reply_text,
        .server_cb_cls = (void *) "Hello world",
        .client_cb = &MHDT_client_get_host,
        .client_cb_cls = "client.ica.gnu",
        .timeout_ms = 2500,
        .use_tls = true,
        .check_server_cert = true
      }


    },
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
  free (client_of_rca_signed_cert);
  free (client_of_rca_private_key);
  free (client_of_ica_chain);
  free (client_of_ica_signed_cert);
  free (client_of_ica_private_key);
  return ret;
}
