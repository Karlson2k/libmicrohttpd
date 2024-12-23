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
 * @file test_authentication.c
 * @brief  test for HTTP authentication
 * @author Christian Grothoff
 */
#include "libtest.h"


int
main (int argc, char *argv[])
{
  struct MHD_DaemonOptionAndValue thread1auto[] = {
    MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_AUTO),
    MHD_D_OPTION_WM_WORKER_THREADS (1),
    MHD_D_OPTION_TERMINATE ()
  };
  struct ServerType
  {
    const char *label;
    MHDT_ServerSetup server_setup;
    void *server_setup_cls;
    MHDT_ServerRunner server_runner;
    void *server_runner_cls;
  } configs[] = {
    {
      .label = "auto-selected mode, single threaded",
      .server_setup = &MHDT_server_setup_minimal,
      .server_setup_cls = thread1auto,
      .server_runner = &MHDT_server_run_minimal,
    },
    {
      .label = "END"
    },
  };
  struct MHDT_Phase phases[] = {
    {
      .label = "simple basic authentication",
      .server_cb = &MHDT_server_reply_check_basic_auth,
      .server_cb_cls = (void *) "username:password",
      .client_cb = &MHDT_client_send_basic_auth,
      .client_cb_cls = (void *) "username:password",
      .timeout_ms = 200,
    },
    {
      .label = "failing basic authentication",
      .server_cb = &MHDT_server_reply_check_basic_auth,
      .server_cb_cls = (void *) "username:password",
      .client_cb = &MHDT_client_fail_basic_auth,
      .client_cb_cls = (void *) "username:word", /* incorrect on purpose */
      .timeout_ms = 200,
    },
    // TODO: digest auth
    {
      .label = NULL,
    },
  };
  unsigned int i;

  (void) argc; /* Unused. Silence compiler warning. */
  (void) argv; /* Unused. Silence compiler warning. */

  for (i = 0; NULL != configs[i].server_setup; i++)
  {
    int ret;

    fprintf (stderr,
             "Running tests with server setup '%s'\n",
             configs[i].label);
    ret = MHDT_test (configs[i].server_setup,
                     configs[i].server_setup_cls,
                     configs[i].server_runner,
                     configs[i].server_runner_cls,
                     phases);
    if (0 != ret)
    {
      fprintf (stderr,
               "Test failed with server of type '%s' (%u)\n",
               configs[i].label,
               i);
      return ret;
    }
  }
  return 0;
}
