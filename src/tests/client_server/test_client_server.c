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
 * @file test_client_server.c
 * @brief  test with client against server
 * @author Christian Grothoff
 */
#include <microhttpd2.h>
#include "mhd_config.h"
#include "libtest.h"


int
main (int argc, char *argv[])
{
  struct MHD_DaemonOptionAndValue thread1select[] = {
    MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_SELECT),
    MHD_D_OPTION_WM_WORKER_THREADS (1),
    MHD_D_OPTION_TERMINATE ()
  };
  struct MHD_DaemonOptionAndValue thread2select[] = {
    MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_SELECT),
    MHD_D_OPTION_WM_WORKER_THREADS (2),
    MHD_D_OPTION_TERMINATE ()
  };
  struct MHD_DaemonOptionAndValue thread1poll[] = {
    MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_POLL),
    MHD_D_OPTION_WM_WORKER_THREADS (1),
    MHD_D_OPTION_TERMINATE ()
  };
  struct MHD_DaemonOptionAndValue thread2poll[] = {
    MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_POLL),
    MHD_D_OPTION_WM_WORKER_THREADS (1),
    MHD_D_OPTION_TERMINATE ()
  };
  struct MHD_DaemonOptionAndValue thread1epoll[] = {
    MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_EPOLL),
    MHD_D_OPTION_WM_WORKER_THREADS (1),
    MHD_D_OPTION_TERMINATE ()
  };
  struct MHD_DaemonOptionAndValue thread2epoll[] = {
    MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_EPOLL),
    MHD_D_OPTION_WM_WORKER_THREADS (1),
    MHD_D_OPTION_TERMINATE ()
  };
  struct MHD_DaemonOptionAndValue thread1auto[] = {
    MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_AUTO),
    MHD_D_OPTION_WM_WORKER_THREADS (1),
    MHD_D_OPTION_TERMINATE ()
  };
  struct MHD_DaemonOptionAndValue external0auto[] = {
    MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_AUTO),
    MHD_D_OPTION_WM_EXTERNAL_PERIODIC (),
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
#ifdef MHD_USE_SELECT
    {
      .label = "single threaded select",
      .server_setup = &MHDT_server_setup_minimal,
      .server_setup_cls = thread1select,
      .server_runner = &MHDT_server_run_minimal,
    },
    {
      .label = "multi-threaded select",
      .server_setup = &MHDT_server_setup_minimal,
      .server_setup_cls = thread2select,
      .server_runner = &MHDT_server_run_minimal,
    },
#endif
#ifdef MHD_USE_POLL
    {
      .label = "single threaded poll",
      .server_setup = &MHDT_server_setup_minimal,
      .server_setup_cls = thread1poll,
      .server_runner = &MHDT_server_run_minimal,
    },
    {
      .label = "multi-threaded poll",
      .server_setup = &MHDT_server_setup_minimal,
      .server_setup_cls = thread2poll,
      .server_runner = &MHDT_server_run_minimal,
    },
#endif
#if MHD_USE_EPOLL
    {
      .label = "single threaded epoll",
      .server_setup = &MHDT_server_setup_minimal,
      .server_setup_cls = thread1epoll,
      .server_runner = &MHDT_server_run_minimal,
    },
    {
      .label = "multi-threaded epoll",
      .server_setup = &MHDT_server_setup_minimal,
      .server_setup_cls = thread2epoll,
      .server_runner = &MHDT_server_run_minimal,
    },
#endif
    {
      .label = "auto-selected mode, single threaded",
      .server_setup = &MHDT_server_setup_minimal,
      .server_setup_cls = thread1auto,
      .server_runner = &MHDT_server_run_minimal,
    },
#if 1
    /* FIXME: remove once MHD_daemon_process_blocking
       has been implemented */
    {
      .label = "END"
    },
#endif
    {
      .label = "auto-selected external event loop mode, no threads",
      .server_setup = &MHDT_server_setup_minimal,
      .server_setup_cls = external0auto,
      .server_runner = &MHDT_server_run_blocking,
    },
    {
      .label = "END"
    }
  };
  struct MHDT_Phase phases[] = {
    {
      .label = "simple get",
      .server_cb = &MHDT_server_reply_text,
      .server_cb_cls = "Hello world",
      .client_cb = &MHDT_client_get_root,
      .client_cb_cls = "Hello world",
      .timeout_ms = 2500,
    },
    {
      .label = "GET with sendfile",
      .server_cb = &MHDT_server_reply_file,
      .server_cb_cls = "Hello world",
      .client_cb = &MHDT_client_get_root,
      .client_cb_cls = "Hello world",
      .timeout_ms = 2500,
    },
    {
      .label = "client PUT with content-length",
      .server_cb = &MHDT_server_reply_check_upload,
      .server_cb_cls = "simple-upload-value",
      .client_cb = &MHDT_client_put_data,
      .client_cb_cls = "simple-upload-value",
      .timeout_ms = 2500,
    },
    {
      .label = "client PUT with 2 chunks",
      .server_cb = &MHDT_server_reply_check_upload,
      .server_cb_cls = "chunky-upload-value",
      .client_cb = &MHDT_client_chunk_data,
      .client_cb_cls = "chunky-upload-value",
      .timeout_ms = 2500,
    },
    {
      .label = "client request with custom header",
      .server_cb = &MHDT_server_reply_check_header,
      .server_cb_cls = "C-Header:testvalue",
      .client_cb = &MHDT_client_set_header,
      .client_cb_cls = "C-Header:testvalue",
      .timeout_ms = 2500,
    },
    {
      .label = "server response with custom header",
      .server_cb = &MHDT_server_reply_with_header,
      .server_cb_cls = "X-Header:testvalue",
      .client_cb = &MHDT_client_expect_header,
      .client_cb_cls = "X-Header:testvalue",
      .timeout_ms = 2500,
    },
    {
      .label = "URL with query parameters 1",
      .server_cb = &MHDT_server_reply_check_query,
      .server_cb_cls = "a=b&c",
      .client_cb = &MHDT_client_get_with_query,
      .client_cb_cls = "?a=b&c",
      .timeout_ms = 5000,
      .num_clients = 4
    },
    {
      .label = "URL with query parameters 2",
      .server_cb = &MHDT_server_reply_check_query,
      .server_cb_cls = "a=b&c", /* a => b, c => NULL */
      .client_cb = &MHDT_client_get_with_query,
      .client_cb_cls = "?c&a=b",
      .timeout_ms = 5000,
      .num_clients = 1
    },
    {
      .label = "URL with query parameters 3",
      .server_cb = &MHDT_server_reply_check_query,
      .server_cb_cls = "a=&c", /* a => "", c => NULL */
      .client_cb = &MHDT_client_get_with_query,
      .client_cb_cls = "?c&a=",
      .timeout_ms = 5000,
      .num_clients = 1
    },
    {
      .label = "URL with query parameters 4",
      .server_cb = &MHDT_server_reply_check_query,
      .server_cb_cls = "a=", /* a => "" */
      .client_cb = &MHDT_client_get_with_query,
      .client_cb_cls = "?a=",
      .timeout_ms = 5000,
      .num_clients = 1
    },
    {
      .label = "URL with query parameters 5",
      .server_cb = &MHDT_server_reply_check_query,
      .server_cb_cls = "a=b", /* a => "b" */
      .client_cb = &MHDT_client_get_with_query,
      .client_cb_cls = "?a=b",
      .timeout_ms = 5000,
      .num_clients = 1
    },
    {
      .label = "chunked response get",
      .server_cb = &MHDT_server_reply_chunked_text,
      .server_cb_cls = "Hello world",
      .client_cb = &MHDT_client_get_root,
      .client_cb_cls = "Hello world",
      .timeout_ms = 2500,
    },
    // TODO: chunked download
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
             "Running tests with server setup `%s'\n",
             configs[i].label);
    ret = MHDT_test (configs[i].server_setup,
                     configs[i].server_setup_cls,
                     configs[i].server_runner,
                     configs[i].server_runner_cls,
                     phases);
    if (0 != ret)
    {
      fprintf (stderr,
               "Test failed with server of type `%s' (%u)\n",
               configs[i].label,
               i);
      return ret;
    }
  }
  return 0;
}
