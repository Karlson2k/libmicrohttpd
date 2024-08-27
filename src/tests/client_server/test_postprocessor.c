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
 * @file test_postprocessor.c
 * @brief  test with client against server
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
    }
  };
  struct MHDT_PostWant simple_wants[] = {
    {
      .key = "V1",
      .value = "One"
    },
    {
      .key = "V2",
      .value = "Two"
    },
    {
      .key = NULL
    }
  };
  struct MHDT_PostInstructions simple_pi = {
    .enc = MHD_HTTP_POST_ENCODING_FORM_URLENCODED,
    .postdata = "V1=One&V2=Two",
    .postheader = MHD_HTTP_HEADER_CONTENT_TYPE
                  ": application/x-www-form-urlencoded",
    .buffer_size = 32,
    .auto_stream_size = 16,
    .wants = simple_wants
  };
  struct MHDT_PostInstructions simple_mp = {
    .enc = MHD_HTTP_POST_ENCODING_MULTIPART_FORMDATA,
    .postdata = "--{boundary string}\n"
                "Content-Disposition: form-data; name=\"username\",\n"
                "\n"
                "Bob\n"
                "--XXXX\n"
                "Content-Disposition: form-data; name=\"password\",\n"
                "\n"
                "Passwo3d\n"
                "--XXXX\n"
                "Content-Disposition: form-data; name=\"file\"; filename=\"image.jpg\"\n"
                "Content-Type: image/jpeg,\n"
                "\n"
                "IMAGEDATA"
                "--XXXX--\n",
    .postheader = MHD_HTTP_HEADER_CONTENT_TYPE
                  ": multipart/form-data; boundary=XXXX",
    .buffer_size = 32,
    .auto_stream_size = 16
  };
  struct MHDT_PostInstructions simple_tp = {
    .enc = MHD_HTTP_POST_ENCODING_TEXT_PLAIN,
    .postdata = "V1=One\r\nV2=Two\r\n",
    .postheader = MHD_HTTP_HEADER_CONTENT_TYPE ": text/plain",
    .buffer_size = 32,
    .auto_stream_size = 16,
    .wants = simple_wants
  };
  struct MHDT_Phase phases[] = {
    {
      .label = "simple post",
      .server_cb = &MHDT_server_reply_check_post,
      .server_cb_cls = &simple_pi,
      .client_cb = &MHDT_client_do_post,
      .client_cb_cls = &simple_pi,
      .timeout_ms = 2500,
    },
#if 0 // TODO: Enable formats when MHD side is ready
    {
      .label = "multipart post",
      .server_cb = &MHDT_server_reply_check_post,
      .server_cb_cls = &simple_mp,
      .client_cb = &MHDT_client_do_post,
      .client_cb_cls = &simple_mp,
      .timeout_ms = 2500,
    },
#endif
    {
      .label = "plain text post",
      .server_cb = &MHDT_server_reply_check_post,
      .server_cb_cls = &simple_tp,
      .client_cb = &MHDT_client_do_post,
      .client_cb_cls = &simple_tp,
      .timeout_ms = 2500,
    },
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
