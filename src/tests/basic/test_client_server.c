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
#include "libtest.h"


int
main (int argc, char *argv[])
{
  struct MHDT_Phase phases[] = {
    {
      .label = "simple get",
      .server_cb = &MHDT_server_reply_text,
      .server_cb_cls = "Hello world",
      .client_cb = &MHDT_client_get_root,
      .client_cb_cls = "Hello world",
      .timeout_ms = 5,
    },
    // Basic upload
    // HTTP client header
    {
      .label = "client request with custom header",
      .server_cb = &MHDT_server_reply_check_header,
      .server_cb_cls = "C-Header:testvalue",
      .client_cb = &MHDT_client_set_header,
      .client_cb_cls = "C-Header:testvalue",
      .timeout_ms = 5,
    },
    // Response with custom header
    {
      .label = "server response with custom header",
      .server_cb = &MHDT_server_reply_with_header,
      .server_cb_cls = "X-Header:testvalue",
      .client_cb = &MHDT_client_expect_header,
      .client_cb_cls = "X-Header:testvalue",
      .timeout_ms = 5,
    },
    // URL with query parameters
    {
      .label = "URL with query parameters",
      .server_cb = &MHDT_server_reply_check_query,
      .server_cb_cls = "a=b&c",
      .client_cb = &MHDT_client_get_with_query,
      .client_cb_cls = "a=b&c",
      .timeout_ms = 5,
      .num_clients = 10
    },
    // chunked upload
    // chunked download
    {
      .label = NULL,
    },
  };
  (void) argc; /* Unused. Silence compiler warning. */
  (void) argv; /* Unused. Silence compiler warning. */

  // threading modi
  // socket polling functions (select, poll, epoll, internal, external edge, external level)
  //
  return MHDT_test (&MHDT_server_setup_minimal,
                    NULL,
                    &MHDT_server_run_minimal,
                    NULL,
                    phases);
}
