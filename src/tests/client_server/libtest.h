/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Christian Grothoff

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
 * @file libtest.h
 * @brief testing harness with clients against server
 * @author Christian Grothoff
 */
#ifndef LIBTEST_H
#define LIBTEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd2.h>

/**
 * Information about the current phase.
 */
struct MHDT_PhaseContext
{
  /**
   * Base URL of the server
   */
  const char *base_url;

  /**
   * Specific client we are running.
   */
  unsigned int client_id;
};


/**
 * Function called to run some client logic against
 * the server.
 *
 * @param cls closure
 * @param pc context for the client
 * @return error message, NULL on success
 */
typedef const char *
(*MHDT_ClientLogic)(void *cls,
                    const struct MHDT_PhaseContext *pc);


/**
 * Run request against the base URL and expect the
 * string in @a cls to be returned
 *
 * @param cls closure with text string to be returned
 * @param pc context for the client
 * @return error message, NULL on success
 */
const char *
MHDT_client_get_root (void *cls,
                      const struct MHDT_PhaseContext *pc);


/**
 * Run request against the base URL with the
 * query arguments from @a cls appended to it.
 * Expect the server to return a 200 OK response.
 *
 * @param cls closure with query parameters to append
 *  to the base URL of the server
 * @param pc context for the client
 * @return error message, NULL on success
 */
const char *
MHDT_client_get_with_query (void *cls,
                            const struct MHDT_PhaseContext *pc);


/**
 * Run request against the base URL with the
 * custom header from @a cls set.
 * Expect the server to return a 204 No content response.
 *
 * @param cls closure with custom header to set
 * @param pc context for the client
 * @return error message, NULL on success
 */
const char *
MHDT_client_set_header (void *cls,
                        const struct MHDT_PhaseContext *pc);


/**
 * Run request against the base URL and expect the header from @a cls to be
 * set in the 204 No content response.
 *
 * @param cls closure with custom header to set,
 *      must be of the format "$KEY:$VALUE"
 *      without space before the "$VALUE".
 * @param pc context for the client
 * @return error message, NULL on success
 */
const char *
MHDT_client_expect_header (void *cls,
                           const struct MHDT_PhaseContext *pc);


/**
 * Run simple upload against the base URL and expect a
 * 204 No Content response.
 *
 * @param cls 0-terminated string with data to PUT
 * @param pc context for the client
 * @return error message, NULL on success
 */
const char *
MHDT_client_put_data (void *cls,
                      const struct MHDT_PhaseContext *pc);


/**
 * Run chunked upload against the base URL and expect a
 * 204 No Content response.
 *
 * @param cls 0-terminated string with data to PUT
 * @param pc context for the client
 * @return error message, NULL on success
 */
const char *
MHDT_client_chunk_data (void *cls,
                        const struct MHDT_PhaseContext *pc);


/**
 * A phase defines some server and client-side
 * behaviors to execute.
 */
struct MHDT_Phase
{

  /**
   * Name of the phase, for debugging/logging.
   */
  const char *label;

  /**
   * Logic for the MHD server for this phase.
   */
  MHD_RequestCallback server_cb;

  /**
   * Closure for @e server_cb.
   */
  void *server_cb_cls;

  /**
   * Logic for the CURL client for this phase.
   */
  MHDT_ClientLogic client_cb;

  /**
   * Closure for @e client_cb.
   */
  void *client_cb_cls;

  /**
   * How long is the phase allowed to run at most before
   * timing out. 0 for no timeout.
   */
  unsigned int timeout_ms;

  /**
   * How many clients should be run in parallel.
   * 0 to run just one client.
   */
  unsigned int num_clients;
};


/**
 * Returns the text from @a cls as the response to any
 * request.
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param request the request object
 * @param path the requested uri (without arguments after "?")
 * @param method the HTTP method used (#MHD_HTTP_METHOD_GET,
 *        #MHD_HTTP_METHOD_PUT, etc.)
 * @param upload_size the size of the message upload content payload,
 *                    #MHD_SIZE_UNKNOWN for chunked uploads (if the
 *                    final chunk has not been processed yet)
 * @return action how to proceed, NULL
 *         if the request must be aborted due to a serious
 *         error while handling the request (implies closure
 *         of underling data stream, for HTTP/1.1 it means
 *         socket closure).
 */
const struct MHD_Action *
MHDT_server_reply_text (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size);


/**
 * Returns the text from @a cls as the response to any
 * request, but using chunks by returning @a cls
 * word-wise (breaking into chunks at spaces).
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param request the request object
 * @param path the requested uri (without arguments after "?")
 * @param method the HTTP method used (#MHD_HTTP_METHOD_GET,
 *        #MHD_HTTP_METHOD_PUT, etc.)
 * @param upload_size the size of the message upload content payload,
 *                    #MHD_SIZE_UNKNOWN for chunked uploads (if the
 *                    final chunk has not been processed yet)
 * @return action how to proceed, NULL
 *         if the request must be aborted due to a serious
 *         error while handling the request (implies closure
 *         of underling data stream, for HTTP/1.1 it means
 *         socket closure).
 */
const struct MHD_Action *
MHDT_server_reply_chunked_text (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size);


/**
 * Returns writes text from @a cls to a temporary file
 * and then uses the file descriptor to serve the
 * content to the client.
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param request the request object
 * @param path the requested uri (without arguments after "?")
 * @param method the HTTP method used (#MHD_HTTP_METHOD_GET,
 *        #MHD_HTTP_METHOD_PUT, etc.)
 * @param upload_size the size of the message upload content payload,
 *                    #MHD_SIZE_UNKNOWN for chunked uploads (if the
 *                    final chunk has not been processed yet)
 * @return action how to proceed, NULL
 *         if the request must be aborted due to a serious
 *         error while handling the request (implies closure
 *         of underling data stream, for HTTP/1.1 it means
 *         socket closure).
 */
const struct MHD_Action *
MHDT_server_reply_file (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size);


/**
 * Returns an emtpy response with a custom header
 * set from @a cls and the #MHD_HTTP_STATUS_NO_CONTENT.
 *
 * @param cls header in the format "$NAME:$VALUE"
 *        without a space before "$VALUE".
 * @param request the request object
 * @param path the requested uri (without arguments after "?")
 * @param method the HTTP method used (#MHD_HTTP_METHOD_GET,
 *        #MHD_HTTP_METHOD_PUT, etc.)
 * @param upload_size the size of the message upload content payload,
 *                    #MHD_SIZE_UNKNOWN for chunked uploads (if the
 *                    final chunk has not been processed yet)
 * @return action how to proceed, NULL
 *         if the request must be aborted due to a serious
 *         error while handling the request (implies closure
 *         of underling data stream, for HTTP/1.1 it means
 *         socket closure).
 */
const struct MHD_Action *
MHDT_server_reply_with_header (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size);


/**
 * Checks that the request query arguments match the
 * arguments given in @a cls.
 * request.
 *
 * @param cls string with expected arguments separated by '&' and '='. URI encoding is NOT supported.
 * @param request the request object
 * @param path the requested uri (without arguments after "?")
 * @param method the HTTP method used (#MHD_HTTP_METHOD_GET,
 *        #MHD_HTTP_METHOD_PUT, etc.)
 * @param upload_size the size of the message upload content payload,
 *                    #MHD_SIZE_UNKNOWN for chunked uploads (if the
 *                    final chunk has not been processed yet)
 * @return action how to proceed, NULL
 *         if the request must be aborted due to a serious
 *         error while handling the request (implies closure
 *         of underling data stream, for HTTP/1.1 it means
 *         socket closure).
 */
const struct MHD_Action *
MHDT_server_reply_check_query (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size);


/**
 * Checks that the client request includes the given
 * custom header.  If so, returns #MHD_HTTP_STATUS_NO_CONTENT.
 *
 * @param cls expected header with "$NAME:$VALUE" format.
 * @param request the request object
 * @param path the requested uri (without arguments after "?")
 * @param method the HTTP method used (#MHD_HTTP_METHOD_GET,
 *        #MHD_HTTP_METHOD_PUT, etc.)
 * @param upload_size the size of the message upload content payload,
 *                    #MHD_SIZE_UNKNOWN for chunked uploads (if the
 *                    final chunk has not been processed yet)
 * @return action how to proceed, NULL
 *         if the request must be aborted due to a serious
 *         error while handling the request (implies closure
 *         of underling data stream, for HTTP/1.1 it means
 *         socket closure).
 */
const struct MHD_Action *
MHDT_server_reply_check_header (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size);


/**
 * Checks that the client request includes the given
 * upload.  If so, returns #MHD_HTTP_STATUS_NO_CONTENT.
 *
 * @param cls expected upload data as a 0-terminated string.
 * @param request the request object
 * @param path the requested uri (without arguments after "?")
 * @param method the HTTP method used (#MHD_HTTP_METHOD_GET,
 *        #MHD_HTTP_METHOD_PUT, etc.)
 * @param upload_size the size of the message upload content payload,
 *                    #MHD_SIZE_UNKNOWN for chunked uploads (if the
 *                    final chunk has not been processed yet)
 * @return action how to proceed, NULL
 *         if the request must be aborted due to a serious
 *         error while handling the request (implies closure
 *         of underling data stream, for HTTP/1.1 it means
 *         socket closure).
 */
const struct MHD_Action *
MHDT_server_reply_check_upload (
  void *cls,
  struct MHD_Request *MHD_RESTRICT request,
  const struct MHD_String *MHD_RESTRICT path,
  enum MHD_HTTP_Method method,
  uint_fast64_t upload_size);


/**
 * Initialize options for an MHD daemon for a test.
 *
 * @param cls closure
 * @param[in,out] d daemon to initialize
 * @return error message, NULL on success
 */
typedef const char *
(*MHDT_ServerSetup)(void *cls,
                    struct MHD_Daemon *d);


/**
 * Initialize MHD daemon without any special
 * options, binding to any free port.
 *
 * @param cls closure
 * @param[in,out] d daemon to initialize
 * @return error message, NULL on success
 */
const char *
MHDT_server_setup_minimal (void *cls,
                           struct MHD_Daemon *d);


/**
 * Function that runs an MHD daemon until
 * a read() against @a finsig succeeds.
 *
 * @param cls closure
 * @param finsig fd to read from to detect termination request
 * @param[in,out] d daemon to run
 */
typedef void
(*MHDT_ServerRunner)(void *cls,
                     int finsig,
                     struct MHD_Daemon *d);


/**
 * Function that starts an MHD daemon with the
 * simple #MHD_daemon_start() method until
 * a read() against @a finsig succeeds.
 *
 * @param cls closure, pass a NULL-terminated (!)
 *   array of `struct MHD_DaemonOptionAndValue` with the
 *   the threading mode to use
 * @param finsig fd to read from to detect termination request
 * @param[in,out] d daemon to run
 */
void
MHDT_server_run_minimal (void *cls,
                         int finsig,
                         struct MHD_Daemon *d);


/**
 * Function that runs an MHD daemon in blocking mode until
 * a read() against @a finsig succeeds.
 *
 * @param cls closure
 * @param finsig fd to read from to detect termination request
 * @param[in,out] d daemon to run
 */
void
MHDT_server_run_blocking (void *cls,
                          int finsig,
                          struct MHD_Daemon *d);


/**
 * Run test suite with @a phases for a daemon initialized
 * using @a ss_cb on the local machine.
 *
 * @param ss_cb setup logic for the daemon
 * @param ss_cb_cls closure for @a ss_cb
 * @param run_cb runs the daemon
 * @param run_cb_cls closure for @a run_cb
 * @param phases test phases to run in child processes
 * @return 0 on success, 77 if test was skipped,
 *         error code otherwise
 */
int
MHDT_test (MHDT_ServerSetup ss_cb,
           void *ss_cb_cls,
           MHDT_ServerRunner run_cb,
           void *run_cb_cls,
           const struct MHDT_Phase *phases);

#endif
