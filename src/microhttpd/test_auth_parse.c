/*
  This file is part of libmicrohttpd
  Copyright (C) 2022 Karlson2k (Evgeny Grin)

  This test tool is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License as
  published by the Free Software Foundation; either version 2, or
  (at your option) any later version.

  This test tool is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

/**
 * @file microhttpd/test_str_token.c
 * @brief  Unit tests for request's 'Authorization" headers parsing
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_options.h"
#include <string.h>
#include <stdio.h>
#include "gen_auth.h"
#ifdef BAUTH_SUPPORT
#include "basicauth.h"
#endif /* BAUTH_SUPPORT */
#ifdef DAUTH_SUPPORT
#include "digestauth.h"
#endif /* DAUTH_SUPPORT */
#include "mhd_assert.h"
#include "internal.h"
#include "connection.h"


#ifndef MHD_STATICSTR_LEN_
/**
 * Determine length of static string / macro strings at compile time.
 */
#define MHD_STATICSTR_LEN_(macro) (sizeof(macro) / sizeof(char) - 1)
#endif /* ! MHD_STATICSTR_LEN_ */


#if defined(HAVE___FUNC__)
#define externalErrorExit(ignore) \
    _externalErrorExit_func(NULL, __func__, __LINE__)
#define externalErrorExitDesc(errDesc) \
    _externalErrorExit_func(errDesc, __func__, __LINE__)
#define mhdErrorExit(ignore) \
    _mhdErrorExit_func(NULL, __func__, __LINE__)
#define mhdErrorExitDesc(errDesc) \
    _mhdErrorExit_func(errDesc, __func__, __LINE__)
#elif defined(HAVE___FUNCTION__)
#define externalErrorExit(ignore) \
    _externalErrorExit_func(NULL, __FUNCTION__, __LINE__)
#define externalErrorExitDesc(errDesc) \
    _externalErrorExit_func(errDesc, __FUNCTION__, __LINE__)
#define mhdErrorExit(ignore) \
    _mhdErrorExit_func(NULL, __FUNCTION__, __LINE__)
#define mhdErrorExitDesc(errDesc) \
    _mhdErrorExit_func(errDesc, __FUNCTION__, __LINE__)
#else
#define externalErrorExit(ignore) _externalErrorExit_func(NULL, NULL, __LINE__)
#define externalErrorExitDesc(errDesc) \
  _externalErrorExit_func(errDesc, NULL, __LINE__)
#define mhdErrorExit(ignore) _mhdErrorExit_func(NULL, NULL, __LINE__)
#define mhdErrorExitDesc(errDesc) _mhdErrorExit_func(errDesc, NULL, __LINE__)
#endif


_MHD_NORETURN static void
_externalErrorExit_func (const char *errDesc, const char *funcName, int lineNum)
{
  if ((NULL != errDesc) && (0 != errDesc[0]))
    fprintf (stderr, "%s", errDesc);
  else
    fprintf (stderr, "System or external library call failed");
  if ((NULL != funcName) && (0 != funcName[0]))
    fprintf (stderr, " in %s", funcName);
  if (0 < lineNum)
    fprintf (stderr, " at line %d", lineNum);

  fprintf (stderr, ".\nLast errno value: %d (%s)\n", (int) errno,
           strerror (errno));
#ifdef MHD_WINSOCK_SOCKETS
  fprintf (stderr, "WSAGetLastError() value: %d\n", (int) WSAGetLastError ());
#endif /* MHD_WINSOCK_SOCKETS */
  fflush (stderr);
  exit (99);
}


_MHD_NORETURN static void
_mhdErrorExit_func (const char *errDesc, const char *funcName, int lineNum)
{
  if ((NULL != errDesc) && (0 != errDesc[0]))
    fprintf (stderr, "%s", errDesc);
  else
    fprintf (stderr, "MHD unexpected error");
  if ((NULL != funcName) && (0 != funcName[0]))
    fprintf (stderr, " in %s", funcName);
  if (0 < lineNum)
    fprintf (stderr, " at line %d", lineNum);

  fprintf (stderr, ".\nLast errno value: %d (%s)\n", (int) errno,
           strerror (errno));

  fflush (stderr);
  exit (8);
}


/* Declarations for local replacements of MHD functions */
/* None, headers are included */

/* Local replacements implementations */

/**
 * Parameters for function emulation
 */
struct TestArguments
{
  const char *str;
  size_t len;
  enum MHD_Result res;
};


_MHD_EXTERN enum MHD_Result
MHD_lookup_connection_value_n (struct MHD_Connection *connection,
                               enum MHD_ValueKind kind,
                               const char *key,
                               size_t key_size,
                               const char **value_ptr,
                               size_t *value_size_ptr)
{
  struct TestArguments *args;
  if (NULL == connection)
    mhdErrorExitDesc ("The 'connection' parameter is NULL");
  if (MHD_HEADER_KIND != kind)
    mhdErrorExitDesc ("Wrong 'kind' parameter");
  if (NULL == key)
    mhdErrorExitDesc ("The 'key' parameter is NULL");
  if (0 != strcmp (key, MHD_HTTP_HEADER_AUTHORIZATION))
    mhdErrorExitDesc ("Wrong 'key' value");
  if (MHD_STATICSTR_LEN_ (MHD_HTTP_HEADER_AUTHORIZATION) != key_size)
    mhdErrorExitDesc ("Wrong 'key_size' value");
  if (NULL == value_ptr)
    mhdErrorExitDesc ("The 'value_ptr' parameter is NULL");
  if (NULL == value_size_ptr)
    mhdErrorExitDesc ("The 'value_size_ptr' parameter is NULL");

  if (NULL == connection->client_context)
    externalErrorExitDesc ("The 'connection->client_context' value is NULL");

  args = (struct TestArguments *) connection->client_context;
  if (MHD_NO == args->res)
    return args->res;

  *value_ptr = args->str;
  *value_size_ptr = args->len;
  return args->res;
}


void *
MHD_connection_alloc_memory_ (struct MHD_Connection *connection,
                              size_t size)
{
  void *ret;
  if (NULL == connection)
    mhdErrorExitDesc ("'connection' parameter is NULL");
  /* Use 'socket_context' just as a flag */
  if (NULL != connection->socket_context)
    mhdErrorExitDesc ("Unexpected memory allocation, " \
                      "while previous allocation was not freed");
  /* Just use simple "malloc()" here */
  ret = malloc (size);
  if (NULL == ret)
    externalErrorExit ();
  connection->socket_context = ret;
  return ret;
}


_MHD_NORETURN void
MHD_DLOG (const struct MHD_Daemon *daemon,
          const char *format,
          ...)
{
  (void) daemon;
  fprintf (stderr, "Unexpected call of 'MHD_LOG(), format is '%s'.\n", format);
  mhdErrorExit ();
}


/**
 * Static variable to avoid additional malloc()/free() pairs
 */
static struct MHD_Connection conn;

/**
 * Create test "Authorization" client header and return result of its parsing.
 *
 * Function performs basic checking of the parsing result
 * @param use_hdr if set to non-zero value, the test header is added,
 *                if set to zero value, emulated absence "Authorization" client
 *                header
 * @param hdr the test "Authorization" client header string, must be statically
 *                allocated.
 * @param hdr_len the length of the @a hdr
 * @return result of @a hdr parsing (or parsing of header absence if @a use_hdr
 *         is not set), never NULL. Must be free()'ed.
 * @note The function is NOT thread-safe
 */
static const struct MHD_AuthRqHeader *
get_AuthRqHeader (int use_hdr, const char *hdr, size_t hdr_len)
{
  const struct MHD_AuthRqHeader *res1;
  const struct MHD_AuthRqHeader *res2;
  static struct TestArguments test_args;
  if (NULL != conn.socket_context)
    mhdErrorExitDesc ("Memory was not freed in previous check cycle");
  test_args.res = use_hdr ? MHD_YES : MHD_NO;
  test_args.str = hdr;
  test_args.len = hdr_len;
  memset (&conn, 0, sizeof (conn));
  /* Store pointer in some member unused in this test */
  conn.client_context = &test_args;
  conn.state = MHD_CONNECTION_FULL_REQ_RECEIVED; /* Should be typical value */
  res1 = MHD_get_auth_rq_params_ (&conn);
  if (NULL == res1)
    mhdErrorExitDesc ("MHD_get_auth_rq_params_() returned NULL");
  res2 = MHD_get_auth_rq_params_ (&conn);
  if (res1 != res2)
    mhdErrorExitDesc ("MHD_get_auth_rq_params_() returned another pointer when" \
                      "called for the second time");
  return res2;
}


static void
free_AuthRqHeader (void)
{
  if (conn.socket_context != conn.rq_auth)
    externalErrorExitDesc ("Memory allocation is not tracked as it should be");

  if (NULL != conn.rq_auth)
    free (conn.socket_context);
  conn.rq_auth = NULL;
  conn.socket_context = NULL;
}


static const char *
get_auth_type_str (enum MHD_AuthType type)
{
  switch (type)
  {
  case MHD_AUTHTYPE_NONE:
    return "No authorisation";
  case MHD_AUTHTYPE_BASIC:
    return "Basic Authorisation";
  case MHD_AUTHTYPE_DIGEST:
    return "Digest Authorisation";
  case MHD_AUTHTYPE_UNKNOWN:
    return "Unknown/Unsupported authorisation";
  case MHD_AUTHTYPE_INVALID:
    return "Wrong/broken authorisation header";
  default:
    mhdErrorExitDesc ("Wrong 'enum MHD_AuthType' value");
  }
  return "Wrong 'enum MHD_AuthType' value"; /* Unreachable code */
}


/* return zero if succeed, 1 otherwise */
static unsigned int
expect_result_type_n (int use_hdr, const char *hdr, size_t hdr_len,
                      const enum MHD_AuthType expected_type,
                      unsigned int line_num)
{
  const struct MHD_AuthRqHeader *h;
  unsigned int ret;

  h = get_AuthRqHeader (use_hdr, hdr, hdr_len);
  mhd_assert (NULL != h);
  if (expected_type == h->auth_type)
    ret = 0;
  else
  {
    fprintf (stderr,
             "'Authorization' header parsing FAILED:\n"
             "Wrong type:\tRESULT: %s\tEXPECTED: %s\n",
             get_auth_type_str (h->auth_type),
             get_auth_type_str (expected_type));
    if (! use_hdr)
      fprintf (stderr,
               "Input: Absence of 'Authorization' header.\n");
    else if (0 == hdr_len)
      fprintf (stderr,
               "Input: empty 'Authorization' header.\n");
    else
      fprintf (stderr,
               "Input Header: '%.*s'\n", (int) hdr_len, hdr);
    fprintf (stderr,
             "The check is at line: %u\n\n", line_num);
    ret = 1;
  }
  free_AuthRqHeader ();

  return ret;
}


#define expect_result_type(u,h,t) \
    expect_result_type_n(u,h,MHD_STATICSTR_LEN_(h),t,__LINE__)


#ifdef BAUTH_SUPPORT
#define EXPECT_TYPE_FOR_BASIC_AUTH MHD_AUTHTYPE_BASIC
#define EXPECT_TYPE_FOR_BASIC_INVLD MHD_AUTHTYPE_INVALID
#else  /* ! BAUTH_SUPPORT */
#define EXPECT_TYPE_FOR_BASIC_AUTH MHD_AUTHTYPE_UNKNOWN
#define EXPECT_TYPE_FOR_BASIC_INVLD MHD_AUTHTYPE_UNKNOWN
#endif /* ! BAUTH_SUPPORT */
#ifdef DAUTH_SUPPORT
#define EXPECT_TYPE_FOR_DIGEST_AUTH MHD_AUTHTYPE_DIGEST
#define EXPECT_TYPE_FOR_DIGEST_INVLD MHD_AUTHTYPE_INVALID
#else  /* ! DAUTH_SUPPORT */
#define EXPECT_TYPE_FOR_DIGEST_AUTH MHD_AUTHTYPE_UNKNOWN
#define EXPECT_TYPE_FOR_DIGEST_INVLD MHD_AUTHTYPE_UNKNOWN
#endif /* ! DAUTH_SUPPORT */


static unsigned int
check_type (void)
{
  unsigned int r = 0; /**< The number of errors */

  r += expect_result_type (0, "", MHD_AUTHTYPE_NONE);

  r += expect_result_type (1, "", MHD_AUTHTYPE_INVALID);
  r += expect_result_type (1, " ", MHD_AUTHTYPE_INVALID);
  r += expect_result_type (1, "    ", MHD_AUTHTYPE_INVALID);
  r += expect_result_type (1, "\t", MHD_AUTHTYPE_INVALID);
  r += expect_result_type (1, " \t", MHD_AUTHTYPE_INVALID);
  r += expect_result_type (1, "\t ", MHD_AUTHTYPE_INVALID);
  r += expect_result_type (1, "\t \t", MHD_AUTHTYPE_INVALID);
  r += expect_result_type (1, " \t ", MHD_AUTHTYPE_INVALID);
  r += expect_result_type (1, " \t \t", MHD_AUTHTYPE_INVALID);
  r += expect_result_type (1, "\t \t ", MHD_AUTHTYPE_INVALID);

  r += expect_result_type (1, "Basic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, " Basic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\tBasic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\t Basic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, " \tBasic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "    Basic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\t\t\tBasic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\t\t  \tBasic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\t\t  \t Basic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "Basic ", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "Basic \t", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "Basic \t ", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "Basic 123", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "Basic \t123", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "Basic  abc ", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "bAsIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, " bAsIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\tbAsIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\t bAsIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, " \tbAsIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "    bAsIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\t\t\tbAsIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\t\t  \tbAsIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\t\t  \t bAsIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "bAsIC ", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "bAsIC \t", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "bAsIC \t ", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "bAsIC 123", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "bAsIC \t123", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "bAsIC  abc ", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "basic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, " basic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\tbasic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\t basic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, " \tbasic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "    basic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\t\t\tbasic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\t\t  \tbasic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\t\t  \t basic", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "basic ", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "basic \t", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "basic \t ", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "basic 123", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "basic \t123", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "basic  abc ", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "BASIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, " BASIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\tBASIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\t BASIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, " \tBASIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "    BASIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\t\t\tBASIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\t\t  \tBASIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "\t\t  \t BASIC", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "BASIC ", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "BASIC \t", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "BASIC \t ", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "BASIC 123", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "BASIC \t123", EXPECT_TYPE_FOR_BASIC_AUTH);
  r += expect_result_type (1, "BASIC  abc ", EXPECT_TYPE_FOR_BASIC_AUTH);
  /* Only single token is allowed for 'Basic' Authorization */
  r += expect_result_type (1, "Basic a b", EXPECT_TYPE_FOR_BASIC_INVLD);
  r += expect_result_type (1, "Basic a\tb", EXPECT_TYPE_FOR_BASIC_INVLD);
  r += expect_result_type (1, "Basic a\tb", EXPECT_TYPE_FOR_BASIC_INVLD);
  r += expect_result_type (1, "Basic abc1 b", EXPECT_TYPE_FOR_BASIC_INVLD);
  r += expect_result_type (1, "Basic c abc1", EXPECT_TYPE_FOR_BASIC_INVLD);
  r += expect_result_type (1, "Basic c abc1 ", EXPECT_TYPE_FOR_BASIC_INVLD);
  r += expect_result_type (1, "Basic c abc1\t", EXPECT_TYPE_FOR_BASIC_INVLD);
  r += expect_result_type (1, "Basic c\tabc1\t", EXPECT_TYPE_FOR_BASIC_INVLD);
  r += expect_result_type (1, "Basic c abc1 b", EXPECT_TYPE_FOR_BASIC_INVLD);
  r += expect_result_type (1, "Basic zyx, b", EXPECT_TYPE_FOR_BASIC_INVLD);
  r += expect_result_type (1, "Basic zyx,b", EXPECT_TYPE_FOR_BASIC_INVLD);
  r += expect_result_type (1, "Basic zyx ,b", EXPECT_TYPE_FOR_BASIC_INVLD);
  r += expect_result_type (1, "Basic zyx;b", EXPECT_TYPE_FOR_BASIC_INVLD);
  r += expect_result_type (1, "Basic zyx; b", EXPECT_TYPE_FOR_BASIC_INVLD);

  r += expect_result_type (1, "Basic2", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, " Basic2", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, " Basic2 ", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "\tBasic2", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "\t Basic2", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, " \tBasic2", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "    Basic2", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "\t\t\tBasic2", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "\t\t  \tBasic2", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "\t\t  \t Basic2", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "Basic2 ", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "Basic2 \t", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "Basic2 \t ", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "Basic2 123", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "Basic2 \t123", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "Basic2  abc ", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "BasicBasic", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, " BasicBasic", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "\tBasicBasic", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "\t BasicBasic", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, " \tBasicBasic", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "BasicBasic ", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "BasicBasic \t", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "BasicBasic \t\t", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "BasicDigest", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, " BasicDigest", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "BasicDigest ", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "Basic\0", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "\0" "Basic", MHD_AUTHTYPE_UNKNOWN);

  r += expect_result_type (1, "Digest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, " Digest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\tDigest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t Digest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, " \tDigest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "    Digest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t\t\tDigest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t\t  \tDigest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t\t  \t Digest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest \t", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest \t ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\tDigest ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "  Digest \t", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t \tDigest \t ", EXPECT_TYPE_FOR_DIGEST_AUTH);

  r += expect_result_type (1, "digEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, " digEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\tdigEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t digEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, " \tdigEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "    digEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t\t\tdigEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t\t  \tdigEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t\t  \t digEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "digEST ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "digEST \t", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "digEST \t ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\tdigEST ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "  digEST \t", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t \tdigEST \t ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "digest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, " digest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\tdigest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t digest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, " \tdigest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "    digest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t\t\tdigest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t\t  \tdigest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t\t  \t digest", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "digest ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "digest \t", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "digest \t ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\tdigest ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "  digest \t", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t \tdigest \t ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "DIGEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, " DIGEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\tDIGEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t DIGEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, " \tDIGEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "    DIGEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t\t\tDIGEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t\t  \tDIGEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t\t  \t DIGEST", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "DIGEST ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "DIGEST \t", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "DIGEST \t ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\tDIGEST ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "  DIGEST \t", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "\t \tDIGEST \t ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest ,", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest ,\t", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest ,  ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest   ,  ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest ,\t, ,\t, ,\t, ,", \
                           EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest ,\t,\t,\t,\t,\t,\t,", \
                           EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest a=b", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest a=\"b\"", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest nc=1", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest nc=\"1\"", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest a=b ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest a=\"b\" ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest nc=1 ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest nc=\"1\" ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest a = b", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest a\t=\t\"b\"", \
                           EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest nc =1", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest nc= \"1\"", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest a=\tb ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest a = \"b\" ", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest nc\t\t\t= 1 ", \
                           EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest nc   =\t\t\t\"1\" ", \
                           EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest nc =1,,,,", EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest nc =1  ,,,,", \
                           EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest ,,,,nc= \"1 \"", \
                           EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest ,,,,  nc= \" 1\"", \
                           EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest ,,,, nc= \"1\",,,,", \
                           EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest ,,,, nc= \"1\"  ,,,,", \
                           EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest ,,,, nc= \"1\"  ,,,,", \
                           EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest ,,,, nc= \"1\"  ,,,,", \
                           EXPECT_TYPE_FOR_DIGEST_AUTH);
  r += expect_result_type (1, "Digest ,,,, nc= \"1\"  ,,,,,", \
                           EXPECT_TYPE_FOR_DIGEST_AUTH);

  r += expect_result_type (1, "Digest nc", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest   nc", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc  ", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc  ,", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc  , ", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest \tnc\t  ", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest \tnc\t  ", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc,", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc,uri", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc=1,uri", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc=1,uri   ", \
                           EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc=1,uri,", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc=1, uri,", \
                           EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc=1,uri   ,", \
                           EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc=1,uri   , ", \
                           EXPECT_TYPE_FOR_DIGEST_INVLD);
  /* Binary zero */
  r += expect_result_type (1, "Digest nc=1\0", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc=1\0" " ", \
                           EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc=1\t\0", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc=\0" "1", EXPECT_TYPE_FOR_DIGEST_INVLD);
  /* Semicolon */
  r += expect_result_type (1, "Digest nc=1;", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc=1; ", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc=;1", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc;=1", EXPECT_TYPE_FOR_DIGEST_INVLD);
  /* The equal sign alone */
  r += expect_result_type (1, "Digest =", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest   =", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest   =  ", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest ,=", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest , =", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest ,= ", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest , = ", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc=1,=", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest nc=1, =", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest foo=bar,=", EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest foo=bar, =", \
                           EXPECT_TYPE_FOR_DIGEST_INVLD);
  /* Full set of parameters with semicolon inside */
  r += expect_result_type (1, "Digest username=\"test@example.com\", " \
                           "realm=\"users@example.com\", nonce=\"32141232413abcde\", " \
                           "uri=\"/example\", qop=auth, nc=00000001; cnonce=\"0a4f113b\", " \
                           "response=\"6629fae49393a05397450978507c4ef1\", " \
                           "opaque=\"sadfljk32sdaf\"", \
                           EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest username=\"test@example.com\", " \
                           "realm=\"users@example.com\", nonce=\"32141232413abcde\", " \
                           "uri=\"/example\", qop=auth, nc=00000001;cnonce=\"0a4f113b\", " \
                           "response=\"6629fae49393a05397450978507c4ef1\", " \
                           "opaque=\"sadfljk32sdaf\"", \
                           EXPECT_TYPE_FOR_DIGEST_INVLD);
  r += expect_result_type (1, "Digest username;=\"test@example.com\", " \
                           "realm=\"users@example.com\", nonce=\"32141232413abcde\", " \
                           "uri=\"/example\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", " \
                           "response=\"6629fae49393a05397450978507c4ef1\", " \
                           "opaque=\"sadfljk32sdaf\"", \
                           EXPECT_TYPE_FOR_DIGEST_INVLD);

  r += expect_result_type (1, "Digest2", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "2Digest", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "Digest" "a", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "a" "Digest", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, " Digest2", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, " 2Digest", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, " Digest" "a", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, " a" "Digest", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "Digest2 ", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "2Digest ", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "Digest" "a", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "a" "Digest ", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "DigestBasic", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "DigestBasic ", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, " DigestBasic", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "DigestBasic" "a", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "Digest\0", MHD_AUTHTYPE_UNKNOWN);
  r += expect_result_type (1, "\0Digest", MHD_AUTHTYPE_UNKNOWN);
  return r;
}


#ifdef BAUTH_SUPPORT

/* return zero if succeed, 1 otherwise */
static unsigned int
expect_basic_n (const char *hdr, size_t hdr_len,
                const char *tkn, size_t tkn_len,
                unsigned int line_num)
{
  const struct MHD_AuthRqHeader *h;
  unsigned int ret;

  mhd_assert (NULL != hdr);
  mhd_assert (0 != hdr_len);

  h = get_AuthRqHeader (1, hdr, hdr_len);
  mhd_assert (NULL != h);
  if (MHD_AUTHTYPE_BASIC != h->auth_type)
  {
    fprintf (stderr,
             "'Authorization' header parsing FAILED:\n"
             "Wrong type:\tRESULT: %s\tEXPECTED: %s\n",
             get_auth_type_str (h->auth_type),
             get_auth_type_str (MHD_AUTHTYPE_BASIC));
    ret = 1;
  }
  else
  {
    if (NULL == h->params.bauth)
      mhdErrorExitDesc ("'params.bauth' pointer is NULL");
    ret = 1;
    if (tkn_len != h->params.bauth->token68.len)
      fprintf (stderr,
               "'Authorization' header parsing FAILED:\n"
               "Wrong token length:\tRESULT[%u]: %.*s\tEXPECTED[%u]: %.*s\n",
               (unsigned) h->params.bauth->token68.len,
               (int) h->params.bauth->token68.len,
               h->params.bauth->token68.str ?
               h->params.bauth->token68.str : "(NULL)",
               (unsigned) tkn_len, (int) tkn_len, tkn ? tkn : "(NULL)");
    else if ( ((NULL == tkn) != (NULL == h->params.bauth->token68.str)) ||
              ((NULL != tkn) &&
               (0 != memcmp (tkn, h->params.bauth->token68.str, tkn_len))) )
      fprintf (stderr,
               "'Authorization' header parsing FAILED:\n"
               "Wrong token string:\tRESULT[%u]: %.*s\tEXPECTED[%u]: %.*s\n",
               (unsigned) h->params.bauth->token68.len,
               (int) h->params.bauth->token68.len,
               h->params.bauth->token68.str ?
               h->params.bauth->token68.str : "(NULL)",
               (unsigned) tkn_len, (int) tkn_len, tkn ? tkn : "(NULL)");
    else
      ret = 0;
  }
  if (0 != ret)
  {
    fprintf (stderr,
             "Input Header: '%.*s'\n", (int) hdr_len, hdr);
    fprintf (stderr,
             "The check is at line: %u\n\n", line_num);
  }
  free_AuthRqHeader ();

  return ret;
}


#define expect_basic(h,t) \
    expect_basic_n(h,MHD_STATICSTR_LEN_(h),t,MHD_STATICSTR_LEN_(t),__LINE__)

static unsigned int
check_basic (void)
{
  unsigned int r = 0; /**< The number of errors */

  r += expect_basic ("Basic a", "a");
  r += expect_basic ("Basic    a", "a");
  r += expect_basic ("Basic \ta", "a");
  r += expect_basic ("Basic \ta\t", "a");
  r += expect_basic ("Basic \ta ", "a");
  r += expect_basic ("Basic  a ", "a");
  r += expect_basic ("Basic \t a\t ", "a");
  r += expect_basic ("Basic \t abc\t ", "abc");
  r += expect_basic ("Basic 2143sdfa4325sdfgfdab354354314SDSDFc", \
                     "2143sdfa4325sdfgfdab354354314SDSDFc");
  r += expect_basic ("Basic 2143sdfa4325sdfgfdab354354314SDSDFc  ", \
                     "2143sdfa4325sdfgfdab354354314SDSDFc");
  r += expect_basic ("Basic   2143sdfa4325sdfgfdab354354314SDSDFc", \
                     "2143sdfa4325sdfgfdab354354314SDSDFc");
  r += expect_basic ("Basic   2143sdfa4325sdfgfdab354354314SDSDFc  ", \
                     "2143sdfa4325sdfgfdab354354314SDSDFc");
  r += expect_basic ("  Basic 2143sdfa4325sdfgfdab354354314SDSDFc", \
                     "2143sdfa4325sdfgfdab354354314SDSDFc");
  r += expect_basic ("  Basic  2143sdfa4325sdfgfdab354354314SDSDFc", \
                     "2143sdfa4325sdfgfdab354354314SDSDFc");
  r += expect_basic ("  Basic 2143sdfa4325sdfgfdab354354314SDSDFc ", \
                     "2143sdfa4325sdfgfdab354354314SDSDFc");
  r += expect_basic ("  Basic  2143sdfa4325sdfgfdab354354314SDSDFc ", \
                     "2143sdfa4325sdfgfdab354354314SDSDFc");
  r += expect_basic ("  Basic  2143sdfa4325sdfgfdab354354314SDSDFc  ", \
                     "2143sdfa4325sdfgfdab354354314SDSDFc");
  r += expect_basic ("Basic -A.1-z~9+/=====", "-A.1-z~9+/=====");
  r += expect_basic ("  Basic   -A.1-z~9+/===== ", "-A.1-z~9+/=====");

  r += expect_basic_n ("Basic", MHD_STATICSTR_LEN_ ("Basic"), NULL, 0,__LINE__);
  r += expect_basic_n ("   Basic", MHD_STATICSTR_LEN_ ("   Basic"), NULL, 0,
                       __LINE__);
  r += expect_basic_n ("Basic   ", MHD_STATICSTR_LEN_ ("Basic   "), NULL, 0,
                       __LINE__);
  r += expect_basic_n ("Basic \t\t", MHD_STATICSTR_LEN_ ("Basic \t\t"), NULL, 0,
                       __LINE__);

  return r;
}


#endif /* BAUTH_SUPPORT */


#ifdef DAUTH_SUPPORT

/* return zero if succeed, 1 otherwise */
static unsigned int
cmp_dauth_param (const char *pname, const struct MHD_RqDAuthParam *param,
                 const char *expected_value)
{
  unsigned int ret;
  size_t expected_len;
  bool expected_quoted;
  mhd_assert (NULL != param);
  mhd_assert (NULL != pname);
  ret = 0;

  if (NULL == expected_value)
  {
    expected_len = 0;
    expected_quoted = false;
    if (NULL != param->value.str)
      ret = 1;
    else if (param->value.len != expected_len)
      ret = 1;
    else if (param->quoted != expected_quoted)
      ret = 1;
  }
  else
  {
    expected_len = strlen (expected_value);
    expected_quoted = (NULL != memchr (expected_value, '\\', expected_len));
    if (NULL == param->value.str)
      ret = 1;
    else if (param->value.len != expected_len)
      ret = 1;
    else if (param->quoted != expected_quoted)
      ret = 1;
    else if (0 != memcmp (param->value.str, expected_value, expected_len))
      ret = 1;
  }
  if (0 != ret)
  {
    fprintf (stderr, "Parameter '%s' parsed incorrectly:\n", pname);
    fprintf (stderr, "\tRESULT  :\tvalue.str: %s",
             param->value.str ? param->value.str : "(NULL)");
    fprintf (stderr, "\tvalue.len: %u",
             (unsigned) param->value.len);
    fprintf (stderr, "\tquoted: %s\n",
             (unsigned) param->quoted ? "true" : "false");
    fprintf (stderr, "\tEXPECTED:\tvalue.str: %s",
             expected_value ? expected_value : "(NULL)");
    fprintf (stderr, "\tvalue.len: %u",
             (unsigned) expected_len);
    fprintf (stderr, "\tquoted: %s\n",
             (unsigned) expected_quoted ? "true" : "false");
  }
  return ret;
}


/* return zero if succeed, 1 otherwise */
static unsigned int
expect_digest_n (const char *hdr, size_t hdr_len,
                 const char *nonce,
                 const char *algorithm,
                 const char *response,
                 const char *username,
                 const char *username_ext,
                 const char *realm,
                 const char *uri,
                 const char *qop,
                 const char *cnonce,
                 const char *nc,
                 int userhash,
                 unsigned int line_num)
{
  const struct MHD_AuthRqHeader *h;
  unsigned int ret;

  mhd_assert (NULL != hdr);
  mhd_assert (0 != hdr_len);

  h = get_AuthRqHeader (1, hdr, hdr_len);
  mhd_assert (NULL != h);
  if (MHD_AUTHTYPE_DIGEST != h->auth_type)
  {
    fprintf (stderr,
             "'Authorization' header parsing FAILED:\n"
             "Wrong type:\tRESULT: %s\tEXPECTED: %s\n",
             get_auth_type_str (h->auth_type),
             get_auth_type_str (MHD_AUTHTYPE_DIGEST));
    ret = 1;
  }
  else
  {
    const struct MHD_RqDAuth *params;
    if (NULL == h->params.dauth)
      mhdErrorExitDesc ("'params.dauth' pointer is NULL");
    params = h->params.dauth;
    ret = 0;

    ret += cmp_dauth_param ("nonce", &params->nonce, nonce);
    ret += cmp_dauth_param ("algorithm", &params->algorithm, algorithm);
    ret += cmp_dauth_param ("response", &params->response, response);
    ret += cmp_dauth_param ("username", &params->username, username);
    ret += cmp_dauth_param ("username_ext", &params->username_ext,
                            username_ext);
    ret += cmp_dauth_param ("realm", &params->realm, realm);
    ret += cmp_dauth_param ("uri", &params->uri, uri);
    ret += cmp_dauth_param ("qop", &params->qop, qop);
    ret += cmp_dauth_param ("cnonce", &params->cnonce, cnonce);
    ret += cmp_dauth_param ("nc", &params->nc, nc);
    if (params->userhash != ! (! userhash))
    {
      ret += 1;
      fprintf (stderr, "Parameter 'userhash' parsed incorrectly:\n");
      fprintf (stderr, "\tRESULT  :\t%s\n",
               params->userhash ? "true" : "false");
      fprintf (stderr, "\tEXPECTED:\t%s\n",
               userhash ? "true" : "false");
    }
  }
  if (0 != ret)
  {
    fprintf (stderr,
             "Input Header: '%.*s'\n", (int) hdr_len, hdr);
    fprintf (stderr,
             "The check is at line: %u\n\n", line_num);
  }
  free_AuthRqHeader ();

  return ret;
}


#define expect_digest(h,no,a,rs,un,ux,rm,ur,q,c,nc,uh) \
    expect_digest_n(h,MHD_STATICSTR_LEN_(h),\
                    no,a,rs,un,ux,rm,ur,q,c,nc,uh,__LINE__)

static unsigned int
check_digest (void)
{
  unsigned int r = 0; /**< The number of errors */

  r += expect_digest ("Digest", NULL, NULL, NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, NULL, 0);
  r += expect_digest ("Digest nc=1", NULL, NULL, NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, "1", 0);
  r += expect_digest ("Digest nc=\"1\"", NULL, NULL, NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, "1", 0);
  r += expect_digest ("Digest nc=\"1\"   ", NULL, NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, NULL, "1", 0);
  r += expect_digest ("Digest ,nc=\"1\"   ", NULL, NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, NULL, "1", 0);
  r += expect_digest ("Digest nc=\"1\",   ", NULL, NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, NULL, "1", 0);
  r += expect_digest ("Digest nc=\"1\" ,   ", NULL, NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, NULL, "1", 0);
  r += expect_digest ("Digest nc=1,   ", NULL, NULL, NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, "1", 0);
  r += expect_digest ("Digest nc=1 ,   ", NULL, NULL, NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, "1", 0);
  r += expect_digest ("Digest ,,,nc=1,   ", NULL, NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, NULL, "1", 0);
  r += expect_digest ("Digest ,,,nc=1 ,   ", NULL, NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, NULL, "1", 0);
  r += expect_digest ("Digest ,,,nc=\"1 \",   ", NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, NULL, NULL, "1 ", 0);
  r += expect_digest ("Digest nc=\"1 \"", NULL, NULL, NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, "1 ", 0);
  r += expect_digest ("Digest nc=\"1 \" ,", NULL, NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, NULL, "1 ", 0);
  r += expect_digest ("Digest nc=\"1 \", ", NULL, NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, NULL, "1 ", 0);
  r += expect_digest ("Digest nc=\"1;\", ", NULL, NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, NULL, "1;", 0);
  r += expect_digest ("Digest nc=\"1\\;\", ", NULL, NULL, NULL, NULL, NULL, \
                      NULL, NULL, NULL, NULL, "1\\;", 0);

  r += expect_digest ("Digest username=\"test@example.com\", " \
                      "realm=\"users@example.com\", nonce=\"32141232413abcde\", " \
                      "uri=\"/example\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", " \
                      "response=\"6629fae49393a05397450978507c4ef1\", " \
                      "opaque=\"sadfljk32sdaf\"", "32141232413abcde", NULL, \
                      "6629fae49393a05397450978507c4ef1", "test@example.com", \
                      NULL, "users@example.com", "/example", "auth", \
                      "0a4f113b", "00000001", 0);
  r += expect_digest ("Digest username=\"test@example.com\", " \
                      "realm=\"users@example.com\", algorithm=SHA-256, " \
                      "nonce=\"32141232413abcde\", " \
                      "username*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates, " \
                      "uri=\"/example\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", " \
                      "response=\"6629fae49393a05397450978507c4ef1\", " \
                      "opaque=\"sadfljk32sdaf\"", "32141232413abcde", "SHA-256", \
                      "6629fae49393a05397450978507c4ef1", "test@example.com", \
                      "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates", \
                      "users@example.com", "/example", "auth", "0a4f113b", \
                      "00000001", 0);
  r += expect_digest ("Digest username=test@example.com, " \
                      "realm=users@example.com, algorithm=\"SHA-256\", " \
                      "nonce=32141232413abcde, " \
                      "username*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates, " \
                      "uri=/example, qop=\"auth\", nc=\"00000001\", cnonce=0a4f113b, " \
                      "response=6629fae49393a05397450978507c4ef1, " \
                      "opaque=sadfljk32sdaf", "32141232413abcde", "SHA-256", \
                      "6629fae49393a05397450978507c4ef1", "test@example.com", \
                      "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates", \
                      "users@example.com", "/example", "auth", "0a4f113b", \
                      "00000001", 0);
  r += expect_digest ("Digest username = \"test@example.com\", " \
                      "realm\t=\t\"users@example.com\", algorithm\t= SHA-256, " \
                      "nonce\t= \"32141232413abcde\", " \
                      "username*\t=\tUTF-8''%c2%a3%20and%20%e2%82%ac%20rates, " \
                      "uri = \"/example\", qop = auth, nc\t=\t00000001, " \
                      "cnonce\t\t\t=   \"0a4f113b\", " \
                      "response  =\"6629fae49393a05397450978507c4ef1\", " \
                      "opaque=\t\t\"sadfljk32sdaf\"", "32141232413abcde", \
                      "SHA-256", \
                      "6629fae49393a05397450978507c4ef1", "test@example.com", \
                      "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates", \
                      "users@example.com", "/example", "auth", "0a4f113b", \
                      "00000001", 0);
  r += expect_digest ("Digest username=\"test@example.com\"," \
                      "realm=\"users@example.com\",algorithm=SHA-256," \
                      "nonce=\"32141232413abcde\"," \
                      "username*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates," \
                      "uri=\"/example\",qop=auth,nc=00000001,cnonce=\"0a4f113b\"," \
                      "response=\"6629fae49393a05397450978507c4ef1\"," \
                      "opaque=\"sadfljk32sdaf\"", "32141232413abcde", "SHA-256", \
                      "6629fae49393a05397450978507c4ef1", "test@example.com", \
                      "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates", \
                      "users@example.com", "/example", "auth", "0a4f113b", \
                      "00000001", 0);
  r += expect_digest ("Digest username=\"test@example.com\"," \
                      "realm=\"users@example.com\",algorithm=SHA-256," \
                      "nonce=\"32141232413abcde\",asdf=asdffdsaf," \
                      "username*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates," \
                      "uri=\"/example\",qop=auth,nc=00000001,cnonce=\"0a4f113b\"," \
                      "response=\"6629fae49393a05397450978507c4ef1\"," \
                      "opaque=\"sadfljk32sdaf\"", "32141232413abcde", "SHA-256", \
                      "6629fae49393a05397450978507c4ef1", "test@example.com", \
                      "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates", \
                      "users@example.com", "/example", "auth", "0a4f113b", \
                      "00000001", 0);
  r += expect_digest ("Digest abc=zyx, username=\"test@example.com\", " \
                      "realm=\"users@example.com\", algorithm=SHA-256, " \
                      "nonce=\"32141232413abcde\", " \
                      "username*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates, " \
                      "uri=\"/example\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", " \
                      "response=\"6629fae49393a05397450978507c4ef1\", " \
                      "opaque=\"sadfljk32sdaf\"", "32141232413abcde", "SHA-256", \
                      "6629fae49393a05397450978507c4ef1", "test@example.com", \
                      "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates", \
                      "users@example.com", "/example", "auth", "0a4f113b", \
                      "00000001", 0);
  r += expect_digest ("Digest abc=zyx,,,,,,,username=\"test@example.com\", " \
                      "realm=\"users@example.com\", algorithm=SHA-256, " \
                      "nonce=\"32141232413abcde\", " \
                      "username*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates, " \
                      "uri=\"/example\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", " \
                      "response=\"6629fae49393a05397450978507c4ef1\", " \
                      "opaque=\"sadfljk32sdaf\"", "32141232413abcde", "SHA-256", \
                      "6629fae49393a05397450978507c4ef1", "test@example.com", \
                      "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates", \
                      "users@example.com", "/example", "auth", "0a4f113b", \
                      "00000001", 0);
  r += expect_digest ("Digest abc=zyx,,,,,,,username=\"test@example.com\", " \
                      "realm=\"users@example.com\", algorithm=SHA-256, " \
                      "nonce=\"32141232413abcde\", " \
                      "username*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates, " \
                      "uri=\"/example\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", " \
                      "response=\"6629fae49393a05397450978507c4ef1\", " \
                      "opaque=\"sadfljk32sdaf\",,,,,", "32141232413abcde", \
                      "SHA-256", \
                      "6629fae49393a05397450978507c4ef1", "test@example.com", \
                      "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates", \
                      "users@example.com", "/example", "auth", "0a4f113b", \
                      "00000001", 0);
  r += expect_digest ("Digest abc=zyx,,,,,,,username=\"test@example.com\", " \
                      "realm=\"users@example.com\", algorithm=SHA-256, " \
                      "nonce=\"32141232413abcde\", " \
                      "username*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates, " \
                      "uri=\"/example\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", " \
                      "response=\"6629fae49393a05397450978507c4ef1\", " \
                      "opaque=\"sadfljk32sdaf\",foo=bar", "32141232413abcde", \
                      "SHA-256", \
                      "6629fae49393a05397450978507c4ef1", "test@example.com", \
                      "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates", \
                      "users@example.com", "/example", "auth", "0a4f113b", \
                      "00000001", 0);
  r += expect_digest ("Digest abc=\"zyx\", username=\"test@example.com\", " \
                      "realm=\"users@example.com\", algorithm=SHA-256, " \
                      "nonce=\"32141232413abcde\", " \
                      "username*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates, " \
                      "uri=\"/example\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", " \
                      "response=\"6629fae49393a05397450978507c4ef1\", " \
                      "opaque=\"sadfljk32sdaf\",foo=bar", "32141232413abcde", \
                      "SHA-256", \
                      "6629fae49393a05397450978507c4ef1", "test@example.com", \
                      "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates", \
                      "users@example.com", "/example", "auth", "0a4f113b", \
                      "00000001", 0);
  r += expect_digest ("Digest abc=\"zyx, abc\", " \
                      "username=\"test@example.com\", " \
                      "realm=\"users@example.com\", algorithm=SHA-256, " \
                      "nonce=\"32141232413abcde\", " \
                      "username*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates, " \
                      "uri=\"/example\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", " \
                      "response=\"6629fae49393a05397450978507c4ef1\", " \
                      "opaque=\"sadfljk32sdaf\",foo=bar", "32141232413abcde", \
                      "SHA-256", \
                      "6629fae49393a05397450978507c4ef1", "test@example.com", \
                      "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates", \
                      "users@example.com", "/example", "auth", "0a4f113b", \
                      "00000001", 0);
  r += expect_digest ("Digest abc=\"zyx, abc=cde\", " \
                      "username=\"test@example.com\", " \
                      "realm=\"users@example.com\", algorithm=SHA-256, " \
                      "nonce=\"32141232413abcde\", " \
                      "username*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates, " \
                      "uri=\"/example\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", " \
                      "response=\"6629fae49393a05397450978507c4ef1\", " \
                      "opaque=\"sadfljk32sdaf\",foo=bar", "32141232413abcde", \
                      "SHA-256", \
                      "6629fae49393a05397450978507c4ef1", "test@example.com", \
                      "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates", \
                      "users@example.com", "/example", "auth", "0a4f113b", \
                      "00000001", 0);
  r += expect_digest ("Digest abc=\"zyx, abc=cde\", " \
                      "username=\"test@example.com\", " \
                      "realm=\"users@example.com\", algorithm=SHA-256, " \
                      "nonce=\"32141232413abcde\", " \
                      "username*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates, " \
                      "uri=\"/example\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", " \
                      "response=\"6629fae49393a05397450978507c4ef1\", " \
                      "opaque=\"sadfljk32sdaf\", foo=\"bar1, bar2\"", \
                      "32141232413abcde", "SHA-256", \
                      "6629fae49393a05397450978507c4ef1", "test@example.com", \
                      "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates", \
                      "users@example.com", "/example", "auth", "0a4f113b", \
                      "00000001", 0);
  r += expect_digest ("Digest abc=\"zyx, \\\\\"abc=cde\\\\\"\", " \
                      "username=\"test@example.com\", " \
                      "realm=\"users@example.com\", algorithm=SHA-256, " \
                      "nonce=\"32141232413abcde\", " \
                      "username*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates, " \
                      "uri=\"/example\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", " \
                      "response=\"6629fae49393a05397450978507c4ef1\", " \
                      "opaque=\"sadfljk32sdaf\", foo=\"bar1, bar2\"", \
                      "32141232413abcde", "SHA-256", \
                      "6629fae49393a05397450978507c4ef1", "test@example.com", \
                      "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates", \
                      "users@example.com", "/example", "auth", "0a4f113b", \
                      "00000001", 0);
  r += expect_digest ("Digest abc=\"zyx, \\\\\"abc=cde\\\\\"\", " \
                      "username=\"test@example.com\", " \
                      "realm=\"users@example.com\", algorithm=SHA-256, " \
                      "nonce=\"32141232413abcde\", " \
                      "username*=UTF-8''%c2%a3%20and%20%e2%82%ac%20rates, " \
                      "uri=\"/example\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", " \
                      "response=\"6629fae49393a05397450978507c4ef1\", " \
                      "opaque=\"sadfljk32sdaf\", foo=\",nc=02\"",
                      "32141232413abcde", "SHA-256", \
                      "6629fae49393a05397450978507c4ef1", "test@example.com", \
                      "UTF-8''%c2%a3%20and%20%e2%82%ac%20rates", \
                      "users@example.com", "/example", "auth", "0a4f113b", \
                      "00000001", 0);

  return r;
}


#endif /* DAUTH_SUPPORT */

int
main (int argc, char *argv[])
{
  unsigned int errcount = 0;
  (void) argc; (void) argv; /* Unused. Silent compiler warning. */
  errcount += check_type ();
#ifdef BAUTH_SUPPORT
  errcount += check_basic ();
#endif /* BAUTH_SUPPORT */
#ifdef DAUTH_SUPPORT
  errcount += check_digest ();
#endif /* DAUTH_SUPPORT */
  if (0 == errcount)
    printf ("All tests were passed without errors.\n");
  return errcount == 0 ? 0 : 1;
}
