/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Evgeny Grin (Karlson2k)

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
 * @file minimal_auth_digest.c
 * @brief  Minimal example for Digest Authentication
 * @author Karlson2k (Evgeny Grin)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd2.h>
#if defined(_WIN32) && ! defined(__CYGWIN__)
#  include <wincrypt.h> /* For entropy generation */
#else
#  include <sys/types.h>
#  include <fcntl.h>  /* open() function */
#  include <unistd.h> /* close() function */
#endif /* _WIN32 && ! __CYGWIN__ */

static MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_NONNULL_ (3)
const struct MHD_Action *
req_cb (void *cls,
        struct MHD_Request *MHD_RESTRICT request,
        const struct MHD_String *MHD_RESTRICT path,
        enum MHD_HTTP_Method method,
        uint_fast64_t upload_size)
{
  static const char secret_page[] = "Welcome to the cave of treasures!\n";
  static const char auth_required_page[] =
    "You need to know the secret to get in.\n";
  static const char msg_forbidden_page[] =
    "You are not allowed to enter. Go away!\n";
  static const char msg_bad_header_page[] =
    "The Authorization header data is invalid\n";
  static const char realm[] = "The secret cave";
  static const char allowed_username[] = "alibaba";
  static const char allowed_password[] = "open sesam";
  static const size_t allowed_username_len =
    (sizeof(allowed_username) / sizeof(char) - 1);
  union MHD_RequestInfoDynamicData req_data;
  const struct MHD_AuthDigestInfo *uname; /* a shortcut */
  enum MHD_StatusCode res;

  (void) cls;
  (void) path;
  (void) method;
  (void) upload_size; /* Unused */

  res =
    MHD_request_get_info_dynamic (request,
                                  MHD_REQUEST_INFO_DYNAMIC_AUTH_DIGEST_USERNAME,
                                  &req_data);
  if (MHD_SC_AUTH_ABSENT == res)
    return MHD_action_digest_auth_challenge_a (
      request,
      realm,
      "0",
      NULL,
      MHD_NO,
      MHD_DIGEST_AUTH_MULT_QOP_AUTH,
      MHD_DIGEST_AUTH_MULT_ALGO_ANY,
      MHD_NO,
      MHD_YES,
      MHD_response_from_buffer_static (
        MHD_HTTP_STATUS_UNAUTHORIZED,
        sizeof(auth_required_page) / sizeof(char) - 1,
        auth_required_page));

  if (MHD_SC_REQ_AUTH_DATA_BROKEN == res)
    return MHD_action_from_response (
      request,
      MHD_response_from_buffer_static (
        MHD_HTTP_STATUS_BAD_REQUEST,
        sizeof(msg_bad_header_page) / sizeof(char) - 1,
        msg_bad_header_page));

  if (MHD_SC_OK != res)
    return MHD_action_abort_request (request);

  /* Assign result to short-named variable for convenience */
  uname = req_data.v_auth_digest_info;
  if ((uname->username.len == allowed_username_len) &&
      (memcmp (allowed_username,
               uname->username.cstr,
               uname->username.len) == 0))
  {
    /* The client gave the correct username. Check the password match. */
    enum MHD_DigestAuthResult auth_res;

    auth_res = MHD_digest_auth_check (request,
                                      realm,
                                      allowed_username,
                                      allowed_password,
                                      0,
                                      MHD_DIGEST_AUTH_MULT_QOP_AUTH,
                                      MHD_DIGEST_AUTH_MULT_ALGO_ANY);

    if (MHD_DAUTH_OK == auth_res)
      /* User authenticated */
      return MHD_action_from_response (
        request,
        MHD_response_from_buffer_static (
          MHD_HTTP_STATUS_OK,
          sizeof(secret_page) / sizeof(char) - 1,
          secret_page));

    if (MHD_DAUTH_NONCE_STALE == auth_res)
      return MHD_action_digest_auth_challenge_a (
        request,
        realm,
        "0",
        NULL,
        MHD_YES /* Indicate "stale" nonce */,
        MHD_DIGEST_AUTH_MULT_QOP_AUTH,
        MHD_DIGEST_AUTH_MULT_ALGO_ANY,
        MHD_NO,
        MHD_YES,
        MHD_response_from_buffer_static (
          MHD_HTTP_STATUS_UNAUTHORIZED,
          sizeof(auth_required_page) / sizeof(char) - 1,
          auth_required_page));

    if (MHD_DAUTH_NONCE_WRONG <= auth_res)
      /* Wrong password or attack attempt */
      return MHD_action_from_response (
        request,
        MHD_response_from_buffer_static (
          MHD_HTTP_STATUS_FORBIDDEN,
          sizeof(msg_forbidden_page) / sizeof(char) - 1,
          msg_forbidden_page));
  }
  /* Wrong username */

  return MHD_action_from_response (
    request,
    MHD_response_from_buffer_static (
      MHD_HTTP_STATUS_FORBIDDEN,
      sizeof(msg_forbidden_page) / sizeof(char) - 1,
      msg_forbidden_page));
}


static char entropy_bytes[32];

static int
init_entropy_bytes (void);

int
main (int argc,
      char *const *argv)
{
  struct MHD_Daemon *d;
  int port;

  if (argc != 2)
  {
    fprintf (stderr,
             "Usage:\n%s PORT\n",
             argv[0]);
    return 1;
  }
  port = atoi (argv[1]);
  if ((1 > port) || (65535 < port))
  {
    fprintf (stderr,
             "The PORT must be a numeric value between 1 and 65535.\n");
    return 2;
  }
  if (! init_entropy_bytes ())
    return 11;

  d = MHD_daemon_create (&req_cb,
                         NULL);
  if (NULL == d)
  {
    fprintf (stderr,
             "Failed to create MHD daemon.\n");
    return 3;
  }
  if (MHD_SC_OK !=
      MHD_DAEMON_SET_OPTIONS (
        d,
        MHD_D_OPTION_WM_WORKER_THREADS (1),
        MHD_D_OPTION_BIND_PORT (MHD_AF_AUTO,
                                (uint_least16_t) port),
        MHD_D_OPTION_RANDOM_ENTROPY (sizeof(entropy_bytes),
                                     entropy_bytes)))
  {
    fprintf (stderr,
             "Failed to set MHD daemon run parameters.\n");
  }
  else
  {
    if (MHD_SC_OK !=
        MHD_daemon_start (d))
    {
      fprintf (stderr,
               "Failed to start MHD daemon.\n");
    }
    else
    {
      printf ("The MHD daemon is listening on port %d\n"
              "Press ENTER to stop.\n", port);
      (void) fgetc (stdin);
    }
  }
  printf ("Stopping... ");
  fflush (stdout);
  MHD_daemon_destroy (d);
  printf ("OK\n");
  return 0;
}


/**
 * Initialise random data
 * @return non-zero if succeed,
 *         zero if failed
 */
static int
init_entropy_bytes (void)
{
#if ! defined(_WIN32) || defined(__CYGWIN__)
  int fd;
  ssize_t len;
  size_t off;

  fd = open ("/dev/urandom", O_RDONLY);
  if (-1 == fd)
  {
    fd = open ("/dev/arandom", O_RDONLY);
    if (-1 == fd)
      fd = open ("/dev/random", O_RDONLY);
  }
  if (0 > fd)
  {
    fprintf (stderr, "Failed to open random data source.\n");
    return 0;
  }
  for (off = 0; off < sizeof (entropy_bytes); off += (size_t) len)
  {
    len = read (fd,
                entropy_bytes + off,
                sizeof (entropy_bytes) - off);
    if (0 >= len)
    {
      fprintf (stderr, "Failed to read random data source.\n");
      (void) close (fd);
      return 0;
    }
  }
  (void) close (fd);
#else  /* Native W32 */
  HCRYPTPROV cc;
  BOOL b;

  b = CryptAcquireContext (&cc,
                           NULL,
                           NULL,
                           PROV_RSA_FULL,
                           CRYPT_VERIFYCONTEXT);
  if (FALSE == b)
  {
    fprintf (stderr,
             "Failed to acquire crypto provider context: %lu\n",
             (unsigned long) GetLastError ());
    return 0;
  }
  b = CryptGenRandom (cc, sizeof(entropy_bytes), (BYTE *) entropy_bytes);
  if (FALSE == b)
  {
    fprintf (stderr,
             "Failed to generate random bytes: %lu\n",
             GetLastError ());
  }
  CryptReleaseContext (cc, 0);
  return (FALSE != b);
#endif /* Native W32 */
}
