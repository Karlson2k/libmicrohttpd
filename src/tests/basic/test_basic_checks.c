/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2016, 2024 Evgeny Grin (Karlson2k)

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
 * @file test_basic_checks.c
 * @brief  test for create, start and destroy
 * @author Karlson2k (Evgeny Grin)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd2.h>

/* Helper macros */

#define ERR_PRINT_LINE() \
        ((void) fprintf (stderr, "At the line number %u: ", \
                         (unsigned) __LINE__))

/**
 * Check whether SC code is OK, print error if not.
 * @warning Do not use function call in the argument
 * @param sc the status code to check
 */
#define tst_EXPECT_OK(sc) \
        ( (MHD_SC_OK == (sc)) ? (! 0) :                                    \
          (ERR_PRINT_LINE (),                                              \
           ((void) fprintf (stderr, "MHD function failed, returned: %u\n", \
                            (unsigned int) (sc))), (0)) )
#if 0
#define tst_EXPECT_OK(sc) \
        ( (MHD_SC_OK == (sc)) ? (! 0) :                            \
          (ERR_PRINT_LINE (),                                      \
           ((void) fprintf (stderr,                                \
                            "MHD function failed, returned: %s\n", \
                            MHD_status_code_to_string_lazy (sc))), (0)) )
#endif

/**
 * Check whether SC code is OK, print error if not.
 * @warning Do not use function call in the argument
 * @param sc the status code to check
 */
#define tst_EXPECT_FAIL(sc) \
        ( (MHD_SC_OK != (sc)) ? (! 0) : \
          (ERR_PRINT_LINE (),           \
           ((void) fprintf (stderr, "MHD function unexpectedly succeed.\n")), \
           (0)) )

/**
 * Check whether SC code is success/failure as expected, print error if not.
 * @warning Do not use function call in the argument
 * @param sc the status code to check
 * @param expect_ok non-zero if SC should be OK, zero is SC should NOT be OK
 */
#define tst_EXPECT_CHECK(sc,expect_ok) \
        ((expect_ok) ? tst_EXPECT_OK ((sc)) : tst_EXPECT_FAIL ((sc)))

/* Helper functions */

/**
 * Check whether program name contains specific @a marker string.
 * Only last component in pathname is checked for marker presence,
 * all leading directories names (if any) are ignored. Directories
 * separators are handled correctly on both non-W32 and W32
 * platforms.
 * @param prog_name the program name, may include path
 * @param marker    the marker to look for
 * @return zero if any parameter is NULL or empty string or
 *         @a prog_name ends with slash or @a marker is not found in
 *         program name, non-zero if @a maker is found in program
 *         name.
 */
static int
has_in_name (const char *prog_name, const char *marker)
{
  const char *s;
  const char *basename;

  if (! prog_name || ! marker || ! prog_name[0] || ! marker[0])
    return 0;

  basename = prog_name;
  for (s = prog_name; *s; ++s)
  {
    if ('/' == *s)
      basename = s + 1;
#if defined(_WIN32) || defined(__CYGWIN__)
    else if ('\\' == *s)
      basename = s + 1;
#endif /* _WIN32 || __CYGWIN__ */
  }

  return strstr (basename, marker) != NULL;
}


/* The test */

static int use_start = 0;

static int use_ipv4 = 0;

static int use_ipv6 = 0;

static int use_ip_best = 0;

static int use_select = 0;

static int use_poll = 0;

static int use_epoll = 0;

static int use_int_thread = 0;

static int use_thread_per_conn = 0;

static int use_thread_pool = 0;

/* Dynamic run-time variables */

static int err_flag = 0;

MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_NONNULL_ (3) static const struct MHD_Action *
my_req_process (void *cls,
                struct MHD_Request *request,
                const struct MHD_String *path,
                enum MHD_HTTP_Method method,
                uint_fast64_t upload_size)
{
  (void) cls; (void) request; (void) path; (void) method; (void) upload_size;
  fprintf (stderr, "Unexpected call of the request callback.\n");
  err_flag = ! 0;
  return NULL;
}


static struct MHD_Daemon *
test_daemon_create (void)
{
  struct MHD_Daemon *d;

  d = MHD_daemon_create (my_req_process, NULL);
  if (NULL == d)
  {
    err_flag = ! 0;
    ERR_PRINT_LINE ();
    fprintf (stderr, "MHD_daemon_create() failed, NULL returned.\n");
    return NULL;
  }
  return d;
}


static int
test_daemon_setup (struct MHD_Daemon *d,
                   int should_succeed)
{
  enum MHD_StatusCode sc;
  int ret = ! 0;

  if (use_ipv6)
  {
    sc = MHD_DAEMON_SET_OPTIONS ( \
      d, MHD_D_OPTION_BIND_PORT (MHD_AF_DUAL_v4_OPTIONAL, 0));
    if (! tst_EXPECT_CHECK (sc,should_succeed))
      ret = 0;
  }

  if (use_ipv4)
  {
    sc = MHD_DAEMON_SET_OPTIONS ( \
      d, MHD_D_OPTION_BIND_PORT (MHD_AF_DUAL_v6_OPTIONAL, 0));
    if (! tst_EXPECT_CHECK (sc,should_succeed))
      ret = 0;
  }

  if (use_ip_best)
  {
    sc = MHD_DAEMON_SET_OPTIONS ( \
      d, MHD_D_OPTION_BIND_PORT (MHD_AF_AUTO, 0));
    if (! tst_EXPECT_CHECK (sc,should_succeed))
      ret = 0;
  }

  if (use_select)
  {
    sc = MHD_DAEMON_SET_OPTIONS ( \
      d, MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_SELECT));
    if (! tst_EXPECT_CHECK (sc,should_succeed))
      ret = 0;
  }

  if (use_poll)
  {
    sc = MHD_DAEMON_SET_OPTIONS ( \
      d, MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_POLL));
    if (! tst_EXPECT_CHECK (sc, should_succeed))
      ret = 0;
  }

  if (use_epoll)
  {
    sc = MHD_DAEMON_SET_OPTIONS ( \
      d, MHD_D_OPTION_POLL_SYSCALL (MHD_SPS_EPOLL));
    if (! tst_EXPECT_CHECK (sc,should_succeed))
      ret = 0;
  }

  if (use_int_thread)
  {
    sc = MHD_DAEMON_SET_OPTIONS ( \
      d, MHD_D_OPTION_WORK_MODE (MHD_WM_OPTION_WORKER_THREADS (1)));
    if (! tst_EXPECT_CHECK (sc, should_succeed))
      ret = 0;
  }

  if (use_thread_per_conn)
  {
    sc = MHD_DAEMON_SET_OPTIONS ( \
      d, MHD_D_OPTION_WORK_MODE (MHD_WM_OPTION_THREAD_PER_CONNECTION ()));
    if (! tst_EXPECT_CHECK (sc, should_succeed))
      ret = 0;
  }

  if (use_thread_pool)
  {
    sc = MHD_DAEMON_SET_OPTIONS ( \
      d, MHD_D_OPTION_WORK_MODE (MHD_WM_OPTION_WORKER_THREADS (4)));
    if (! tst_EXPECT_CHECK (sc, should_succeed))
      ret = 0;
  }

  if (! ret)
    err_flag = ! 0;

  return ret;
}


static int
test_daemon_start (struct MHD_Daemon *d,
                   int should_succeed)
{
  enum MHD_StatusCode sc;

  sc = MHD_daemon_start (d);
  if (! tst_EXPECT_CHECK (sc,should_succeed))
  {
    err_flag = ! 0;
    return 0;
  }

  return ! 0;
}


static int
test_simple (void)
{
  struct MHD_Daemon *d;
  int ret = ! 0;

  err_flag = 0;

  d = test_daemon_create ();
  if (NULL == d)
    return (ret && ! err_flag);

  test_daemon_setup (d, ! 0);
  if (use_start)
    test_daemon_start (d, ! 0);

  test_daemon_setup (d, ! use_start);

  if (use_start)
    test_daemon_start (d, 0); /* Second "start" should fail */

  MHD_daemon_destroy (d);

  return (ret && ! err_flag);
}


/**
 * Initialise the test data
 * @param prog_name the name of the this program
 * @return non-zero if succeed,
 *         zero if failed
 */
static int
init_test (const char *prog_name)
{
  if (has_in_name (prog_name, "_start"))
    use_start = ! 0;

  if (has_in_name (prog_name, "_ipv4"))
    use_ipv4 = ! 0;

  if (has_in_name (prog_name, "_ipv6"))
    use_ipv6 = ! 0;

  if (has_in_name (prog_name, "_ipbest"))
    use_ip_best = ! 0;

  use_select = has_in_name (prog_name, "_select");

  use_poll = has_in_name (prog_name, "_poll");

  use_epoll = has_in_name (prog_name, "_epoll");

  use_int_thread = has_in_name (prog_name, "_int_thread");

  use_thread_per_conn = has_in_name (prog_name, "_thread_per_conn");

  use_thread_pool = has_in_name (prog_name, "_thread_pool");

  return ! 0;
}


int
main (int argc, char *argv[])
{
  unsigned int num_err = 0;
  (void) argc; /* Unused. Silence compiler warning. */

  if (! init_test (argv[0]))
  {
    fprintf (stderr, "Failed to initialise the test!\n");
    return 77;
  }

  if (! test_simple ())
    ++num_err;

  if (0 != num_err)
  {
    fprintf (stderr, "Number of failed checks: %u\n", num_err);
    return 2;
  }

  printf ("All checks succeed.\n");
  return 0;
}
