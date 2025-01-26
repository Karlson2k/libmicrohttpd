/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2023-2025 Evgeny Grin (Karlson2k)

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
 * @file test_lib_info_version.c
 * @brief  test for getting version info by MHD_lib_get_info_fixed_sz()
 * @author Karlson2k (Evgeny Grin)
 */
#include "mhd_sys_options.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "microhttpd2.h"

/* Helpers */

#define ERR_PRINT_LINE() \
        ((void) fprintf (stderr, "At the line number %u: ", \
                         (unsigned) __LINE__))

/* 1 = success, 0 = failure */
static int
tst_EXPECT_OK_helper (enum MHD_StatusCode code,
                      unsigned long line_num,
                      const char *expression)
{
  if (MHD_SC_OK == code)
    return 1;

  (void) fprintf (stderr,
                  "At the line number %lu: "
                  "MHD function failed: \n"
                  "\"%s\"\n returned %lu.\n",
                  line_num,
                  expression,
                  (unsigned long) code);
  return 0;
}


/**
 * Check whether SC code is OK, print error if not.
 * @warning Do not use function call in the argument
 * @param sc the status code to check
 * @return one if succeed,
 *         zero if failed
 */
#define tst_EXPECT_OK(mhd_func_call) \
        (tst_EXPECT_OK_helper ((mhd_func_call), __LINE__, #mhd_func_call))

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


/* The test */


#ifdef PACKAGE_VERSION
static const char str_macro_pkg_ver[] = PACKAGE_VERSION;
#else  /* ! PACKAGE_VERSION */
static const char str_macro_pkg_ver[] = "error!";
#error No PACKAGE_VERSION defined
#endif /* ! PACKAGE_VERSION */

#ifdef VERSION
static const char str_macro_ver[] = VERSION;
#else  /* ! VERSION */
static const char str_macro_ver[] = "error!";
#error No PACKAGE_VERSION defined
#endif /* ! VERSION */

#ifdef MHD_VERSION
static const uint_fast32_t bin_macro = (uint_fast32_t) (MHD_VERSION);
#else  /* ! MHD_VERSION */
static const uint_fast32_t bin_macro = 0;
#error MHD_VERSION is not defined
#endif /* ! MHD_VERSION */

/* 0 = success, 1 = error */
static int
test_macro1_vs_macro2_str (void)
{
  printf ("Checking PACKAGE_VERSION macro vs VERSION macro.\n");
  if (0 != strcmp (str_macro_pkg_ver, str_macro_ver))
  {
    fprintf (stderr, "'%s' vs '%s' - FAILED.\n",
             str_macro_pkg_ver, str_macro_ver);
    return 1;
  }
  printf ("'%s' vs '%s' - success.\n",
          str_macro_pkg_ver, str_macro_ver);
  return 0;
}


/* 0 = success, 1 = error */
static int
test_macro2_vs_func_str (void)
{
  union MHD_LibInfoFixedData info_data;

  if (! tst_EXPECT_OK (MHD_lib_get_info_fixed (MHD_LIB_INFO_FIXED_VERSION_STR, \
                                               &info_data)))
    return 1;

  printf ("Checking VERSION macro vs "
          "MHD_lib_get_info_fixed (MHD_LIB_INFO_FIXED_VERSION_STR) "
          "function.\n");
  if (NULL == info_data.v_string.cstr)
  {
    fprintf (stderr, "info_data.v_string.cstr is NULL.\n");
    return 1;
  }
  if (0 != strcmp (str_macro_ver, info_data.v_string.cstr))
  {
    fprintf (stderr, "'%s' vs '%s' - FAILED.\n",
             str_macro_ver, info_data.v_string.cstr);
    return 1;
  }
  printf ("'%s' vs '%s' - success.\n",
          str_macro_ver, info_data.v_string.cstr);
  return 0;
}


/* 0 = success, 1 = error */
static int
test_func_str_vs_macro_bin (void)
{
  char bin_print[64];
  int res;
  union MHD_LibInfoFixedData info_data;

  if (! tst_EXPECT_OK (MHD_lib_get_info_fixed (MHD_LIB_INFO_FIXED_VERSION_STR, \
                                               &info_data)))
    return 1;

  printf ("Checking MHD_lib_get_info_fixed(MHD_LIB_INFO_FIXED_VERSION_STR) " \
          "function vs MHD_VERSION macro.\n");
#ifdef HAVE_SNPRINTF
  res = snprintf (bin_print, sizeof(bin_print), "%X.%X.%X",
                  (unsigned int) ((bin_macro >> 24) & 0xFF),
                  (unsigned int) ((bin_macro >> 16) & 0xFF),
                  (unsigned int) ((bin_macro >> 8) & 0xFF));
#else  /* ! HAVE_SNPRINTF */
  res = sprintf (bin_print, "%X.%X.%X",
                 (unsigned int) ((bin_macro >> 24) & 0xFF),
                 (unsigned int) ((bin_macro >> 16) & 0xFF),
                 (unsigned int) ((bin_macro >> 8) & 0xFF));
#endif /* ! HAVE_SNPRINTF */
  if ((9 < res) || (0 >= res))
  {
    fprintf (stderr, "snprintf() error.\n");
    exit (99);
  }

  if (0 != strcmp (info_data.v_string.cstr, bin_print))
  {
    fprintf (stderr, "'%s' vs '0x%08lX' ('%s') - FAILED.\n",
             info_data.v_string.cstr,
             (unsigned long) bin_macro,
             bin_print);
    return 1;
  }
  printf ("'%s' vs '0x%08lX' ('%s') - success.\n",
          info_data.v_string.cstr,
          (unsigned long) bin_macro,
          bin_print);
  return 0;
}


/* 0 = success, 1 = error */
static int
test_macro_vs_func_bin (void)
{
  const uint_fast32_t bin_func = MHD_lib_get_info_ver_num ();

  printf ("Checking MHD_VERSION macro vs "
          "MHD_lib_get_info_ver_num() function.\n");
  if (bin_macro != bin_func)
  {
    fprintf (stderr, "'0x%08lu' vs '0x%08lX' - FAILED.\n",
             (unsigned long) bin_macro, (unsigned long) bin_func);
    return 1;
  }
  printf ("'0x%08lu' vs '0x%08lX' - success.\n",
          (unsigned long) bin_macro, (unsigned long) bin_func);
  return 0;
}


/* 0 = success, 1 = error */
static int
test_func_bin_format (void)
{
  const uint_fast32_t bin_func = MHD_lib_get_info_ver_num ();
  unsigned int test_byte;
  int ret = 0;
  printf ("Checking format of MHD_lib_get_info_ver_num() "
          "function return value.\n");
  test_byte = (unsigned int) ((bin_func >> 24) & 0xFF);
  if ((0xA <= (test_byte & 0xF))
      || (0xA <= (test_byte >> 4)))
  {
    fprintf (stderr,
             "Invalid value in the first (most significant) byte: %02X\n",
             test_byte);
    ret = 1;
  }
  test_byte = (unsigned int) ((bin_func >> 16) & 0xFF);
  if ((0xA <= (test_byte & 0xF))
      || (0xA <= (test_byte >> 4)))
  {
    fprintf (stderr,
             "Invalid value in the second byte: %02X\n",
             test_byte);
    ret = 1;
  }
  test_byte = (unsigned int) ((bin_func >> 8) & 0xFF);
  if ((0xA <= (test_byte & 0xF))
      || (0xA <= (test_byte >> 4)))
  {
    fprintf (stderr,
             "Invalid value in the third byte: %02X\n",
             test_byte);
    ret = 1;
  }
  if (0 != ret)
  {
    fprintf (stderr,
             "The value (0x%08lX) returned by MHD_get_version_bin() "
             "function is invalid as it cannot be used as packed BCD form "
             "(its hexadecimal representation has at least one digit in "
             "A-F range).\n",
             (unsigned long) bin_func);
    return 1;
  }
  printf ("'0x%08lX' - success.\n", (unsigned long) bin_func);
  return 0;
}


/* 0 = success, 1 = error */
static int
test_func_str_format (void)
{
  size_t ver_len;
  union MHD_LibInfoFixedData info_data;

  if (! tst_EXPECT_OK (MHD_lib_get_info_fixed (MHD_LIB_INFO_FIXED_VERSION_STR, \
                                               &info_data)))
    return 1;

  printf ("Checking MHD_lib_get_info_fixed(MHD_LIB_INFO_FIXED_VERSION_STR) " \
          "function resulting value format.\n");
  ver_len = strlen (info_data.v_string.cstr);

  if (ver_len != info_data.v_string.len)
  {
    fprintf (stderr,
             "strlen(info_data.v_string.cstr) ('%lu') != "
             "info_data.v_string.len ('%lu') - FAILED.\n",
             (unsigned long) ver_len,
             (unsigned long) info_data.v_string.len);
    return 1;
  }
  printf ("strlen(info_data.v_string.cstr) ('%lu') == "
          "info_data.v_string.len ('%lu') - success.\n",
          (unsigned long) ver_len,
          (unsigned long) info_data.v_string.len);
  return 0;
}


int
main (int argc, char *argv[])
{
  int num_err;

  (void) argc; (void) argv; /* Unused. Silence compiler warning. */

  num_err = test_macro1_vs_macro2_str ();
  num_err += test_macro2_vs_func_str ();
  num_err += test_func_str_vs_macro_bin ();
  num_err += test_macro_vs_func_bin ();
  num_err += test_func_bin_format ();
  num_err += test_func_str_format ();

  if (0 != num_err)
  {
    fprintf (stderr, "Number of failed checks: %d\n", num_err);
    return 2;
  }
  printf ("All checks succeed.\n");
  return 0;
}
