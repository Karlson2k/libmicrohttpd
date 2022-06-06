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
 * @file microhttpd/test_str_quote.c
 * @brief  Unit tests for quoted strings processing
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_options.h"
#include <string.h>
#include <stdio.h>
#include "mhd_str.h"
#include "mhd_assert.h"

#ifndef MHD_STATICSTR_LEN_
/**
 * Determine length of static string / macro strings at compile time.
 */
#define MHD_STATICSTR_LEN_(macro) (sizeof(macro) / sizeof(char) - 1)
#endif /* ! MHD_STATICSTR_LEN_ */


#define TEST_STR_MAX_LEN 1024

/* return zero if succeed, non-zero otherwise */
static unsigned int
expect_result_unquote_n (const char *const quoted, const size_t quoted_len,
                         const char *const unquoted, const size_t unquoted_len,
                         const unsigned int line_num)
{
  static char buf[TEST_STR_MAX_LEN];
  size_t res_len;
  unsigned int ret1;
  unsigned int ret2;

  mhd_assert (NULL != quoted);
  mhd_assert (NULL != unquoted);
  mhd_assert (TEST_STR_MAX_LEN > quoted_len);

  /* First check: MHD_str_unquote () */
  ret1 = 0;
  memset (buf, '#', sizeof(buf)); /* Fill buffer with character unused in the check */
  res_len = MHD_str_unquote (quoted, quoted_len, buf);

  if (res_len != unquoted_len)
  {
    ret1 = 1;
    fprintf (stderr,
             "'MHD_str_unquote ()' FAILED: Wrong result size:\n");
  }
  else if (0 != memcmp (buf, unquoted, unquoted_len))
  {
    ret1 = 1;
    fprintf (stderr,
             "'MHD_str_unquote ()' FAILED: Wrong result string:\n");
  }
  if (0 != ret1)
  {
    /* This does NOT print part of the string after binary zero */
    fprintf (stderr,
             "\tRESULT  : MHD_str_unquote('%.*s', %u, ->'%.*s') -> %u\n"
             "\tEXPECTED: MHD_str_unquote('%.*s', %u, ->'%.*s') -> %u\n",
             (int) quoted_len, quoted, (unsigned) quoted_len,
             (int) res_len, buf, (unsigned) res_len,
             (int) quoted_len, quoted, (unsigned) quoted_len,
             (int) unquoted_len, unquoted, (unsigned) unquoted_len);
    fprintf (stderr,
             "The check is at line: %u\n\n", line_num);
  }

  /* Second check: MHD_str_equal_quoted_bin_n () */
  ret2 = 0;
  if (! MHD_str_equal_quoted_bin_n (quoted, quoted_len, unquoted, unquoted_len))
  {
    fprintf (stderr,
             "'MHD_str_equal_quoted_bin_n ()' FAILED: Wrong result:\n");
    /* This does NOT print part of the string after binary zero */
    fprintf (stderr,
             "\tRESULT  : MHD_str_equal_quoted_bin_n('%.*s', %u, "
             "'%.*s', %u) -> true\n"
             "\tEXPECTED: MHD_str_equal_quoted_bin_n('%.*s', %u, "
             "'%.*s', %u) -> false\n",
             (int) quoted_len, quoted, (unsigned) quoted_len,
             (int) unquoted_len, unquoted, (unsigned) unquoted_len,
             (int) quoted_len, quoted, (unsigned) quoted_len,
             (int) unquoted_len, unquoted, (unsigned) unquoted_len);
    fprintf (stderr,
             "The check is at line: %u\n\n", line_num);
    ret2 = 1;
  }

  return ret1 + ret2;
}


#define expect_result_unquote(q,u) \
    expect_result_unquote_n(q,MHD_STATICSTR_LEN_(q),\
                            u,MHD_STATICSTR_LEN_(u),__LINE__)


static unsigned int
check_match (void)
{
  unsigned int r = 0; /**< The number of errors */

  r += expect_result_unquote ("", "");
  r += expect_result_unquote ("a", "a");
  r += expect_result_unquote ("abc", "abc");
  r += expect_result_unquote ("abcdef", "abcdef");
  r += expect_result_unquote ("a\0" "bc", "a\0" "bc");
  r += expect_result_unquote ("abc\\\"", "abc\"");
  r += expect_result_unquote ("\\\"", "\"");
  r += expect_result_unquote ("\\\"abc", "\"abc");
  r += expect_result_unquote ("abc\\\\", "abc\\");
  r += expect_result_unquote ("\\\\", "\\");
  r += expect_result_unquote ("\\\\abc", "\\abc");
  r += expect_result_unquote ("123\\\\\\\\\\\\\\\\", "123\\\\\\\\");
  r += expect_result_unquote ("\\\\\\\\\\\\\\\\", "\\\\\\\\");
  r += expect_result_unquote ("\\\\\\\\\\\\\\\\123", "\\\\\\\\123");
  r += expect_result_unquote ("\\\\\\\"\\\\\\\"\\\\\\\"\\\\\\\"\\\\\\\"" \
                              "\\\\\\\"\\\\\\\"\\\\\\\"\\\\\\\"\\\\\\\"", \
                              "\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"\\\"");

  return r;
}


/* return zero if succeed, one otherwise */
static unsigned int
expect_result_invalid_n (const char *const quoted, const size_t quoted_len,
                         const unsigned int line_num)
{
  static char buf[TEST_STR_MAX_LEN];
  size_t res_len;
  unsigned int ret1;

  mhd_assert (NULL != quoted);
  mhd_assert (TEST_STR_MAX_LEN > quoted_len);

  /* The check: MHD_str_unquote () */
  ret1 = 0;
  memset (buf, '#', sizeof(buf)); /* Fill buffer with character unused in the check */
  res_len = MHD_str_unquote (quoted, quoted_len, buf);

  if (res_len != 0)
  {
    ret1 = 1;
    fprintf (stderr,
             "'MHD_str_unquote ()' FAILED: Wrong result size:\n");
  }
  if (0 != ret1)
  {
    /* This does NOT print part of the string after binary zero */
    fprintf (stderr,
             "\tRESULT  : MHD_str_unquote('%.*s', %u, (not checked)) -> %u\n"
             "\tEXPECTED: MHD_str_unquote('%.*s', %u, (not checked)) -> 0\n",
             (int) quoted_len, quoted, (unsigned) quoted_len,
             (unsigned) res_len,
             (int) quoted_len, quoted, (unsigned) quoted_len);
    fprintf (stderr,
             "The check is at line: %u\n\n", line_num);
  }

  return ret1;
}


#define expect_result_invalid(q) \
    expect_result_invalid_n(q,MHD_STATICSTR_LEN_(q),__LINE__)


static unsigned int
check_invalid (void)
{
  unsigned int r = 0; /**< The number of errors */

  r += expect_result_invalid ("\\");
  r += expect_result_invalid ("\\\\\\");
  r += expect_result_invalid ("\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\");
  r += expect_result_invalid ("xyz\\");
  r += expect_result_invalid ("\\\"\\");
  r += expect_result_invalid ("\\\"\\\"\\\"\\");

  return r;
}


/* return zero if succeed, one otherwise */
static unsigned int
expect_result_unmatch_n (const char *const quoted, const size_t quoted_len,
                         const char *const unquoted, const size_t unquoted_len,
                         const unsigned int line_num)
{
  unsigned int ret2;

  mhd_assert (NULL != quoted);
  mhd_assert (NULL != unquoted);

  /* The check: MHD_str_equal_quoted_bin_n () */
  ret2 = 0;
  if (MHD_str_equal_quoted_bin_n (quoted, quoted_len, unquoted, unquoted_len))
  {
    fprintf (stderr,
             "'MHD_str_equal_quoted_bin_n ()' FAILED: Wrong result:\n");
    /* This does NOT print part of the string after binary zero */
    fprintf (stderr,
             "\tRESULT  : MHD_str_equal_quoted_bin_n('%.*s', %u, "
             "'%.*s', %u) -> true\n"
             "\tEXPECTED: MHD_str_equal_quoted_bin_n('%.*s', %u, "
             "'%.*s', %u) -> false\n",
             (int) quoted_len, quoted, (unsigned) quoted_len,
             (int) unquoted_len, unquoted, (unsigned) unquoted_len,
             (int) quoted_len, quoted, (unsigned) quoted_len,
             (int) unquoted_len, unquoted, (unsigned) unquoted_len);
    fprintf (stderr,
             "The check is at line: %u\n\n", line_num);
    ret2 = 1;
  }

  return ret2;
}


#define expect_result_unmatch(q,u) \
    expect_result_unmatch_n(q,MHD_STATICSTR_LEN_(q),\
                            u,MHD_STATICSTR_LEN_(u),__LINE__)


static unsigned int
check_unmatch (void)
{
  unsigned int r = 0; /**< The number of errors */

  /* Matched sequence except invalid backslash at the end */
  r += expect_result_unmatch ("\\", "");
  r += expect_result_unmatch ("a\\", "a");
  r += expect_result_unmatch ("abc\\", "abc");
  r += expect_result_unmatch ("a\0" "bc\\", "a\0" "bc");
  r += expect_result_unmatch ("abc\\\"\\", "abc\"");
  r += expect_result_unmatch ("\\\"\\", "\"");
  r += expect_result_unmatch ("\\\"abc\\", "\"abc");
  r += expect_result_unmatch ("abc\\\\\\", "abc\\");
  r += expect_result_unmatch ("\\\\\\", "\\");
  r += expect_result_unmatch ("\\\\abc\\", "\\abc");
  r += expect_result_unmatch ("123\\\\\\\\\\\\\\\\\\", "123\\\\\\\\");
  r += expect_result_unmatch ("\\\\\\\\\\\\\\\\\\", "\\\\\\\\");
  r += expect_result_unmatch ("\\\\\\\\\\\\\\\\123\\", "\\\\\\\\123");
  /* Invalid backslash at the end and empty string */
  r += expect_result_unmatch ("\\", "");
  r += expect_result_unmatch ("a\\", "");
  r += expect_result_unmatch ("abc\\", "");
  r += expect_result_unmatch ("a\0" "bc\\", "");
  r += expect_result_unmatch ("abc\\\"\\", "");
  r += expect_result_unmatch ("\\\"\\", "");
  r += expect_result_unmatch ("\\\"abc\\", "");
  r += expect_result_unmatch ("abc\\\\\\", "");
  r += expect_result_unmatch ("\\\\\\", "");
  r += expect_result_unmatch ("\\\\abc\\", "");
  r += expect_result_unmatch ("123\\\\\\\\\\\\\\\\\\", "");
  r += expect_result_unmatch ("\\\\\\\\\\\\\\\\\\", "");
  r += expect_result_unmatch ("\\\\\\\\\\\\\\\\123\\", "");
  /* Difference at binary zero */
  r += expect_result_unmatch ("\0", "");
  r += expect_result_unmatch ("", "\0");
  r += expect_result_unmatch ("a\0", "a");
  r += expect_result_unmatch ("a", "a\0");
  r += expect_result_unmatch ("abc\0", "abc");
  r += expect_result_unmatch ("abc", "abc\0");
  r += expect_result_unmatch ("a\0" "bc\0", "a\0" "bc");
  r += expect_result_unmatch ("a\0" "bc", "a\0" "bc\0");
  r += expect_result_unmatch ("abc\\\"\0", "abc\"");
  r += expect_result_unmatch ("abc\\\"", "abc\"\0");
  r += expect_result_unmatch ("\\\"\0", "\"");
  r += expect_result_unmatch ("\\\"", "\"\0");
  r += expect_result_unmatch ("\\\"abc\0", "\"abc");
  r += expect_result_unmatch ("\\\"abc", "\"abc\0");
  r += expect_result_unmatch ("\\\\\\\\\\\\\\\\\0", "\\\\\\\\");
  r += expect_result_unmatch ("\\\\\\\\\\\\\\\\", "\\\\\\\\\0");
  r += expect_result_unmatch ("\\\\\\\\\\\\\0" "\\\\", "\\\\\\\\");
  r += expect_result_unmatch ("\\\\\\\\\\\\\\\\", "\\\\\\\0" "\\");
  r += expect_result_unmatch ("\0" "abc", "abc");
  r += expect_result_unmatch ("abc", "\0" "abc");
  r += expect_result_unmatch ("\0" "abc", "0abc");
  r += expect_result_unmatch ("0abc", "\0" "abc");
  r += expect_result_unmatch ("xyz", "xy" "\0" "z");
  r += expect_result_unmatch ("xy" "\0" "z", "xyz");
  /* Difference after binary zero */
  r += expect_result_unmatch ("abc\0" "1", "abc\0" "2");
  r += expect_result_unmatch ("a\0" "bcx", "a\0" "bcy");
  r += expect_result_unmatch ("\0" "abc\\\"2", "\0" "abc\"1");
  r += expect_result_unmatch ("\0" "abc1\\\"", "\0" "abc2\"");
  r += expect_result_unmatch ("\0" "\\\"c", "\0" "\"d");
  r += expect_result_unmatch ("\\\"ab" "\0" "1c", "\"ab" "\0" "2c");
  r += expect_result_unmatch ("a\0" "bcdef2", "a\0" "bcdef1");
  r += expect_result_unmatch ("a\0" "bc2def", "a\0" "bc1def");
  r += expect_result_unmatch ("a\0" "1bcdef", "a\0" "2bcdef");
  r += expect_result_unmatch ("abcde\0" "f2", "abcde\0" "f1");
  r += expect_result_unmatch ("123\\\\\\\\\\\\\0" "\\\\1", "123\\\\\\\0" "\\2");
  r += expect_result_unmatch ("\\\\\\\\\\\\\0" "1\\\\", "\\\\\\" "2\\");
  /* One side is empty */
  r += expect_result_unmatch ("abc", "");
  r += expect_result_unmatch ("", "abc");
  r += expect_result_unmatch ("1234567890", "");
  r += expect_result_unmatch ("", "1234567890");
  r += expect_result_unmatch ("abc\\\"", "");
  r += expect_result_unmatch ("", "abc\"");
  r += expect_result_unmatch ("\\\"", "");
  r += expect_result_unmatch ("", "\"");
  r += expect_result_unmatch ("\\\"abc", "");
  r += expect_result_unmatch ("", "\"abc");
  r += expect_result_unmatch ("abc\\\\", "");
  r += expect_result_unmatch ("", "abc\\");
  r += expect_result_unmatch ("\\\\", "");
  r += expect_result_unmatch ("", "\\");
  r += expect_result_unmatch ("\\\\abc", "");
  r += expect_result_unmatch ("", "\\abc");
  r += expect_result_unmatch ("123\\\\\\\\\\\\\\\\", "");
  r += expect_result_unmatch ("", "123\\\\\\\\");
  r += expect_result_unmatch ("\\\\\\\\\\\\\\\\", "");
  r += expect_result_unmatch ("", "\\\\\\\\");
  r += expect_result_unmatch ("\\\\\\\\\\\\\\\\123", "");
  r += expect_result_unmatch ("", "\\\\\\\\123");
  /* Various unmatched strings */
  r += expect_result_unmatch ("abc", "ABC");
  r += expect_result_unmatch ("ABCabc", "abcABC");
  r += expect_result_unmatch ("a", "x");
  r += expect_result_unmatch ("abc", "abcabc");
  r += expect_result_unmatch ("abc", "abcabcabc");
  r += expect_result_unmatch ("abc", "abcabcabcabc");
  r += expect_result_unmatch ("ABCABC", "ABC");
  r += expect_result_unmatch ("ABCABCABC", "ABC");
  r += expect_result_unmatch ("ABCABCABCABC", "ABC");
  r += expect_result_unmatch ("123\\\\\\\\\\\\\\\\\\\\", "123\\\\\\\\");
  r += expect_result_unmatch ("\\\\\\\\\\\\\\\\\\\\", "\\\\\\\\");
  r += expect_result_unmatch ("\\\\\\\\\\\\\\\\123\\\\", "\\\\\\\\123");
  r += expect_result_unmatch ("\\\\\\\\\\\\\\\\", "\\\\\\\\\\");

  return r;
}


int
main (int argc, char *argv[])
{
  unsigned int errcount = 0;
  (void) argc; (void) argv; /* Unused. Silent compiler warning. */
  errcount += check_match ();
  errcount += check_invalid ();
  errcount += check_unmatch ();
  if (0 == errcount)
    printf ("All tests were passed without errors.\n");
  return errcount == 0 ? 0 : 1;
}
