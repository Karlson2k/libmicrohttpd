/*
  This file is part of libmicrohttpd
  Copyright (C) 2015 Karlson2k (Evgeny Grin)

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/

/**
 * @file microhttpd/mhd_str.h
 * @brief  Header for string manipulating helpers
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef MHD_STR_H
#define MHD_STR_H 1

#include <stdint.h>
#include <stdlib.h>

/*
 * Block of functions/macros that use US-ASCII charset as required by HTTP
 * standards. Not affected by current locale settings.
 */

/**
 * Check two string for equality, ignoring case of US-ASCII letters.
 * @param str1 first string to compare
 * @param str2 second string to compare
 * @return non-zero if two strings are equal, zero otherwise.
 */
int
MHD_str_equal_caseless_ (const char * str1,
                 const char * str2);


/**
 * Check two string for equality, ignoring case of US-ASCII letters and
 * checking not more than @a maxlen characters.
 * Compares up to first terminating null character, but not more than
 * first @a maxlen characters.
 * @param str1 first string to compare
 * @param str2 second string to compare
 * @patam maxlen maximum number of characters to compare
 * @return non-zero if two strings are equal, zero otherwise.
 */
int
MHD_str_equal_caseless_n_ (const char * const str1,
                  const char * const str2,
                  size_t maxlen);

/**
 * Convert decimal US-ASCII digits in string to number in uint64_t.
 * Conversion stopped at first non-digit character.
 * @param str string to convert
 * @param out_val pointer to uint64_t to store result of conversion
 * @param next_char pointer to store pointer to character next to last
 *                  converted digit, ignored if NULL
 * @return non-zero if conversion succeed; zero if no digit is found,
 *         value is larger then possible to store in uint64_t or
 *         @a out_val is NULL
 */
int
MHD_str_to_uint64_ (const char * str,
                    uint64_t * out_val,
                    const char ** next_char);

/**
 * Convert not more then @a maxlen decimal US-ASCII digits in string to
 * number in uint64_t.
 * Conversion stopped at first non-digit character or after @a maxlen 
 * digits.
 * @param str string to convert
 * @param out_val pointer to uint64_t to store result of conversion
 * @param next_char pointer to store pointer to character next to last
 *                  converted digit, ignored if NULL
 * @return non-zero if conversion succeed; zero if no digit is found,
 *         value is larger then possible to store in uint64_t or
 *         @a out_val is NULL
 */
int
MHD_str_to_uint64_n_ (const char * str,
                      size_t maxlen,
                      uint64_t * out_val,
                      const char ** next_char);

#endif /* MHD_STR_H */
