/*
  This file is part of libmicrohttpd
  Copyright (C) 2016 Karlson2k (Evgeny Grin)

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
 * @file microhttpd/unit_str_test.h
 * @brief  Unit tests for mhd_str functions
 * @author Karlson2k (Evgeny Grin)
 */

#include <stdio.h>
#include <locale.h>
#include <string.h>
#include "mhd_options.h"
#include <stdint.h>
#include "mhd_limits.h"
#include "mhd_str.h"
#include "test_helpers.h"


static int verbose = 0; /* verbose level (0-3)*/

/* Locale names to test.
 * Functions must not depend of current current locale,
 * so result must be the same in any locale.
 */
static const char * const locale_names[] = {
    "C",
    "",      /* System default locale */
#if defined(_WIN32) && !defined(__CYGWIN__)
    ".OCP",   /* W32 system default OEM code page */
    ".ACP",   /* W32 system default ANSI code page */
    ".65001", /* UTF-8 */
    ".437",
    ".850",
    ".857",
    ".866",
    ".1250",
    ".1251",
    ".1252",
    ".1254",
    ".20866", /* number for KOI8-R */
    ".28591", /* number for ISO-8859-1 */
    ".28595", /* number for ISO-8859-5 */
    ".28599", /* number for ISO-8859-9 */
    ".28605", /* number for ISO-8859-15 */
    "en",
    "english",
    "en-US",
    "English-US",
    "en-US.437",
    "English_United States.437",
    "en-US.1252",
    "English_United States.1252",
    "English_United States.28591",
    "English_United States.65001",
    "fra",
    "french",
    "fr-FR",
    "French_France",
    "fr-FR.850",
    "french_france.850",
    "fr-FR.1252",
    "French_france.1252",
    "French_france.28605",
    "French_France.65001",
    "de",
    "de-DE",
    "de-DE.850",
    "German_Germany.850",
    "German_Germany.1250",
    "de-DE.1252",
    "German_Germany.1252",
    "German_Germany.28605",
    "German_Germany.65001",
    "tr",
    "trk",
    "turkish",
    "tr-TR",
    "tr-TR.1254",
    "Turkish_Turkey.1254",
    "tr-TR.857",
    "Turkish_Turkey.857",
    "Turkish_Turkey.28599",
    "Turkish_Turkey.65001",
    "ru",
    "ru-RU",
    "Russian",
    "ru-RU.866",
    "Russian_Russia.866",
    "ru-RU.1251",
    "Russian_Russia.1251",
    "Russian_Russia.20866",
    "Russian_Russia.28595",
    "Russian_Russia.65001"
#else /* ! _WIN32 || __CYGWIN__ */
    "C.UTF-8",
    "POSIX",
    "en",
    "en_US",
    "en_US.ISO-8859-1",
    "en_US.ISO_8859-1",
    "en_US.ISO8859-1",
    "en_US.iso88591",
    "en_US.ISO-8859-15",
    "en_US.DIS_8859-15",
    "en_US.ISO8859-15",
    "en_US.iso885915",
    "en_US.1252",
    "en_US.CP1252",
    "en_US.UTF-8",
    "en_US.utf8",
    "fr",
    "fr_FR",
    "fr_FR.850",
    "fr_FR.IBM850",
    "fr_FR.1252",
    "fr_FR.CP1252",
    "fr_FR.ISO-8859-1",
    "fr_FR.ISO_8859-1",
    "fr_FR.ISO8859-1",
    "fr_FR.iso88591",
    "fr_FR.ISO-8859-15",
    "fr_FR.DIS_8859-15",
    "fr_FR.ISO8859-15",
    "fr_FR.iso8859-15",
    "fr_FR.UTF-8",
    "fr_FR.utf8",
    "de",
    "de_DE",
    "de_DE.850",
    "de_DE.IBM850",
    "de_DE.1250",
    "de_DE.CP1250",
    "de_DE.1252",
    "de_DE.CP1252",
    "de_DE.ISO-8859-1",
    "de_DE.ISO_8859-1",
    "de_DE.ISO8859-1",
    "de_DE.iso88591",
    "de_DE.ISO-8859-15",
    "de_DE.DIS_8859-15",
    "de_DE.ISO8859-15",
    "de_DE.iso885915",
    "de_DE.UTF-8",
    "de_DE.utf8",
    "tr",
    "tr_TR",
    "tr_TR.1254",
    "tr_TR.CP1254",
    "tr_TR.857",
    "tr_TR.IBM857",
    "tr_TR.ISO-8859-9",
    "tr_TR.ISO8859-9",
    "tr_TR.iso88599",
    "tr_TR.UTF-8",
    "tr_TR.utf8",
    "ru",
    "ru_RU",
    "ru_RU.1251",
    "ru_RU.CP1251",
    "ru_RU.866",
    "ru_RU.IBM866",
    "ru_RU.KOI8-R",
    "ru_RU.koi8-r",
    "ru_RU.KOI8-RU",
    "ru_RU.ISO-8859-5",
    "ru_RU.ISO_8859-5",
    "ru_RU.ISO8859-5",
    "ru_RU.iso88595",
    "ru_RU.UTF-8"
#endif /* ! _WIN32 || __CYGWIN__ */
};

static const unsigned int locale_name_count = sizeof(locale_names) / sizeof(locale_names[0]);


/*
 *  Helper functions
 */

int set_test_locale(unsigned int num)
{
  if (num >= locale_name_count)
    return -1;
  if (verbose > 2)
    printf("Setting locale \"%s\":", locale_names[num]);
   if (setlocale(LC_ALL, locale_names[num]))
     {
       if (verbose > 2)
         printf(" succeed.\n");
       return 1;
     }
   if (verbose > 2)
     printf(" failed.\n");
   return 0;
}

const char * get_current_locale_str(void)
{
  char const * loc_str = setlocale(LC_ALL, NULL);
  return loc_str ? loc_str : "unknown";
}

static char tmp_bufs[4][4*1024]; /* should be enough for testing */
static size_t buf_idx = 0;

/* print non-printable chars as char codes */
char * n_prnt(const char * str)
{
  static char * buf; /* should be enough for testing */
  static const size_t buf_size = sizeof(tmp_bufs[0]);
  const unsigned char * p = (const unsigned char*)str;
  size_t w_pos = 0;
  if (++buf_idx > 3)
    buf_idx = 0;
  buf = tmp_bufs[buf_idx];

  while(*p && w_pos + 1 < buf_size)
    {
      const unsigned char c = *p;
      if (c == '\\' || c == '"')
        {
          if (w_pos + 2 >= buf_size)
            break;
          buf[w_pos++] = '\\';
          buf[w_pos++] = c;
        }
      else if (c >= 0x20 && c <= 0x7E)
          buf[w_pos++] = c;
      else
        {
          if (w_pos + 4 >= buf_size)
            break;
          if (snprintf(buf + w_pos, buf_size - w_pos, "\\x%02hX", (short unsigned int)c) != 4)
            break;
          w_pos += 4;
        }
      p++;
    }
  if (*p)
    { /* not full string is printed */
      /* enough space for "..." ? */
      if (w_pos + 3 > buf_size)
        w_pos = buf_size - 4;
      buf[w_pos++] = '.';
      buf[w_pos++] = '.';
      buf[w_pos++] = '.';
    }
  buf[w_pos] = 0;
  return buf;
}


struct str_with_len
{
  const char * const str;
  const size_t len;
};

#define D_STR_W_LEN(s) {(s), (sizeof((s)) / sizeof(char)) - 1}

/*
 * String caseless equality functions tests
 */

struct two_eq_strs
{
  const struct str_with_len s1;
  const struct str_with_len s2;
};

static const struct two_eq_strs eq_strings[] = {
    {D_STR_W_LEN("1234567890!@~%&$@#{}[]\\/!?`."), D_STR_W_LEN("1234567890!@~%&$@#{}[]\\/!?`.")},
    {D_STR_W_LEN("Simple string."), D_STR_W_LEN("Simple string.")},
    {D_STR_W_LEN("SIMPLE STRING."), D_STR_W_LEN("SIMPLE STRING.")},
    {D_STR_W_LEN("simple string."), D_STR_W_LEN("simple string.")},
    {D_STR_W_LEN("simple string."), D_STR_W_LEN("Simple String.")},
    {D_STR_W_LEN("sImPlE StRiNg."), D_STR_W_LEN("SiMpLe sTrInG.")},
    {D_STR_W_LEN("SIMPLE STRING."), D_STR_W_LEN("simple string.")},
    {D_STR_W_LEN("abcdefghijklmnopqrstuvwxyz"), D_STR_W_LEN("abcdefghijklmnopqrstuvwxyz")},
    {D_STR_W_LEN("ABCDEFGHIJKLMNOPQRSTUVWXYZ"), D_STR_W_LEN("ABCDEFGHIJKLMNOPQRSTUVWXYZ")},
    {D_STR_W_LEN("abcdefghijklmnopqrstuvwxyz"), D_STR_W_LEN("ABCDEFGHIJKLMNOPQRSTUVWXYZ")},
    {D_STR_W_LEN("zyxwvutsrqponMLKJIHGFEDCBA"), D_STR_W_LEN("ZYXWVUTSRQPONmlkjihgfedcba")},

    {D_STR_W_LEN("Cha\x8cne pour le test."),
     D_STR_W_LEN("Cha\x8cne pour le test.")},     /* "Chaîne pour le test." in CP850 */
    {D_STR_W_LEN("cha\x8cne pOur Le TEst."),
     D_STR_W_LEN("Cha\x8cne poUr Le teST.")},
    {D_STR_W_LEN("Cha\xeene pour le test."),
     D_STR_W_LEN("Cha\xeene pour le test.")},     /* "Chaîne pour le test." in CP1252/ISO-8859-1/ISO-8859-15 */
    {D_STR_W_LEN("CHa\xeene POUR le test."),
     D_STR_W_LEN("Cha\xeeNe pour lE TEST.")},
    {D_STR_W_LEN("Cha\xc3\xaene pour le Test."),
     D_STR_W_LEN("Cha\xc3\xaene pour le Test.")}, /* "Chaîne pour le test." in UTF-8 */
    {D_STR_W_LEN("ChA\xc3\xaene pouR lE TesT."),
     D_STR_W_LEN("Cha\xc3\xaeNe Pour le teSt.")},

    {D_STR_W_LEN(".Beispiel Zeichenfolge"),
     D_STR_W_LEN(".Beispiel Zeichenfolge")},
    {D_STR_W_LEN(".bEisPiel ZEIchenfoLgE"),
     D_STR_W_LEN(".BEiSpiEl zeIcheNfolge")},

    {D_STR_W_LEN("Do\xa7rulama \x87izgi!"),
     D_STR_W_LEN("Do\xa7rulama \x87izgi!")},      /* "Doğrulama çizgi!" in CP857 */
    {D_STR_W_LEN("Do\xa7rulama \x87IzgI!"),       /* Spelling intentionally incorrect here */
     D_STR_W_LEN("Do\xa7rulama \x87izgi!")},      /* Note: 'i' is not caseless equal to 'I' in Turkish */
    {D_STR_W_LEN("Do\xf0rulama \xe7izgi!"),
     D_STR_W_LEN("Do\xf0rulama \xe7izgi!")},      /* "Doğrulama çizgi!" in CP1254/ISO-8859-9 */
    {D_STR_W_LEN("Do\xf0rulamA \xe7Izgi!"),
     D_STR_W_LEN("do\xf0rulama \xe7izgi!")},
    {D_STR_W_LEN("Do\xc4\x9frulama \xc3\xa7izgi!"),
     D_STR_W_LEN("Do\xc4\x9frulama \xc3\xa7izgi!")},        /* "Doğrulama çizgi!" in UTF-8 */
    {D_STR_W_LEN("do\xc4\x9fruLAMA \xc3\xa7Izgi!"),         /* Spelling intentionally incorrect here */
     D_STR_W_LEN("DO\xc4\x9frulama \xc3\xa7izgI!")},        /* Spelling intentionally incorrect here */

    {D_STR_W_LEN("\x92\xa5\xe1\xe2\xae\xa2\xa0\xef \x91\xe2\xe0\xae\xaa\xa0."),
     D_STR_W_LEN("\x92\xa5\xe1\xe2\xae\xa2\xa0\xef \x91\xe2\xe0\xae\xaa\xa0.")}, /* "Тестовая Строка." in CP866 */
    {D_STR_W_LEN("\xd2\xe5\xf1\xf2\xee\xe2\xe0\xff \xd1\xf2\xf0\xee\xea\xe0."),
     D_STR_W_LEN("\xd2\xe5\xf1\xf2\xee\xe2\xe0\xff \xd1\xf2\xf0\xee\xea\xe0.")}, /* "Тестовая Строка." in CP1251 */
    {D_STR_W_LEN("\xf4\xc5\xd3\xd4\xcf\xd7\xc1\xd1 \xf3\xd4\xd2\xcf\xcb\xc1."),
     D_STR_W_LEN("\xf4\xc5\xd3\xd4\xcf\xd7\xc1\xd1 \xf3\xd4\xd2\xcf\xcb\xc1.")}, /* "Тестовая Строка." in KOI8-R */
    {D_STR_W_LEN("\xc2\xd5\xe1\xe2\xde\xd2\xd0\xef \xc1\xe2\xe0\xde\xda\xd0."),
     D_STR_W_LEN("\xc2\xd5\xe1\xe2\xde\xd2\xd0\xef \xc1\xe2\xe0\xde\xda\xd0.")}, /* "Тестовая Строка." in ISO-8859-5 */
    {D_STR_W_LEN("\xd0\xa2\xd0\xb5\xd1\x81\xd1\x82\xd0\xbe\xd0\xb2\xd0\xb0\xd1"
                 "\x8f \xd0\xa1\xd1\x82\xd1\x80\xd0\xbe\xd0\xba\xd0\xb0."),
     D_STR_W_LEN("\xd0\xa2\xd0\xb5\xd1\x81\xd1\x82\xd0\xbe\xd0\xb2\xd0\xb0\xd1"
                 "\x8f \xd0\xa1\xd1\x82\xd1\x80\xd0\xbe\xd0\xba\xd0\xb0.")},     /* "Тестовая Строка." in UTF-8 */

    {D_STR_W_LEN("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
                 "\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?@[\\]"
                 "^_`{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
                 "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4"
                 "\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8"
                 "\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc"
                 "\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
                 "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4"
                 "\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"),
     D_STR_W_LEN("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
                 "\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?@[\\]"
                 "^_`{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
                 "\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4"
                 "\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8"
                 "\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc"
                 "\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
                 "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4"
                 "\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")}, /* Full sequence without a-z */
    {D_STR_W_LEN("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
                 "\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?@AB"
                 "CDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f\x80\x81\x82\x83"
                 "\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97"
                 "\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab"
                 "\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
                 "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3"
                 "\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7"
                 "\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb"
                 "\xfc\xfd\xfe\xff"),
     D_STR_W_LEN("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
                 "\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?@AB"
                 "CDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~\x7f\x80\x81\x82\x83"
                 "\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97"
                 "\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab"
                 "\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
                 "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3"
                 "\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7"
                 "\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb"
                 "\xfc\xfd\xfe\xff")}, /* Full sequence */
    {D_STR_W_LEN("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
                 "\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?@AB"
                 "CDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89"
                 "\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d"
                 "\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1"
                 "\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5"
                 "\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9"
                 "\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed"
                 "\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"),
     D_STR_W_LEN("\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
                 "\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f !\"#$%&'()*+,-./0123456789:;<=>?@ab"
                 "cdefghijklmnopqrstuvwxyz[\\]^_`{|}~\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89"
                 "\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d"
                 "\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1"
                 "\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5"
                 "\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9"
                 "\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed"
                 "\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")} /* Full with A/a match */
};

struct two_neq_strs
{
  const struct str_with_len s1;
  const struct str_with_len s2;
  const size_t dif_pos;
};

static const struct two_neq_strs neq_strings[] = {
    {D_STR_W_LEN("1234567890!@~%&$@#{}[]\\/!?`."), D_STR_W_LEN("1234567890!@~%&$@#{}[]\\/!?`"), 27},
    {D_STR_W_LEN(".1234567890!@~%&$@#{}[]\\/!?`."), D_STR_W_LEN("1234567890!@~%&$@#{}[]\\/!?`"), 0},
    {D_STR_W_LEN("Simple string."), D_STR_W_LEN("Simple ctring."), 7},
    {D_STR_W_LEN("simple string."), D_STR_W_LEN("simple string"), 13},
    {D_STR_W_LEN("simple strings"), D_STR_W_LEN("Simple String."), 13},
    {D_STR_W_LEN("sImPlE StRiNg."), D_STR_W_LEN("SYMpLe sTrInG."), 1},
    {D_STR_W_LEN("SIMPLE STRING."), D_STR_W_LEN("simple string.2"), 14},
    {D_STR_W_LEN("abcdefghijklmnopqrstuvwxyz,"), D_STR_W_LEN("abcdefghijklmnopqrstuvwxyz."), 26},
    {D_STR_W_LEN("abcdefghijklmnopqrstuvwxyz!"), D_STR_W_LEN("ABCDEFGHIJKLMNOPQRSTUVWXYZ?"), 26},
    {D_STR_W_LEN("zyxwvutsrqponwMLKJIHGFEDCBA"), D_STR_W_LEN("ZYXWVUTSRQPON%mlkjihgfedcba"), 13},

    {D_STR_W_LEN("S\xbdur veulent plus d'\xbdufs."),    /* "Sœur veulent plus d'œufs." in ISO-8859-15 */
     D_STR_W_LEN("S\xbcUR VEULENT PLUS D'\xbcUFS."), 1},/* "SŒUR VEULENT PLUS D'ŒUFS." in ISO-8859-15 */
    {D_STR_W_LEN("S\x9cur veulent plus d'\x9cufs."),    /* "Sœur veulent plus d'œufs." in CP1252 */
     D_STR_W_LEN("S\x8cUR VEULENT PLUS D'\x8cUFS."), 1},/* "SŒUR VEULENT PLUS D'ŒUFS." in CP1252 */
    {D_STR_W_LEN("S\xc5\x93ur veulent plus d'\xc5\x93ufs."),    /* "Sœur veulent plus d'œufs." in UTF-8 */
     D_STR_W_LEN("S\xc5\x92UR VEULENT PLUS D'\xc5\x92UFS."), 2},/* "SŒUR VEULENT PLUS D'ŒUFS." in UTF-8 */

    {D_STR_W_LEN("Um ein sch\x94nes M\x84" "dchen zu k\x81ssen."),     /* "Um ein schönes Mädchen zu küssen." in CP850 */
     D_STR_W_LEN("UM EIN SCH\x99NES M\x8e" "DCHEN ZU K\x9aSSEN."), 10},/* "UM EIN SCHÖNES MÄDCHEN ZU KÜSSEN." in CP850 */
    {D_STR_W_LEN("Um ein sch\xf6nes M\xe4" "dchen zu k\xfcssen."),     /* "Um ein schönes Mädchen zu küssen." in ISO-8859-1/ISO-8859-15/CP1250/CP1252 */
     D_STR_W_LEN("UM EIN SCH\xd6NES M\xc4" "DCHEN ZU K\xdcSSEN."), 10},/* "UM EIN SCHÖNES MÄDCHEN ZU KÜSSEN." in ISO-8859-1/ISO-8859-15/CP1250/CP1252 */
    {D_STR_W_LEN("Um ein sch\xc3\xb6nes M\xc3\xa4" "dchen zu k\xc3\xbcssen."),     /* "Um ein schönes Mädchen zu küssen." in UTF-8 */
     D_STR_W_LEN("UM EIN SCH\xc3\x96NES M\xc3\x84" "DCHEN ZU K\xc3\x9cSSEN."), 11},/* "UM EIN SCHÖNES MÄDCHEN ZU KÜSSEN." in UTF-8 */

    {D_STR_W_LEN("\x98stanbul"),           /* "İstanbul" in CP857 */
     D_STR_W_LEN("istanbul"), 0},          /* "istanbul" in CP857 */
    {D_STR_W_LEN("\xddstanbul"),           /* "İstanbul" in ISO-8859-9/CP1254 */
     D_STR_W_LEN("istanbul"), 0},          /* "istanbul" in ISO-8859-9/CP1254 */
    {D_STR_W_LEN("\xc4\xb0stanbul"),       /* "İstanbul" in UTF-8 */
     D_STR_W_LEN("istanbul"), 0},          /* "istanbul" in UTF-8 */
    {D_STR_W_LEN("Diyarbak\x8dr"),         /* "Diyarbakır" in CP857 */
     D_STR_W_LEN("DiyarbakIR"), 8},        /* "DiyarbakIR" in CP857 */
    {D_STR_W_LEN("Diyarbak\xfdr"),         /* "Diyarbakır" in ISO-8859-9/CP1254 */
     D_STR_W_LEN("DiyarbakIR"), 8},        /* "DiyarbakIR" in ISO-8859-9/CP1254 */
    {D_STR_W_LEN("Diyarbak\xc4\xb1r"),     /* "Diyarbakır" in UTF-8 */
     D_STR_W_LEN("DiyarbakIR"), 8},        /* "DiyarbakIR" in UTF-8 */

    {D_STR_W_LEN("\x92\xa5\xe1\xe2\xae\xa2\xa0\xef \x91\xe2\xe0\xae\xaa\xa0."),     /* "Тестовая Строка." in CP866 */
     D_STR_W_LEN("\x92\x85\x91\x92\x8e\x82\x80\x9f \x91\x92\x90\x8e\x8a\x80."), 1}, /* "ТЕСТОВАЯ СТРОКА." in CP866 */
    {D_STR_W_LEN("\xd2\xe5\xf1\xf2\xee\xe2\xe0\xff \xd1\xf2\xf0\xee\xea\xe0."),     /* "Тестовая Строка." in CP1251 */
     D_STR_W_LEN("\xd2\xc5\xd1\xd2\xce\xc2\xc0\xdf \xd1\xd2\xd0\xce\xca\xc0."), 1}, /* "ТЕСТОВАЯ СТРОКА." in CP1251 */
    {D_STR_W_LEN("\xf4\xc5\xd3\xd4\xcf\xd7\xc1\xd1 \xf3\xd4\xd2\xcf\xcb\xc1."),     /* "Тестовая Строка." in KOI8-R */
     D_STR_W_LEN("\xf4\xe5\xf3\xf4\xef\xf7\xe1\xf1 \xf3\xf4\xf2\xef\xeb\xe1."), 1}, /* "ТЕСТОВАЯ СТРОКА." in KOI8-R */
    {D_STR_W_LEN("\xc2\xd5\xe1\xe2\xde\xd2\xd0\xef \xc1\xe2\xe0\xde\xda\xd0."),     /* "Тестовая Строка." in ISO-8859-5 */
     D_STR_W_LEN("\xc2\xb5\xc1\xc2\xbe\xb2\xb0\xcf \xc1\xc2\xc0\xbe\xba\xb0."), 1}, /* "ТЕСТОВАЯ СТРОКА." in ISO-8859-5 */
    {D_STR_W_LEN("\xd0\xa2\xd0\xb5\xd1\x81\xd1\x82\xd0\xbe\xd0\xb2\xd0\xb0\xd1"
                 "\x8f \xd0\xa1\xd1\x82\xd1\x80\xd0\xbe\xd0\xba\xd0\xb0."),         /* "Тестовая Строка." in UTF-8 */
     D_STR_W_LEN("\xd0\xa2\xd0\x95\xd0\xa1\xd0\xa2\xd0\x9e\xd0\x92\xd0\x90\xd0"
                 "\xaf \xd0\xa1\xd0\xa2\xd0\xa0\xd0\x9e\xd0\x9a\xd0\x90."), 3}      /* "ТЕСТОВАЯ СТРОКА." in UTF-8 */
};


int check_eq_strings(void)
{
  size_t t_failed = 0;
  size_t i, j;
  static const size_t n_checks = sizeof(eq_strings) / sizeof(eq_strings[0]);
  int c_failed[n_checks];

  memset(c_failed, 0, sizeof(c_failed));

  for(j = 0; j < locale_name_count; j++)
    {
      set_test_locale(j); /* setlocale() can be slow! */
      for(i = 0; i < n_checks; i++)
        {
          const struct two_eq_strs * const t = eq_strings + i;
          if (c_failed[i])
            continue; /* skip already failed checks */
          if (!MHD_str_equal_caseless_(t->s1.str, t->s2.str))
            {
              t_failed++;
              c_failed[i] = !0;
              fprintf(stderr, "FAILED: MHD_str_equal_caseless_(\"%s\", \"%s\") returned zero, while expected non-zero."
                      " Locale: %s\n", n_prnt(t->s1.str), n_prnt(t->s2.str), get_current_locale_str());
            }
          else if (!MHD_str_equal_caseless_(t->s2.str, t->s1.str))
            {
              t_failed++;
              c_failed[i] = !0;
              fprintf(stderr, "FAILED: MHD_str_equal_caseless_(\"%s\", \"%s\") returned zero, while expected non-zero."
                      " Locale: %s\n", n_prnt(t->s2.str), n_prnt(t->s1.str), get_current_locale_str());
            }
          if (verbose > 1 && j == locale_name_count - 1 && !c_failed[i])
            printf("PASSED: MHD_str_equal_caseless_(\"%s\", \"%s\") != 0 && \\\n"
                   "        MHD_str_equal_caseless_(\"%s\", \"%s\") != 0\n", n_prnt(t->s1.str), n_prnt(t->s2.str),
                   n_prnt(t->s2.str), n_prnt(t->s1.str));
        }
    }
  return t_failed;
}

int check_neq_strings(void)
{
  size_t t_failed = 0;
  size_t i, j;
  static const size_t n_checks = sizeof(neq_strings) / sizeof(neq_strings[0]);
  int c_failed[n_checks];

  memset(c_failed, 0, sizeof(c_failed));

  for(j = 0; j < locale_name_count; j++)
    {
      set_test_locale(j); /* setlocale() can be slow! */
      for(i = 0; i < n_checks; i++)
        {
          const struct two_neq_strs * const t = neq_strings + i;
          if (c_failed[i])
            continue; /* skip already failed checks */
          if (MHD_str_equal_caseless_(t->s1.str, t->s2.str))
            {
              t_failed++;
              c_failed[i] = !0;
              fprintf(stderr, "FAILED: MHD_str_equal_caseless_(\"%s\", \"%s\") returned non-zero, while expected zero."
                      " Locale: %s\n", n_prnt(t->s1.str), n_prnt(t->s2.str), get_current_locale_str());
            }
          else if (MHD_str_equal_caseless_(t->s2.str, t->s1.str))
            {
              t_failed++;
              c_failed[i] = !0;
              fprintf(stderr, "FAILED: MHD_str_equal_caseless_(\"%s\", \"%s\") returned non-zero, while expected zero."
                      " Locale: %s\n", n_prnt(t->s2.str), n_prnt(t->s1.str), get_current_locale_str());
            }
          if (verbose > 1 && j == locale_name_count - 1 && !c_failed[i])
            printf("PASSED: MHD_str_equal_caseless_(\"%s\", \"%s\") == 0 && \\\n"
                   "        MHD_str_equal_caseless_(\"%s\", \"%s\") == 0\n", n_prnt(t->s1.str), n_prnt(t->s2.str),
                   n_prnt(t->s2.str), n_prnt(t->s1.str));
        }
    }
  return t_failed;
}

int check_eq_strings_n(void)
{
  size_t t_failed = 0;
  size_t i, j, k;
  static const size_t n_checks = sizeof(eq_strings) / sizeof(eq_strings[0]);
  int c_failed[n_checks];

  memset(c_failed, 0, sizeof(c_failed));

  for(j = 0; j < locale_name_count; j++)
    {
      set_test_locale(j); /* setlocale() can be slow! */
      for(i = 0; i < n_checks; i++)
        {
          size_t m_len;
          const struct two_eq_strs * const t = eq_strings + i;
          m_len = (t->s1.len > t->s2.len) ? t->s1.len : t->s2.len;
          for(k = 0; k <= m_len + 1 && !c_failed[i]; k++)
            {
              if (!MHD_str_equal_caseless_n_(t->s1.str, t->s2.str, k))
                {
                  t_failed++;
                  c_failed[i] = !0;
                  fprintf(stderr, "FAILED: MHD_str_equal_caseless_n_(\"%s\", \"%s\", %u) returned zero,"
                                  " while expected non-zero. Locale: %s\n",
                                  n_prnt(t->s1.str), n_prnt(t->s2.str), (unsigned int) k, get_current_locale_str());
                }
              else if (!MHD_str_equal_caseless_n_(t->s2.str, t->s1.str, k))
                {
                  t_failed++;
                  c_failed[i] = !0;
                  fprintf(stderr, "FAILED: MHD_str_equal_caseless_n_(\"%s\", \"%s\", %u) returned zero,"
                                  " while expected non-zero. Locale: %s\n",
                                  n_prnt(t->s2.str), n_prnt(t->s1.str), (unsigned int) k, get_current_locale_str());
                }
            }
          if (verbose > 1 && j == locale_name_count - 1 && !c_failed[i])
            printf("PASSED: MHD_str_equal_caseless_n_(\"%s\", \"%s\", N) != 0 && \\\n"
                   "        MHD_str_equal_caseless_n_(\"%s\", \"%s\", N) != 0, where N is 0..%u\n",
                   n_prnt(t->s1.str), n_prnt(t->s2.str), n_prnt(t->s2.str), n_prnt(t->s1.str), (unsigned int) m_len + 1);
        }
    }
  return t_failed;
}

int check_neq_strings_n(void)
{
  size_t t_failed = 0;
  size_t i, j, k;
  static const size_t n_checks = sizeof(neq_strings) / sizeof(neq_strings[0]);
  int c_failed[n_checks];

  memset(c_failed, 0, sizeof(c_failed));

  for(j = 0; j < locale_name_count; j++)
    {
      set_test_locale(j); /* setlocale() can be slow! */
      for(i = 0; i < n_checks; i++)
        {
          size_t m_len;
          const struct two_neq_strs * const t = neq_strings + i;
          m_len = t->s1.len > t->s2.len ? t->s1.len : t->s2.len;
          if (t->dif_pos >= m_len)
            {
              fprintf(stderr, "ERROR: neq_strings[%u] has wrong dif_pos (%u): dif_pos is expected to be less than "
                              "s1.len (%u) or s2.len (%u).\n", (unsigned int) i, (unsigned int) t->dif_pos,
                              (unsigned int) t->s1.len, (unsigned int) t->s2.len);
              return -1;
            }
          if (t->dif_pos > t->s1.len)
            {
              fprintf(stderr, "ERROR: neq_strings[%u] has wrong dif_pos (%u): dif_pos is expected to be less or "
                              "equal to s1.len (%u).\n", (unsigned int) i, (unsigned int) t->dif_pos,
                              (unsigned int) t->s1.len);
              return -1;
            }
          if (t->dif_pos > t->s2.len)
            {
              fprintf(stderr, "ERROR: neq_strings[%u] has wrong dif_pos (%u): dif_pos is expected to be less or "
                              "equal to s2.len (%u).\n", (unsigned int) i, (unsigned int) t->dif_pos,
                              (unsigned int) t->s2.len);
              return -1;
            }
          for(k = 0; k <= m_len + 1 && !c_failed[i]; k++)
            {
              if (k <= t->dif_pos)
                {
                  if (!MHD_str_equal_caseless_n_(t->s1.str, t->s2.str, k))
                    {
                      t_failed++;
                      c_failed[i] = !0;
                      fprintf(stderr, "FAILED: MHD_str_equal_caseless_n_(\"%s\", \"%s\", %u) returned zero,"
                                      " while expected non-zero. Locale: %s\n",
                                      n_prnt(t->s1.str), n_prnt(t->s2.str), (unsigned int) k, get_current_locale_str());
                    }
                  else if (!MHD_str_equal_caseless_n_(t->s2.str, t->s1.str, k))
                    {
                      t_failed++;
                      c_failed[i] = !0;
                      fprintf(stderr, "FAILED: MHD_str_equal_caseless_n_(\"%s\", \"%s\", %u) returned zero,"
                                      " while expected non-zero. Locale: %s\n",
                                      n_prnt(t->s2.str), n_prnt(t->s1.str), (unsigned int) k, get_current_locale_str());
                    }
                }
              else
                {
                  if (MHD_str_equal_caseless_n_(t->s1.str, t->s2.str, k))
                    {
                      t_failed++;
                      c_failed[i] = !0;
                      fprintf(stderr, "FAILED: MHD_str_equal_caseless_n_(\"%s\", \"%s\", %u) returned non-zero,"
                                      " while expected zero. Locale: %s\n",
                                      n_prnt(t->s1.str), n_prnt(t->s2.str), (unsigned int) k, get_current_locale_str());
                    }
                  else if (MHD_str_equal_caseless_n_(t->s2.str, t->s1.str, k))
                    {
                      t_failed++;
                      c_failed[i] = !0;
                      fprintf(stderr, "FAILED: MHD_str_equal_caseless_n_(\"%s\", \"%s\", %u) returned non-zero,"
                                      " while expected zero. Locale: %s\n",
                                      n_prnt(t->s2.str), n_prnt(t->s1.str), (unsigned int) k, get_current_locale_str());
                    }
                }
            }
          if (verbose > 1 && j == locale_name_count - 1 && !c_failed[i])
            {
              printf("PASSED: MHD_str_equal_caseless_n_(\"%s\", \"%s\", N) != 0 && \\\n"
                     "        MHD_str_equal_caseless_n_(\"%s\", \"%s\", N) != 0, where N is 0..%u\n",
                     n_prnt(t->s1.str), n_prnt(t->s2.str), n_prnt(t->s2.str), n_prnt(t->s1.str),
                     (unsigned int) t->dif_pos);

              printf("PASSED: MHD_str_equal_caseless_n_(\"%s\", \"%s\", N) == 0 && \\\n"
                     "        MHD_str_equal_caseless_n_(\"%s\", \"%s\", N) == 0, where N is %u..%u\n",
                     n_prnt(t->s1.str), n_prnt(t->s2.str), n_prnt(t->s2.str), n_prnt(t->s1.str),
                     (unsigned int) t->dif_pos + 1, (unsigned int) m_len + 1);
            }
        }
    }
  return t_failed;
}

/*
 * Run eq/neq strings tests
 */
int run_eq_neq_str_tests(void)
{
  int str_equal_caseless_fails = 0;
  int str_equal_caseless_n_fails = 0;
  int res;

  res = check_eq_strings();
  if (res != 0)
    {
      if (res < 0)
        {
          fprintf(stderr, "ERROR: test internal error in check_eq_strings().\n");
          return 99;
        }
      str_equal_caseless_fails += res;
      fprintf(stderr, "FAILED: testcase check_eq_strings() failed.\n\n");
    }
  else if (verbose > 1)
    printf("PASSED: testcase check_eq_strings() successfully passed.\n\n");

  res = check_neq_strings();
  if (res != 0)
    {
      if (res < 0)
        {
          fprintf(stderr, "ERROR: test internal error in check_neq_strings().\n");
          return 99;
        }
      str_equal_caseless_fails += res;
      fprintf(stderr, "FAILED: testcase check_neq_strings() failed.\n\n");
    }
  else if (verbose > 1)
    printf("PASSED: testcase check_neq_strings() successfully passed.\n\n");

  if (str_equal_caseless_fails)
    fprintf(stderr, "FAILED: function MHD_str_equal_caseless_() failed %d time%s.\n\n",
                     str_equal_caseless_fails, str_equal_caseless_fails == 1 ? "" : "s");
  else if (verbose > 0)
    printf("PASSED: function MHD_str_equal_caseless_() successfully passed all checks.\n\n");

  res = check_eq_strings_n();
  if (res != 0)
    {
      if (res < 0)
        {
          fprintf(stderr, "ERROR: test internal error in check_eq_strings_n().\n");
          return 99;
        }
      str_equal_caseless_n_fails += res;
      fprintf(stderr, "FAILED: testcase check_eq_strings_n() failed.\n\n");
    }
  else if (verbose > 1)
    printf("PASSED: testcase check_eq_strings_n() successfully passed.\n\n");

  res = check_neq_strings_n();
  if (res != 0)
    {
      if (res < 0)
        {
          fprintf(stderr, "ERROR: test internal error in check_neq_strings_n().\n");
          return 99;
        }
      str_equal_caseless_n_fails += res;
      fprintf(stderr, "FAILED: testcase check_neq_strings_n() failed.\n\n");
    }
  else if (verbose > 1)
    printf("PASSED: testcase check_neq_strings_n() successfully passed.\n\n");

  if (str_equal_caseless_n_fails)
    fprintf(stderr, "FAILED: function MHD_str_equal_caseless_n_() failed %d time%s.\n\n",
                     str_equal_caseless_n_fails, str_equal_caseless_n_fails == 1 ? "" : "s");
  else if (verbose > 0)
    printf("PASSED: function MHD_str_equal_caseless_n_() successfully passed all checks.\n\n");

  if (str_equal_caseless_fails || str_equal_caseless_n_fails)
    {
      if (verbose > 0)
        printf("At least one test failed.\n");

      return 1;
    }

  if (verbose > 0)
    printf("All tests passed successfully.\n");

  return 0;
}

int main(int argc, char * argv[])
{
  if (has_param(argc, argv, "-v") || has_param(argc, argv, "--verbose") || has_param(argc, argv, "--verbose1"))
    verbose = 1;
  if (has_param(argc, argv, "-vv") || has_param(argc, argv, "--verbose2"))
    verbose = 2;
  if (has_param(argc, argv, "-vvv") || has_param(argc, argv, "--verbose3"))
    verbose = 3;

  return run_eq_neq_str_tests();
}
