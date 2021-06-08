/*
     This file is part of libmicrohttpd
     Copyright (C) 2007, 2011, 2017, 2019 Christian Grothoff, Karlson2k (Evgeny Grin)

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
 * @file reason_phrase.c
 * @brief  Tables of the string response phrases
 * @author Elliot Glaysher
 * @author Christian Grothoff (minor code clean up)
 * @author Karlson2k (Evgeny Grin)
 */
#include "platform.h"
#include "microhttpd.h"
#include "mhd_str.h"

#ifndef NULL
#define NULL ((void*) 0)
#endif

static const struct _MHD_str_w_len invalid_hundred[] = {
  { NULL, 0 }
};

static const struct _MHD_str_w_len one_hundred[] = {
  /* 100 */ _MHD_S_STR_W_LEN ("Continue"),       /* RFC7231, Section 6.2.1 */
  /* 101 */ _MHD_S_STR_W_LEN ("Switching Protocols"), /* RFC7231, Section 6.2.2 */
  /* 102 */ _MHD_S_STR_W_LEN ("Processing"),     /* RFC2518 */
  /* 103 */ _MHD_S_STR_W_LEN ("Early Hints")     /* RFC8297 */
};

static const struct _MHD_str_w_len two_hundred[] = {
  /* 200 */ _MHD_S_STR_W_LEN ("OK"),             /* RFC7231, Section 6.3.1 */
  /* 201 */ _MHD_S_STR_W_LEN ("Created"),        /* RFC7231, Section 6.3.2 */
  /* 202 */ _MHD_S_STR_W_LEN ("Accepted"),       /* RFC7231, Section 6.3.3 */
  /* 203 */ _MHD_S_STR_W_LEN ("Non-Authoritative Information"), /* RFC7231, Section 6.3.4 */
  /* 204 */ _MHD_S_STR_W_LEN ("No Content"),     /* RFC7231, Section 6.3.5 */
  /* 205 */ _MHD_S_STR_W_LEN ("Reset Content"),  /* RFC7231, Section 6.3.6 */
  /* 206 */ _MHD_S_STR_W_LEN ("Partial Content"), /* RFC7233, Section 4.1 */
  /* 207 */ _MHD_S_STR_W_LEN ("Multi-Status"),   /* RFC4918 */
  /* 208 */ _MHD_S_STR_W_LEN ("Already Reported"), /* RFC5842 */
  /* 209 */ {"Unknown", 0},                      /* Not used */
  /* 210 */ {"Unknown", 0},                      /* Not used */
  /* 211 */ {"Unknown", 0},                      /* Not used */
  /* 212 */ {"Unknown", 0},                      /* Not used */
  /* 213 */ {"Unknown", 0},                      /* Not used */
  /* 214 */ {"Unknown", 0},                      /* Not used */
  /* 215 */ {"Unknown", 0},                      /* Not used */
  /* 216 */ {"Unknown", 0},                      /* Not used */
  /* 217 */ {"Unknown", 0},                      /* Not used */
  /* 218 */ {"Unknown", 0},                      /* Not used */
  /* 219 */ {"Unknown", 0},                      /* Not used */
  /* 220 */ {"Unknown", 0},                      /* Not used */
  /* 221 */ {"Unknown", 0},                      /* Not used */
  /* 222 */ {"Unknown", 0},                      /* Not used */
  /* 223 */ {"Unknown", 0},                      /* Not used */
  /* 224 */ {"Unknown", 0},                      /* Not used */
  /* 225 */ {"Unknown", 0},                      /* Not used */
  /* 226 */ _MHD_S_STR_W_LEN ("IM Used")         /* RFC3229 */
};

static const struct _MHD_str_w_len three_hundred[] = {
  /* 300 */ _MHD_S_STR_W_LEN ("Multiple Choices"), /* RFC7231, Section 6.4.1 */
  /* 301 */ _MHD_S_STR_W_LEN ("Moved Permanently"), /* RFC7231, Section 6.4.2 */
  /* 302 */ _MHD_S_STR_W_LEN ("Found"),          /* RFC7231, Section 6.4.3 */
  /* 303 */ _MHD_S_STR_W_LEN ("See Other"),      /* RFC7231, Section 6.4.4 */
  /* 304 */ _MHD_S_STR_W_LEN ("Not Modified"),   /* RFC7232, Section 4.1 */
  /* 305 */ _MHD_S_STR_W_LEN ("Use Proxy"),      /* RFC7231, Section 6.4.5 */
  /* 306 */ _MHD_S_STR_W_LEN ("Switch Proxy"),   /* Not used! RFC7231, Section 6.4.6 */
  /* 307 */ _MHD_S_STR_W_LEN ("Temporary Redirect"), /* RFC7231, Section 6.4.7 */
  /* 308 */ _MHD_S_STR_W_LEN ("Permanent Redirect") /* RFC7538 */
};

static const struct _MHD_str_w_len four_hundred[] = {
  /* 400 */ _MHD_S_STR_W_LEN ("Bad Request"),    /* RFC7231, Section 6.5.1 */
  /* 401 */ _MHD_S_STR_W_LEN ("Unauthorized"),   /* RFC7235, Section 3.1 */
  /* 402 */ _MHD_S_STR_W_LEN ("Payment Required"), /* RFC7231, Section 6.5.2 */
  /* 403 */ _MHD_S_STR_W_LEN ("Forbidden"),      /* RFC7231, Section 6.5.3 */
  /* 404 */ _MHD_S_STR_W_LEN ("Not Found"),      /* RFC7231, Section 6.5.4 */
  /* 405 */ _MHD_S_STR_W_LEN ("Method Not Allowed"), /* RFC7231, Section 6.5.5 */
  /* 406 */ _MHD_S_STR_W_LEN ("Not Acceptable"), /* RFC7231, Section 6.5.6 */
  /* 407 */ _MHD_S_STR_W_LEN ("Proxy Authentication Required"), /* RFC7235, Section 3.2 */
  /* 408 */ _MHD_S_STR_W_LEN ("Request Timeout"), /* RFC7231, Section 6.5.7 */
  /* 409 */ _MHD_S_STR_W_LEN ("Conflict"),       /* RFC7231, Section 6.5.8 */
  /* 410 */ _MHD_S_STR_W_LEN ("Gone"),           /* RFC7231, Section 6.5.9 */
  /* 411 */ _MHD_S_STR_W_LEN ("Length Required"), /* RFC7231, Section 6.5.10 */
  /* 412 */ _MHD_S_STR_W_LEN ("Precondition Failed"), /* RFC7232, Section 4.2; RFC8144, Section 3.2 */
  /* 413 */ _MHD_S_STR_W_LEN ("Payload Too Large"), /* RFC7231, Section 6.5.11 */
  /* 414 */ _MHD_S_STR_W_LEN ("URI Too Long"),   /* RFC7231, Section 6.5.12 */
  /* 415 */ _MHD_S_STR_W_LEN ("Unsupported Media Type"), /* RFC7231, Section 6.5.13; RFC7694, Section 3 */
  /* 416 */ _MHD_S_STR_W_LEN ("Range Not Satisfiable"), /* RFC7233, Section 4.4 */
  /* 417 */ _MHD_S_STR_W_LEN ("Expectation Failed"), /* RFC7231, Section 6.5.14 */
  /* 418 */ {"Unknown", 0},                      /* Not used */
  /* 419 */ {"Unknown", 0},                      /* Not used */
  /* 420 */ {"Unknown", 0},                      /* Not used */
  /* 421 */ _MHD_S_STR_W_LEN ("Misdirected Request"), /* RFC7540, Section 9.1.2 */
  /* 422 */ _MHD_S_STR_W_LEN ("Unprocessable Entity"), /* RFC4918 */
  /* 423 */ _MHD_S_STR_W_LEN ("Locked"),         /* RFC4918 */
  /* 424 */ _MHD_S_STR_W_LEN ("Failed Dependency"), /* RFC4918 */
  /* 425 */ _MHD_S_STR_W_LEN ("Too Early"),      /* RFC8470 */
  /* 426 */ _MHD_S_STR_W_LEN ("Upgrade Required"), /* RFC7231, Section 6.5.15 */
  /* 427 */ {"Unknown", 0},                      /* Not used */
  /* 428 */ _MHD_S_STR_W_LEN ("Precondition Required"), /* RFC6585 */
  /* 429 */ _MHD_S_STR_W_LEN ("Too Many Requests"), /* RFC6585 */
  /* 430 */ {"Unknown", 0},                      /* Not used */
  /* 431 */ _MHD_S_STR_W_LEN ("Request Header Fields Too Large"), /* RFC6585 */
  /* 432 */ {"Unknown", 0},                      /* Not used */
  /* 433 */ {"Unknown", 0},                      /* Not used */
  /* 434 */ {"Unknown", 0},                      /* Not used */
  /* 435 */ {"Unknown", 0},                      /* Not used */
  /* 436 */ {"Unknown", 0},                      /* Not used */
  /* 437 */ {"Unknown", 0},                      /* Not used */
  /* 438 */ {"Unknown", 0},                      /* Not used */
  /* 439 */ {"Unknown", 0},                      /* Not used */
  /* 440 */ {"Unknown", 0},                      /* Not used */
  /* 441 */ {"Unknown", 0},                      /* Not used */
  /* 442 */ {"Unknown", 0},                      /* Not used */
  /* 443 */ {"Unknown", 0},                      /* Not used */
  /* 444 */ {"Unknown", 0},                      /* Not used */
  /* 445 */ {"Unknown", 0},                      /* Not used */
  /* 446 */ {"Unknown", 0},                      /* Not used */
  /* 447 */ {"Unknown", 0},                      /* Not used */
  /* 448 */ {"Unknown", 0},                      /* Not used */
  /* 449 */ _MHD_S_STR_W_LEN ("Reply With"),     /* MS IIS extension */
  /* 450 */ _MHD_S_STR_W_LEN ("Blocked by Windows Parental Controls"), /* MS extension */
  /* 451 */ _MHD_S_STR_W_LEN ("Unavailable For Legal Reasons") /* RFC7725 */
};

static const struct _MHD_str_w_len five_hundred[] = {
  /* 500 */ _MHD_S_STR_W_LEN ("Internal Server Error"), /* RFC7231, Section 6.6.1 */
  /* 501 */ _MHD_S_STR_W_LEN ("Not Implemented"), /* RFC7231, Section 6.6.2 */
  /* 502 */ _MHD_S_STR_W_LEN ("Bad Gateway"),    /* RFC7231, Section 6.6.3 */
  /* 503 */ _MHD_S_STR_W_LEN ("Service Unavailable"), /* RFC7231, Section 6.6.4 */
  /* 504 */ _MHD_S_STR_W_LEN ("Gateway Timeout"), /* RFC7231, Section 6.6.5 */
  /* 505 */ _MHD_S_STR_W_LEN ("HTTP Version Not Supported"), /* RFC7231, Section 6.6.6 */
  /* 506 */ _MHD_S_STR_W_LEN ("Variant Also Negotiates"), /* RFC2295 */
  /* 507 */ _MHD_S_STR_W_LEN ("Insufficient Storage"), /* RFC4918 */
  /* 508 */ _MHD_S_STR_W_LEN ("Loop Detected"),  /* RFC5842 */
  /* 509 */ _MHD_S_STR_W_LEN ("Bandwidth Limit Exceeded"), /* Apache extension */
  /* 510 */ _MHD_S_STR_W_LEN ("Not Extended"),   /* RFC2774 */
  /* 511 */ _MHD_S_STR_W_LEN ("Network Authentication Required") /* RFC6585 */
};


struct MHD_Reason_Block
{
  size_t max;
  const struct _MHD_str_w_len *const data;
};

#define BLOCK(m) { (sizeof(m) / sizeof(m[0])), m }

static const struct MHD_Reason_Block reasons[] = {
  BLOCK (invalid_hundred),
  BLOCK (one_hundred),
  BLOCK (two_hundred),
  BLOCK (three_hundred),
  BLOCK (four_hundred),
  BLOCK (five_hundred),
};


const char *
MHD_get_reason_phrase_for (unsigned int code)
{
  if ( (code >= 100) &&
       (code < 600) &&
       (reasons[code / 100].max > (code % 100)) )
    return reasons[code / 100].data[code % 100].str;
  return "Unknown";
}


size_t
MHD_get_reason_phrase_len_for (unsigned int code)
{
  if ( (code >= 100) &&
       (code < 600) &&
       (reasons[code / 100].max > (code % 100)) )
    return reasons[code / 100].data[code % 100].len;
  return 0;
}
