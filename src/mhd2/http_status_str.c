/*
     This file is part of libmicrohttpd
     Copyright (C) 2017-2024 Evgeny Grin (Karlson2k)
     Copyright (C) 2007, 2011, 2017, 2019 Christian Grothoff

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
 * @file src/mhd2/http_status_str.c
 * @brief  Tables of the string response phrases
 * @author Elliot Glaysher
 * @author Christian Grothoff (minor code clean up)
 * @author Karlson2k (Evgeny Grin) (massively refactored and updated)
 */
#include "mhd_sys_options.h"

#include "http_status_str.h"

#include "sys_base_types.h"
#include "mhd_public_api.h"
#include "mhd_str_macros.h"

#define UNUSED_STATUS {0, NULL}

static const struct MHD_String invalid_hundred[] = {
  { 0, NULL }
};

static const struct MHD_String one_hundred[] = {
  /* 100 */ mhd_MSTR_INIT ("Continue"),       /* RFC9110, Section 15.2.1 */
  /* 101 */ mhd_MSTR_INIT ("Switching Protocols"), /* RFC9110, Section 15.2.2 */
  /* 102 */ mhd_MSTR_INIT ("Processing"),     /* RFC2518 */
  /* 103 */ mhd_MSTR_INIT ("Early Hints")     /* RFC8297 */
};

static const struct MHD_String two_hundred[] = {
  /* 200 */ mhd_MSTR_INIT ("OK"),             /* RFC9110, Section 15.3.1 */
  /* 201 */ mhd_MSTR_INIT ("Created"),        /* RFC9110, Section 15.3.2 */
  /* 202 */ mhd_MSTR_INIT ("Accepted"),       /* RFC9110, Section 15.3.3 */
  /* 203 */ mhd_MSTR_INIT ("Non-Authoritative Information"), /* RFC9110, Section 15.3.4 */
  /* 204 */ mhd_MSTR_INIT ("No Content"),     /* RFC9110, Section 15.3.5 */
  /* 205 */ mhd_MSTR_INIT ("Reset Content"),  /* RFC9110, Section 15.3.6 */
  /* 206 */ mhd_MSTR_INIT ("Partial Content"), /* RFC9110, Section 15.3.7 */
  /* 207 */ mhd_MSTR_INIT ("Multi-Status"),   /* RFC4918 */
  /* 208 */ mhd_MSTR_INIT ("Already Reported"), /* RFC5842 */
  /* 209 */ UNUSED_STATUS,                    /* Not used */
  /* 210 */ UNUSED_STATUS,                    /* Not used */
  /* 211 */ UNUSED_STATUS,                    /* Not used */
  /* 212 */ UNUSED_STATUS,                    /* Not used */
  /* 213 */ UNUSED_STATUS,                    /* Not used */
  /* 214 */ UNUSED_STATUS,                    /* Not used */
  /* 215 */ UNUSED_STATUS,                    /* Not used */
  /* 216 */ UNUSED_STATUS,                    /* Not used */
  /* 217 */ UNUSED_STATUS,                    /* Not used */
  /* 218 */ UNUSED_STATUS,                    /* Not used */
  /* 219 */ UNUSED_STATUS,                    /* Not used */
  /* 220 */ UNUSED_STATUS,                    /* Not used */
  /* 221 */ UNUSED_STATUS,                    /* Not used */
  /* 222 */ UNUSED_STATUS,                    /* Not used */
  /* 223 */ UNUSED_STATUS,                    /* Not used */
  /* 224 */ UNUSED_STATUS,                    /* Not used */
  /* 225 */ UNUSED_STATUS,                    /* Not used */
  /* 226 */ mhd_MSTR_INIT ("IM Used")         /* RFC3229 */
};

static const struct MHD_String three_hundred[] = {
  /* 300 */ mhd_MSTR_INIT ("Multiple Choices"), /* RFC9110, Section 15.4.1 */
  /* 301 */ mhd_MSTR_INIT ("Moved Permanently"), /* RFC9110, Section 15.4.2 */
  /* 302 */ mhd_MSTR_INIT ("Found"),          /* RFC9110, Section 15.4.3 */
  /* 303 */ mhd_MSTR_INIT ("See Other"),      /* RFC9110, Section 15.4.4 */
  /* 304 */ mhd_MSTR_INIT ("Not Modified"),   /* RFC9110, Section 15.4.5 */
  /* 305 */ mhd_MSTR_INIT ("Use Proxy"),      /* RFC9110, Section 15.4.6 */
  /* 306 */ mhd_MSTR_INIT ("Switch Proxy"),   /* Not used! RFC9110, Section 15.4.7 */
  /* 307 */ mhd_MSTR_INIT ("Temporary Redirect"), /* RFC9110, Section 15.4.8 */
  /* 308 */ mhd_MSTR_INIT ("Permanent Redirect") /* RFC9110, Section 15.4.9 */
};

static const struct MHD_String four_hundred[] = {
  /* 400 */ mhd_MSTR_INIT ("Bad Request"),    /* RFC9110, Section 15.5.1 */
  /* 401 */ mhd_MSTR_INIT ("Unauthorized"),   /* RFC9110, Section 15.5.2 */
  /* 402 */ mhd_MSTR_INIT ("Payment Required"), /* RFC9110, Section 15.5.3 */
  /* 403 */ mhd_MSTR_INIT ("Forbidden"),      /* RFC9110, Section 15.5.4 */
  /* 404 */ mhd_MSTR_INIT ("Not Found"),      /* RFC9110, Section 15.5.5 */
  /* 405 */ mhd_MSTR_INIT ("Method Not Allowed"), /* RFC9110, Section 15.5.6 */
  /* 406 */ mhd_MSTR_INIT ("Not Acceptable"), /* RFC9110, Section 15.5.7 */
  /* 407 */ mhd_MSTR_INIT ("Proxy Authentication Required"), /* RFC9110, Section 15.5.8 */
  /* 408 */ mhd_MSTR_INIT ("Request Timeout"), /* RFC9110, Section 15.5.9 */
  /* 409 */ mhd_MSTR_INIT ("Conflict"),       /* RFC9110, Section 15.5.10 */
  /* 410 */ mhd_MSTR_INIT ("Gone"),           /* RFC9110, Section 15.5.11 */
  /* 411 */ mhd_MSTR_INIT ("Length Required"), /* RFC9110, Section 15.5.12 */
  /* 412 */ mhd_MSTR_INIT ("Precondition Failed"), /* RFC9110, Section 15.5.13 */
  /* 413 */ mhd_MSTR_INIT ("Content Too Large"), /* RFC9110, Section 15.5.14 */
  /* 414 */ mhd_MSTR_INIT ("URI Too Long"),   /* RFC9110, Section 15.5.15 */
  /* 415 */ mhd_MSTR_INIT ("Unsupported Media Type"), /* RFC9110, Section 15.5.16 */
  /* 416 */ mhd_MSTR_INIT ("Range Not Satisfiable"), /* RFC9110, Section 15.5.17 */
  /* 417 */ mhd_MSTR_INIT ("Expectation Failed"), /* RFC9110, Section 15.5.18 */
  /* 418 */ UNUSED_STATUS,                    /* Not used */
  /* 419 */ UNUSED_STATUS,                    /* Not used */
  /* 420 */ UNUSED_STATUS,                    /* Not used */
  /* 421 */ mhd_MSTR_INIT ("Misdirected Request"), /* RFC9110, Section 15.5.20 */
  /* 422 */ mhd_MSTR_INIT ("Unprocessable Content"), /* RFC9110, Section 15.5.21 */
  /* 423 */ mhd_MSTR_INIT ("Locked"),         /* RFC4918 */
  /* 424 */ mhd_MSTR_INIT ("Failed Dependency"), /* RFC4918 */
  /* 425 */ mhd_MSTR_INIT ("Too Early"),      /* RFC8470 */
  /* 426 */ mhd_MSTR_INIT ("Upgrade Required"), /* RFC9110, Section 15.5.22 */
  /* 427 */ UNUSED_STATUS,                    /* Not used */
  /* 428 */ mhd_MSTR_INIT ("Precondition Required"), /* RFC6585 */
  /* 429 */ mhd_MSTR_INIT ("Too Many Requests"), /* RFC6585 */
  /* 430 */ UNUSED_STATUS,                    /* Not used */
  /* 431 */ mhd_MSTR_INIT ("Request Header Fields Too Large"), /* RFC6585 */
  /* 432 */ UNUSED_STATUS,                    /* Not used */
  /* 433 */ UNUSED_STATUS,                    /* Not used */
  /* 434 */ UNUSED_STATUS,                    /* Not used */
  /* 435 */ UNUSED_STATUS,                    /* Not used */
  /* 436 */ UNUSED_STATUS,                    /* Not used */
  /* 437 */ UNUSED_STATUS,                    /* Not used */
  /* 438 */ UNUSED_STATUS,                    /* Not used */
  /* 439 */ UNUSED_STATUS,                    /* Not used */
  /* 440 */ UNUSED_STATUS,                    /* Not used */
  /* 441 */ UNUSED_STATUS,                    /* Not used */
  /* 442 */ UNUSED_STATUS,                    /* Not used */
  /* 443 */ UNUSED_STATUS,                    /* Not used */
  /* 444 */ UNUSED_STATUS,                    /* Not used */
  /* 445 */ UNUSED_STATUS,                    /* Not used */
  /* 446 */ UNUSED_STATUS,                    /* Not used */
  /* 447 */ UNUSED_STATUS,                    /* Not used */
  /* 448 */ UNUSED_STATUS,                    /* Not used */
  /* 449 */ mhd_MSTR_INIT ("Reply With"),     /* MS IIS extension */
  /* 450 */ mhd_MSTR_INIT ("Blocked by Windows Parental Controls"), /* MS extension */
  /* 451 */ mhd_MSTR_INIT ("Unavailable For Legal Reasons") /* RFC7725 */
};

static const struct MHD_String five_hundred[] = {
  /* 500 */ mhd_MSTR_INIT ("Internal Server Error"), /* RFC9110, Section 15.6.1 */
  /* 501 */ mhd_MSTR_INIT ("Not Implemented"), /* RFC9110, Section 15.6.2 */
  /* 502 */ mhd_MSTR_INIT ("Bad Gateway"),    /* RFC9110, Section 15.6.3 */
  /* 503 */ mhd_MSTR_INIT ("Service Unavailable"), /* RFC9110, Section 15.6.4 */
  /* 504 */ mhd_MSTR_INIT ("Gateway Timeout"), /* RFC9110, Section 15.6.5 */
  /* 505 */ mhd_MSTR_INIT ("HTTP Version Not Supported"), /* RFC9110, Section 15.6.6 */
  /* 506 */ mhd_MSTR_INIT ("Variant Also Negotiates"), /* RFC2295 */
  /* 507 */ mhd_MSTR_INIT ("Insufficient Storage"), /* RFC4918 */
  /* 508 */ mhd_MSTR_INIT ("Loop Detected"),  /* RFC5842 */
  /* 509 */ mhd_MSTR_INIT ("Bandwidth Limit Exceeded"), /* Apache extension */
  /* 510 */ mhd_MSTR_INIT ("Not Extended"),   /* (OBSOLETED) RFC2774; status-change-http-experiments-to-historic */
  /* 511 */ mhd_MSTR_INIT ("Network Authentication Required") /* RFC6585 */
};


struct mhd_HttpStatusesBlock
{
  size_t num_elmnts;
  const struct MHD_String *const data;
};

#define STATUSES_BLOCK(m) { (sizeof(m) / sizeof(m[0])), m}

static const struct mhd_HttpStatusesBlock statuses[] = {
  STATUSES_BLOCK (invalid_hundred),
  STATUSES_BLOCK (one_hundred),
  STATUSES_BLOCK (two_hundred),
  STATUSES_BLOCK (three_hundred),
  STATUSES_BLOCK (four_hundred),
  STATUSES_BLOCK (five_hundred)
};

MHD_EXTERN_ MHD_FN_CONST_ const struct MHD_String *
MHD_HTTP_status_code_to_string (enum MHD_HTTP_StatusCode code)
{
  const struct MHD_String *res;
  const unsigned int code_i = (unsigned int) code;
  if (100 > code_i)
    return NULL;
  if (600 < code)
    return NULL;
  if (statuses[code_i / 100].num_elmnts <= (code_i % 100))
    return NULL;
  res = statuses[code_i / 100].data + (code_i % 100);
  if (NULL == res->cstr)
    return NULL;
  return res;
}


MHD_INTERNAL MHD_FN_CONST_ const struct MHD_String *
mhd_HTTP_status_code_to_string_int (uint_fast16_t code)
{
  static const struct MHD_String no_status =
    mhd_MSTR_INIT ("Nonstandard Status");
  const struct MHD_String *res;

  res = MHD_HTTP_status_code_to_string ((enum MHD_HTTP_StatusCode) code);
  if (NULL != res)
    return res;

  return &no_status;
}
