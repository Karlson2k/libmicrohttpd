/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2014-2024 Evgeny Grin (Karlson2k)
  Copyright (C) 2007-2020 Daniel Pittman and Christian Grothoff

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
 * @file src/mhd2/stream_process_request.c
 * @brief  The implementation of internal functions for requests parsing
 *         and processing
 * @author Karlson2k (Evgeny Grin)
 *
 * Based on the MHD v0.x code by Daniel Pittman, Christian Grothoff and other
 * contributors.
 */

#include "mhd_sys_options.h"
#include "stream_process_request.h"

#include "sys_bool_type.h"
#include "sys_base_types.h"

#include "sys_malloc.h"

#include "mhd_str_types.h"
#include "mhd_str_macros.h"
#include "mhd_str.h"

#include <string.h>

#include "mhd_daemon.h"
#include "mhd_connection.h"

#include "daemon_logger.h"
#include "mhd_assert.h"
#include "mhd_panic.h"

#include "mhd_mempool.h"

#include "request_funcs.h"
#include "request_get_value.h"
#include "respond_with_error.h"
#include "stream_funcs.h"
#include "daemon_funcs.h"

#include "mhd_public_api.h"


/**
 * Response text used when the request (http header) is
 * malformed.
 */
#define ERR_RSP_REQUEST_MALFORMED \
        "<html><head><title>Request malformed</title></head>" \
        "<body>HTTP request is syntactically incorrect.</body></html>"

/**
 * Response text used when the request HTTP version is too old.
 */
#define ERR_RSP_REQ_HTTP_VER_IS_TOO_OLD \
        "<html>" \
        "<head><title>Requested HTTP version is not supported</title></head>" \
        "<body>Requested HTTP version is too old and not " \
        "supported.</body></html>"
/**
 * Response text used when the request HTTP version is not supported.
 */
#define ERR_RSP_REQ_HTTP_VER_IS_NOT_SUPPORTED \
        "<html>" \
        "<head><title>Requested HTTP version is not supported</title></head>" \
        "<body>Requested HTTP version is not supported.</body></html>"

/**
 * Response text used when the request HTTP header has bare CR character
 * without LF character (and CR is not allowed to be treated as whitespace).
 */
#define ERR_RSP_BARE_CR_IN_HEADER \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>Request HTTP header has bare CR character without " \
        "following LF character.</body>" \
        "</html>"

/**
 * Response text used when the request HTTP footer has bare CR character
 * without LF character (and CR is not allowed to be treated as whitespace).
 */
#define ERR_RSP_BARE_CR_IN_FOOTER \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>Request HTTP footer has bare CR character without " \
        "following LF character.</body>" \
        "</html>"

/**
 * Response text used when the request HTTP header has bare LF character
 * without CR character.
 */
#define ERR_RSP_BARE_LF_IN_HEADER \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>Request HTTP header has bare LF character without " \
        "preceding CR character.</body>" \
        "</html>"
/**
 * Response text used when the request HTTP footer has bare LF character
 * without CR character.
 */
#define ERR_RSP_BARE_LF_IN_FOOTER \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>Request HTTP footer has bare LF character without " \
        "preceding CR character.</body>" \
        "</html>"

/**
 * Response text used when the request line has more then two whitespaces.
 */
#define ERR_RSP_RQ_LINE_TOO_MANY_WSP \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>The request line has more then two whitespaces.</body>" \
        "</html>"

/**
 * Response text used when the request line has invalid characters in URI.
 */
#define ERR_RSP_RQ_TARGET_INVALID_CHAR \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>HTTP request has invalid characters in " \
        "the request-target.</body>" \
        "</html>"

/**
 * Response text used when line folding is used in request headers.
 */
#define ERR_RSP_OBS_FOLD \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>Obsolete line folding is used in HTTP request header.</body>" \
        "</html>"

/**
 * Response text used when line folding is used in request footers.
 */
#define ERR_RSP_OBS_FOLD_FOOTER \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>Obsolete line folding is used in HTTP request footer.</body>" \
        "</html>"

/**
 * Response text used when request header has no colon character.
 */
#define ERR_RSP_HEADER_WITHOUT_COLON \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>HTTP request header line has no colon character.</body>" \
        "</html>"

/**
 * Response text used when request footer has no colon character.
 */
#define ERR_RSP_FOOTER_WITHOUT_COLON \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>HTTP request footer line has no colon character.</body>" \
        "</html>"
/**
 * Response text used when the request has whitespace at the start
 * of the first header line.
 */
#define ERR_RSP_WSP_BEFORE_HEADER \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>HTTP request has whitespace between the request line and " \
        "the first header.</body>" \
        "</html>"

/**
 * Response text used when the request has whitespace at the start
 * of the first footer line.
 */
#define ERR_RSP_WSP_BEFORE_FOOTER \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>First HTTP footer line has whitespace at the first " \
        "position.</body>" \
        "</html>"

/**
 * Response text used when the whitespace found before colon (inside header
 * name or between header name and colon).
 */
#define ERR_RSP_WSP_IN_HEADER_NAME \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>HTTP request has whitespace before the first colon " \
        "in header line.</body>" \
        "</html>"

/**
 * Response text used when the whitespace found before colon (inside header
 * name or between header name and colon).
 */
#define ERR_RSP_WSP_IN_FOOTER_NAME \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>HTTP request has whitespace before the first colon " \
        "in footer line.</body>" \
        "</html>"
/**
 * Response text used when request header has invalid character.
 */
#define ERR_RSP_INVALID_CHR_IN_HEADER \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>HTTP request has invalid character in header.</body>" \
        "</html>"

/**
 * Response text used when request header has invalid character.
 */
#define ERR_RSP_INVALID_CHR_IN_FOOTER \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>HTTP request has invalid character in footer.</body>" \
        "</html>"

/**
 * Response text used when request header has zero-length header (filed) name.
 */
#define ERR_RSP_EMPTY_HEADER_NAME \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>HTTP request header has empty header name.</body>" \
        "</html>"

/**
 * Response text used when request header has zero-length header (filed) name.
 */
#define ERR_RSP_EMPTY_FOOTER_NAME \
        "<html>" \
        "<head><title>Request broken</title></head>" \
        "<body>HTTP request footer has empty footer name.</body>" \
        "</html>"

/**
 * Response text used when the request header is too big to be processed.
 */
#define ERR_RSP_REQUEST_HEADER_TOO_BIG \
        "<html>" \
        "<head><title>Request too big</title></head>" \
        "<body><p>The total size of the request headers, which includes the " \
        "request target and the request field lines, exceeds the memory " \
        "constraints of this web server.</p>" \
        "<p>The request could be re-tried with shorter field lines, a shorter " \
        "request target or a shorter request method token.</p></body>" \
        "</html>"

/**
 * Response text used when the request header is too big to be processed.
 */
#define ERR_RSP_REQUEST_FOOTER_TOO_BIG \
        "<html>" \
        "<head><title>Request too big</title></head>" \
        "<body><p>The total size of the request headers, which includes the " \
        "request target, the request field lines and the chunked trailer " \
        "section exceeds the memory constraints of this web server.</p>" \
        "<p>The request could be re-tried with a shorter chunked trailer " \
        "section, shorter field lines, a shorter request target or " \
        "a shorter request method token.</p></body>" \
        "</html>"

/**
 * Response text used when the request (http header) is too big to
 * be processed.
 */
#define ERR_RSP_MSG_REQUEST_TOO_BIG \
        "<html>" \
        "<head><title>Request too big</title></head>" \
        "<body>Request HTTP header is too big for the memory constraints " \
        "of this webserver.</body>" \
        "</html>"
/**
 * Response text used when the request chunk size line with chunk extension
 * cannot fit the buffer.
 */
#define ERR_RSP_REQUEST_CHUNK_LINE_EXT_TOO_BIG \
        "<html>" \
        "<head><title>Request too big</title></head>" \
        "<body><p>The total size of the request target, the request field lines " \
        "and the chunk size line exceeds the memory constraints of this web " \
        "server.</p>" \
        "<p>The request could be re-tried without chunk extensions, with a smaller " \
        "chunk size, shorter field lines, a shorter request target or a shorter " \
        "request method token.</p></body>" \
        "</html>"

/**
 * Response text used when the request chunk size line without chunk extension
 * cannot fit the buffer.
 */
#define ERR_RSP_REQUEST_CHUNK_LINE_TOO_BIG \
        "<html>" \
        "<head><title>Request too big</title></head>" \
        "<body><p>The total size of the request target, the request field lines " \
        "and the chunk size line exceeds the memory constraints of this web " \
        "server.</p>" \
        "<p>The request could be re-tried with a smaller " \
        "chunk size, shorter field lines, a shorter request target or a shorter " \
        "request method token.</p></body>" \
        "</html>"

/**
 * Response text used when the request (http header) does not
 * contain a "Host:" header and still claims to be HTTP 1.1.
 */
#define ERR_RSP_REQUEST_LACKS_HOST \
        "<html>" \
        "<head><title>&quot;Host:&quot; header required</title></head>" \
        "<body>HTTP/1.1 request without <b>&quot;Host:&quot;</b>.</body>" \
        "</html>"

/**
 * Response text used when the request has more than one "Host:" header.
 */
#define ERR_RSP_REQUEST_HAS_SEVERAL_HOSTS \
        "<html>" \
        "<head>" \
        "<title>Several &quot;Host:&quot; headers used</title></head>" \
        "<body>" \
        "Request with more than one <b>&quot;Host:&quot;</b> header.</body>" \
        "</html>"

/**
 * Response text used when the request has unsupported "Transfer-Encoding:".
 */
#define ERR_RSP_UNSUPPORTED_TR_ENCODING \
        "<html>" \
        "<head><title>Unsupported Transfer-Encoding</title></head>" \
        "<body>The Transfer-Encoding used in request is not supported.</body>" \
        "</html>"

/**
 * Response text used when the request has unsupported both headers:
 * "Transfer-Encoding:" and "Content-Length:"
 */
#define ERR_RSP_REQUEST_CNTNLENGTH_WITH_TR_ENCODING \
        "<html>" \
        "<head><title>Malformed request</title></head>" \
        "<body>Wrong combination of the request headers: both Transfer-Encoding " \
        "and Content-Length headers are used at the same time.</body>" \
        "</html>"

/**
 * Response text used when the request HTTP content is too large.
 */
#define ERR_RSP_REQUEST_CONTENTLENGTH_TOOLARGE \
        "<html><head><title>Request content too large</title></head>" \
        "<body>HTTP request has too large value for " \
        "<b>Content-Length</b> header.</body></html>"

/**
 * Response text used when the request HTTP chunked encoding is
 * malformed.
 */
#define ERR_RSP_REQUEST_CONTENTLENGTH_MALFORMED \
        "<html><head><title>Request malformed</title></head>" \
        "<body>HTTP request has wrong value for " \
        "<b>Content-Length</b> header.</body></html>"

/**
 * Response text used when the request has more than one "Content-Length:"
 * header.
 */
#define ERR_RSP_REQUEST_CONTENTLENGTH_SEVERAL \
        "<html><head><title>Request malformed</title></head>" \
        "<body>HTTP request has several " \
        "<b>Content-Length</b> headers.</body></html>"

/**
 * Response text used when the request HTTP chunked encoding is
 * malformed.
 */
#define ERR_RSP_REQUEST_CHUNKED_MALFORMED \
        "<html><head><title>Request malformed</title></head>" \
        "<body>HTTP chunked encoding is syntactically incorrect.</body></html>"

/**
 * Response text used when the request HTTP chunk is too large.
 */
#define ERR_RSP_REQUEST_CHUNK_TOO_LARGE \
        "<html><head><title>Request content too large</title></head>" \
        "<body>The chunk size used in HTTP chunked encoded " \
        "request is too large.</body></html>"


/**
 * The reasonable length of the upload chunk "header" (the size specifier
 * with optional chunk extension).
 * MHD tries to keep the space in the read buffer large enough to read
 * the chunk "header" in one step.
 * The real "header" could be much larger, it will be handled correctly
 * anyway, however it may require several rounds of buffer grow.
 */
#define MHD_CHUNK_HEADER_REASONABLE_LEN 24

/**
 * Get whether bare LF in HTTP header and other protocol elements
 * should be treated as the line termination depending on the configured
 * strictness level.
 * RFC 9112, section 2.2
 */
#define MHD_ALLOW_BARE_LF_AS_CRLF_(discp_lvl) (0 >= discp_lvl)

/**
 * The valid length of any HTTP version string
 */
#define HTTP_VER_LEN (mhd_SSTR_LEN (MHD_HTTP_VERSION_1_1_STR))


/**
 * Detect standard HTTP request method
 *
 * @param connection the connection
 * @param method the pointer to HTTP request method string
 * @param len the length of @a method in bytes
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_IN_SIZE_ (3,2) void
parse_http_std_method (struct MHD_Connection *restrict connection,
                       size_t len,
                       const char *restrict method)
{
  const char *const m = method; /**< short alias */
  mhd_assert (NULL != m);
  mhd_assert (0 != len);

  if ((mhd_SSTR_LEN (MHD_HTTP_METHOD_STR_GET) == len) &&
      (0 == memcmp (m, MHD_HTTP_METHOD_STR_GET, len)))
    connection->rq.http_mthd = mhd_HTTP_METHOD_GET;
  else if ((mhd_SSTR_LEN (MHD_HTTP_METHOD_STR_HEAD) == len) &&
           (0 == memcmp (m, MHD_HTTP_METHOD_STR_HEAD, len)))
    connection->rq.http_mthd = mhd_HTTP_METHOD_HEAD;
  else if ((mhd_SSTR_LEN (MHD_HTTP_METHOD_STR_POST) == len) &&
           (0 == memcmp (m, MHD_HTTP_METHOD_STR_POST, len)))
    connection->rq.http_mthd = mhd_HTTP_METHOD_POST;
  else if ((mhd_SSTR_LEN (MHD_HTTP_METHOD_STR_PUT) == len) &&
           (0 == memcmp (m, MHD_HTTP_METHOD_STR_PUT, len)))
    connection->rq.http_mthd = mhd_HTTP_METHOD_PUT;
  else if ((mhd_SSTR_LEN (MHD_HTTP_METHOD_STR_DELETE) == len) &&
           (0 == memcmp (m, MHD_HTTP_METHOD_STR_DELETE, len)))
    connection->rq.http_mthd = mhd_HTTP_METHOD_DELETE;
  else if ((mhd_SSTR_LEN (MHD_HTTP_METHOD_STR_CONNECT) == len) &&
           (0 == memcmp (m, MHD_HTTP_METHOD_STR_CONNECT, len)))
    connection->rq.http_mthd = mhd_HTTP_METHOD_CONNECT;
  else if ((mhd_SSTR_LEN (MHD_HTTP_METHOD_STR_OPTIONS) == len) &&
           (0 == memcmp (m, MHD_HTTP_METHOD_STR_OPTIONS, len)))
    connection->rq.http_mthd = mhd_HTTP_METHOD_OPTIONS;
  else if ((mhd_SSTR_LEN (MHD_HTTP_METHOD_STR_TRACE) == len) &&
           (0 == memcmp (m, MHD_HTTP_METHOD_STR_TRACE, len)))
    connection->rq.http_mthd = mhd_HTTP_METHOD_TRACE;
  else if ((mhd_SSTR_LEN (MHD_HTTP_METHOD_STR_ASTERISK) == len) &&
           (0 == memcmp (m, MHD_HTTP_METHOD_STR_ASTERISK, len)))
    connection->rq.http_mthd = mhd_HTTP_METHOD_ASTERISK;
  else
    connection->rq.http_mthd = mhd_HTTP_METHOD_OTHER;
}


/**
 * Detect HTTP version, send error response if version is not supported
 *
 * @param connection the connection
 * @param http_string the pointer to HTTP version string
 * @param len the length of @a http_string in bytes
 * @return true if HTTP version is correct and supported,
 *         false if HTTP version is not correct or unsupported.
 */
static bool
parse_http_version (struct MHD_Connection *restrict connection,
                    const char *restrict http_string,
                    size_t len)
{
  const char *const h = http_string; /**< short alias */
  mhd_assert (NULL != http_string);

  /* String must start with 'HTTP/d.d', case-sensetive match.
   * See https://www.rfc-editor.org/rfc/rfc9112#name-http-version */
  if ((HTTP_VER_LEN != len) ||
      ('H' != h[0]) || ('T' != h[1]) || ('T' != h[2]) || ('P' != h[3]) ||
      ('/' != h[4])
      || ('.' != h[6]))
  {
    connection->rq.http_ver = MHD_HTTP_VERSION_INVALID;
    mhd_RESPOND_WITH_ERROR_STATIC (connection,
                                   MHD_HTTP_STATUS_BAD_REQUEST,
                                   ERR_RSP_REQUEST_MALFORMED);
    return false;
  }
  if (1 == h[5] - '0')
  {
    /* HTTP/1.x */
    if (1 == h[7] - '0')
    {
      connection->rq.http_ver = MHD_HTTP_VERSION_1_1;
      return true;
    }
    else if (0 == h[7] - '0')
    {
      connection->rq.http_ver = MHD_HTTP_VERSION_1_0;
      return true;
    }
    else
      connection->rq.http_ver = MHD_HTTP_VERSION_INVALID;

  }
  else if (0 == h[5] - '0')
  {
    /* Too old major version */
    connection->rq.http_ver = MHD_HTTP_VERSION_INVALID;
    mhd_RESPOND_WITH_ERROR_STATIC (connection,
                                   MHD_HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED,
                                   ERR_RSP_REQ_HTTP_VER_IS_TOO_OLD);
    return false;
  }
  else if ((2 == h[5] - '0') && ('0' == h[7] - '0'))
    connection->rq.http_ver = MHD_HTTP_VERSION_2;
  else
    connection->rq.http_ver = MHD_HTTP_VERSION_INVALID;

  mhd_RESPOND_WITH_ERROR_STATIC (connection,
                                 MHD_HTTP_STATUS_HTTP_VERSION_NOT_SUPPORTED,
                                 ERR_RSP_REQ_HTTP_VER_IS_NOT_SUPPORTED);
  return false;
}


#ifndef MHD_MAX_EMPTY_LINES_SKIP
/**
 * The maximum number of ignored empty line before the request line
 * at default "strictness" level.
 */
#  define MHD_MAX_EMPTY_LINES_SKIP 1024
#endif /* ! MHD_MAX_EMPTY_LINES_SKIP */


/**
 * Find and parse the request line.
 * @param c the connection to process
 * @return true if request line completely processed (or unrecoverable error
 *         found) and state is changed,
 *         false if not enough data yet in the receive buffer
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
get_request_line_inner (struct MHD_Connection *restrict c)
{
  size_t p; /**< The current processing position */
  const int discp_lvl = c->daemon->req_cfg.strictnees;
  /* Allow to skip one or more empty lines before the request line.
     RFC 9112, section 2.2 */
  const bool skip_empty_lines = (1 >= discp_lvl);
  /* Allow to skip more then one empty line before the request line.
     RFC 9112, section 2.2 */
  const bool skip_several_empty_lines = (skip_empty_lines && (0 >= discp_lvl));
  /* Allow to skip unlimited number of empty lines before the request line.
     RFC 9112, section 2.2 */
  const bool skip_unlimited_empty_lines =
    (skip_empty_lines && (-3 >= discp_lvl));
  /* Treat bare LF as the end of the line.
     RFC 9112, section 2.2 */
  const bool bare_lf_as_crlf = MHD_ALLOW_BARE_LF_AS_CRLF_ (discp_lvl);
  /* Treat tab as whitespace delimiter.
     RFC 9112, section 3 */
  const bool tab_as_wsp = (0 >= discp_lvl);
  /* Treat VT (vertical tab) and FF (form feed) as whitespace delimiters.
     RFC 9112, section 3 */
  const bool other_wsp_as_wsp = (-1 >= discp_lvl);
  /* Treat continuous whitespace block as a single space.
     RFC 9112, section 3 */
  const bool wsp_blocks = (-1 >= discp_lvl);
  /* Parse whitespace in URI, special parsing of the request line.
     RFC 9112, section 3.2 */
  const bool wsp_in_uri = (0 >= discp_lvl);
  /* Keep whitespace in URI, give app URI with whitespace instead of
     automatic redirect to fixed URI.
     Violates RFC 9112, section 3.2 */
  const bool wsp_in_uri_keep = (-2 >= discp_lvl);
  /* Keep bare CR character as is.
     Violates RFC 9112, section 2.2 */
  const bool bare_cr_keep = (wsp_in_uri_keep && (-3 >= discp_lvl));
  /* Treat bare CR as space; replace it with space before processing.
     RFC 9112, section 2.2 */
  const bool bare_cr_as_sp = ((! bare_cr_keep) && (-1 >= discp_lvl));

  mhd_assert (MHD_CONNECTION_INIT == c->state || \
              MHD_CONNECTION_REQ_LINE_RECEIVING == c->state);
  mhd_assert (NULL == c->rq.method || \
              MHD_CONNECTION_REQ_LINE_RECEIVING == c->state);
  mhd_assert (mhd_HTTP_METHOD_NO_METHOD == c->rq.http_mthd || \
              MHD_CONNECTION_REQ_LINE_RECEIVING == c->state);
  mhd_assert (mhd_HTTP_METHOD_NO_METHOD == c->rq.http_mthd || \
              0 != c->rq.hdrs.rq_line.proc_pos);

  if (0 == c->read_buffer_offset)
  {
    mhd_assert (MHD_CONNECTION_INIT == c->state);
    return false; /* No data to process */
  }
  p = c->rq.hdrs.rq_line.proc_pos;
  mhd_assert (p <= c->read_buffer_offset);

  /* Skip empty lines, if any (and if allowed) */
  /* See RFC 9112, section 2.2 */
  if ((0 == p)
      && (skip_empty_lines))
  {
    /* Skip empty lines before the request line.
       See RFC 9112, section 2.2 */
    bool is_empty_line;
    mhd_assert (MHD_CONNECTION_INIT == c->state);
    mhd_assert (NULL == c->rq.method);
    mhd_assert (NULL == c->rq.url);
    mhd_assert (0 == c->rq.url_len);
    mhd_assert (NULL == c->rq.hdrs.rq_line.rq_tgt);
    mhd_assert (0 == c->rq.req_target_len);
    mhd_assert (NULL == c->rq.version);
    do
    {
      is_empty_line = false;
      if ('\r' == c->read_buffer[0])
      {
        if (1 == c->read_buffer_offset)
          return false; /* Not enough data yet */
        if ('\n' == c->read_buffer[1])
        {
          is_empty_line = true;
          c->read_buffer += 2;
          c->read_buffer_size -= 2;
          c->read_buffer_offset -= 2;
          c->rq.hdrs.rq_line.skipped_empty_lines++;
        }
      }
      else if (('\n' == c->read_buffer[0]) &&
               (bare_lf_as_crlf))
      {
        is_empty_line = true;
        c->read_buffer += 1;
        c->read_buffer_size -= 1;
        c->read_buffer_offset -= 1;
        c->rq.hdrs.rq_line.skipped_empty_lines++;
      }
      if (is_empty_line)
      {
        if ((! skip_unlimited_empty_lines) &&
            (((unsigned int) ((skip_several_empty_lines) ?
                              MHD_MAX_EMPTY_LINES_SKIP : 1)) <
             c->rq.hdrs.rq_line.skipped_empty_lines))
        {
          mhd_STREAM_ABORT (c, mhd_CONN_CLOSE_CLIENT_HTTP_ERR_ABORT_CONN,
                            "Too many meaningless extra empty lines " \
                            "received before the request.");
          return true; /* Process connection closure */
        }
        if (0 == c->read_buffer_offset)
          return false;  /* No more data to process */
      }
    } while (is_empty_line);
  }
  /* All empty lines are skipped */

  c->state = MHD_CONNECTION_REQ_LINE_RECEIVING;
  /* Read and parse the request line */
  mhd_assert (1 <= c->read_buffer_offset);

  while (p < c->read_buffer_offset)
  {
    char *const restrict read_buffer = c->read_buffer;
    const char chr = read_buffer[p];
    bool end_of_line;
    /*
       The processing logic is different depending on the configured strictness:

       When whitespace BLOCKS are NOT ALLOWED, the end of the whitespace is
       processed BEFORE processing of the current character.
       When whitespace BLOCKS are ALLOWED, the end of the whitespace is
       processed AFTER processing of the current character.

       When space char in the URI is ALLOWED, the delimiter between the URI and
       the HTTP version string is processed only at the END of the line.
       When space in the URI is NOT ALLOWED, the delimiter between the URI and
       the HTTP version string is processed as soon as the FIRST whitespace is
       found after URI start.
     */

    end_of_line = false;

    mhd_assert ((0 == c->rq.hdrs.rq_line.last_ws_end) || \
                (c->rq.hdrs.rq_line.last_ws_end > \
                 c->rq.hdrs.rq_line.last_ws_start));
    mhd_assert ((0 == c->rq.hdrs.rq_line.last_ws_start) || \
                (0 != c->rq.hdrs.rq_line.last_ws_end));

    /* Check for the end of the line */
    if ('\r' == chr)
    {
      if (p + 1 == c->read_buffer_offset)
      {
        c->rq.hdrs.rq_line.proc_pos = p;
        return false; /* Not enough data yet */
      }
      else if ('\n' == read_buffer[p + 1])
        end_of_line = true;
      else
      {
        /* Bare CR alone */
        /* Must be rejected or replaced with space char.
           See RFC 9112, section 2.2 */
        if (bare_cr_as_sp)
        {
          read_buffer[p] = ' ';
          c->rq.num_cr_sp_replaced++;
          continue; /* Re-start processing of the current character */
        }
        else if (! bare_cr_keep)
        {
          /* A quick simple check whether this line looks like an HTTP request */
          if ((mhd_HTTP_METHOD_GET <= c->rq.http_mthd) &&
              (mhd_HTTP_METHOD_DELETE >= c->rq.http_mthd))
          {
            mhd_RESPOND_WITH_ERROR_STATIC (c,
                                           MHD_HTTP_STATUS_BAD_REQUEST,
                                           ERR_RSP_BARE_CR_IN_HEADER);
          }
          else
            mhd_STREAM_ABORT (c, mhd_CONN_CLOSE_CLIENT_HTTP_ERR_ABORT_CONN,
                              "Bare CR characters are not allowed " \
                              "in the request line.");

          return true; /* Error in the request */
        }
      }
    }
    else if ('\n' == chr)
    {
      /* Bare LF may be recognised as a line delimiter.
         See RFC 9112, section 2.2 */
      if (bare_lf_as_crlf)
        end_of_line = true;
      else
      {
        /* While RFC does not enforce error for bare LF character,
           if this char is not treated as a line delimiter, it should be
           rejected to avoid any security weakness due to request smuggling. */
        /* A quick simple check whether this line looks like an HTTP request */
        if ((mhd_HTTP_METHOD_GET <= c->rq.http_mthd) &&
            (mhd_HTTP_METHOD_DELETE >= c->rq.http_mthd))
        {
          mhd_RESPOND_WITH_ERROR_STATIC (c,
                                         MHD_HTTP_STATUS_BAD_REQUEST,
                                         ERR_RSP_BARE_LF_IN_HEADER);
        }
        else
          mhd_STREAM_ABORT (c, mhd_CONN_CLOSE_CLIENT_HTTP_ERR_ABORT_CONN,
                            "Bare LF characters are not allowed " \
                            "in the request line.");
        return true; /* Error in the request */
      }
    }

    if (end_of_line)
    {
      /* Handle the end of the request line */

      if (NULL != c->rq.method)
      {
        if (wsp_in_uri)
        {
          /* The end of the URI and the start of the HTTP version string
             should be determined now. */
          mhd_assert (NULL == c->rq.version);
          mhd_assert (0 == c->rq.req_target_len);
          if (0 != c->rq.hdrs.rq_line.last_ws_end)
          {
            /* Determine the end and the length of the URI */
            if (NULL != c->rq.hdrs.rq_line.rq_tgt)
            {
              read_buffer [c->rq.hdrs.rq_line.last_ws_start] = 0; /* Zero terminate the URI */
              c->rq.req_target_len =
                c->rq.hdrs.rq_line.last_ws_start
                - (size_t) (c->rq.hdrs.rq_line.rq_tgt - read_buffer);
            }
            else if ((c->rq.hdrs.rq_line.last_ws_start + 1 <
                      c->rq.hdrs.rq_line.last_ws_end) &&
                     (HTTP_VER_LEN == (p - c->rq.hdrs.rq_line.last_ws_end)))
            {
              /* Found only HTTP method and HTTP version and more than one
                 whitespace between them. Assume zero-length URI. */
              mhd_assert (wsp_blocks);
              c->rq.hdrs.rq_line.last_ws_start++;
              read_buffer[c->rq.hdrs.rq_line.last_ws_start] = 0; /* Zero terminate the URI */
              c->rq.hdrs.rq_line.rq_tgt =
                read_buffer + c->rq.hdrs.rq_line.last_ws_start;
              c->rq.req_target_len = 0;
              c->rq.hdrs.rq_line.num_ws_in_uri = 0;
              c->rq.hdrs.rq_line.rq_tgt_qmark = NULL;
            }
            /* Determine the start of the HTTP version string */
            if (NULL != c->rq.hdrs.rq_line.rq_tgt)
            {
              c->rq.version = read_buffer + c->rq.hdrs.rq_line.last_ws_end;
            }
          }
        }
        else
        {
          /* The end of the URI and the start of the HTTP version string
             should be already known. */
          if ((NULL == c->rq.version)
              && (NULL != c->rq.hdrs.rq_line.rq_tgt)
              && (HTTP_VER_LEN == p - (size_t) (c->rq.hdrs.rq_line.rq_tgt
                                                - read_buffer))
              && (0 != read_buffer[(size_t)
                                   (c->rq.hdrs.rq_line.rq_tgt
                                    - read_buffer) - 1]))
          {
            /* Found only HTTP method and HTTP version and more than one
               whitespace between them. Assume zero-length URI. */
            size_t uri_pos;
            mhd_assert (wsp_blocks);
            mhd_assert (0 == c->rq.req_target_len);
            uri_pos = (size_t) (c->rq.hdrs.rq_line.rq_tgt - read_buffer) - 1;
            mhd_assert (uri_pos < p);
            c->rq.version = c->rq.hdrs.rq_line.rq_tgt;
            read_buffer[uri_pos] = 0;  /* Zero terminate the URI */
            c->rq.hdrs.rq_line.rq_tgt = read_buffer + uri_pos;
            c->rq.req_target_len = 0;
            c->rq.hdrs.rq_line.num_ws_in_uri = 0;
            c->rq.hdrs.rq_line.rq_tgt_qmark = NULL;
          }
        }

        if (NULL != c->rq.version)
        {
          mhd_assert (NULL != c->rq.hdrs.rq_line.rq_tgt);
          if (! parse_http_version (c, c->rq.version,
                                    p
                                    - (size_t) (c->rq.version
                                                - read_buffer)))
          {
            mhd_assert (MHD_CONNECTION_REQ_LINE_RECEIVING < c->state);
            return true; /* Unsupported / broken HTTP version */
          }
          read_buffer[p] = 0; /* Zero terminate the HTTP version strings */
          if ('\r' == chr)
          {
            p++; /* Consume CR */
            mhd_assert (p < c->read_buffer_offset); /* The next character has been already checked */
          }
          p++; /* Consume LF */
          c->read_buffer += p;
          c->read_buffer_size -= p;
          c->read_buffer_offset -= p;
          mhd_assert (c->rq.hdrs.rq_line.num_ws_in_uri <= \
                      c->rq.req_target_len);
          mhd_assert ((NULL == c->rq.hdrs.rq_line.rq_tgt_qmark) || \
                      (0 != c->rq.req_target_len));
          mhd_assert ((NULL == c->rq.hdrs.rq_line.rq_tgt_qmark) || \
                      ((size_t) (c->rq.hdrs.rq_line.rq_tgt_qmark \
                                 - c->rq.hdrs.rq_line.rq_tgt) < \
                       c->rq.req_target_len));
          mhd_assert ((NULL == c->rq.hdrs.rq_line.rq_tgt_qmark) || \
                      (c->rq.hdrs.rq_line.rq_tgt_qmark >= \
                       c->rq.hdrs.rq_line.rq_tgt));
          return true; /* The request line is successfully parsed */
        }
      }
      /* Error in the request line */

      /* A quick simple check whether this line looks like an HTTP request */
      if ((mhd_HTTP_METHOD_GET <= c->rq.http_mthd) &&
          (mhd_HTTP_METHOD_DELETE >= c->rq.http_mthd))
      {
        mhd_RESPOND_WITH_ERROR_STATIC (c,
                                       MHD_HTTP_STATUS_BAD_REQUEST,
                                       ERR_RSP_REQUEST_MALFORMED);
      }
      else
        mhd_STREAM_ABORT (c, mhd_CONN_CLOSE_CLIENT_HTTP_ERR_ABORT_CONN,
                          "The request line is malformed.");

      return true;
    }

    /* Process possible end of the previously found whitespace delimiter */
    if ((! wsp_blocks) &&
        (p == c->rq.hdrs.rq_line.last_ws_end) &&
        (0 != c->rq.hdrs.rq_line.last_ws_end))
    {
      /* Previous character was a whitespace char and whitespace blocks
         are not allowed. */
      /* The current position is the next character after
         a whitespace delimiter */
      if (NULL == c->rq.hdrs.rq_line.rq_tgt)
      {
        /* The current position is the start of the URI */
        mhd_assert (0 == c->rq.req_target_len);
        mhd_assert (NULL == c->rq.version);
        c->rq.hdrs.rq_line.rq_tgt = read_buffer + p;
        /* Reset the whitespace marker */
        c->rq.hdrs.rq_line.last_ws_start = 0;
        c->rq.hdrs.rq_line.last_ws_end = 0;
      }
      else
      {
        /* It was a whitespace after the start of the URI */
        if (! wsp_in_uri)
        {
          mhd_assert ((0 != c->rq.req_target_len) || \
                      (c->rq.hdrs.rq_line.rq_tgt + 1 == read_buffer + p));
          mhd_assert (NULL == c->rq.version); /* Too many whitespaces? This error is handled at whitespace start */
          c->rq.version = read_buffer + p;
          /* Reset the whitespace marker */
          c->rq.hdrs.rq_line.last_ws_start = 0;
          c->rq.hdrs.rq_line.last_ws_end = 0;
        }
      }
    }

    /* Process the current character.
       Is it not the end of the line.  */
    if ((' ' == chr)
        || (('\t' == chr) && (tab_as_wsp))
        || ((other_wsp_as_wsp) && ((0xb == chr) || (0xc == chr))))
    {
      /* A whitespace character */
      if ((0 == c->rq.hdrs.rq_line.last_ws_end) ||
          (p != c->rq.hdrs.rq_line.last_ws_end) ||
          (! wsp_blocks))
      {
        /* Found first whitespace char of the new whitespace block */
        if (NULL == c->rq.method)
        {
          /* Found the end of the HTTP method string */
          mhd_assert (0 == c->rq.hdrs.rq_line.last_ws_start);
          mhd_assert (0 == c->rq.hdrs.rq_line.last_ws_end);
          mhd_assert (NULL == c->rq.hdrs.rq_line.rq_tgt);
          mhd_assert (0 == c->rq.req_target_len);
          mhd_assert (NULL == c->rq.version);
          if (0 == p)
          {
            mhd_STREAM_ABORT (c, mhd_CONN_CLOSE_CLIENT_HTTP_ERR_ABORT_CONN,
                              "The request line starts with a whitespace.");
            return true; /* Error in the request */
          }
          read_buffer[p] = 0; /* Zero-terminate the request method string */
          c->rq.method = read_buffer;
          parse_http_std_method (c, p, c->rq.method);
        }
        else
        {
          /* A whitespace after the start of the URI */
          if (! wsp_in_uri)
          {
            /* Whitespace in URI is not allowed to be parsed */
            if (NULL == c->rq.version)
            {
              mhd_assert (NULL != c->rq.hdrs.rq_line.rq_tgt);
              /* This is a delimiter between URI and HTTP version string */
              read_buffer[p] = 0; /* Zero-terminate request URI string */
              mhd_assert (((size_t) (c->rq.hdrs.rq_line.rq_tgt   \
                                     - read_buffer)) <= p);
              c->rq.req_target_len =
                p - (size_t) (c->rq.hdrs.rq_line.rq_tgt - read_buffer);
            }
            else
            {
              /* This is a delimiter AFTER version string */

              /* A quick simple check whether this line looks like an HTTP request */
              if ((mhd_HTTP_METHOD_GET <= c->rq.http_mthd) &&
                  (mhd_HTTP_METHOD_DELETE >= c->rq.http_mthd))
              {
                mhd_RESPOND_WITH_ERROR_STATIC (c,
                                               MHD_HTTP_STATUS_BAD_REQUEST,
                                               ERR_RSP_RQ_LINE_TOO_MANY_WSP);
              }
              else
                mhd_STREAM_ABORT (c, mhd_CONN_CLOSE_CLIENT_HTTP_ERR_ABORT_CONN,
                                  "The request line has more than "
                                  "two whitespaces.");
              return true; /* Error in the request */
            }
          }
          else
          {
            /* Whitespace in URI is allowed to be parsed */
            if (0 != c->rq.hdrs.rq_line.last_ws_end)
            {
              /* The whitespace after the start of the URI has been found already */
              c->rq.hdrs.rq_line.num_ws_in_uri +=
                c->rq.hdrs.rq_line.last_ws_end
                - c->rq.hdrs.rq_line.last_ws_start;
            }
          }
        }
        c->rq.hdrs.rq_line.last_ws_start = p;
        c->rq.hdrs.rq_line.last_ws_end = p + 1; /* Will be updated on the next char parsing */
      }
      else
      {
        /* Continuation of the whitespace block */
        mhd_assert (0 != c->rq.hdrs.rq_line.last_ws_end);
        mhd_assert (0 != p);
        c->rq.hdrs.rq_line.last_ws_end = p + 1;
      }
    }
    else
    {
      /* Non-whitespace char, not the end of the line */
      mhd_assert ((0 == c->rq.hdrs.rq_line.last_ws_end) || \
                  (c->rq.hdrs.rq_line.last_ws_end == p) || \
                  wsp_in_uri);

      if ((p == c->rq.hdrs.rq_line.last_ws_end) &&
          (0 != c->rq.hdrs.rq_line.last_ws_end) &&
          (wsp_blocks))
      {
        /* The end of the whitespace block */
        if (NULL == c->rq.hdrs.rq_line.rq_tgt)
        {
          /* This is the first character of the URI */
          mhd_assert (0 == c->rq.req_target_len);
          mhd_assert (NULL == c->rq.version);
          c->rq.hdrs.rq_line.rq_tgt = read_buffer + p;
          /* Reset the whitespace marker */
          c->rq.hdrs.rq_line.last_ws_start = 0;
          c->rq.hdrs.rq_line.last_ws_end = 0;
        }
        else
        {
          if (! wsp_in_uri)
          {
            /* This is the first character of the HTTP version */
            mhd_assert (NULL != c->rq.hdrs.rq_line.rq_tgt);
            mhd_assert ((0 != c->rq.req_target_len) || \
                        (c->rq.hdrs.rq_line.rq_tgt + 1 == read_buffer + p));
            mhd_assert (NULL == c->rq.version); /* Handled at whitespace start */
            c->rq.version = read_buffer + p;
            /* Reset the whitespace marker */
            c->rq.hdrs.rq_line.last_ws_start = 0;
            c->rq.hdrs.rq_line.last_ws_end = 0;
          }
        }
      }

      /* Handle other special characters */
      if ('?' == chr)
      {
        if ((NULL == c->rq.hdrs.rq_line.rq_tgt_qmark) &&
            (NULL != c->rq.hdrs.rq_line.rq_tgt))
        {
          c->rq.hdrs.rq_line.rq_tgt_qmark = read_buffer + p;
        }
      }
      else if ((0xb == chr) || (0xc == chr))
      {
        /* VT or LF characters */
        mhd_assert (! other_wsp_as_wsp);
        if ((NULL != c->rq.hdrs.rq_line.rq_tgt) &&
            (NULL == c->rq.version) &&
            (wsp_in_uri))
        {
          c->rq.hdrs.rq_line.num_ws_in_uri++;
        }
        else
        {
          mhd_STREAM_ABORT (c, mhd_CONN_CLOSE_CLIENT_HTTP_ERR_ABORT_CONN,
                            "Invalid character is in the request line.");
          return true; /* Error in the request */
        }
      }
      else if (0 == chr)
      {
        /* NUL character */
        mhd_STREAM_ABORT (c, mhd_CONN_CLOSE_CLIENT_HTTP_ERR_ABORT_CONN,
                          "The NUL character is in the request line.");
        return true; /* Error in the request */
      }
    }

    p++;
  }

  c->rq.hdrs.rq_line.proc_pos = p;
  return false; /* Not enough data yet */
}


/**
 * Callback for iterating over GET parameters
 * @param cls the iterator metadata
 * @param name the name of the parameter
 * @param value the value of the parameter
 * @return bool to continue iterations,
 *         false to stop the iteration
 */
static MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_NONNULL_ (3) bool
request_add_get_arg (void *restrict cls,
                     const struct MHD_String *restrict name,
                     const struct MHD_StringNullable *restrict value)
{
  struct MHD_Connection *c = (struct MHD_Connection *) cls;

  return mhd_stream_add_field_nullable (c, MHD_VK_GET_ARGUMENT, name, value);
}


MHD_INTERNAL
MHD_FN_PAR_NONNULL_ (2) MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_INOUT_ (2) bool
// TODO: detect and report errors
mhd_parse_get_args (size_t args_len,
                    char *restrict args,
                    mhd_GetArgumentInter cb,
                    void *restrict cls)
{
  size_t i;

  mhd_assert (args_len < (size_t) (args_len + 1)); /* Does not work when args_len == SIZE_MAX */

  for (i = 0; i < args_len; ++i) /* Looking for names of the parameters */
  {
    size_t name_start;
    size_t name_len;
    size_t value_start;
    size_t value_len;
    struct MHD_String name;
    struct MHD_StringNullable value;

    /* Found start of the name */

    value_start = 0;
    for (name_start = i; i < args_len; ++i) /* Processing parameter */
    {
      if ('+' == args[i])
        args[i] = ' ';
      else if ('=' == args[i])
      {
        /* Found start of the value */
        args[i] = 0; /* zero-terminate the name */
        for (value_start = ++i; i < args_len; ++i) /* Processing parameter value */
        {
          if ('+' == args[i])
            args[i] = ' ';
          else if ('&' == args[i]) /* delimiter for the next parameter */
            break; /* Next parameter */
        }
        break; /* End of the current parameter */
      }
      else if ('&' == args[i])
        break; /* End of the name of the parameter without a value */
    }
    if (i < args_len) /* Zero-terminate if not terminated */
      args[i] = 0;
    mhd_assert (0 == args[i]);

    /* Store found parameter */

    if (0 != value_start) /* Value cannot start at zero position */
    { /* Name with value */
      mhd_assert (name_start + 2 <= value_start);
      name_len = value_start - name_start - 1;

      value_len =
        mhd_str_pct_decode_lenient_n (args + value_start, i - value_start,
                                      args + value_start, i - value_start,
                                      NULL); // TODO: add support for broken encoding detection
      value.cstr = args + value_start;
      value.len = value_len;
    }
    else
    { /* Name without value */
      name_len = i - name_start;

      value.cstr = NULL;
      value.len = 0;
    }
    name_len = mhd_str_pct_decode_lenient_n (args + name_start, name_len,
                                             args + name_start, name_len,
                                             NULL); // TODO: add support for broken encoding detection
    name.cstr = args + name_start;
    name.len = name_len;
    if (! cb (cls, &name, &value))
      return false;
  }
  return true;
}


/**
 * Process request-target string, form URI and URI parameters
 * @param c the connection to process
 * @return true if request-target successfully processed,
 *         false if error encountered
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
process_request_target (struct MHD_Connection *c)
{
  size_t params_len;

  mhd_assert (MHD_CONNECTION_REQ_LINE_RECEIVING == c->state);
  mhd_assert (NULL == c->rq.url);
  mhd_assert (0 == c->rq.url_len);
  mhd_assert (NULL != c->rq.hdrs.rq_line.rq_tgt);
  mhd_assert ((NULL == c->rq.hdrs.rq_line.rq_tgt_qmark) || \
              (c->rq.hdrs.rq_line.rq_tgt <= c->rq.hdrs.rq_line.rq_tgt_qmark));
  mhd_assert ((NULL == c->rq.hdrs.rq_line.rq_tgt_qmark) || \
              (c->rq.req_target_len > \
               (size_t) (c->rq.hdrs.rq_line.rq_tgt_qmark \
                         - c->rq.hdrs.rq_line.rq_tgt)));

  /* Log callback before the request-target is modified/decoded */
  if (NULL != c->daemon->req_cfg.uri_cb.cb)
  {
    struct MHD_String full_uri;
    struct MHD_EarlyUriCbData req_data;
    full_uri.cstr = c->rq.hdrs.rq_line.rq_tgt;
    full_uri.len = c->rq.req_target_len;
    req_data.request = &(c->rq);
    req_data.request_app_context = NULL;
    c->rq.app_aware = true;
    c->daemon->req_cfg.uri_cb.cb (c->daemon->req_cfg.uri_cb.cls,
                                  &full_uri,
                                  &req_data);
    c->rq.app_context = req_data.request_app_context;
  }

  if (NULL != c->rq.hdrs.rq_line.rq_tgt_qmark)
  {
    params_len =
      c->rq.req_target_len
      - (size_t) (c->rq.hdrs.rq_line.rq_tgt_qmark - c->rq.hdrs.rq_line.rq_tgt);

    mhd_assert (1 <= params_len);

    c->rq.hdrs.rq_line.rq_tgt_qmark[0] = 0; /* Replace '?' with zero termination */

    // TODO: support detection of decoding errors
    if (! mhd_parse_get_args (params_len - 1,
                              c->rq.hdrs.rq_line.rq_tgt_qmark + 1,
                              &request_add_get_arg,
                              c))
    {
      mhd_LOG_MSG (c->daemon, MHD_SC_CONNECTION_POOL_NO_MEM_GET_PARAM,
                   "Not enough memory in the pool to store GET parameter");

      mhd_RESPOND_WITH_ERROR_STATIC (
        c,
        mhd_stream_get_no_space_err_status_code (c,
                                                 MHD_PROC_RECV_URI,
                                                 0,
                                                 NULL),
        ERR_RSP_MSG_REQUEST_TOO_BIG);
      mhd_assert (MHD_CONNECTION_REQ_LINE_RECEIVING != c->state);
      return false;

    }
  }
  else
    params_len = 0;

  mhd_assert (strlen (c->rq.hdrs.rq_line.rq_tgt) == \
              c->rq.req_target_len - params_len);

  /* Finally unescape URI itself */
  // TODO: support detection of decoding errors
  c->rq.url_len =
    mhd_str_pct_decode_lenient_n (c->rq.hdrs.rq_line.rq_tgt,
                                  c->rq.req_target_len - params_len,
                                  c->rq.hdrs.rq_line.rq_tgt,
                                  c->rq.req_target_len - params_len,
                                  NULL);
  c->rq.url = c->rq.hdrs.rq_line.rq_tgt;

  return true;
}


#ifndef MHD_MAX_FIXED_URI_LEN
/**
 * The maximum size of the fixed URI for automatic redirection
 */
#define MHD_MAX_FIXED_URI_LEN (64 * 1024)
#endif /* ! MHD_MAX_FIXED_URI_LEN */

/**
 * Send the automatic redirection to fixed URI when received URI with
 * whitespaces.
 * If URI is too large, close connection with error.
 *
 * @param c the connection to process
 */
static void
send_redirect_fixed_rq_target (struct MHD_Connection *restrict c)
{
  static const char hdr_prefix[] = MHD_HTTP_HEADER_LOCATION ": ";
  static const size_t hdr_prefix_len =
    mhd_SSTR_LEN (MHD_HTTP_HEADER_LOCATION ": ");
  char *hdr_line;
  char *b;
  size_t fixed_uri_len;
  size_t i;
  size_t o;

  mhd_assert (MHD_CONNECTION_REQ_LINE_RECEIVING == c->state);
  mhd_assert (0 != c->rq.hdrs.rq_line.num_ws_in_uri);
  mhd_assert (c->rq.hdrs.rq_line.num_ws_in_uri <= \
              c->rq.req_target_len);
  fixed_uri_len = c->rq.req_target_len
                  + 2 * c->rq.hdrs.rq_line.num_ws_in_uri;
  if ( (fixed_uri_len + 200 > c->daemon->conns.cfg.mem_pool_size) ||
       (fixed_uri_len > MHD_MAX_FIXED_URI_LEN) ||
       (NULL == (hdr_line = malloc (fixed_uri_len + 1 + hdr_prefix_len))) )
  {
    mhd_STREAM_ABORT (c, mhd_CONN_CLOSE_CLIENT_HTTP_ERR_ABORT_CONN, \
                      "The request has whitespace character is " \
                      "in the URI and the URI is too large to " \
                      "send automatic redirect to fixed URI.");
    return;
  }
  memcpy (hdr_line, hdr_prefix, hdr_prefix_len);
  b = hdr_line + hdr_prefix_len;
  i = 0;
  o = 0;

  do
  {
    const char chr = c->rq.hdrs.rq_line.rq_tgt[i++];

    mhd_assert ('\r' != chr); /* Replaced during request line parsing */
    mhd_assert ('\n' != chr); /* Rejected during request line parsing */
    mhd_assert (0 != chr); /* Rejected during request line parsing */
    switch (chr)
    {
    case ' ':
      b[o++] = '%';
      b[o++] = '2';
      b[o++] = '0';
      break;
    case '\t':
      b[o++] = '%';
      b[o++] = '0';
      b[o++] = '9';
      break;
    case 0x0B:   /* VT (vertical tab) */
      b[o++] = '%';
      b[o++] = '0';
      b[o++] = 'B';
      break;
    case 0x0C:   /* FF (form feed) */
      b[o++] = '%';
      b[o++] = '0';
      b[o++] = 'C';
      break;
    default:
      b[o++] = chr;
      break;
    }
  } while (i < c->rq.req_target_len);
  mhd_assert (fixed_uri_len == o);
  b[o] = 0; /* Zero-terminate the result */

  mhd_RESPOND_WITH_ERROR_HEADER (c,
                                 MHD_HTTP_STATUS_MOVED_PERMANENTLY,
                                 ERR_RSP_RQ_TARGET_INVALID_CHAR,
                                 o + hdr_prefix_len,
                                 hdr_line);

  return;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_stream_get_request_line (struct MHD_Connection *restrict c)
{
  const int discp_lvl = c->daemon->req_cfg.strictnees;
  /* Parse whitespace in URI, special parsing of the request line */
  const bool wsp_in_uri = (0 >= discp_lvl);
  /* Keep whitespace in URI, give app URI with whitespace instead of
     automatic redirect to fixed URI */
  const bool wsp_in_uri_keep = (-2 >= discp_lvl);

  if (! get_request_line_inner (c))
  {
    /* End of the request line has not been found yet */
    mhd_assert ((! wsp_in_uri) || NULL == c->rq.version);
    if ((NULL != c->rq.version) &&
        (HTTP_VER_LEN <
         (c->rq.hdrs.rq_line.proc_pos
          - (size_t) (c->rq.version - c->read_buffer))))
    {
      c->rq.http_ver = MHD_HTTP_VERSION_INVALID;
      mhd_RESPOND_WITH_ERROR_STATIC (c,
                                     MHD_HTTP_STATUS_BAD_REQUEST,
                                     ERR_RSP_REQUEST_MALFORMED);
      return true; /* Error in the request */
    }
    return false;
  }
  if (MHD_CONNECTION_REQ_LINE_RECEIVING < c->state)
    return true; /* Error in the request */

  mhd_assert (MHD_CONNECTION_REQ_LINE_RECEIVING == c->state);
  mhd_assert (NULL == c->rq.url);
  mhd_assert (0 == c->rq.url_len);
  mhd_assert (NULL != c->rq.hdrs.rq_line.rq_tgt);
  if (0 != c->rq.hdrs.rq_line.num_ws_in_uri)
  {
    if (! wsp_in_uri)
    {
      mhd_RESPOND_WITH_ERROR_STATIC (c,
                                     MHD_HTTP_STATUS_BAD_REQUEST,
                                     ERR_RSP_RQ_TARGET_INVALID_CHAR);
      return true; /* Error in the request */
    }
    if (! wsp_in_uri_keep)
    {
      send_redirect_fixed_rq_target (c);
      return true; /* Error in the request */
    }
  }
  if (! process_request_target (c))
    return true; /* Error in processing */

  c->state = MHD_CONNECTION_REQ_LINE_RECEIVED;
  return true;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_stream_switch_to_rq_headers_proc (struct MHD_Connection *restrict c)
{
  c->rq.field_lines.start = c->read_buffer;
  mhd_stream_reset_rq_hdr_proc_state (c);
  c->state = MHD_CONNECTION_REQ_HEADERS_RECEIVING;
}


/**
 * Send error reply when receive buffer space exhausted while receiving or
 * storing the request headers
 * @param c the connection to handle
 * @param add_header the optional pointer to the current header string being
 *                   processed or the header failed to be added.
 *                   Could be not zero-terminated and can contain binary zeros.
 *                   Can be NULL.
 * @param add_header_size the size of the @a add_header
 */
MHD_static_inline_
MHD_FN_PAR_NONNULL_ (1) void
handle_req_headers_no_space (struct MHD_Connection *restrict c,
                             const char *restrict add_header,
                             size_t add_header_size)
{
  unsigned int err_code;

  err_code = mhd_stream_get_no_space_err_status_code (c,
                                                      MHD_PROC_RECV_HEADERS,
                                                      add_header_size,
                                                      add_header);
  mhd_RESPOND_WITH_ERROR_STATIC (c,
                                 err_code,
                                 ERR_RSP_REQUEST_HEADER_TOO_BIG);
}


/**
 * Send error reply when receive buffer space exhausted while receiving or
 * storing the request footers (for chunked requests).
 * @param c the connection to handle
 * @param add_footer the optional pointer to the current footer string being
 *                   processed or the footer failed to be added.
 *                   Could be not zero-terminated and can contain binary zeros.
 *                   Can be NULL.
 * @param add_footer_size the size of the @a add_footer
 */
MHD_static_inline_
MHD_FN_PAR_NONNULL_ (1) void
handle_req_footers_no_space (struct MHD_Connection *restrict c,
                             const char *restrict add_footer,
                             size_t add_footer_size)
{
  (void) add_footer; (void) add_footer_size; /* Unused */
  mhd_assert (c->rq.have_chunked_upload);

  /* Footers should be optional */
  mhd_RESPOND_WITH_ERROR_STATIC (
    c,
    MHD_HTTP_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE,
    ERR_RSP_REQUEST_FOOTER_TOO_BIG);
}


/**
 * Results of header line reading
 */
enum MHD_FIXED_ENUM_ mhd_HdrLineReadRes
{
  /**
   * Not enough data yet
   */
  MHD_HDR_LINE_READING_NEED_MORE_DATA = 0,
  /**
   * New header line has been read
   */
  MHD_HDR_LINE_READING_GOT_HEADER,
  /**
   * Error in header data, error response has been queued
   */
  MHD_HDR_LINE_READING_DATA_ERROR,
  /**
   * Found the end of the request header (end of field lines)
   */
  MHD_HDR_LINE_READING_GOT_END_OF_HEADER
};


/**
 * Find the end of the request header line and make basic header parsing.
 * Handle errors and header folding.
 * @param c the connection to process
 * @param process_footers if true then footers are processed,
 *                        if false then headers are processed
 * @param[out] hdr_name the name of the parsed header (field)
 * @param[out] hdr_name the value of the parsed header (field)
 * @return mhd_HdrLineReadRes value
 */
static enum mhd_HdrLineReadRes
get_req_header (struct MHD_Connection *restrict c,
                bool process_footers,
                struct MHD_String *restrict hdr_name,
                struct MHD_String *restrict hdr_value)
{
  const int discp_lvl = c->daemon->req_cfg.strictnees;
  /* Treat bare LF as the end of the line.
     RFC 9112, section 2.2-3
     Note: MHD never replaces bare LF with space (RFC 9110, section 5.5-5).
     Bare LF is processed as end of the line or rejected as broken request. */
  const bool bare_lf_as_crlf = MHD_ALLOW_BARE_LF_AS_CRLF_ (discp_lvl);
  /* Keep bare CR character as is.
     Violates RFC 9112, section 2.2-4 */
  const bool bare_cr_keep = (-3 >= discp_lvl);
  /* Treat bare CR as space; replace it with space before processing.
     RFC 9112, section 2.2-4 */
  const bool bare_cr_as_sp = ((! bare_cr_keep) && (-1 >= discp_lvl));
  /* Treat NUL as space; replace it with space before processing.
     RFC 9110, section 5.5-5 */
  const bool nul_as_sp = (-1 >= discp_lvl);
  /* Allow folded header lines.
     RFC 9112, section 5.2-4 */
  const bool allow_folded = (0 >= discp_lvl);
  /* Do not reject headers with the whitespace at the start of the first line.
     When allowed, the first line with whitespace character at the first
     position is ignored (as well as all possible line foldings of the first
     line).
     RFC 9112, section 2.2-8 */
  const bool allow_wsp_at_start = allow_folded && (-1 >= discp_lvl);
  /* Allow whitespace in header (field) name.
     Violates RFC 9110, section 5.1-2 */
  const bool allow_wsp_in_name = (-2 >= discp_lvl);
  /* Allow zero-length header (field) name.
     Violates RFC 9110, section 5.1-2 */
  const bool allow_empty_name = (-2 >= discp_lvl);
  /* Allow whitespace before colon.
     Violates RFC 9112, section 5.1-2 */
  const bool allow_wsp_before_colon = (-3 >= discp_lvl);
  /* Do not abort the request when header line has no colon, just skip such
     bad lines.
     RFC 9112, section 5-1 */
  const bool allow_line_without_colon = (-2 >= discp_lvl);

  size_t p; /**< The position of the currently processed character */

  (void) process_footers; /* Unused parameter in non-debug and no messages */

  mhd_assert ((process_footers ? MHD_CONNECTION_FOOTERS_RECEIVING : \
               MHD_CONNECTION_REQ_HEADERS_RECEIVING) == \
              c->state);

  p = c->rq.hdrs.hdr.proc_pos;

  mhd_assert (p <= c->read_buffer_offset);
  while (p < c->read_buffer_offset)
  {
    char *const restrict read_buffer = c->read_buffer;
    const char chr = read_buffer[p];
    bool end_of_line;

    mhd_assert ((0 == c->rq.hdrs.hdr.name_len) || \
                (c->rq.hdrs.hdr.name_len < p));
    mhd_assert ((0 == c->rq.hdrs.hdr.name_len) || (0 != p));
    mhd_assert ((0 == c->rq.hdrs.hdr.name_len) || \
                (c->rq.hdrs.hdr.name_end_found));
    mhd_assert ((0 == c->rq.hdrs.hdr.value_start) || \
                (c->rq.hdrs.hdr.name_len < c->rq.hdrs.hdr.value_start));
    mhd_assert ((0 == c->rq.hdrs.hdr.value_start) || \
                (0 != c->rq.hdrs.hdr.name_len));
    mhd_assert ((0 == c->rq.hdrs.hdr.ws_start) || \
                (0 == c->rq.hdrs.hdr.name_len) || \
                (c->rq.hdrs.hdr.ws_start > c->rq.hdrs.hdr.name_len));
    mhd_assert ((0 == c->rq.hdrs.hdr.ws_start) || \
                (0 == c->rq.hdrs.hdr.value_start) || \
                (c->rq.hdrs.hdr.ws_start > c->rq.hdrs.hdr.value_start));

    /* Check for the end of the line */
    if ('\r' == chr)
    {
      if (0 != p)
      {
        /* Line is not empty, need to check for possible line folding */
        if (p + 2 >= c->read_buffer_offset)
          break; /* Not enough data yet to check for folded line */
      }
      else
      {
        /* Line is empty, no need to check for possible line folding */
        if (p + 2 > c->read_buffer_offset)
          break; /* Not enough data yet to check for the end of the line */
      }
      if ('\n' == read_buffer[p + 1])
        end_of_line = true;
      else
      {
        /* Bare CR alone */
        /* Must be rejected or replaced with space char.
           See RFC 9112, section 2.2-4 */
        if (bare_cr_as_sp)
        {
          read_buffer[p] = ' ';
          c->rq.num_cr_sp_replaced++;
          continue; /* Re-start processing of the current character */
        }
        else if (! bare_cr_keep)
        {
          if (! process_footers)
            mhd_RESPOND_WITH_ERROR_STATIC (c,
                                           MHD_HTTP_STATUS_BAD_REQUEST,
                                           ERR_RSP_BARE_CR_IN_HEADER);
          else
            mhd_RESPOND_WITH_ERROR_STATIC (c,
                                           MHD_HTTP_STATUS_BAD_REQUEST,
                                           ERR_RSP_BARE_CR_IN_FOOTER);
          return MHD_HDR_LINE_READING_DATA_ERROR; /* Error in the request */
        }
        end_of_line = false;
      }
    }
    else if ('\n' == chr)
    {
      /* Bare LF may be recognised as a line delimiter.
         See RFC 9112, section 2.2-3 */
      if (bare_lf_as_crlf)
      {
        if (0 != p)
        {
          /* Line is not empty, need to check for possible line folding */
          if (p + 1 >= c->read_buffer_offset)
            break; /* Not enough data yet to check for folded line */
        }
        end_of_line = true;
      }
      else
      {
        if (! process_footers)
          mhd_RESPOND_WITH_ERROR_STATIC (c,
                                         MHD_HTTP_STATUS_BAD_REQUEST,
                                         ERR_RSP_BARE_LF_IN_HEADER);
        else
          mhd_RESPOND_WITH_ERROR_STATIC (c,
                                         MHD_HTTP_STATUS_BAD_REQUEST,
                                         ERR_RSP_BARE_LF_IN_FOOTER);
        return MHD_HDR_LINE_READING_DATA_ERROR; /* Error in the request */
      }
    }
    else
      end_of_line = false;

    if (end_of_line)
    {
      /* Handle the end of the line */
      /**
       *  The full length of the line, including CRLF (or bare LF).
       */
      const size_t line_len = p + (('\r' == chr) ? 2 : 1);
      char next_line_char;
      mhd_assert (line_len <= c->read_buffer_offset);

      if (0 == p)
      {
        /* Zero-length header line. This is the end of the request header
           section.
           RFC 9112, Section 2.1-1 */
        mhd_assert (! c->rq.hdrs.hdr.starts_with_ws);
        mhd_assert (! c->rq.hdrs.hdr.name_end_found);
        mhd_assert (0 == c->rq.hdrs.hdr.name_len);
        mhd_assert (0 == c->rq.hdrs.hdr.ws_start);
        mhd_assert (0 == c->rq.hdrs.hdr.value_start);
        /* Consume the line with CRLF (or bare LF) */
        c->read_buffer += line_len;
        c->read_buffer_offset -= line_len;
        c->read_buffer_size -= line_len;
        return MHD_HDR_LINE_READING_GOT_END_OF_HEADER;
      }

      mhd_assert (line_len < c->read_buffer_offset);
      mhd_assert (0 != line_len);
      mhd_assert ('\n' == read_buffer[line_len - 1]);
      next_line_char = read_buffer[line_len];
      if ((' ' == next_line_char) ||
          ('\t' == next_line_char))
      {
        /* Folded line */
        if (! allow_folded)
        {
          if (! process_footers)
            mhd_RESPOND_WITH_ERROR_STATIC (c,
                                           MHD_HTTP_STATUS_BAD_REQUEST,
                                           ERR_RSP_OBS_FOLD);
          else
            mhd_RESPOND_WITH_ERROR_STATIC (c,
                                           MHD_HTTP_STATUS_BAD_REQUEST,
                                           ERR_RSP_OBS_FOLD_FOOTER);

          return MHD_HDR_LINE_READING_DATA_ERROR; /* Error in the request */
        }
        /* Replace CRLF (or bare LF) character(s) with space characters.
           See RFC 9112, Section 5.2-4 */
        read_buffer[p] = ' ';
        if ('\r' == chr)
          read_buffer[p + 1] = ' ';
        continue; /* Re-start processing of the current character */
      }
      else
      {
        /* It is not a folded line, it's the real end of the non-empty line */
        bool skip_line = false;
        mhd_assert (0 != p);
        if (c->rq.hdrs.hdr.starts_with_ws)
        {
          /* This is the first line and it starts with whitespace. This line
             must be discarded completely.
             See RFC 9112, Section 2.2-8 */
          mhd_assert (allow_wsp_at_start);

          mhd_LOG_MSG (c->daemon, MHD_SC_REQ_FIRST_HEADER_LINE_SPACE_PREFIXED,
                       "Whitespace-prefixed first header line " \
                       "has been skipped.");
          skip_line = true;
        }
        else if (! c->rq.hdrs.hdr.name_end_found)
        {
          if (! allow_line_without_colon)
          {
            if (! process_footers)
              mhd_RESPOND_WITH_ERROR_STATIC (c,
                                             MHD_HTTP_STATUS_BAD_REQUEST,
                                             ERR_RSP_HEADER_WITHOUT_COLON);
            else
              mhd_RESPOND_WITH_ERROR_STATIC (c,
                                             MHD_HTTP_STATUS_BAD_REQUEST,
                                             ERR_RSP_FOOTER_WITHOUT_COLON);

            return MHD_HDR_LINE_READING_DATA_ERROR; /* Error in the request */
          }
          /* Skip broken line completely */
          c->rq.skipped_broken_lines++;
          skip_line = true;
        }
        if (skip_line)
        {
          /* Skip the entire line */
          c->read_buffer += line_len;
          c->read_buffer_offset -= line_len;
          c->read_buffer_size -= line_len;
          p = 0;
          /* Reset processing state */
          memset (&c->rq.hdrs.hdr, 0, sizeof(c->rq.hdrs.hdr));
          /* Start processing of the next line */
          continue;
        }
        else
        {
          /* This line should be valid header line */
          size_t value_len;
          mhd_assert ((0 != c->rq.hdrs.hdr.name_len) || allow_empty_name);

          hdr_name->cstr = read_buffer + 0; /* The name always starts at the first character */
          hdr_name->len = c->rq.hdrs.hdr.name_len;
          mhd_assert (0 == hdr_name->cstr[hdr_name->len]);

          if (0 == c->rq.hdrs.hdr.value_start)
          {
            c->rq.hdrs.hdr.value_start = p;
            read_buffer[p] = 0;
            value_len = 0;
          }
          else if (0 != c->rq.hdrs.hdr.ws_start)
          {
            mhd_assert (p > c->rq.hdrs.hdr.ws_start);
            mhd_assert (c->rq.hdrs.hdr.ws_start > c->rq.hdrs.hdr.value_start);
            read_buffer[c->rq.hdrs.hdr.ws_start] = 0;
            value_len = c->rq.hdrs.hdr.ws_start - c->rq.hdrs.hdr.value_start;
          }
          else
          {
            mhd_assert (p > c->rq.hdrs.hdr.ws_start);
            read_buffer[p] = 0;
            value_len = p - c->rq.hdrs.hdr.value_start;
          }
          hdr_value->cstr = read_buffer + c->rq.hdrs.hdr.value_start;
          hdr_value->len = value_len;
          mhd_assert (0 == hdr_value->cstr[hdr_value->len]);
          /* Consume the entire line */
          c->read_buffer += line_len;
          c->read_buffer_offset -= line_len;
          c->read_buffer_size -= line_len;
          return MHD_HDR_LINE_READING_GOT_HEADER;
        }
      }
    }
    else if ((' ' == chr) || ('\t' == chr))
    {
      if (0 == p)
      {
        if (! allow_wsp_at_start)
        {
          if (! process_footers)
            mhd_RESPOND_WITH_ERROR_STATIC (c,
                                           MHD_HTTP_STATUS_BAD_REQUEST,
                                           ERR_RSP_WSP_BEFORE_HEADER);
          else
            mhd_RESPOND_WITH_ERROR_STATIC (c,
                                           MHD_HTTP_STATUS_BAD_REQUEST,
                                           ERR_RSP_WSP_BEFORE_FOOTER);
          return MHD_HDR_LINE_READING_DATA_ERROR; /* Error in the request */
        }
        c->rq.hdrs.hdr.starts_with_ws = true;
      }
      else if ((! c->rq.hdrs.hdr.name_end_found) &&
               (! c->rq.hdrs.hdr.starts_with_ws))
      {
        /* Whitespace in header name / between header name and colon */
        if (allow_wsp_in_name || allow_wsp_before_colon)
        {
          if (0 == c->rq.hdrs.hdr.ws_start)
            c->rq.hdrs.hdr.ws_start = p;
        }
        else
        {
          if (! process_footers)
            mhd_RESPOND_WITH_ERROR_STATIC (c,
                                           MHD_HTTP_STATUS_BAD_REQUEST,
                                           ERR_RSP_WSP_IN_HEADER_NAME);
          else
            mhd_RESPOND_WITH_ERROR_STATIC (c,
                                           MHD_HTTP_STATUS_BAD_REQUEST,
                                           ERR_RSP_WSP_IN_FOOTER_NAME);

          return MHD_HDR_LINE_READING_DATA_ERROR; /* Error in the request */
        }
      }
      else
      {
        /* Whitespace before/inside/after header (field) value */
        if (0 == c->rq.hdrs.hdr.ws_start)
          c->rq.hdrs.hdr.ws_start = p;
      }
    }
    else if (0 == chr)
    {
      if (! nul_as_sp)
      {
        if (! process_footers)
          mhd_RESPOND_WITH_ERROR_STATIC (c,
                                         MHD_HTTP_STATUS_BAD_REQUEST,
                                         ERR_RSP_INVALID_CHR_IN_HEADER);
        else
          mhd_RESPOND_WITH_ERROR_STATIC (c,
                                         MHD_HTTP_STATUS_BAD_REQUEST,
                                         ERR_RSP_INVALID_CHR_IN_FOOTER);

        return MHD_HDR_LINE_READING_DATA_ERROR; /* Error in the request */
      }
      read_buffer[p] = ' ';
      continue; /* Re-start processing of the current character */
    }
    else
    {
      /* Not a whitespace, not the end of the header line */
      mhd_assert ('\r' != chr);
      mhd_assert ('\n' != chr);
      mhd_assert ('\0' != chr);
      if ((! c->rq.hdrs.hdr.name_end_found) &&
          (! c->rq.hdrs.hdr.starts_with_ws))
      {
        /* Processing the header (field) name */
        if (':' == chr)
        {
          if (0 == c->rq.hdrs.hdr.ws_start)
            c->rq.hdrs.hdr.name_len = p;
          else
          {
            mhd_assert (allow_wsp_in_name || allow_wsp_before_colon);
            if (! allow_wsp_before_colon)
            {
              if (! process_footers)
                mhd_RESPOND_WITH_ERROR_STATIC (c,
                                               MHD_HTTP_STATUS_BAD_REQUEST,
                                               ERR_RSP_WSP_IN_HEADER_NAME);
              else
                mhd_RESPOND_WITH_ERROR_STATIC (c,
                                               MHD_HTTP_STATUS_BAD_REQUEST,
                                               ERR_RSP_WSP_IN_FOOTER_NAME);
              return MHD_HDR_LINE_READING_DATA_ERROR; /* Error in the request */
            }
            c->rq.hdrs.hdr.name_len = c->rq.hdrs.hdr.ws_start;
#ifndef MHD_FAVOR_SMALL_CODE
            c->rq.hdrs.hdr.ws_start = 0; /* Not on whitespace anymore */
#endif /* ! MHD_FAVOR_SMALL_CODE */
          }
          if ((0 == c->rq.hdrs.hdr.name_len) && ! allow_empty_name)
          {
            if (! process_footers)
              mhd_RESPOND_WITH_ERROR_STATIC (c,
                                             MHD_HTTP_STATUS_BAD_REQUEST,
                                             ERR_RSP_EMPTY_HEADER_NAME);
            else
              mhd_RESPOND_WITH_ERROR_STATIC (c,
                                             MHD_HTTP_STATUS_BAD_REQUEST,
                                             ERR_RSP_EMPTY_FOOTER_NAME);
            return MHD_HDR_LINE_READING_DATA_ERROR; /* Error in the request */
          }
          c->rq.hdrs.hdr.name_end_found = true;
          read_buffer[c->rq.hdrs.hdr.name_len] = 0; /* Zero-terminate the name */
        }
        else
        {
          if (0 != c->rq.hdrs.hdr.ws_start)
          {
            /* End of the whitespace in header (field) name */
            mhd_assert (allow_wsp_in_name || allow_wsp_before_colon);
            if (! allow_wsp_in_name)
            {
              if (! process_footers)
                mhd_RESPOND_WITH_ERROR_STATIC (c,
                                               MHD_HTTP_STATUS_BAD_REQUEST,
                                               ERR_RSP_WSP_IN_HEADER_NAME);
              else
                mhd_RESPOND_WITH_ERROR_STATIC (c,
                                               MHD_HTTP_STATUS_BAD_REQUEST,
                                               ERR_RSP_WSP_IN_FOOTER_NAME);

              return MHD_HDR_LINE_READING_DATA_ERROR; /* Error in the request */
            }
#ifndef MHD_FAVOR_SMALL_CODE
            c->rq.hdrs.hdr.ws_start = 0; /* Not on whitespace anymore */
#endif /* ! MHD_FAVOR_SMALL_CODE */
          }
        }
      }
      else
      {
        /* Processing the header (field) value */
        if (0 == c->rq.hdrs.hdr.value_start)
          c->rq.hdrs.hdr.value_start = p;
#ifndef MHD_FAVOR_SMALL_CODE
        c->rq.hdrs.hdr.ws_start = 0; /* Not on whitespace anymore */
#endif /* ! MHD_FAVOR_SMALL_CODE */
      }
#ifdef MHD_FAVOR_SMALL_CODE
      c->rq.hdrs.hdr.ws_start = 0; /* Not on whitespace anymore */
#endif /* MHD_FAVOR_SMALL_CODE */
    }
    p++;
  }
  c->rq.hdrs.hdr.proc_pos = p;
  return MHD_HDR_LINE_READING_NEED_MORE_DATA; /* Not enough data yet */
}


/**
 * Reset request header processing state.
 *
 * This function resets the processing state before processing the next header
 * (or footer) line.
 * @param c the connection to process
 */
MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_stream_reset_rq_hdr_proc_state (struct MHD_Connection *c)
{
  memset (&c->rq.hdrs.hdr, 0, sizeof(c->rq.hdrs.hdr));
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_stream_get_request_headers (struct MHD_Connection *restrict c,
                                bool process_footers)
{
  do
  {
    struct MHD_String hdr_name;
    struct MHD_String hdr_value;
    enum mhd_HdrLineReadRes res;

    mhd_assert ((process_footers ? MHD_CONNECTION_FOOTERS_RECEIVING : \
                 MHD_CONNECTION_REQ_HEADERS_RECEIVING) == \
                c->state);

#ifndef NDEBUG
    hdr_name.cstr = NULL;
    hdr_value.cstr = NULL;
#endif /* ! NDEBUG */
    res = get_req_header (c, process_footers, &hdr_name, &hdr_value);
    if (MHD_HDR_LINE_READING_GOT_HEADER == res)
    {
      mhd_assert ((process_footers ? MHD_CONNECTION_FOOTERS_RECEIVING : \
                   MHD_CONNECTION_REQ_HEADERS_RECEIVING) == \
                  c->state);
      mhd_assert (NULL != hdr_name.cstr);
      mhd_assert (NULL != hdr_value.cstr);
      /* Values must be zero-terminated and must not have binary zeros */
      mhd_assert (strlen (hdr_name.cstr) == hdr_name.len);
      mhd_assert (strlen (hdr_value.cstr) == hdr_value.len);
      /* Values must not have whitespaces at the start or at the end */
      mhd_assert ((hdr_name.len == 0) || (hdr_name.cstr[0] != ' '));
      mhd_assert ((hdr_name.len == 0) || (hdr_name.cstr[0] != '\t'));
      mhd_assert ((hdr_name.len == 0) || \
                  (hdr_name.cstr[hdr_name.len - 1] != ' '));
      mhd_assert ((hdr_name.len == 0) || \
                  (hdr_name.cstr[hdr_name.len - 1] != '\t'));
      mhd_assert ((hdr_value.len == 0) || (hdr_value.cstr[0] != ' '));
      mhd_assert ((hdr_value.len == 0) || (hdr_value.cstr[0] != '\t'));
      mhd_assert ((hdr_value.len == 0) || \
                  (hdr_value.cstr[hdr_value.len - 1] != ' '));
      mhd_assert ((hdr_value.len == 0) || \
                  (hdr_value.cstr[hdr_value.len - 1] != '\t'));

      if (! mhd_stream_add_field (c,
                                  process_footers ?
                                  MHD_VK_FOOTER : MHD_VK_HEADER,
                                  &hdr_name,
                                  &hdr_value))
      {
        size_t add_element_size;

        mhd_assert (hdr_name.cstr < hdr_value.cstr);

        if (! process_footers)
          mhd_LOG_MSG (c->daemon, MHD_SC_CONNECTION_POOL_MALLOC_FAILURE_REQ, \
                       "Failed to allocate memory in the connection memory " \
                       "pool to store header.");
        else
          mhd_LOG_MSG (c->daemon, MHD_SC_CONNECTION_POOL_MALLOC_FAILURE_REQ, \
                       "Failed to allocate memory in the connection memory " \
                       "pool to store footer.");

        add_element_size = hdr_value.len
                           + (size_t) (hdr_value.cstr - hdr_name.cstr);

        if (! process_footers)
          handle_req_headers_no_space (c, hdr_name.cstr, add_element_size);
        else
          handle_req_footers_no_space (c, hdr_name.cstr, add_element_size);

        mhd_assert (MHD_CONNECTION_FULL_REQ_RECEIVED < c->state);
        return true;
      }
      /* Reset processing state */
      mhd_stream_reset_rq_hdr_proc_state (c);
      mhd_assert ((process_footers ? MHD_CONNECTION_FOOTERS_RECEIVING : \
                   MHD_CONNECTION_REQ_HEADERS_RECEIVING) == \
                  c->state);
      /* Read the next header (field) line */
      continue;
    }
    else if (MHD_HDR_LINE_READING_NEED_MORE_DATA == res)
    {
      mhd_assert ((process_footers ? MHD_CONNECTION_FOOTERS_RECEIVING : \
                   MHD_CONNECTION_REQ_HEADERS_RECEIVING) == \
                  c->state);
      return false;
    }
    else if (MHD_HDR_LINE_READING_DATA_ERROR == res)
    {
      mhd_assert ((process_footers ? \
                   MHD_CONNECTION_FOOTERS_RECEIVING : \
                   MHD_CONNECTION_REQ_HEADERS_RECEIVING) < c->state);
      mhd_assert (c->stop_with_error);
      mhd_assert (c->discard_request);
      return true;
    }
    mhd_assert (MHD_HDR_LINE_READING_GOT_END_OF_HEADER == res);
    break;
  } while (1);

  if (1 == c->rq.num_cr_sp_replaced)
  {
    if (! process_footers)
      mhd_LOG_MSG (c->daemon, MHD_SC_REQ_HEADER_CR_REPLACED, \
                   "One bare CR character has been replaced with space " \
                   "in the request line or in the request headers.");
    else
      mhd_LOG_MSG (c->daemon, MHD_SC_REQ_FOOTER_CR_REPLACED, \
                   "One bare CR character has been replaced with space " \
                   "in the request footers.");
  }
  else if (0 != c->rq.num_cr_sp_replaced)
  {
    if (! process_footers)
      mhd_LOG_PRINT (c->daemon, MHD_SC_REQ_HEADER_CR_REPLACED, \
                     mhd_LOG_FMT ("%" PRIuFAST64 " bare CR characters have " \
                                  "been replaced with spaces in the request " \
                                  "line and/or in the request headers."), \
                     (uint_fast64_t) c->rq.num_cr_sp_replaced);
    else
      mhd_LOG_PRINT (c->daemon, MHD_SC_REQ_HEADER_CR_REPLACED, \
                     mhd_LOG_FMT ("%" PRIuFAST64 " bare CR characters have " \
                                  "been replaced with spaces in the request " \
                                  "footers."), \
                     (uint_fast64_t) c->rq.num_cr_sp_replaced);


  }
  if (1 == c->rq.skipped_broken_lines)
  {
    if (! process_footers)
      mhd_LOG_MSG (c->daemon, MHD_SC_REQ_HEADER_LINE_NO_COLON, \
                   "One header line without colon has been skipped.");
    else
      mhd_LOG_MSG (c->daemon, MHD_SC_REQ_FOOTER_LINE_NO_COLON, \
                   "One footer line without colon has been skipped.");
  }
  else if (0 != c->rq.skipped_broken_lines)
  {
    if (! process_footers)
      mhd_LOG_PRINT (c->daemon, MHD_SC_REQ_HEADER_CR_REPLACED, \
                     mhd_LOG_FMT ("%" PRIu64 " header lines without colons "
                                  "have been skipped."),
                     (uint_fast64_t) c->rq.skipped_broken_lines);
    else
      mhd_LOG_PRINT (c->daemon, MHD_SC_REQ_HEADER_CR_REPLACED, \
                     mhd_LOG_FMT ("%" PRIu64 " footer lines without colons "
                                  "have been skipped."),
                     (uint_fast64_t) c->rq.skipped_broken_lines);
  }

  mhd_assert (c->rq.method < c->read_buffer);
  if (! process_footers)
  {
    c->rq.header_size = (size_t) (c->read_buffer - c->rq.method);
    mhd_assert (NULL != c->rq.field_lines.start);
    c->rq.field_lines.size =
      (size_t) ((c->read_buffer - c->rq.field_lines.start) - 1);
    if ('\r' == *(c->read_buffer - 2))
      c->rq.field_lines.size--;
    c->state = MHD_CONNECTION_HEADERS_RECEIVED;

    if (mhd_BUF_INC_SIZE > c->read_buffer_size)
    {
      /* Try to re-use some of the last bytes of the request header */
      /* Do this only if space in the read buffer is limited AND
         amount of read ahead data is small. */
      /**
       *  The position of the terminating NUL after the last character of
       *  the last header element.
       */
      const char *last_elmnt_end;
      size_t shift_back_size;
      struct mhd_RequestField *header;
      header = mhd_DLINKEDL_GET_LAST (&(c->rq), fields);
      if (NULL != header)
        last_elmnt_end =
          header->field.nv.value.cstr + header->field.nv.value.len;
      else
        last_elmnt_end = c->rq.version + HTTP_VER_LEN;
      mhd_assert ((last_elmnt_end + 1) < c->read_buffer);
      shift_back_size = (size_t) (c->read_buffer - (last_elmnt_end + 1));
      if (0 != c->read_buffer_offset)
        memmove (c->read_buffer - shift_back_size,
                 c->read_buffer,
                 c->read_buffer_offset);
      c->read_buffer -= shift_back_size;
      c->read_buffer_size += shift_back_size;
    }
  }
  else
    c->state = MHD_CONNECTION_FOOTERS_RECEIVED;

  return true;
}


#ifdef COOKIE_SUPPORT

/**
 * Cookie parsing result
 */
enum _MHD_ParseCookie
{
  MHD_PARSE_COOKIE_OK_LAX = 2        /**< Cookies parsed, but workarounds used */
  ,
  MHD_PARSE_COOKIE_OK = 1            /**< Success or no cookies in headers */
  ,
  MHD_PARSE_COOKIE_NO_MEMORY = 0     /**< Not enough memory in the pool */
  ,
  MHD_PARSE_COOKIE_MALFORMED = -1    /**< Invalid cookie header */
};


/**
 * Parse the cookies string (see RFC 6265).
 *
 * Try to parse the cookies string even if it is not strictly formed
 * as specified by RFC 6265.
 *
 * @param str the string to parse, without leading whitespaces
 * @param str_len the size of the @a str, not including mandatory
 *                zero-termination
 * @param connection the connection to add parsed cookies
 * @return #MHD_PARSE_COOKIE_OK for success, error code otherwise
 */
static MHD_FN_PAR_NONNULL_ALL_
MHD_FN_PAR_CSTR_ (2)
MHD_FN_PAR_INOUT_SIZE_ (2,1) enum _MHD_ParseCookie
parse_cookies_string (const size_t str_len,
                      char *restrict str,
                      struct MHD_Connection *restrict connection)
{
  size_t i;
  bool non_strict;
  /* Skip extra whitespaces and empty cookies */
  const bool allow_wsp_empty = (0 >= connection->daemon->req_cfg.strictnees);
  /* Allow whitespaces around '=' character */
  const bool wsp_around_eq = (-3 >= connection->daemon->req_cfg.strictnees);
  /* Allow whitespaces in quoted cookie value */
  const bool wsp_in_quoted = (-2 >= connection->daemon->req_cfg.strictnees);
  /* Allow tab as space after semicolon between cookies */
  const bool tab_as_sp = (0 >= connection->daemon->req_cfg.strictnees);
  /* Allow no space after semicolon between cookies */
  const bool allow_no_space = (0 >= connection->daemon->req_cfg.strictnees);

  non_strict = false;
  i = 0;
  while (i < str_len)
  {
    size_t name_start;
    size_t name_len;
    size_t value_start;
    size_t value_len;
    bool val_quoted;
    /* Skip any whitespaces and empty cookies */
    while (' ' == str[i] || '\t' == str[i] || ';' == str[i])
    {
      if (! allow_wsp_empty)
        return MHD_PARSE_COOKIE_MALFORMED;
      non_strict = true;
      i++;
      if (i == str_len)
        return non_strict? MHD_PARSE_COOKIE_OK_LAX : MHD_PARSE_COOKIE_OK;
    }
    /* 'i' must point to the first char of cookie-name */
    name_start = i;
    /* Find the end of the cookie-name */
    do
    {
      const char l = str[i];
      if (('=' == l) || (' ' == l) || ('\t' == l) || ('"' == l) || (',' == l) ||
          (';' == l) || (0 == l))
        break;
    } while (str_len > ++i);
    name_len = i - name_start;
    /* Skip any whitespaces */
    while (str_len > i && (' ' == str[i] || '\t' == str[i]))
    {
      if (! wsp_around_eq)
        return MHD_PARSE_COOKIE_MALFORMED;
      non_strict = true;
      i++;
    }
    if ((str_len == i) || ('=' != str[i]) || (0 == name_len))
      return MHD_PARSE_COOKIE_MALFORMED; /* Incomplete cookie name */
    /* 'i' must point to the '=' char */
    mhd_assert ('=' == str[i]);
    i++;
    /* Skip any whitespaces */
    while (str_len > i && (' ' == str[i] || '\t' == str[i]))
    {
      if (! wsp_around_eq)
        return MHD_PARSE_COOKIE_MALFORMED;
      non_strict = true;
      i++;
    }
    /* 'i' must point to the first char of cookie-value */
    if (str_len == i)
    {
      value_start = 0;
      value_len = 0;
#ifndef NDEBUG
      val_quoted = false; /* This assignment used in assert */
#endif
    }
    else
    {
      bool valid_cookie;
      val_quoted = ('"' == str[i]);
      if (val_quoted)
        i++;
      value_start = i;
      /* Find the end of the cookie-value */
      while (str_len > i)
      {
        const char l = str[i];
        if ((';' == l) || ('"' == l) || (',' == l) || (';' == l) ||
            ('\\' == l) || (0 == l))
          break;
        if ((' ' == l) || ('\t' == l))
        {
          if (! val_quoted)
            break;
          if (! wsp_in_quoted)
            return MHD_PARSE_COOKIE_MALFORMED;
          non_strict = true;
        }
        i++;
      }
      value_len = i - value_start;
      if (val_quoted)
      {
        if ((str_len == i) || ('"' != str[i]))
          return MHD_PARSE_COOKIE_MALFORMED; /* Incomplete cookie value, no closing quote */
        i++;
      }
      /* Skip any whitespaces */
      if ((str_len > i) && ((' ' == str[i]) || ('\t' == str[i])))
      {
        do
        {
          i++;
        } while (str_len > i && (' ' == str[i] || '\t' == str[i]));
        /* Whitespace at the end? */
        if (str_len > i)
        {
          if (! allow_wsp_empty)
            return MHD_PARSE_COOKIE_MALFORMED;
          non_strict = true;
        }
      }
      if (str_len == i)
        valid_cookie = true;
      else if (';' == str[i])
        valid_cookie = true;
      else
        valid_cookie = false;

      if (! valid_cookie)
        return MHD_PARSE_COOKIE_MALFORMED; /* Garbage at the end of the cookie value */
    }
    mhd_assert (0 != name_len);
    str[name_start + name_len] = 0; /* Zero-terminate the name */
    if (0 != value_len)
    {
      struct MHD_String name;
      struct MHD_String value;
      mhd_assert (value_start + value_len <= str_len);
      name.cstr = str + name_start;
      name.len = name_len;
      str[value_start + value_len] = 0; /* Zero-terminate the value */
      value.cstr = str + value_start;
      value.len = value_len;
      if (! mhd_stream_add_field (connection,
                                  MHD_VK_COOKIE,
                                  &name,
                                  &value))
        return MHD_PARSE_COOKIE_NO_MEMORY;
    }
    else
    {
      struct MHD_String name;
      struct MHD_String value;
      name.cstr = str + name_start;
      name.len = name_len;
      value.cstr = "";
      value.len = 0;
      if (! mhd_stream_add_field (connection,
                                  MHD_VK_COOKIE,
                                  &name,
                                  &value))
        return MHD_PARSE_COOKIE_NO_MEMORY;
    }
    if (str_len > i)
    {
      mhd_assert (0 == str[i] || ';' == str[i]);
      mhd_assert (! val_quoted || ';' == str[i]);
      mhd_assert (';' != str[i] || val_quoted || non_strict || 0 == value_len);
      i++;
      if (str_len == i)
      { /* No next cookie after semicolon */
        if (! allow_wsp_empty)
          return MHD_PARSE_COOKIE_MALFORMED;
        non_strict = true;
      }
      else if (' ' != str[i])
      {/* No space after semicolon */
        if (('\t' == str[i]) && tab_as_sp)
          i++;
        else if (! allow_no_space)
          return MHD_PARSE_COOKIE_MALFORMED;
        non_strict = true;
      }
      else
      {
        i++;
        if (str_len == i)
        {
          if (! allow_wsp_empty)
            return MHD_PARSE_COOKIE_MALFORMED;
          non_strict = true;
        }
      }
    }
  }
  return non_strict? MHD_PARSE_COOKIE_OK_LAX : MHD_PARSE_COOKIE_OK;
}


/**
 * Parse the cookie header (see RFC 6265).
 *
 * @param connection connection to parse header of
 * @param cookie_val the value of the "Cookie:" header
 * @return #MHD_PARSE_COOKIE_OK for success, error code otherwise
 */
static enum _MHD_ParseCookie
parse_cookie_header (struct MHD_Connection *restrict connection,
                     struct MHD_StringNullable *restrict cookie_val)
{
  char *cpy;
  size_t i;
  enum _MHD_ParseCookie parse_res;
  struct mhd_RequestField *const saved_tail =
    connection->rq.fields.last;  // FIXME: a better way?
  const bool allow_partially_correct_cookie =
    (1 >= connection->daemon->req_cfg.strictnees);

  if (NULL == cookie_val)
    return MHD_PARSE_COOKIE_OK;
  if (0 == cookie_val->len)
    return MHD_PARSE_COOKIE_OK;

  cpy = mhd_stream_alloc_memory (connection,
                                 cookie_val->len + 1);
  if (NULL == cpy)
    parse_res = MHD_PARSE_COOKIE_NO_MEMORY;
  else
  {
    memcpy (cpy,
            cookie_val->cstr,
            cookie_val->len + 1);
    mhd_assert (0 == cpy[cookie_val->len]);

    /* Must not have initial whitespaces */
    mhd_assert (' ' != cpy[0]);
    mhd_assert ('\t' != cpy[0]);

    i = 0;
    parse_res = parse_cookies_string (cookie_val->len - i, cpy + i, connection);
  }

  switch (parse_res)
  {
  case MHD_PARSE_COOKIE_OK:
    break;
  case MHD_PARSE_COOKIE_OK_LAX:
    if (saved_tail != connection->rq.fields.last)
      mhd_LOG_MSG (connection->daemon, MHD_SC_REQ_COOKIE_PARSED_NOT_COMPLIANT, \
                   "The Cookie header has been parsed, but it is not "
                   "fully compliant with specifications.");
    break;
  case MHD_PARSE_COOKIE_MALFORMED:
    if (saved_tail != connection->rq.fields.last) // FIXME: a better way?
    {
      if (! allow_partially_correct_cookie)
      {
        /* Remove extracted values from partially broken cookie */
        /* Memory remains allocated until the end of the request processing */
        connection->rq.fields.last = saved_tail;  // FIXME: a better way?
        saved_tail->fields.next = NULL;  // FIXME: a better way?
        mhd_LOG_MSG ( \
          connection->daemon, MHD_SC_REQ_COOKIE_IGNORED_NOT_COMPLIANT, \
          "The Cookie header is ignored as it contains malformed data.");
      }
      else
        mhd_LOG_MSG (connection->daemon, MHD_SC_REQ_COOKIE_PARSED_PARTIALLY, \
                     "The Cookie header has been only partially parsed " \
                     "as it contains malformed data.");
    }
    else
      mhd_LOG_MSG (connection->daemon, MHD_SC_REQ_COOKIE_INVALID,
                   "The Cookie header has malformed data.");
    break;
  case MHD_PARSE_COOKIE_NO_MEMORY:
    mhd_LOG_MSG (connection->daemon, MHD_SC_CONNECTION_POOL_NO_MEM_COOKIE,
                 "Not enough memory in the connection pool to "
                 "parse client cookies!\n");
    break;
  default:
    mhd_assert (0 && "Impossible value");
    MHD_UNREACHABLE_;
    break;
  }

  return parse_res;
}


/**
 * Send error reply when receive buffer space exhausted while receiving or
 * storing the request headers
 * @param c the connection to handle
 * @param add_header the optional pointer to the current header string being
 *                   processed or the header failed to be added.
 *                   Could be not zero-terminated and can contain binary zeros.
 *                   Can be NULL.
 * @param add_header_size the size of the @a add_header
 */
MHD_static_inline_ void
handle_req_cookie_no_space (struct MHD_Connection *restrict c)
{
  unsigned int err_code;

  err_code = mhd_stream_get_no_space_err_status_code (c,
                                                      MHD_PROC_RECV_COOKIE,
                                                      0,
                                                      NULL);
  mhd_RESPOND_WITH_ERROR_STATIC (c,
                                 err_code,
                                 ERR_RSP_REQUEST_HEADER_TOO_BIG);
}


#endif /* COOKIE_SUPPORT */


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ void
mhd_stream_parse_request_headers (struct MHD_Connection *restrict c)
{
  bool has_host;
  bool has_trenc;
  bool has_cntnlen;
  bool has_keepalive;
  struct mhd_RequestField *f;

  /* The presence of the request body is indicated by "Content-Length:" or
     "Transfer-Encoding:" request headers.
     Unless one of these two headers is used, the request has no request body.
     See RFC9112, Section 6, paragraph 4. */
  c->rq.have_chunked_upload = false;
  c->rq.cntn.cntn_size = 0;

  has_host = false;
  has_trenc = false;
  has_cntnlen = false;
  has_keepalive = true;

  for (f = mhd_DLINKEDL_GET_FIRST (&(c->rq), fields);
       NULL != f;
       f = mhd_DLINKEDL_GET_NEXT (f, fields))
  {
    if (MHD_VK_HEADER != f->field.kind)
      continue;

    /* "Host:" */
    if (mhd_str_equal_caseless_n_st (MHD_HTTP_HEADER_HOST,
                                     f->field.nv.name.cstr,
                                     f->field.nv.name.len))
    {
      if ((has_host)
          && (-3 < c->daemon->req_cfg.strictnees))
      {
        mhd_LOG_MSG (c->daemon, MHD_SC_HOST_HEADER_SEVERAL, \
                     "Received request with more than one 'Host' header.");
        mhd_RESPOND_WITH_ERROR_STATIC (c,
                                       MHD_HTTP_STATUS_BAD_REQUEST,
                                       ERR_RSP_REQUEST_HAS_SEVERAL_HOSTS);
        return;
      }
      has_host = true;
      continue;
    }

#ifdef COOKIE_SUPPORT
    /* "Cookie:" */
    if (mhd_str_equal_caseless_n_st (MHD_HTTP_HEADER_COOKIE,
                                     f->field.nv.name.cstr,
                                     f->field.nv.name.len))
    {
      if (MHD_PARSE_COOKIE_NO_MEMORY ==
          parse_cookie_header (c,
                               &(f->field.nv.value)))
      {
        handle_req_cookie_no_space (c);
        return;
      }
      continue;
    }
#endif /* COOKIE_SUPPORT */

    /* "Content-Length:" */
    if (mhd_str_equal_caseless_n_st (MHD_HTTP_HEADER_CONTENT_LENGTH,
                                     f->field.nv.name.cstr,
                                     f->field.nv.name.len))
    {
      size_t num_digits;
      uint_fast64_t cntn_size;

      num_digits = mhd_str_to_uint64_n (f->field.nv.value.cstr,
                                        f->field.nv.value.len,
                                        &cntn_size);
      if (((0 == num_digits) &&
           (0 != f->field.nv.value.len) &&
           ('9' >= f->field.nv.value.cstr[0])
           && ('0' <= f->field.nv.value.cstr[0]))
          || (MHD_SIZE_UNKNOWN == c->rq.cntn.cntn_size))
      {
        mhd_LOG_MSG (c->daemon, MHD_SC_CONTENT_LENGTH_TOO_LARGE, \
                     "Too large value of 'Content-Length' header. " \
                     "Closing connection.");
        mhd_RESPOND_WITH_ERROR_STATIC (c, \
                                       MHD_HTTP_STATUS_CONTENT_TOO_LARGE, \
                                       ERR_RSP_REQUEST_CONTENTLENGTH_TOOLARGE);
        return;
      }
      else if ((f->field.nv.value.len != num_digits) ||
               (0 == num_digits))
      {
        mhd_LOG_MSG (c->daemon, MHD_SC_CONTENT_LENGTH_MALFORMED, \
                     "Failed to parse 'Content-Length' header. " \
                     "Closing connection.");
        mhd_RESPOND_WITH_ERROR_STATIC (c, \
                                       MHD_HTTP_STATUS_BAD_REQUEST, \
                                       ERR_RSP_REQUEST_CONTENTLENGTH_MALFORMED);
        return;
      }

      if (has_cntnlen)
      {
        bool send_err;
        send_err = false;
        if (c->rq.cntn.cntn_size == cntn_size)
        {
          if (0 < c->daemon->req_cfg.strictnees)
          {
            mhd_LOG_MSG (c->daemon, MHD_SC_CONTENT_LENGTH_SEVERAL_SAME, \
                         "Received request with more than one " \
                         "'Content-Length' header with the same value.");
            send_err = true;
          }
        }
        else
        {
          mhd_LOG_MSG (c->daemon, MHD_SC_CONTENT_LENGTH_SEVERAL_DIFFERENT, \
                       "Received request with more than one " \
                       "'Content-Length' header with conflicting values.");
          send_err = true;
        }

        if (send_err)
        {
          mhd_RESPOND_WITH_ERROR_STATIC ( \
            c, \
            MHD_HTTP_STATUS_BAD_REQUEST, \
            ERR_RSP_REQUEST_CONTENTLENGTH_SEVERAL);
          return;
        }
      }
      mhd_assert ((0 == c->rq.cntn.cntn_size) || \
                  (c->rq.cntn.cntn_size == cntn_size));
      c->rq.cntn.cntn_size = cntn_size;
      has_cntnlen = true;
      continue;
    }

    /* "Connection:" */
    if (mhd_str_equal_caseless_n_st (MHD_HTTP_HEADER_CONNECTION,
                                     f->field.nv.name.cstr,
                                     f->field.nv.name.len))
    {
      if (mhd_str_has_token_caseless (f->field.nv.value.cstr, // TODO: compare as size string
                                      "close",
                                      mhd_SSTR_LEN ("close")))
      {
        mhd_assert (mhd_CONN_MUST_UPGRADE != c->conn_reuse);
        c->conn_reuse = mhd_CONN_MUST_CLOSE;
      }
      else if ((MHD_HTTP_VERSION_1_0 == c->rq.http_ver)
               && (mhd_CONN_MUST_CLOSE != c->conn_reuse))
      {
        if (mhd_str_has_token_caseless (f->field.nv.value.cstr,  // TODO: compare as size string
                                        "keep-alive",
                                        mhd_SSTR_LEN ("keep-alive")))
          has_keepalive = true;
      }

      continue;
    }

    /* "Transfer-Encoding:" */
    if (mhd_str_equal_caseless_n_st (MHD_HTTP_HEADER_TRANSFER_ENCODING,
                                     f->field.nv.name.cstr,
                                     f->field.nv.name.len))
    {
      if (mhd_str_equal_caseless_n_st ("chunked",
                                       f->field.nv.value.cstr,
                                       f->field.nv.value.len))
      {
        c->rq.have_chunked_upload = true;
        c->rq.cntn.cntn_size = MHD_SIZE_UNKNOWN;
      }
      else
      {
        mhd_LOG_MSG (c->daemon, MHD_SC_CHUNKED_ENCODING_UNSUPPORTED, \
                     "The 'Transfer-Encoding' used in request is " \
                     "unsupported or invalid.");
        mhd_RESPOND_WITH_ERROR_STATIC (c,
                                       MHD_HTTP_STATUS_BAD_REQUEST,
                                       ERR_RSP_UNSUPPORTED_TR_ENCODING);
        return;
      }
      has_trenc = true;
      continue;
    }
  }

  if (has_trenc && has_cntnlen)
  {
    if (0 < c->daemon->req_cfg.strictnees)
    {
      mhd_RESPOND_WITH_ERROR_STATIC ( \
        c, \
        MHD_HTTP_STATUS_BAD_REQUEST, \
        ERR_RSP_REQUEST_CNTNLENGTH_WITH_TR_ENCODING);
      return;
    }
    /* Must close connection after reply to prevent potential attack */
    c->conn_reuse = mhd_CONN_MUST_CLOSE;
    c->rq.cntn.cntn_size = MHD_SIZE_UNKNOWN;
    mhd_assert (c->rq.have_chunked_upload);
    mhd_LOG_MSG (c->daemon, MHD_SC_CONTENT_LENGTH_AND_TR_ENC, \
                 "The 'Content-Length' request header is ignored " \
                 "as chunked 'Transfer-Encoding' is used " \
                 "for this request.");
  }

  if (MHD_HTTP_VERSION_1_1 <= c->rq.http_ver)
  {
    if ((! has_host) &&
        (-3 < c->daemon->req_cfg.strictnees))
    {
      mhd_LOG_MSG (c->daemon, MHD_SC_HOST_HEADER_MISSING, \
                   "Received HTTP/1.1 request without 'Host' header.");
      mhd_RESPOND_WITH_ERROR_STATIC (c,
                                     MHD_HTTP_STATUS_BAD_REQUEST,
                                     ERR_RSP_REQUEST_LACKS_HOST);
      return;
    }
  }
  else
  {
    if (! has_keepalive)
      c->conn_reuse = mhd_CONN_MUST_CLOSE; /* Do not re-use HTTP/1.0 connection by default */
    if (has_trenc)
      c->conn_reuse = mhd_CONN_MUST_CLOSE; /* Framing could be incorrect */
  }

  c->state = MHD_CONNECTION_HEADERS_PROCESSED;
  return;
}


/**
 * Is "100 CONTINUE" needed to be sent for current request?
 *
 * @param c the connection to check
 * @return false 100 CONTINUE is not needed,
 *         true otherwise
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
need_100_continue (struct MHD_Connection *restrict c)
{
  const struct MHD_StringNullable *hvalue;

  mhd_assert (MHD_HTTP_VERSION_IS_SUPPORTED (c->rq.http_ver));
  mhd_assert (MHD_CONNECTION_BODY_RECEIVING > c->state);

  if (MHD_HTTP_VERSION_1_0 == c->rq.http_ver)
    return false;

  if (0 != c->read_buffer_offset)
    return false; /* Part of the content has been received already */

  hvalue = mhd_request_get_value_st (&(c->rq),
                                     MHD_VK_HEADER,
                                     MHD_HTTP_HEADER_EXPECT);
  if (NULL == hvalue)
    return false;

  if (mhd_str_equal_caseless_n_st ("100-continue", \
                                   hvalue->cstr, hvalue->len))
    return true;

  return false;
}


/**
 * Check whether special buffer is required to handle the upload content and
 * try to allocate if necessary.
 * Respond with error to the client if buffer cannot be allocated
 * @param c the connection to
 * @return true if succeed,
 *         false if error response is set
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
check_and_alloc_buf_for_upload_processing (struct MHD_Connection *restrict c)
{
  mhd_assert ((mhd_ACTION_UPLOAD == c->rq.app_act.head_act.act) || \
              (mhd_ACTION_POST_PROCESS == c->rq.app_act.head_act.act));

  if (c->rq.have_chunked_upload)
    return true; /* The size is unknown, buffers will be dynamically allocated
                    and re-allocated */
  mhd_assert (c->read_buffer_size > c->read_buffer_offset);
#if 0 // TODO: support processing full response in the connection buffer
  if ((c->read_buffer_size - c->read_buffer_offset) >=
      c->rq.cntn.cntn_size)
    return true; /* No additional buffer needed */
#endif

  if ((mhd_ACTION_UPLOAD == c->rq.app_act.head_act.act) &&
      (NULL == c->rq.app_act.head_act.data.upload.full.cb))
    return true; /* data will be processed only incrementally */

  if (mhd_ACTION_UPLOAD != c->rq.app_act.head_act.act)
  {
    // TODO: add check for intermental-only POST processing */
    mhd_assert (0 && "Not implemented yet");
    return false;
  }

  if ((c->rq.cntn.cntn_size >
       c->rq.app_act.head_act.data.upload.large_buffer_size) ||
      ! mhd_daemon_get_lbuf (c->daemon, c->rq.cntn.cntn_size,
                             &(c->rq.cntn.lbuf)))
  {
    if (NULL != c->rq.app_act.head_act.data.upload.inc.cb)
    {
      c->rq.app_act.head_act.data.upload.full.cb = NULL;
      return true; /* Data can be processed incrementally */
    }

    mhd_RESPOND_WITH_ERROR_STATIC (c,
                                   MHD_HTTP_STATUS_CONTENT_TOO_LARGE,
                                   ERR_RSP_REQUEST_CONTENTLENGTH_TOOLARGE);
    return false;
  }

  return true;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_stream_call_app_request_cb (struct MHD_Connection *restrict c)
{
  struct MHD_Daemon *restrict d = c->daemon;
  struct MHD_String path;
  const struct MHD_Action *a;

  mhd_assert (mhd_HTTP_METHOD_NO_METHOD != c->rq.http_mthd);
  mhd_assert (NULL == c->rp.response);

  if (mhd_ACTION_NO_ACTION != c->rq.app_act.head_act.act)
    MHD_PANIC ("MHD_Action has been set already");

  path.cstr = c->rq.url;
  path.len = c->rq.url_len;

  c->rq.app_aware = true;
  a = d->req_cfg.cb (d->req_cfg.cb_cls,
                     &(c->rq),
                     &path,
                     (enum MHD_HTTP_Method) c->rq.http_mthd,
                     c->rq.cntn.cntn_size);

  if ((NULL != a)
      && (((&(c->rq.app_act.head_act) != a))
          || ! mhd_ACTION_IS_VALID (c->rq.app_act.head_act.act)))
  {
    mhd_LOG_MSG (d, MHD_SC_ACTION_INVALID, \
                 "Provided action is not a correct action generated " \
                 "for the current request.");
    a = NULL;
  }
  if (NULL == a)
    c->rq.app_act.head_act.act = mhd_ACTION_ABORT;

  switch (c->rq.app_act.head_act.act)
  {
  case mhd_ACTION_RESPONSE:
    c->rp.response = c->rq.app_act.head_act.data.response;
    c->state = MHD_CONNECTION_REQ_RECV_FINISHED;
    return true;
  case mhd_ACTION_UPLOAD:
    if (0 != c->rq.cntn.cntn_size)
    {
      if (! check_and_alloc_buf_for_upload_processing (c))
        return true;
      if (need_100_continue (c))
      {
        c->state = MHD_CONNECTION_CONTINUE_SENDING;
        return true;
      }
      c->state = MHD_CONNECTION_BODY_RECEIVING;
      return (0 != c->read_buffer_offset);
    }
    c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
    return true;
  case mhd_ACTION_POST_PROCESS:
    mhd_assert (0 && "Not implemented yet");
    return true;
  case mhd_ACTION_SUSPEND:
    c->suspended = true;
    return false;
  case mhd_ACTION_ABORT:
    mhd_conn_pre_close_app_abort (c);
    return false;
  case mhd_ACTION_NO_ACTION:
  default:
    mhd_assert (0 && "Impossible value");
    break;
  }
  MHD_UNREACHABLE_;
  return false;
}


/**
 * React on provided action for upload
 * @param c the stream to use
 * @param act the action provided by application
 * @param final set to 'true' if this is final upload callback
 * @return true if connection state has been changed,
 *         false otherwise
 */
static MHD_FN_PAR_NONNULL_ (1) bool
process_upload_action (struct MHD_Connection *restrict c,
                       const struct MHD_UploadAction *act,
                       bool final)
{
  if (NULL != act)
  {
    if ((&(c->rq.app_act.upl_act) != act) ||
        ! mhd_UPLOAD_ACTION_IS_VALID (c->rq.app_act.upl_act.act) ||
        (final &&
         (mhd_UPLOAD_ACTION_CONTINUE == c->rq.app_act.upl_act.act)))
    {
      mhd_LOG_MSG (c->daemon, MHD_SC_UPLOAD_ACTION_INVALID, \
                   "Provided action is not a correct action generated " \
                   "for the current request.");
      act = NULL;
    }
  }
  if (NULL == act)
    c->rq.app_act.upl_act.act = mhd_UPLOAD_ACTION_ABORT;

  switch (c->rq.app_act.upl_act.act)
  {
  case mhd_UPLOAD_ACTION_RESPONSE:
    c->rp.response = c->rq.app_act.upl_act.data.response;
    c->state = MHD_CONNECTION_REQ_RECV_FINISHED;
    return true;
  case mhd_UPLOAD_ACTION_CONTINUE:
    memset (&(c->rq.app_act.upl_act), 0, sizeof(c->rq.app_act.upl_act));
    return false;
  case mhd_UPLOAD_ACTION_SUSPEND:
    c->suspended = true;
    return false;
  case mhd_UPLOAD_ACTION_ABORT:
    mhd_conn_pre_close_app_abort (c);
    return false;
  case mhd_UPLOAD_ACTION_NO_ACTION:
  default:
    mhd_assert (0 && "Impossible value");
    break;
  }
  MHD_UNREACHABLE_;
  return false;
}


static MHD_FN_PAR_NONNULL_ALL_ bool
process_request_chunked_body (struct MHD_Connection *restrict c)
{
  struct MHD_Daemon *restrict d = c->daemon;
  size_t available;
  bool has_more_data;
  char *restrict buffer_head;
  const int discp_lvl = d->req_cfg.strictnees;
  /* Treat bare LF as the end of the line.
     RFC 9112, section 2.2-3
     Note: MHD never replaces bare LF with space (RFC 9110, section 5.5-5).
     Bare LF is processed as end of the line or rejected as broken request. */
  const bool bare_lf_as_crlf = MHD_ALLOW_BARE_LF_AS_CRLF_ (discp_lvl);
  /* Allow "Bad WhiteSpace" in chunk extension.
     RFC 9112, Section 7.1.1, Paragraph 2 */
  const bool allow_bws = (2 < discp_lvl);
  bool state_updated;

  mhd_assert (NULL == c->rp.response);
  mhd_assert (c->rq.have_chunked_upload);
  mhd_assert (MHD_SIZE_UNKNOWN == c->rq.cntn.cntn_size);

  buffer_head = c->read_buffer;
  available = c->read_buffer_offset;
  state_updated = false;
  do
  {
    size_t cntn_data_ready;
    bool need_inc_proc;

    has_more_data = false;

    if ( (c->rq.current_chunk_offset ==
          c->rq.current_chunk_size) &&
         (0 != c->rq.current_chunk_size) )
    {
      size_t i;
      mhd_assert (0 != available);
      /* skip new line at the *end* of a chunk */
      i = 0;
      if ( (2 <= available) &&
           ('\r' == buffer_head[0]) &&
           ('\n' == buffer_head[1]) )
        i += 2;                        /* skip CRLF */
      else if (bare_lf_as_crlf && ('\n' == buffer_head[0]))
        i++;                           /* skip bare LF */
      else if (2 > available)
        break;                         /* need more upload data */
      if (0 == i)
      {
        /* malformed encoding */
        mhd_RESPOND_WITH_ERROR_STATIC (c,
                                       MHD_HTTP_STATUS_BAD_REQUEST,
                                       ERR_RSP_REQUEST_CHUNKED_MALFORMED);
        return true;
      }
      available -= i;
      buffer_head += i;
      c->rq.current_chunk_offset = 0;
      c->rq.current_chunk_size = 0;
      if (0 == available)
        break;
    }
    if (0 != c->rq.current_chunk_size)
    {
      uint_fast64_t cur_chunk_left;
      mhd_assert (c->rq.current_chunk_offset < \
                  c->rq.current_chunk_size);
      /* we are in the middle of a chunk, give
         as much as possible to the client (without
         crossing chunk boundaries) */
      cur_chunk_left
        = c->rq.current_chunk_size
          - c->rq.current_chunk_offset;
      if (cur_chunk_left > available)
        cntn_data_ready = available;
      else
      {         /* cur_chunk_left <= (size_t)available */
        cntn_data_ready = (size_t) cur_chunk_left;
        if (available > cntn_data_ready)
          has_more_data = true;
      }
    }
    else
    { /* Need the parse the chunk size line */
      /** The number of found digits in the chunk size number */
      size_t num_dig;
      uint_fast64_t chunk_size;
      bool broken;
      bool overflow;

      mhd_assert (0 != available);

      overflow = false;
      chunk_size = 0; /* Mute possible compiler warning.
                         The real value will be set later. */

      num_dig = mhd_strx_to_uint64_n (buffer_head,
                                      available,
                                      &chunk_size);
      mhd_assert (num_dig <= available);
      if (num_dig == available)
        continue; /* Need line delimiter */

      broken = (0 == num_dig);
      if (broken)
        /* Check whether result is invalid due to uint64_t overflow */
        overflow = ((('0' <= buffer_head[0]) && ('9' >= buffer_head[0])) ||
                    (('A' <= buffer_head[0]) && ('F' >= buffer_head[0])) ||
                    (('a' <= buffer_head[0]) && ('f' >= buffer_head[0])));
      else
      {
        /**
         * The length of the string with the number of the chunk size,
         * including chunk extension
         */
        size_t chunk_size_line_len;

        chunk_size_line_len = 0;
        if ((';' == buffer_head[num_dig]) ||
            (allow_bws &&
             ((' ' == buffer_head[num_dig]) ||
              ('\t' == buffer_head[num_dig]))))
        { /* Chunk extension */
          size_t i;

          /* Skip bad whitespaces (if any) */
          for (i = num_dig; i < available; ++i)
          {
            if ((' ' != buffer_head[i]) && ('\t' != buffer_head[i]))
              break;
          }
          if (i == available)
            break; /* need more data */
          if (';' == buffer_head[i])
          {
            for (++i; i < available; ++i)
            {
              if ('\n' == buffer_head[i])
                break;
            }
            if (i == available)
              break; /* need more data */
            mhd_assert (i > num_dig);
            mhd_assert (1 <= i);
            /* Found LF position */
            if (bare_lf_as_crlf)
              chunk_size_line_len = i; /* Don't care about CR before LF */
            else if ('\r' == buffer_head[i - 1])
              chunk_size_line_len = i;
          }
          else
          { /* No ';' after "bad whitespace" */
            mhd_assert (allow_bws);
            mhd_assert (0 == chunk_size_line_len);
          }
        }
        else
        {
          mhd_assert (available >= num_dig);
          if ((2 <= (available - num_dig)) &&
              ('\r' == buffer_head[num_dig]) &&
              ('\n' == buffer_head[num_dig + 1]))
            chunk_size_line_len = num_dig + 2;
          else if (bare_lf_as_crlf &&
                   ('\n' == buffer_head[num_dig]))
            chunk_size_line_len = num_dig + 1;
          else if (2 > (available - num_dig))
            break; /* need more data */
        }

        if (0 != chunk_size_line_len)
        { /* Valid termination of the chunk size line */
          mhd_assert (chunk_size_line_len <= available);
          /* Start reading payload data of the chunk */
          c->rq.current_chunk_offset = 0;
          c->rq.current_chunk_size = chunk_size;

          available -= chunk_size_line_len;
          buffer_head += chunk_size_line_len;

          if (0 == chunk_size)
          { /* The final (termination) chunk */
            c->rq.cntn.cntn_size = c->rq.cntn.recv_size;
            c->state = MHD_CONNECTION_BODY_RECEIVED;
            state_updated = true;
            break;
          }
          if (available > 0)
            has_more_data = true;
          continue;
        }
        /* Invalid chunk size line */
      }

      if (! overflow)
        mhd_RESPOND_WITH_ERROR_STATIC (c,
                                       MHD_HTTP_STATUS_BAD_REQUEST,
                                       ERR_RSP_REQUEST_CHUNKED_MALFORMED);
      else
        mhd_RESPOND_WITH_ERROR_STATIC (c,
                                       MHD_HTTP_STATUS_CONTENT_TOO_LARGE,
                                       ERR_RSP_REQUEST_CHUNK_TOO_LARGE);
      return true;
    }
    mhd_assert (c->rq.app_aware);

    if (mhd_ACTION_POST_PROCESS == c->rq.app_act.head_act.act)
    {
      mhd_assert (0 && "Not implemented yet"); // TODO: implement POST
      return false;
    }

    if (NULL != c->rq.app_act.head_act.data.upload.full.cb)
    {
      need_inc_proc = false;

      mhd_assert (0 == c->rq.cntn.proc_size);
      if ((uint_fast64_t) c->rq.cntn.lbuf.size <
          c->rq.cntn.recv_size + cntn_data_ready)
      {
        size_t grow_size;

        grow_size = (size_t) (c->rq.cntn.recv_size + cntn_data_ready
                              - c->rq.cntn.lbuf.size);
        if (((size_t) (c->rq.cntn.recv_size + cntn_data_ready) <
             cntn_data_ready) || (! mhd_daemon_grow_lbuf (d,
                                                          grow_size,
                                                          &(c->rq.cntn.lbuf))))
        {
          /* Failed to grow the buffer, no space to put the new data */
          const struct MHD_UploadAction *act;
          if (NULL != c->rq.app_act.head_act.data.upload.inc.cb)
          {
            mhd_RESPOND_WITH_ERROR_STATIC (
              c,
              MHD_HTTP_STATUS_CONTENT_TOO_LARGE,
              ERR_RSP_MSG_REQUEST_TOO_BIG);
            return true;
          }
          c->rq.app_act.head_act.data.upload.full.cb = NULL; /* Cannot process "full" content */
          /* Process previously buffered data */
          mhd_assert (c->rq.cntn.recv_size <= c->rq.cntn.lbuf.size);
          act = c->rq.app_act.head_act.data.upload.inc.cb (
            c->rq.app_act.head_act.data.upload.inc.cls,
            &(c->rq),
            c->rq.cntn.recv_size,
            c->rq.cntn.lbuf.buf);
          c->rq.cntn.proc_size = c->rq.cntn.recv_size;
          mhd_daemon_free_lbuf (d, &(c->rq.cntn.lbuf));
          if (process_upload_action (c, act, false))
            return true;
          need_inc_proc = true;
        }
      }
      if (! need_inc_proc)
      {
        memcpy (c->rq.cntn.lbuf.buf + c->rq.cntn.recv_size,
                buffer_head, cntn_data_ready);
        c->rq.cntn.recv_size += cntn_data_ready;
      }
    }
    else
      need_inc_proc = true;

    if (need_inc_proc)
    {
      const struct MHD_UploadAction *act;
      mhd_assert (NULL != c->rq.app_act.head_act.data.upload.inc.cb);

      c->rq.cntn.recv_size += cntn_data_ready;
      act = c->rq.app_act.head_act.data.upload.inc.cb (
        c->rq.app_act.head_act.data.upload.inc.cls,
        &(c->rq),
        cntn_data_ready,
        buffer_head);
      c->rq.cntn.proc_size += cntn_data_ready;
      state_updated = process_upload_action (c, act, false);
    }

    /* dh left "processed" bytes in buffer for next time... */
    buffer_head += cntn_data_ready;
    available -= cntn_data_ready;
    mhd_assert (MHD_SIZE_UNKNOWN == c->rq.cntn.cntn_size);
    c->rq.current_chunk_offset += cntn_data_ready;
  } while (has_more_data && ! state_updated);
  /* TODO: optionally? zero out reused memory region */
  if ( (available > 0) &&
       (buffer_head != c->read_buffer) )
    memmove (c->read_buffer,
             buffer_head,
             available);
  else
    mhd_assert ((0 == available) || \
                (c->read_buffer_offset == available));
  c->read_buffer_offset = available;

  return state_updated;
}


static MHD_FN_PAR_NONNULL_ALL_ bool
process_request_nonchunked_body (struct MHD_Connection *restrict c)
{
  size_t cntn_data_ready;
  bool read_buf_reuse;
  bool state_updated;

  mhd_assert (NULL == c->rp.response);
  mhd_assert (! c->rq.have_chunked_upload);
  mhd_assert (MHD_SIZE_UNKNOWN != c->rq.cntn.cntn_size);
  mhd_assert (c->rq.cntn.recv_size < c->rq.cntn.cntn_size);
  mhd_assert (c->rq.app_aware);

  if ((c->rq.cntn.cntn_size - c->rq.cntn.recv_size) < c->read_buffer_offset)
    cntn_data_ready = (size_t) (c->rq.cntn.cntn_size - c->rq.cntn.recv_size);
  else
    cntn_data_ready = c->read_buffer_offset;

  if (mhd_ACTION_POST_PROCESS == c->rq.app_act.head_act.act)
  {
    mhd_assert (0 && "Not implemented yet"); // TODO: implement POST
    return false;
  }

  mhd_assert (mhd_ACTION_UPLOAD == c->rq.app_act.head_act.act);
  read_buf_reuse = false;
  state_updated = false;
  if (NULL != c->rq.app_act.head_act.data.upload.full.cb)
  {
    // TODO: implement processing in pool memory if buffer is large enough
    mhd_assert ((c->rq.cntn.recv_size + cntn_data_ready) <=
                (uint_fast64_t) c->rq.cntn.lbuf.size);
    memcpy (c->rq.cntn.lbuf.buf + c->rq.cntn.recv_size,
            c->read_buffer, cntn_data_ready);
    c->rq.cntn.recv_size += cntn_data_ready;
    read_buf_reuse = true;
    if (c->rq.cntn.recv_size == c->rq.cntn.cntn_size)
    {
      c->state = MHD_CONNECTION_FULL_REQ_RECEIVED;
      state_updated = true;
    }
  }
  else
  {
    const struct MHD_UploadAction *act;
    mhd_assert (NULL != c->rq.app_act.head_act.data.upload.inc.cb);

    c->rq.cntn.recv_size += cntn_data_ready;
    act = c->rq.app_act.head_act.data.upload.inc.cb (
      c->rq.app_act.head_act.data.upload.inc.cls,
      &(c->rq),
      cntn_data_ready,
      c->read_buffer);
    c->rq.cntn.proc_size += cntn_data_ready;
    read_buf_reuse = true;
    state_updated = process_upload_action (c, act, false);
  }

  if (read_buf_reuse)
  {
    size_t data_left_size;
    mhd_assert (c->read_buffer_offset >= cntn_data_ready);
    data_left_size = c->read_buffer_offset - cntn_data_ready;
    if (0 != data_left_size)
      memmove (c->read_buffer, c->read_buffer + cntn_data_ready, data_left_size)
      ;
    c->read_buffer_offset = data_left_size;
  }

  return state_updated;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_stream_process_request_body (struct MHD_Connection *restrict c)
{
  if (c->rq.have_chunked_upload)
    return process_request_chunked_body (c);

  return process_request_nonchunked_body (c);
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_stream_call_app_final_upload_cb (struct MHD_Connection *restrict c)
{
  const struct MHD_UploadAction *act;
  mhd_assert (mhd_ACTION_POST_PROCESS == c->rq.app_act.head_act.act || \
              mhd_ACTION_UPLOAD == c->rq.app_act.head_act.act);

  if (mhd_ACTION_POST_PROCESS == c->rq.app_act.head_act.act)
  {
    mhd_assert (0 && "Not implemented yet"); // TODO: implement POST
    return false;
  }

  if (NULL != c->rq.app_act.head_act.data.upload.full.cb)
  {
    mhd_assert (c->rq.cntn.recv_size == c->rq.cntn.cntn_size);
    mhd_assert (0 == c->rq.cntn.proc_size);
    mhd_assert (NULL != c->rq.cntn.lbuf.buf);
    mhd_assert (c->rq.cntn.recv_size <= c->rq.cntn.lbuf.size);
    // TODO: implement processing in pool memory if it is large enough
    act = c->rq.app_act.head_act.data.upload.full.cb (
      c->rq.app_act.head_act.data.upload.full.cls,
      &(c->rq),
      c->rq.cntn.recv_size,
      c->rq.cntn.lbuf.buf);
    c->rq.cntn.proc_size = c->rq.cntn.recv_size;
  }
  else
  {
    mhd_assert (NULL != c->rq.app_act.head_act.data.upload.inc.cb);
    mhd_assert (c->rq.cntn.cntn_size == c->rq.cntn.proc_size);
    act = c->rq.app_act.head_act.data.upload.inc.cb (
      c->rq.app_act.head_act.data.upload.inc.cls,
      &(c->rq),
      0,
      NULL);
  }
  return process_upload_action (c, act, true);
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_stream_process_req_recv_finished (struct MHD_Connection *restrict c)
{
  if (NULL != c->rq.cntn.lbuf.buf)
    mhd_daemon_free_lbuf (c->daemon, &(c->rq.cntn.lbuf));
  c->rq.cntn.lbuf.buf = NULL;
  if (c->rq.cntn.cntn_size != c->rq.cntn.proc_size)
    c->discard_request = true;
  mhd_assert (NULL != c->rp.response);
  c->state = MHD_CONNECTION_START_REPLY;
  return true;
}


/**
 * Send error reply when receive buffer space exhausted while receiving
 * the chunk size line.
 * @param c the connection to handle
 * @param add_header the optional pointer to the partially received
 *                   the current chunk size line.
 *                   Could be not zero-terminated and can contain binary zeros.
 *                   Can be NULL.
 * @param add_header_size the size of the @a add_header
 */
static void
handle_req_chunk_size_line_no_space (struct MHD_Connection *c,
                                     const char *chunk_size_line,
                                     size_t chunk_size_line_size)
{
  unsigned int err_code;

  if (NULL != chunk_size_line)
  {
    const char *semicol;
    /* Check for chunk extension */
    semicol = memchr (chunk_size_line, ';', chunk_size_line_size);
    if (NULL != semicol)
    { /* Chunk extension present. It could be removed without any loss of the
         details of the request. */
      mhd_RESPOND_WITH_ERROR_STATIC (c,
                                     MHD_HTTP_STATUS_CONTENT_TOO_LARGE,
                                     ERR_RSP_REQUEST_CHUNK_LINE_EXT_TOO_BIG);
    }
  }
  err_code = mhd_stream_get_no_space_err_status_code (c,
                                                      MHD_PROC_RECV_BODY_CHUNKED,
                                                      chunk_size_line_size,
                                                      chunk_size_line);
  mhd_RESPOND_WITH_ERROR_STATIC (c,
                                 err_code,
                                 ERR_RSP_REQUEST_CHUNK_LINE_TOO_BIG);
}


/**
 * Handle situation with read buffer exhaustion.
 * Must be called when no more space left in the read buffer, no more
 * space left in the memory pool to grow the read buffer, but more data
 * need to be received from the client.
 * Could be called when the result of received data processing cannot be
 * stored in the memory pool (like some header).
 * @param c the connection to process
 * @param stage the receive stage where the exhaustion happens.
 */
static MHD_FN_PAR_NONNULL_ALL_ void
handle_recv_no_space (struct MHD_Connection *c,
                      enum MHD_ProcRecvDataStage stage)
{
  mhd_assert (MHD_PROC_RECV_INIT <= stage);
  mhd_assert (MHD_PROC_RECV_FOOTERS >= stage);
  mhd_assert (MHD_CONNECTION_FULL_REQ_RECEIVED > c->state);
  mhd_assert ((MHD_PROC_RECV_INIT != stage) || \
              (MHD_CONNECTION_INIT == c->state));
  mhd_assert ((MHD_PROC_RECV_METHOD != stage) || \
              (MHD_CONNECTION_REQ_LINE_RECEIVING == c->state));
  mhd_assert ((MHD_PROC_RECV_URI != stage) || \
              (MHD_CONNECTION_REQ_LINE_RECEIVING == c->state));
  mhd_assert ((MHD_PROC_RECV_HTTPVER != stage) || \
              (MHD_CONNECTION_REQ_LINE_RECEIVING == c->state));
  mhd_assert ((MHD_PROC_RECV_HEADERS != stage) || \
              (MHD_CONNECTION_REQ_HEADERS_RECEIVING == c->state));
  mhd_assert (MHD_PROC_RECV_COOKIE != stage); /* handle_req_cookie_no_space() must be called directly */
  mhd_assert ((MHD_PROC_RECV_BODY_NORMAL != stage) || \
              (MHD_CONNECTION_BODY_RECEIVING == c->state));
  mhd_assert ((MHD_PROC_RECV_BODY_CHUNKED != stage) || \
              (MHD_CONNECTION_BODY_RECEIVING == c->state));
  mhd_assert ((MHD_PROC_RECV_FOOTERS != stage) || \
              (MHD_CONNECTION_FOOTERS_RECEIVING == c->state));
  mhd_assert ((MHD_PROC_RECV_BODY_NORMAL != stage) || \
              (! c->rq.have_chunked_upload));
  mhd_assert ((MHD_PROC_RECV_BODY_CHUNKED != stage) || \
              (c->rq.have_chunked_upload));
  switch (stage)
  {
  case MHD_PROC_RECV_INIT:
  case MHD_PROC_RECV_METHOD:
    /* Some data has been received, but it is not clear yet whether
     * the received data is an valid HTTP request */
    mhd_STREAM_ABORT (c, mhd_CONN_CLOSE_NO_POOL_MEM_FOR_REQUEST, \
                      "No space left in the read buffer when " \
                      "receiving the initial part of " \
                      "the request line.");
    return;
  case MHD_PROC_RECV_URI:
  case MHD_PROC_RECV_HTTPVER:
    /* Some data has been received, but the request line is incomplete */
    mhd_assert (mhd_HTTP_METHOD_NO_METHOD != c->rq.http_mthd);
    mhd_assert (MHD_HTTP_VERSION_INVALID == c->rq.http_ver);
    /* A quick simple check whether the incomplete line looks
     * like an HTTP request */
    if ((mhd_HTTP_METHOD_GET <= c->rq.http_mthd) &&
        (mhd_HTTP_METHOD_DELETE >= c->rq.http_mthd))
    {
      mhd_RESPOND_WITH_ERROR_STATIC (c,
                                     MHD_HTTP_STATUS_URI_TOO_LONG,
                                     ERR_RSP_MSG_REQUEST_TOO_BIG);
      return;
    }
    mhd_STREAM_ABORT (c, mhd_CONN_CLOSE_NO_POOL_MEM_FOR_REQUEST, \
                      "No space left in the read buffer when " \
                      "receiving the URI in " \
                      "the request line. " \
                      "The request uses non-standard HTTP request " \
                      "method token.");
    return;
  case MHD_PROC_RECV_HEADERS:
    handle_req_headers_no_space (c, c->read_buffer, c->read_buffer_offset);
    return;
  case MHD_PROC_RECV_BODY_NORMAL:
    /* A header probably has been added to a suspended connection and
       it took precisely all the space in the buffer.
       Very low probability. */
    mhd_assert (! c->rq.have_chunked_upload);
    handle_req_headers_no_space (c, NULL, 0); // FIXME: check
    return;
  case MHD_PROC_RECV_BODY_CHUNKED:
    mhd_assert (c->rq.have_chunked_upload);
    if (c->rq.current_chunk_offset != c->rq.current_chunk_size)
    { /* Receiving content of the chunk */
      /* A header probably has been added to a suspended connection and
         it took precisely all the space in the buffer.
         Very low probability. */
      handle_req_headers_no_space (c, NULL, 0);  // FIXME: check
    }
    else
    {
      if (0 != c->rq.current_chunk_size)
      { /* Waiting for chunk-closing CRLF */
        /* Not really possible as some payload should be
           processed and the space used by payload should be available. */
        handle_req_headers_no_space (c, NULL, 0);  // FIXME: check
      }
      else
      { /* Reading the line with the chunk size */
        handle_req_chunk_size_line_no_space (c,
                                             c->read_buffer,
                                             c->read_buffer_offset);
      }
    }
    return;
  case MHD_PROC_RECV_FOOTERS:
    handle_req_footers_no_space (c, c->read_buffer, c->read_buffer_offset);
    return;
  /* The next cases should not be possible */
  case MHD_PROC_RECV_COOKIE:
  default:
    break;
  }
  mhd_assert (0 && "Should be unreachable");
}


/**
 * Try growing the read buffer.  We initially claim half the available
 * buffer space for the read buffer (the other half being left for
 * management data structures; the write buffer can in the end take
 * virtually everything as the read buffer can be reduced to the
 * minimum necessary at that point.
 *
 * @param connection the connection
 * @param required set to 'true' if grow is required, i.e. connection
 *                 will fail if no additional space is granted
 * @return 'true' on success, 'false' on failure
 */
static MHD_FN_PAR_NONNULL_ALL_ bool
try_grow_read_buffer (struct MHD_Connection *restrict connection,
                      bool required)
{
  size_t new_size;
  size_t avail_size;
  const size_t def_grow_size = 1536; // TODO: remove hardcoded increment
  void *rb;

  avail_size = mhd_pool_get_free (connection->pool);
  if (0 == avail_size)
    return false;               /* No more space available */
  if (0 == connection->read_buffer_size)
    new_size = avail_size / 2;  /* Use half of available buffer for reading */
  else
  {
    size_t grow_size;

    grow_size = avail_size / 8;
    if (def_grow_size > grow_size)
    {                  /* Shortage of space */
      const size_t left_free =
        connection->read_buffer_size - connection->read_buffer_offset;
      mhd_assert (connection->read_buffer_size >= \
                  connection->read_buffer_offset);
      if ((def_grow_size <= grow_size + left_free)
          && (left_free < def_grow_size))
        grow_size = def_grow_size - left_free;  /* Use precise 'def_grow_size' for new free space */
      else if (! required)
        return false;                           /* Grow is not mandatory, leave some space in pool */
      else
      {
        /* Shortage of space, but grow is mandatory */
        const size_t small_inc =
          ((mhd_BUF_INC_SIZE > def_grow_size) ?
           def_grow_size : mhd_BUF_INC_SIZE) / 8;
        if (small_inc < avail_size)
          grow_size = small_inc;
        else
          grow_size = avail_size;
      }
    }
    new_size = connection->read_buffer_size + grow_size;
  }
  /* Make sure that read buffer will not be moved */
  if ((NULL != connection->read_buffer) &&
      ! mhd_pool_is_resizable_inplace (connection->pool,
                                       connection->read_buffer,
                                       connection->read_buffer_size))
  {
    mhd_assert (0);
    return false;
  }
  /* we can actually grow the buffer, do it! */
  rb = mhd_pool_reallocate (connection->pool,
                            connection->read_buffer,
                            connection->read_buffer_size,
                            new_size);
  if (NULL == rb)
  {
    /* This should NOT be possible: we just computed 'new_size' so that
       it should fit. If it happens, somehow our read buffer is not in
       the right position in the pool, say because someone called
       mhd_pool_allocate() without 'from_end' set to 'true'? Anyway,
       should be investigated! (Ideally provide all data from
       *pool and connection->read_buffer and new_size for debugging). */
    mhd_assert (0);
    return false;
  }
  mhd_assert (connection->read_buffer == rb);
  connection->read_buffer = rb;
  mhd_assert (NULL != connection->read_buffer);
  connection->read_buffer_size = new_size;
  return true;
}


MHD_INTERNAL MHD_FN_PAR_NONNULL_ALL_ bool
mhd_stream_check_and_grow_read_buffer_space (struct MHD_Connection *restrict c)
{
  /**
   * The increase of read buffer size is desirable.
   */
  bool rbuff_grow_desired;
  /**
   * The increase of read buffer size is a hard requirement.
   */
  bool rbuff_grow_required;

  mhd_assert (0 != (MHD_EVENT_LOOP_INFO_READ & c->event_loop_info));
  mhd_assert (! c->discard_request);

  rbuff_grow_required = (c->read_buffer_offset == c->read_buffer_size);
  if (rbuff_grow_required)
    rbuff_grow_desired = true;
  else
  {
    rbuff_grow_desired = (c->read_buffer_offset + 1536 > // TODO: remove handcoded buffer grow size
                          c->read_buffer_size);

    if ((rbuff_grow_desired) &&
        (MHD_CONNECTION_BODY_RECEIVING == c->state))
    {
      if (! c->rq.have_chunked_upload)
      {
        mhd_assert (MHD_SIZE_UNKNOWN != c->rq.cntn.cntn_size);
        /* Do not grow read buffer more than necessary to process the current
           request. */
        rbuff_grow_desired =
          (c->rq.cntn.cntn_size - c->rq.cntn.recv_size > c->read_buffer_size); // FIXME
      }
      else
      {
        mhd_assert (MHD_SIZE_UNKNOWN == c->rq.cntn.cntn_size);
        if (0 == c->rq.current_chunk_size)
          rbuff_grow_desired =  /* Reading value of the next chunk size */
                               (MHD_CHUNK_HEADER_REASONABLE_LEN >
                                c->read_buffer_size);
        else
        {
          const uint_fast64_t cur_chunk_left =
            c->rq.current_chunk_size - c->rq.current_chunk_offset;
          /* Do not grow read buffer more than necessary to process the current
             chunk with terminating CRLF. */
          mhd_assert (c->rq.current_chunk_offset <= c->rq.current_chunk_size);
          rbuff_grow_desired =
            ((cur_chunk_left + 2) > (uint_fast64_t) (c->read_buffer_size));
        }
      }
    }
  }

  if (! rbuff_grow_desired)
    return true; /* No need to increase the buffer */

  if (try_grow_read_buffer (c, rbuff_grow_required))
    return true; /* Buffer increase succeed */

  if (! rbuff_grow_required)
    return true; /* Can continue without buffer increase */

  /* Failed to increase the read buffer size, but need to read the data
     from the network.
     No more space left in the buffer, no more space to increase the buffer. */

  if (1)
  {
    enum MHD_ProcRecvDataStage stage;

    switch (c->state)
    {
    case MHD_CONNECTION_INIT:
      stage = MHD_PROC_RECV_INIT;
      break;
    case MHD_CONNECTION_REQ_LINE_RECEIVING:
      if (mhd_HTTP_METHOD_NO_METHOD == c->rq.http_mthd)
        stage = MHD_PROC_RECV_METHOD;
      else if (0 == c->rq.req_target_len)
        stage = MHD_PROC_RECV_URI;
      else
        stage = MHD_PROC_RECV_HTTPVER;
      break;
    case MHD_CONNECTION_REQ_HEADERS_RECEIVING:
      stage = MHD_PROC_RECV_HEADERS;
      break;
    case MHD_CONNECTION_BODY_RECEIVING:
      stage = c->rq.have_chunked_upload ?
              MHD_PROC_RECV_BODY_CHUNKED : MHD_PROC_RECV_BODY_NORMAL;
      break;
    case MHD_CONNECTION_FOOTERS_RECEIVING:
      stage = MHD_PROC_RECV_FOOTERS;
      break;
    case MHD_CONNECTION_REQ_LINE_RECEIVED:
    case MHD_CONNECTION_HEADERS_RECEIVED:
    case MHD_CONNECTION_HEADERS_PROCESSED:
    case MHD_CONNECTION_CONTINUE_SENDING:
    case MHD_CONNECTION_BODY_RECEIVED:
    case MHD_CONNECTION_FOOTERS_RECEIVED:
    case MHD_CONNECTION_FULL_REQ_RECEIVED:
    case MHD_CONNECTION_REQ_RECV_FINISHED:
    case MHD_CONNECTION_START_REPLY:
    case MHD_CONNECTION_HEADERS_SENDING:
    case MHD_CONNECTION_HEADERS_SENT:
    case MHD_CONNECTION_UNCHUNKED_BODY_UNREADY:
    case MHD_CONNECTION_UNCHUNKED_BODY_READY:
    case MHD_CONNECTION_CHUNKED_BODY_UNREADY:
    case MHD_CONNECTION_CHUNKED_BODY_READY:
    case MHD_CONNECTION_CHUNKED_BODY_SENT:
    case MHD_CONNECTION_FOOTERS_SENDING:
    case MHD_CONNECTION_FULL_REPLY_SENT:
    case MHD_CONNECTION_CLOSED:
#if 0 // def UPGRADE_SUPPORT // TODO: Upgrade support
    case MHD_CONNECTION_UPGRADE:
#endif
    default:
      mhd_assert (0);
      MHD_UNREACHABLE_;
      stage = MHD_PROC_RECV_BODY_NORMAL;
    }

    handle_recv_no_space (c, stage);
  }
  return false;
}
