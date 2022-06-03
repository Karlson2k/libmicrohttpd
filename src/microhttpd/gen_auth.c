/*
  This file is part of libmicrohttpd
  Copyright (C) 2022 Evgeny Grin (Karlson2k)

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library.
  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file microhttpd/gen_auth.c
 * @brief  HTTP authorisation general functions
 * @author Karlson2k (Evgeny Grin)
 */

#include "gen_auth.h"
#include "internal.h"
#include "connection.h"
#include "mhd_str.h"
#include "mhd_assert.h"

#ifdef BAUTH_SUPPORT
#include "basicauth.h"
#endif /* BAUTH_SUPPORT */
#ifdef DAUTH_SUPPORT
#include "digestauth.h"
#endif /* DAUTH_SUPPORT */

#if ! defined(BAUTH_SUPPORT) && ! defined(DAUTH_SUPPORT)
#error This file requires Basic or Digest authentication support
#endif

#ifdef BAUTH_SUPPORT
/**
 * Parse request Authorization header parameters for Basic Authentication
 * @param str the header string, everything after "Basic " substring
 * @param str_len the length of @a str in characters
 * @param[out] pbauth the pointer to the structure with Basic Authentication
 *               parameters
 * @return true if parameters has been successfully parsed,
 *         false if format of the @a str is invalid
 */
static bool
parse_bauth_params (const char *str,
                    size_t str_len,
                    struct MHD_RqBAuth *pbauth)
{
  size_t i;

  i = 0;

  /* Skip all whitespaces at start */
  while (i < str_len && (' ' == str[i] || '\t' == str[i]))
    i++;

  if (str_len > i)
  {
    size_t token68_start;
    size_t token68_len;

    /* 'i' points to the first non-whitespace char after scheme token */
    token68_start = i;
    /* Find end of the token. Token cannot contain whitespace. */
    while (i < str_len && ' ' != str[i] && '\t' != str[i])
    {
      if (0 == str[0])
        return false; /* Binary zero is not allowed */
      i++;
    }
    token68_len = i - token68_start;
    mhd_assert (0 != token68_len);

    /* Skip all whitespaces */
    while (i < str_len && (' ' == str[i] || '\t' == str[i]))
      i++;
    /* Check whether any garbage is present at the end of the string */
    if (str_len != i)
      return false;
    else
    {
      /* No more data in the string, only single token68. */
      const struct _MHD_cstr_w_len tkn = { str + token68_start, token68_len};
      memcpy (&pbauth->token68, &tkn, sizeof(tkn));
    }
  }
  return true;
}


#endif /* BAUTH_SUPPORT */

#ifdef DAUTH_SUPPORT

/**
 * Helper structure to map token name to position where to put token's value
 */
struct dauth_token_param
{
  const struct _MHD_cstr_w_len *const tk_name;
  struct MHD_RqDAuthParam *const param;
};

/**
 * Parse request Authorization header parameters for Digest Authentication
 * @param str the header string, everything after "Digest " substring
 * @param str_len the length of @a str in characters
 * @param[out] pdauth the pointer to the structure with Digest Authentication
 *               parameters
 * @return true if parameters has been successfully parsed,
 *         false if format of the @a str is invalid
 */
static bool
parse_dauth_params (const char *str,
                    const size_t str_len,
                    struct MHD_RqDAuth *pdauth)
{
  static const struct _MHD_cstr_w_len nonce_tk = _MHD_S_STR_W_LEN ("nonce");
  static const struct _MHD_cstr_w_len opaque_tk = _MHD_S_STR_W_LEN ("opaque");
  static const struct _MHD_cstr_w_len algorithm_tk =
    _MHD_S_STR_W_LEN ("algorithm");
  static const struct _MHD_cstr_w_len response_tk =
    _MHD_S_STR_W_LEN ("response");
  static const struct _MHD_cstr_w_len username_tk =
    _MHD_S_STR_W_LEN ("username");
  static const struct _MHD_cstr_w_len username_ext_tk =
    _MHD_S_STR_W_LEN ("username*");
  static const struct _MHD_cstr_w_len realm_tk = _MHD_S_STR_W_LEN ("realm");
  static const struct _MHD_cstr_w_len uri_tk = _MHD_S_STR_W_LEN ("uri");
  static const struct _MHD_cstr_w_len qop_tk = _MHD_S_STR_W_LEN ("qop");
  static const struct _MHD_cstr_w_len cnonce_tk = _MHD_S_STR_W_LEN ("cnonce");
  static const struct _MHD_cstr_w_len nc_tk = _MHD_S_STR_W_LEN ("nc");
  static const struct _MHD_cstr_w_len userhash_tk =
    _MHD_S_STR_W_LEN ("userhash");
  struct MHD_RqDAuthParam userhash;
  struct dauth_token_param map[] = {
    {&nonce_tk, &(pdauth->nonce)},
    {&opaque_tk, &(pdauth->opaque)},
    {&algorithm_tk, &(pdauth->algorithm)},
    {&response_tk, &(pdauth->response)},
    {&username_tk, &(pdauth->username)},
    {&username_ext_tk, &(pdauth->username_ext)},
    {&realm_tk, &(pdauth->realm)},
    {&uri_tk, &(pdauth->uri)},
    {&qop_tk, &(pdauth->qop)},
    {&cnonce_tk, &(pdauth->cnonce)},
    {&nc_tk, &(pdauth->nc)},
    {&userhash_tk, &userhash}
  };
  size_t i;
  size_t p;

  memset (&userhash, 0, sizeof(userhash));
  i = 0;

  /* Skip all whitespaces at start */
  while (i < str_len && (' ' == str[i] || '\t' == str[i]))
    i++;

  while (str_len > i)
  {
    size_t left;
    mhd_assert (' ' != str[i]);
    mhd_assert ('\t' != str[i]);

    left = str_len - i;
    for (p = 0; p < sizeof(map) / sizeof(map[0]); p++)
    {
      struct dauth_token_param *const aparam = map + p;
      if ( (aparam->tk_name->len <= left) &&
           MHD_str_equal_caseless_bin_n_ (str + i, aparam->tk_name->str,
                                          aparam->tk_name->len) &&
           ((aparam->tk_name->len == left) ||
            ('=' == str[i + aparam->tk_name->len]) ||
            (' ' == str[i + aparam->tk_name->len]) ||
            ('\t' == str[i + aparam->tk_name->len]) ||
            (',' == str[i + aparam->tk_name->len])) )
      {
        size_t value_start;
        size_t value_len;
        bool quoted; /* Only mark as "quoted" if backslash-escape used */

        if (aparam->tk_name->len == left)
          return false; /* No equal sign after parameter name, broken data */

        quoted = false;
        i += aparam->tk_name->len;
        /* Skip all whitespaces before '=' */
        while (str_len > i && (' ' == str[i] || '\t' == str[i]))
          i++;
        if ((i == str_len) || ('=' != str[i]))
          return false; /* No equal sign, broken data */
        i++;
        /* Skip all whitespaces after '=' */
        while (str_len > i && (' ' == str[i] || '\t' == str[i]))
          i++;
        if ((str_len > i) && ('"' == str[i]))
        { /* Value is in quotation marks */
          i++; /* Advance after the opening quote */
          value_start = i;
          while (str_len > i && '"' != str[i])
          {
            if ('\\' == str[i])
            {
              i++;
              quoted = true; /* Have escaped chars */
            }
            if (0 == str[i])
              return false; /* Binary zero in parameter value */
            i++;
          }
          if (str_len <= i)
            return false; /* No closing quote */
          mhd_assert ('"' == str[i]);
          value_len = i - value_start;
          i++; /* Advance after the closing quote */
        }
        else
        {
          value_start = i;
          while (str_len > i && ',' != str[i] &&
                 ' ' != str[i] && '\t' != str[i] && ';' != str[i])
          {
            if (0 == str[i])
              return false;  /* Binary zero in parameter value */
            i++;
          }
          value_len = i - value_start;
        }
        /* Skip all whitespaces after parameter value */
        while (str_len > i && (' ' == str[i] || '\t' == str[i]))
          i++;
        if ((str_len > i) && (',' != str[i]))
          return false; /* Garbage after parameter value */

        /* Have valid parameter name and value */
        mhd_assert (! quoted || 0 != value_len);
        if (1)
        {
          const struct _MHD_cstr_w_len val = {str + value_start, value_len};
          memcpy (&aparam->param->value, &val, sizeof(val));
        }
        aparam->param->quoted = quoted;

        break; /* Found matching parameter name */
      }
    }
    if (p == sizeof(map) / sizeof(map[0]))
    {
      /* No matching parameter name */
      while (str_len > i && ',' != str[i])
      {
        if ('"' == str[i])
        { /* Skip quoted part */
          i++; /* Advance after the opening quote */
          while (str_len > i && '"' != str[i])
          {
            if ('\\' == str[i])
              i++; /* Skip escaped char */
            i++;
          }
          if (str_len <= i)
            return false; /* No closing quote */
          mhd_assert ('"' == str[i]);
        }
        i++;
      }
    }
    mhd_assert (str_len == i || ',' == str[i]);
    if (str_len > i)
      i++; /* Advance after ',' */
    /* Skip all whitespaces before next parameter name */
    while (i < str_len && (' ' == str[i] || '\t' == str[i]))
      i++;
  }

  /* Postprocess values */
  if ((NULL != userhash.value.str) && (0 != userhash.value.len))
  {
    const char *param_str;
    size_t param_len;
    char buf[5 * 2]; /* 5 is the length of "false" (longer then "true") */
    if (! userhash.quoted)
    {
      param_str = userhash.value.str;
      param_len = userhash.value.len;
    }
    else
    {
      if (sizeof(buf) / sizeof(buf[0]) >= userhash.value.len)
      {
        param_len = MHD_str_unquote (userhash.value.str, userhash.value.len,
                                     buf);
        param_str = buf;
      }
      else
      {
        param_len = 0;
        param_str = NULL; /* Actually not used */
      }
    }
    if ((param_len == 4) && MHD_str_equal_caseless_bin_n_ (param_str, "true",
                                                           4))
      pdauth->userhash = true;
    else
      pdauth->userhash = false;
  }
  else
    pdauth->userhash = false;

  return true;
}


#endif /* DAUTH_SUPPORT */


/**
 * Parse request "Authorization" header
 * @param c the connection to process
 * @return true if any supported Authorisation scheme were found,
 *         false if no "Authorization" header found, no supported scheme found,
 *         or an error occurred.
 */
_MHD_static_inline bool
parse_auth_rq_header_ (struct MHD_Connection *c)
{
  const char *h; /**< The "Authorization" header */
  size_t h_len;
  struct MHD_AuthRqHeader *rq_auth;
  size_t i;

  mhd_assert (NULL == c->rq_auth);
  mhd_assert (MHD_CONNECTION_HEADERS_PROCESSED <= c->state);
  if (MHD_CONNECTION_HEADERS_PROCESSED > c->state)
    return false;

  if (MHD_NO ==
      MHD_lookup_connection_value_n (c, MHD_HEADER_KIND,
                                     MHD_HTTP_HEADER_AUTHORIZATION,
                                     MHD_STATICSTR_LEN_ ( \
                                       MHD_HTTP_HEADER_AUTHORIZATION), &h,
                                     &h_len))
  {
    rq_auth = (struct MHD_AuthRqHeader *)
              MHD_connection_alloc_memory_ (c,
                                            sizeof (struct MHD_AuthRqHeader));
    c->rq_auth = rq_auth;
    if (NULL != rq_auth)
    {
      memset (rq_auth, 0, sizeof(struct MHD_AuthRqHeader));
      rq_auth->auth_type = MHD_AUTHTYPE_NONE;
    }
    return false;
  }

  rq_auth = NULL;
  i = 0;
  /* Skip the leading whitespace */
  while (i < h_len)
  {
    const char ch = h[i];
    if ((' ' != ch) && ('\t' != ch))
      break;
    i++;
  }
  h += i;
  h_len -= i;

  if (0 == h_len)
  { /* The header is an empty string */
    rq_auth = (struct MHD_AuthRqHeader *)
              MHD_connection_alloc_memory_ (c,
                                            sizeof (struct MHD_AuthRqHeader));
    c->rq_auth = rq_auth;
    if (NULL != rq_auth)
    {
      memset (rq_auth, 0, sizeof(struct MHD_AuthRqHeader));
      rq_auth->auth_type = MHD_AUTHTYPE_INVALID;
    }
    return false;
  }

#ifdef DAUTH_SUPPORT
  if (1)
  {
    static const struct _MHD_cstr_w_len scheme_token =
      _MHD_S_STR_W_LEN (_MHD_AUTH_DIGEST_BASE);

    if ((scheme_token.len <= h_len) &&
        MHD_str_equal_caseless_bin_n_ (h, scheme_token.str, scheme_token.len))
    {
      i = scheme_token.len;
      /* RFC 7235 require only space after scheme token */
      if ( (h_len <= i) ||
           ((' ' == h[i]) || ('\t' == h[i])) ) /* Actually tab should NOT be allowed */
      { /* Matched Digest authorisation scheme */
        i++; /* Advance to the next char (even if it is beyond the end of the string) */

        rq_auth = (struct MHD_AuthRqHeader *)
                  MHD_connection_alloc_memory_ (c,
                                                sizeof (struct MHD_AuthRqHeader)
                                                + sizeof (struct MHD_RqDAuth));
        c->rq_auth = rq_auth;
        if (NULL == rq_auth)
        {
#ifdef HAVE_MESSAGES
          MHD_DLOG (c->daemon,
                    _ ("Failed to allocate memory in connection pool to " \
                       "process \"" MHD_HTTP_HEADER_AUTHORIZATION "\" " \
                       "header.\n"));
#endif /* HAVE_MESSAGES */
          return false;
        }
        memset (rq_auth, 0, sizeof (struct MHD_AuthRqHeader)
                + sizeof (struct MHD_RqDAuth));
        rq_auth->params.dauth = (struct MHD_RqDAuth *) (rq_auth + 1);

        if (h_len > i)
        {
          if (! parse_dauth_params (h + i, h_len - i, rq_auth->params.dauth))
          {
            rq_auth->auth_type = MHD_AUTHTYPE_INVALID;
            return false;
          }
        }

        rq_auth->auth_type = MHD_AUTHTYPE_DIGEST;
        return true;
      }
    }
  }
#endif /* DAUTH_SUPPORT */
#ifdef BAUTH_SUPPORT
  if (1)
  {
    static const struct _MHD_cstr_w_len scheme_token =
      _MHD_S_STR_W_LEN (_MHD_AUTH_BASIC_BASE);

    if ((scheme_token.len <= h_len) &&
        MHD_str_equal_caseless_bin_n_ (h, scheme_token.str, scheme_token.len))
    {
      i = scheme_token.len;
      /* RFC 7235 require only space after scheme token */
      if ( (h_len <= i) ||
           ((' ' == h[i]) || ('\t' == h[i])) ) /* Actually tab should NOT be allowed */
      { /* Matched Basic authorisation scheme */
        i++; /* Advance to the next char (even if it is beyond the end of the string) */

        rq_auth = (struct MHD_AuthRqHeader *)
                  MHD_connection_alloc_memory_ (c,
                                                sizeof (struct MHD_AuthRqHeader)
                                                + sizeof (struct MHD_RqBAuth));
        c->rq_auth = rq_auth;
        if (NULL == rq_auth)
        {
#ifdef HAVE_MESSAGES
          MHD_DLOG (c->daemon,
                    _ ("Failed to allocate memory in connection pool to " \
                       "process \"" MHD_HTTP_HEADER_AUTHORIZATION "\" " \
                       "header.\n"));
#endif /* HAVE_MESSAGES */
          return false;
        }
        memset (rq_auth, 0, sizeof (struct MHD_AuthRqHeader)
                + sizeof (struct MHD_RqBAuth));
        rq_auth->params.bauth = (struct MHD_RqBAuth *) (rq_auth + 1);

        if (h_len > i)
        {
          if (! parse_bauth_params (h + i, h_len - i, rq_auth->params.bauth))
          {
            rq_auth->auth_type = MHD_AUTHTYPE_INVALID;
            return false;
          }
        }

        rq_auth->auth_type = MHD_AUTHTYPE_BASIC;
        return true;
      }
    }
  }
#endif /* BAUTH_SUPPORT */

  if (NULL == rq_auth)
    rq_auth = (struct MHD_AuthRqHeader *)
              MHD_connection_alloc_memory_ (c,
                                            sizeof (struct MHD_AuthRqHeader));
  c->rq_auth = rq_auth;
  if (NULL != rq_auth)
  {
    memset (rq_auth, 0, sizeof(struct MHD_AuthRqHeader));
    rq_auth->auth_type = MHD_AUTHTYPE_UNKNOWN;
  }
  return false;
}


/**
 * Return request's Authentication type and parameters.
 *
 * Function return result of parsing of the request's "Authorization" header or
 * returns cached parsing result if the header was already parsed for
 * the current request.
 * @param connection the connection to process
 * @return the pointer to structure with Authentication type and parameters,
 *         NULL if no memory in memory pool or if called too early (before
 *         header has been received).
 */
const struct MHD_AuthRqHeader *
MHD_get_auth_rq_params_ (struct MHD_Connection *connection)
{
  mhd_assert (MHD_CONNECTION_HEADERS_PROCESSED <= connection->state);

  if (NULL != connection->rq_auth)
    return connection->rq_auth;

  if (MHD_CONNECTION_HEADERS_PROCESSED > connection->state)
    return NULL;

  parse_auth_rq_header_ (connection);

  return connection->rq_auth;
}
