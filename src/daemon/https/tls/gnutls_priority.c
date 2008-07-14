/*
 * Copyright (C) 2004, 2005, 2006, 2007 Free Software Foundation
 *
 * Author: Nikos Mavrogiannopoulos
 *
 * This file is part of GNUTLS.
 *
 * The GNUTLS library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 * USA
 *
 */

/* Here lies the code of the gnutls_*_set_priority() functions.
 */

#include "gnutls_int.h"
#include "gnutls_algorithms.h"
#include "gnutls_errors.h"
#include <gnutls_num.h>

#define MAX_ELEMENTS 48

/**
 * gnutls_cipher_set_priority - Sets the priority on the ciphers supported by gnutls.
 * @session: is a #gnutls_session_t structure.
 * @list: is a 0 terminated list of gnutls_cipher_algorithm_t elements.
 *
 * Sets the priority on the ciphers supported by gnutls.
 * Priority is higher for elements specified before others.
 * After specifying the ciphers you want, you must append a 0.
 * Note that the priority is set on the client. The server does
 * not use the algorithm's priority except for disabling
 * algorithms that were not specified.
 *
 * Returns 0 on success.
 *
 **/
int
gnutls_cipher_set_priority (gnutls_session_t session, const int *list)
{
  int num = 0, i;

  while (list[num] != 0)
    num++;
  if (num > MAX_ALGOS)
    num = MAX_ALGOS;
  session->internals.priorities.cipher.algorithms = num;

  for (i = 0; i < num; i++)
    {
      session->internals.priorities.cipher.priority[i] = list[i];
    }

  return 0;
}

inline static int
_set_priority (priority_st * st, const int *list)
{
  int num = 0, i;

  while (list[num] != 0)
    num++;
  if (num > MAX_ALGOS)
    num = MAX_ALGOS;
  st->algorithms = num;

  for (i = 0; i < num; i++)
    {
      st->priority[i] = list[i];
    }

  return 0;
}

/**
 * gnutls_kx_set_priority - Sets the priority on the key exchange algorithms supported by gnutls.
 * @session: is a #gnutls_session_t structure.
 * @list: is a 0 terminated list of gnutls_kx_algorithm_t elements.
 *
 * Sets the priority on the key exchange algorithms supported by gnutls.
 * Priority is higher for elements specified before others.
 * After specifying the algorithms you want, you must append a 0.
 * Note that the priority is set on the client. The server does
 * not use the algorithm's priority except for disabling
 * algorithms that were not specified.
 *
 * Returns 0 on success.
 *
 **/
int
gnutls_kx_set_priority (gnutls_session_t session, const int *list)
{
  return _set_priority (&session->internals.priorities.kx, list);
}

/**
 * gnutls_mac_set_priority - Sets the priority on the mac algorithms supported by gnutls.
 * @session: is a #gnutls_session_t structure.
 * @list: is a 0 terminated list of gnutls_mac_algorithm_t elements.
 *
 * Sets the priority on the mac algorithms supported by gnutls.
 * Priority is higher for elements specified before others.
 * After specifying the algorithms you want, you must append a 0.
 * Note that the priority is set on the client. The server does
 * not use the algorithm's priority except for disabling
 * algorithms that were not specified.
 *
 * Returns 0 on success.
 *
 **/
int
gnutls_mac_set_priority (gnutls_session_t session, const int *list)
{
  return _set_priority (&session->internals.priorities.mac, list);
}

/**
 * gnutls_compression_set_priority - Sets the priority on the compression algorithms supported by gnutls.
 * @session: is a #gnutls_session_t structure.
 * @list: is a 0 terminated list of gnutls_compression_method_t elements.
 *
 * Sets the priority on the compression algorithms supported by gnutls.
 * Priority is higher for elements specified before others.
 * After specifying the algorithms you want, you must append a 0.
 * Note that the priority is set on the client. The server does
 * not use the algorithm's priority except for disabling
 * algorithms that were not specified.
 *
 * TLS 1.0 does not define any compression algorithms except
 * NULL. Other compression algorithms are to be considered
 * as gnutls extensions.
 *
 * Returns 0 on success.
 *
 **/
int
gnutls_compression_set_priority (gnutls_session_t session, const int *list)
{
  return _set_priority (&session->internals.priorities.compression, list);
}

/**
 * gnutls_protocol_set_priority - Sets the priority on the protocol versions supported by gnutls.
 * @session: is a #gnutls_session_t structure.
 * @list: is a 0 terminated list of gnutls_protocol_t elements.
 *
 * Sets the priority on the protocol versions supported by gnutls.
 * This function actually enables or disables protocols. Newer protocol
 * versions always have highest priority.
 *
 * Returns 0 on success.
 *
 **/
int
gnutls_protocol_set_priority (gnutls_session_t session, const int *list)
{
  int ret;

  ret = _set_priority (&session->internals.priorities.protocol, list);

  /* set the current version to the first in the chain.
   * This will be overridden later.
   */
  if (list)
    _gnutls_set_current_version (session, list[0]);

  return ret;
}

/**
 * gnutls_certificate_type_set_priority - Sets the priority on the certificate types supported by gnutls.
 * @session: is a #gnutls_session_t structure.
 * @list: is a 0 terminated list of gnutls_certificate_type_t elements.
 *
 * Sets the priority on the certificate types supported by gnutls.
 * Priority is higher for elements specified before others.
 * After specifying the types you want, you must append a 0.
 * Note that the certificate type priority is set on the client.
 * The server does not use the cert type priority except for disabling
 * types that were not specified.
 *
 * Returns 0 on success.
 *
 **/
int
gnutls_certificate_type_set_priority (gnutls_session_t session,
                                      const int *list)
{
#if ENABLE_OPENPGP
  return _set_priority (&session->internals.priorities.cert_type, list);
#else

  return GNUTLS_E_UNIMPLEMENTED_FEATURE;

#endif
}

static const int protocol_priority[] = { GNUTLS_TLS1_1,
  GNUTLS_TLS1_0,
  GNUTLS_SSL3,
  0
};

static const int cipher_priority_secure256[] = { GNUTLS_CIPHER_AES_256_CBC,
  0
};

static const int kx_priority_secure[] = { GNUTLS_KX_RSA,
  0
};

static const int mac_priority_secure[] = { GNUTLS_MAC_SHA1,
  0
};

static int cert_type_priority[] = { GNUTLS_CRT_X509,
  0
};

static const int comp_priority[] = { GNUTLS_COMP_NULL,
  0
};

typedef void (rmadd_func) (priority_st * priority_list, int alg);

/**
 * gnutls_priority_set - Sets priorities for the cipher suites supported by gnutls.
 * @session: is a #gnutls_session_t structure.
 * @priority: is a #gnutls_priority_t structure.
 *
 * Sets the priorities to use on the ciphers, key exchange methods,
 * macs and compression methods.
 *
 * On success 0 is returned.
 *
 **/
int
gnutls_priority_set (gnutls_session_t session, gnutls_priority_t priority)
{
  if (priority == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_NO_CIPHER_SUITES;
    }

  memcpy (&session->internals.priorities, priority,
          sizeof (struct gnutls_priority_st));

  return 0;
}

/**
 * gnutls_priority_init - Sets priorities for the cipher suites supported by gnutls.
 * @priority_cache: is a #gnutls_prioritity_t structure.
 * @priorities: is a string describing priorities
 * @err_pos: In case of an error this will have the position in the string the error occured
 *
 * Sets priorities for the ciphers, key exchange methods, macs and
 * compression methods. This is to avoid using the
 * gnutls_*_priority() functions.
 *
 * The #priorities option allows you to specify a semi-colon
 * separated list of the cipher priorities to enable.
 *
 * Unless the first keyword is "NONE" the defaults are:
 * Protocols: TLS1.1, TLS1.0, and SSL3.0.
 * Compression: NULL.
 * Certificate types: X.509, OpenPGP.
 *
 * You can also use predefined sets of ciphersuites: "PERFORMANCE"
 * all the "secure" ciphersuites are enabled, limited to 128 bit
 * ciphers and sorted by terms of speed performance.
 *
 * "NORMAL" option enables all "secure" ciphersuites. The 256-bit ciphers
 * are included as a fallback only. The ciphers are sorted by security margin.
 *
 * "SECURE128" flag enables all "secure" ciphersuites with ciphers up to
 * 128 bits, sorted by security margin.
 *
 * "SECURE256" flag enables all "secure" ciphersuites including the 256 bit
 * ciphers, sorted by security margin.
 *
 * "EXPORT" all the ciphersuites are enabled, including the
 * low-security 40 bit ciphers.
 *
 * "NONE" nothing is enabled. This disables even protocols and
 * compression methods.
 *
 * Special keywords:
 * '!' or '-' appended with an algorithm will remove this algorithm.
 * '+' appended with an algorithm will add this algorithm.
 * '%COMPAT' will enable compatibility features for a server.
 *
 * To avoid collisions in order to specify a compression algorithm in
 * this string you have to prefix it with "COMP-", protocol versions
 * with "VERS-" and certificate types with "CTYPE-". All other
 * algorithms don't need a prefix.
 *
 * For key exchange algorithms when in NORMAL or SECURE levels the
 * perfect forward secrecy algorithms take precendence of the other
 * protocols.  In all cases all the supported key exchange algorithms
 * are enabled (except for the RSA-EXPORT which is only enabled in
 * EXPORT level).
 *
 * Note that although one can select very long key sizes (such as 256 bits)
 * for symmetric algorithms, to actually increase security the public key
 * algorithms have to use longer key sizes as well.
 *
 * Examples: "NORMAL:!AES-128-CBC",
 * "EXPORT:!VERS-TLS1.0:+COMP-DEFLATE:+CTYPE-OPENPGP",
 * "NONE:+VERS-TLS1.0:+AES-128-CBC:+RSA:+SHA1:+COMP-NULL", "NORMAL",
 * "NORMAL:%COMPAT".
 *
 * Returns: On syntax error GNUTLS_E_INVALID_REQUEST is returned and
 * 0 on success.
 **/
int
gnutls_priority_init (gnutls_priority_t * priority_cache,
                      const char *priorities, const char **err_pos)
{
  *priority_cache = gnutls_calloc (1, sizeof (struct gnutls_priority_st));
  if (*priority_cache == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  /* set mode to "SECURE256" */
  _set_priority (&(*priority_cache)->protocol, protocol_priority);
  _set_priority (&(*priority_cache)->cipher, cipher_priority_secure256);
  _set_priority (&(*priority_cache)->kx, kx_priority_secure);
  _set_priority (&(*priority_cache)->mac, mac_priority_secure);
  _set_priority (&(*priority_cache)->cert_type, cert_type_priority);
  _set_priority (&(*priority_cache)->compression, comp_priority);

  (*priority_cache)->no_padding = 0;
  return 0;
}

/**
 * gnutls_priority_deinit - Deinitialize the priorities cache for the cipher suites supported by gnutls.
 * @priority_cache: is a #gnutls_prioritity_t structure.
 *
 * Deinitializes the priority cache.
 *
 **/
void
gnutls_priority_deinit (gnutls_priority_t priority_cache)
{
  gnutls_free (priority_cache);
}

/**
 * gnutls_priority_set_direct - Sets priorities for the cipher suites supported by gnutls.
 * @session: is a #gnutls_session_t structure.
 * @priorities: is a string describing priorities
 * @err_pos: In case of an error this will have the position in the string the error occured
 *
 * Sets the priorities to use on the ciphers, key exchange methods,
 * macs and compression methods. This function avoids keeping a
 * priority cache and is used to directly set string priorities to a
 * TLS session.  For documentation check the gnutls_priority_init().
 *
 * On syntax error GNUTLS_E_INVALID_REQUEST is returned and 0 on success.
 *
 **/
int
gnutls_priority_set_direct (gnutls_session_t session,
                            const char *priorities, const char **err_pos)
{
  gnutls_priority_t prio;
  int ret;

  ret = gnutls_priority_init (&prio, priorities, err_pos);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = gnutls_priority_set (session, prio);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  gnutls_priority_deinit (prio);

  return 0;
}

/**
 * gnutls_set_default_priority - Sets some default priority on the cipher suites supported by gnutls.
 * @session: is a #gnutls_session_t structure.
 *
 * Sets some default priority on the ciphers, key exchange methods,
 * macs and compression methods.
 *
 * This is the same as calling:
 *
 * gnutls_priority_set_direct (session, "NORMAL", NULL);
 *
 * This function is kept around for backwards compatibility, but
 * because of its wide use it is still fully supported.  If you wish
 * to allow users to provide a string that specify which ciphers to
 * use (which is recommended), you should use
 * gnutls_priority_set_direct() or gnutls_priority_set() instead.
 *
 * Returns 0 on success.
 **/
int
gnutls_set_default_priority (gnutls_session_t session)
{
  return gnutls_priority_set_direct (session, "NORMAL", NULL);
}

/**
 * gnutls_set_default_export_priority - Sets some default priority on the cipher suites supported by gnutls.
 * @session: is a #gnutls_session_t structure.
 *
 * Sets some default priority on the ciphers, key exchange methods, macs
 * and compression methods.  This function also includes weak algorithms.
 *
 * This is the same as calling:
 *
 * gnutls_priority_set_direct (session, "EXPORT", NULL);
 *
 * This function is kept around for backwards compatibility, but
 * because of its wide use it is still fully supported.  If you wish
 * to allow users to provide a string that specify which ciphers to
 * use (which is recommended), you should use
 * gnutls_priority_set_direct() or gnutls_priority_set() instead.
 *
 * Returns 0 on success.
 **/
int
gnutls_set_default_export_priority (gnutls_session_t session)
{
  return gnutls_priority_set_direct (session, "EXPORT", NULL);
}
