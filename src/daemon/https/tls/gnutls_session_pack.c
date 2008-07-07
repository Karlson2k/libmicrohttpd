/*
 * Copyright (C) 2000, 2004, 2005, 2007 Free Software Foundation
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

/* Contains functions that are supposed to pack and unpack session data,
 * before and after they are sent to the database backend.
 */

#include <gnutls_int.h>
#ifdef ENABLE_SRP
# include <auth_srp.h>
#endif
#ifdef ENABLE_PSK
# include <auth_psk.h>
#endif
#include <auth_anon.h>
#include <auth_cert.h>
#include <gnutls_errors.h>
#include <gnutls_auth_int.h>
#include <gnutls_session_pack.h>
#include <gnutls_datum.h>
#include <gnutls_num.h>

#define PACK_HEADER_SIZE 1
#define MAX_SEC_PARAMS 7+MAX_SRP_USERNAME+MAX_SERVER_NAME_EXTENSIONS*(3+MAX_SERVER_NAME_SIZE)+165
static int pack_certificate_auth_info (gnutls_session_t,
                                       gnutls_datum_t * packed_session);
static int unpack_certificate_auth_info (gnutls_session_t,
                                         const gnutls_datum_t *
                                         packed_session);

static int unpack_security_parameters (gnutls_session_t session,
                                       const gnutls_datum_t * packed_session);
static int pack_security_parameters (gnutls_session_t session,
                                     gnutls_datum_t * packed_session);


/* Since auth_info structures contain malloced data, this function
 * is required in order to pack these structures in a vector in
 * order to store them to the DB.
 *
 * packed_session will contain the session data.
 *
 * The data will be in a platform independent format.
 */
int
_gnutls_session_pack (gnutls_session_t session,
                      gnutls_datum_t * packed_session)
{
  int ret;

  if (packed_session == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }


  switch (gnutls_auth_get_type (session))
    {
#ifdef ENABLE_SRP
    case GNUTLS_CRD_SRP:
      ret = pack_srp_auth_info (session, packed_session);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
      break;
#endif
#ifdef ENABLE_PSK
    case GNUTLS_CRD_PSK:
      ret = pack_psk_auth_info (session, packed_session);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
      break;
#endif
#ifdef ENABLE_ANON
    case GNUTLS_CRD_ANON:
      ret = pack_anon_auth_info (session, packed_session);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
      break;
#endif
    case GNUTLS_CRD_CERTIFICATE:
      ret = pack_certificate_auth_info (session, packed_session);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
      break;
    default:
      return GNUTLS_E_INTERNAL_ERROR;

    }

  /* Auth_info structures copied. Now copy security_parameters_st. 
   * packed_session must have allocated space for the security parameters.
   */
  ret = pack_security_parameters (session, packed_session);
  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_free_datum (packed_session);
      return ret;
    }

  return 0;
}


/* Load session data from a buffer.
 */
int
_gnutls_session_unpack (gnutls_session_t session,
                        const gnutls_datum_t * packed_session)
{
  int ret;

  if (packed_session == NULL || packed_session->size == 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (_gnutls_get_auth_info (session) != NULL)
    {
      _gnutls_free_auth_info (session);
    }

  switch (packed_session->data[0])
    {
#ifdef ENABLE_SRP
    case GNUTLS_CRD_SRP:
      ret = unpack_srp_auth_info (session, packed_session);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
      break;
#endif
#ifdef ENABLE_PSK
    case GNUTLS_CRD_PSK:
      ret = unpack_psk_auth_info (session, packed_session);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
      break;
#endif
#ifdef ENABLE_ANON
    case GNUTLS_CRD_ANON:
      ret = unpack_anon_auth_info (session, packed_session);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
      break;
#endif
    case GNUTLS_CRD_CERTIFICATE:
      ret = unpack_certificate_auth_info (session, packed_session);
      if (ret < 0)
        {
          gnutls_assert ();
          return ret;
        }
      break;
    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;

    }

  /* Auth_info structures copied. Now copy security_parameters_st. 
   * packed_session must have allocated space for the security parameters.
   */
  ret = unpack_security_parameters (session, packed_session);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return 0;
}


/* Format:
 *      1 byte the credentials type
 *      4 bytes the size of the whole structure
 *        DH stuff
 *      2 bytes the size of secret key in bits
 *      4 bytes the size of the prime
 *      x bytes the prime
 *      4 bytes the size of the generator
 *      x bytes the generator
 *      4 bytes the size of the public key
 *      x bytes the public key
 *        RSA stuff
 *      4 bytes the size of the modulus
 *      x bytes the modulus
 *      4 bytes the size of the exponent
 *      x bytes the exponent
 *        CERTIFICATES
 *      4 bytes the length of the certificate list
 *      4 bytes the size of first certificate
 *      x bytes the certificate
 *       and so on...
 */
static int
pack_certificate_auth_info (gnutls_session_t session,
                            gnutls_datum_t * packed_session)
{
  unsigned int pos = 0, i;
  int cert_size, pack_size;
  cert_auth_info_t info = _gnutls_get_auth_info (session);

  if (info)
    {
      cert_size = 4;

      for (i = 0; i < info->ncerts; i++)
        cert_size += 4 + info->raw_certificate_list[i].size;

      pack_size = 2 + 4 + info->dh.prime.size +
        4 + info->dh.generator.size + 4 + info->dh.public_key.size +
        4 + info->rsa_export.modulus.size +
        4 + info->rsa_export.exponent.size + cert_size;
    }
  else
    pack_size = 0;

  packed_session->size = PACK_HEADER_SIZE + pack_size + sizeof (uint32_t);

  /* calculate the size and allocate the data.
   */
  packed_session->data =
    gnutls_malloc (packed_session->size + MAX_SEC_PARAMS);

  if (packed_session->data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  packed_session->data[0] = GNUTLS_CRD_CERTIFICATE;
  _gnutls_write_uint32 (pack_size, &packed_session->data[PACK_HEADER_SIZE]);
  pos += 4 + PACK_HEADER_SIZE;


  if (pack_size > 0)
    {

      _gnutls_write_uint16 (info->dh.secret_bits, &packed_session->data[pos]);
      pos += 2;

      _gnutls_write_datum32 (&packed_session->data[pos], info->dh.prime);
      pos += 4 + info->dh.prime.size;
      _gnutls_write_datum32 (&packed_session->data[pos], info->dh.generator);
      pos += 4 + info->dh.generator.size;
      _gnutls_write_datum32 (&packed_session->data[pos], info->dh.public_key);
      pos += 4 + info->dh.public_key.size;

      _gnutls_write_datum32 (&packed_session->data[pos],
                             info->rsa_export.modulus);
      pos += 4 + info->rsa_export.modulus.size;
      _gnutls_write_datum32 (&packed_session->data[pos],
                             info->rsa_export.exponent);
      pos += 4 + info->rsa_export.exponent.size;

      _gnutls_write_uint32 (info->ncerts, &packed_session->data[pos]);
      pos += 4;

      for (i = 0; i < info->ncerts; i++)
        {
          _gnutls_write_datum32 (&packed_session->data[pos],
                                 info->raw_certificate_list[i]);
          pos += sizeof (uint32_t) + info->raw_certificate_list[i].size;
        }
    }

  return 0;
}


/* Upack certificate info.
 */
static int
unpack_certificate_auth_info (gnutls_session_t session,
                              const gnutls_datum_t * packed_session)
{
  int pos = 0, size, ret;
  unsigned int i = 0, j;
  size_t pack_size;
  cert_auth_info_t info;

  if (packed_session->data[0] != GNUTLS_CRD_CERTIFICATE)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  pack_size = _gnutls_read_uint32 (&packed_session->data[PACK_HEADER_SIZE]);
  pos += PACK_HEADER_SIZE + 4;

  if (pack_size == 0)
    return 0;                   /* nothing to be done */

  /* a simple check for integrity */
  if (pack_size + PACK_HEADER_SIZE + 4 > packed_session->size)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* client and server have the same auth_info here
   */
  ret =
    _gnutls_auth_info_set (session, GNUTLS_CRD_CERTIFICATE,
                           sizeof (cert_auth_info_st), 1);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  info = _gnutls_get_auth_info (session);
  if (info == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  info->dh.secret_bits = _gnutls_read_uint16 (&packed_session->data[pos]);
  pos += 2;

  size = _gnutls_read_uint32 (&packed_session->data[pos]);
  pos += 4;
  ret = _gnutls_set_datum (&info->dh.prime, &packed_session->data[pos], size);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pos += size;

  size = _gnutls_read_uint32 (&packed_session->data[pos]);
  pos += 4;
  ret =
    _gnutls_set_datum (&info->dh.generator, &packed_session->data[pos], size);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pos += size;

  size = _gnutls_read_uint32 (&packed_session->data[pos]);
  pos += 4;
  ret =
    _gnutls_set_datum (&info->dh.public_key, &packed_session->data[pos],
                       size);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pos += size;

  size = _gnutls_read_uint32 (&packed_session->data[pos]);
  pos += 4;
  ret =
    _gnutls_set_datum (&info->rsa_export.modulus,
                       &packed_session->data[pos], size);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pos += size;

  size = _gnutls_read_uint32 (&packed_session->data[pos]);
  pos += 4;
  ret =
    _gnutls_set_datum (&info->rsa_export.exponent,
                       &packed_session->data[pos], size);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pos += size;

  info->ncerts = _gnutls_read_uint32 (&packed_session->data[pos]);
  pos += 4;

  if (info->ncerts > 0)
    {
      info->raw_certificate_list =
        gnutls_calloc (1, sizeof (gnutls_datum_t) * info->ncerts);
      if (info->raw_certificate_list == NULL)
        {
          gnutls_assert ();
          ret = GNUTLS_E_MEMORY_ERROR;
          goto error;
        }
    }

  for (i = 0; i < info->ncerts; i++)
    {
      size = _gnutls_read_uint32 (&packed_session->data[pos]);
      pos += sizeof (uint32_t);

      ret =
        _gnutls_set_datum (&info->raw_certificate_list[i],
                           &packed_session->data[pos], size);
      pos += size;

      if (ret < 0)
        {
          gnutls_assert ();
          goto error;
        }
    }


  return 0;

error:
  _gnutls_free_datum (&info->dh.prime);
  _gnutls_free_datum (&info->dh.generator);
  _gnutls_free_datum (&info->dh.public_key);

  _gnutls_free_datum (&info->rsa_export.modulus);
  _gnutls_free_datum (&info->rsa_export.exponent);

  for (j = 0; j < i; j++)
    _gnutls_free_datum (&info->raw_certificate_list[j]);

  gnutls_free (info->raw_certificate_list);

  return ret;

}

#ifdef ENABLE_SRP
/* Packs the SRP session authentication data.
 */

/* Format: 
 *      1 byte the credentials type
 *      4 bytes the size of the SRP username (x)
 *      x bytes the SRP username
 */
static int
pack_srp_auth_info (gnutls_session_t session, gnutls_datum_t * packed_session)
{
  srp_server_auth_info_t info = _gnutls_get_auth_info (session);
  int pack_size;

  if (info && info->username)
    pack_size = strlen (info->username) + 1;    /* include the terminating null */
  else
    pack_size = 0;

  packed_session->size = PACK_HEADER_SIZE + pack_size + sizeof (uint32_t);

  /* calculate the size and allocate the data.
   */
  packed_session->data =
    gnutls_malloc (packed_session->size + MAX_SEC_PARAMS);

  if (packed_session->data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  packed_session->data[0] = GNUTLS_CRD_SRP;
  _gnutls_write_uint32 (pack_size, &packed_session->data[PACK_HEADER_SIZE]);

  if (pack_size > 0)
    memcpy (&packed_session->data[PACK_HEADER_SIZE + sizeof (uint32_t)],
            info->username, pack_size + 1);

  return 0;
}


static int
unpack_srp_auth_info (gnutls_session_t session,
                      const gnutls_datum_t * packed_session)
{
  size_t username_size;
  int ret;
  srp_server_auth_info_t info;

  if (packed_session->data[0] != GNUTLS_CRD_SRP)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  username_size =
    _gnutls_read_uint32 (&packed_session->data[PACK_HEADER_SIZE]);

  if (username_size == 0)
    return 0;                   /* nothing to be done */

  /* a simple check for integrity */
  if (username_size + 4 + PACK_HEADER_SIZE > packed_session->size)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  ret =
    _gnutls_auth_info_set (session, GNUTLS_CRD_SRP,
                           sizeof (srp_server_auth_info_st), 1);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  info = _gnutls_get_auth_info (session);
  if (info == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  memcpy (info->username,
          &packed_session->data[PACK_HEADER_SIZE + sizeof (uint32_t)],
          username_size);

  return 0;
}
#endif


#ifdef ENABLE_ANON
/* Packs the ANON session authentication data.
 */

/* Format: 
 *      1 byte the credentials type
 *      4 bytes the size of the whole structure
 *      2 bytes the size of secret key in bits
 *      4 bytes the size of the prime
 *      x bytes the prime
 *      4 bytes the size of the generator
 *      x bytes the generator
 *      4 bytes the size of the public key
 *      x bytes the public key
 */
static int
pack_anon_auth_info (gnutls_session_t session,
                     gnutls_datum_t * packed_session)
{
  anon_auth_info_t info = _gnutls_get_auth_info (session);
  int pos = 0;
  size_t pack_size;

  if (info)
    pack_size = 2 + 4 * 3 + info->dh.prime.size +
      info->dh.generator.size + info->dh.public_key.size;
  else
    pack_size = 0;

  packed_session->size = PACK_HEADER_SIZE + pack_size + sizeof (uint32_t);

  /* calculate the size and allocate the data.
   */
  packed_session->data =
    gnutls_malloc (packed_session->size + MAX_SEC_PARAMS);

  if (packed_session->data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  packed_session->data[0] = GNUTLS_CRD_ANON;
  _gnutls_write_uint32 (pack_size, &packed_session->data[PACK_HEADER_SIZE]);
  pos += 4 + PACK_HEADER_SIZE;

  if (pack_size > 0)
    {
      _gnutls_write_uint16 (info->dh.secret_bits, &packed_session->data[pos]);
      pos += 2;

      _gnutls_write_datum32 (&packed_session->data[pos], info->dh.prime);
      pos += 4 + info->dh.prime.size;
      _gnutls_write_datum32 (&packed_session->data[pos], info->dh.generator);
      pos += 4 + info->dh.generator.size;
      _gnutls_write_datum32 (&packed_session->data[pos], info->dh.public_key);
      pos += 4 + info->dh.public_key.size;

    }

  return 0;
}


static int
unpack_anon_auth_info (gnutls_session_t session,
                       const gnutls_datum_t * packed_session)
{
  size_t pack_size;
  int pos = 0, size, ret;
  anon_auth_info_t info;

  if (packed_session->data[0] != GNUTLS_CRD_ANON)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  pack_size = _gnutls_read_uint32 (&packed_session->data[PACK_HEADER_SIZE]);
  pos += PACK_HEADER_SIZE + 4;


  if (pack_size == 0)
    return 0;                   /* nothing to be done */

  /* a simple check for integrity */
  if (pack_size + PACK_HEADER_SIZE + 4 > packed_session->size)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* client and serer have the same auth_info here
   */
  ret =
    _gnutls_auth_info_set (session, GNUTLS_CRD_ANON,
                           sizeof (anon_auth_info_st), 1);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  info = _gnutls_get_auth_info (session);
  if (info == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  info->dh.secret_bits = _gnutls_read_uint16 (&packed_session->data[pos]);
  pos += 2;

  size = _gnutls_read_uint32 (&packed_session->data[pos]);
  pos += 4;
  ret = _gnutls_set_datum (&info->dh.prime, &packed_session->data[pos], size);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pos += size;

  size = _gnutls_read_uint32 (&packed_session->data[pos]);
  pos += 4;
  ret =
    _gnutls_set_datum (&info->dh.generator, &packed_session->data[pos], size);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pos += size;

  size = _gnutls_read_uint32 (&packed_session->data[pos]);
  pos += 4;
  ret =
    _gnutls_set_datum (&info->dh.public_key, &packed_session->data[pos],
                       size);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pos += size;

  return 0;

error:
  _gnutls_free_datum (&info->dh.prime);
  _gnutls_free_datum (&info->dh.generator);
  _gnutls_free_datum (&info->dh.public_key);
  return ret;
}
#endif /* ANON */

#ifdef ENABLE_PSK
/* Packs the PSK session authentication data.
 */

/* Format: 
 *      1 byte the credentials type
 *      4 bytes the size of the whole structure
 *      4 bytes the size of the PSK username (x)
 *      x bytes the PSK username
 *      2 bytes the size of secret key in bits
 *      4 bytes the size of the prime
 *      x bytes the prime
 *      4 bytes the size of the generator
 *      x bytes the generator
 *      4 bytes the size of the public key
 *      x bytes the public key
 */
static int
pack_psk_auth_info (gnutls_session_t session, gnutls_datum_t * packed_session)
{
  psk_auth_info_t info;
  int pack_size, username_size = 0, pos;

  info = _gnutls_get_auth_info (session);

  if (info)
    {
      username_size = strlen (info->username) + 1;      /* include the terminating null */
      pack_size = username_size +
        2 + 4 * 3 + info->dh.prime.size + info->dh.generator.size +
        info->dh.public_key.size;
    }
  else
    pack_size = 0;

  packed_session->size = PACK_HEADER_SIZE + pack_size + sizeof (uint32_t);

  /* calculate the size and allocate the data.
   */
  packed_session->data =
    gnutls_malloc (packed_session->size + MAX_SEC_PARAMS);

  if (packed_session->data == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  pos = 0;

  packed_session->data[pos] = GNUTLS_CRD_PSK;
  pos++;

  _gnutls_write_uint32 (pack_size, &packed_session->data[pos]);
  pos += 4;


  if (pack_size > 0)
    {
      _gnutls_write_uint32 (username_size, &packed_session->data[pos]);
      pos += 4;

      memcpy (&packed_session->data[pos], info->username, username_size);
      pos += username_size;

      _gnutls_write_uint16 (info->dh.secret_bits, &packed_session->data[pos]);
      pos += 2;

      _gnutls_write_datum32 (&packed_session->data[pos], info->dh.prime);
      pos += 4 + info->dh.prime.size;
      _gnutls_write_datum32 (&packed_session->data[pos], info->dh.generator);
      pos += 4 + info->dh.generator.size;
      _gnutls_write_datum32 (&packed_session->data[pos], info->dh.public_key);
      pos += 4 + info->dh.public_key.size;

    }


  return 0;
}

static int
unpack_psk_auth_info (gnutls_session_t session,
                      const gnutls_datum_t * packed_session)
{
  size_t username_size;
  size_t pack_size;
  int pos = 0, size, ret;
  psk_auth_info_t info;

  if (packed_session->data[0] != GNUTLS_CRD_PSK)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  pack_size = _gnutls_read_uint32 (&packed_session->data[PACK_HEADER_SIZE]);
  pos += PACK_HEADER_SIZE + 4;


  if (pack_size == 0)
    return 0;                   /* nothing to be done */

  /* a simple check for integrity */
  if (pack_size + PACK_HEADER_SIZE + 4 > packed_session->size)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  /* client and serer have the same auth_info here
   */
  ret =
    _gnutls_auth_info_set (session, GNUTLS_CRD_PSK,
                           sizeof (psk_auth_info_st), 1);
  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  info = _gnutls_get_auth_info (session);
  if (info == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  username_size = _gnutls_read_uint32 (&packed_session->data[pos]);
  pos += 4;

  memcpy (info->username, &packed_session->data[pos], username_size);
  pos += username_size;

  info->dh.secret_bits = _gnutls_read_uint16 (&packed_session->data[pos]);
  pos += 2;

  size = _gnutls_read_uint32 (&packed_session->data[pos]);
  pos += 4;
  ret = _gnutls_set_datum (&info->dh.prime, &packed_session->data[pos], size);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pos += size;

  size = _gnutls_read_uint32 (&packed_session->data[pos]);
  pos += 4;
  ret =
    _gnutls_set_datum (&info->dh.generator, &packed_session->data[pos], size);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pos += size;

  size = _gnutls_read_uint32 (&packed_session->data[pos]);
  pos += 4;
  ret =
    _gnutls_set_datum (&info->dh.public_key, &packed_session->data[pos],
                       size);
  if (ret < 0)
    {
      gnutls_assert ();
      goto error;
    }
  pos += size;

  return 0;

error:
  _gnutls_free_datum (&info->dh.prime);
  _gnutls_free_datum (&info->dh.generator);
  _gnutls_free_datum (&info->dh.public_key);
  return ret;
}
#endif


/* Packs the security parameters.
 */

/* Format: 
 *      4 bytes the total security data size
 *      1 byte the entity type (client/server)
 *      1 byte the key exchange algorithm used
 *      1 byte the read cipher algorithm
 *      1 byte the read mac algorithm
 *      1 byte the read compression algorithm
 *
 *      1 byte the write cipher algorithm
 *      1 byte the write mac algorithm
 *      1 byte the write compression algorithm
 *
 *      1 byte the certificate type
 *      1 byte the protocol version
 *
 *      2 bytes the cipher suite
 *
 *      48 bytes the master secret
 *
 *      32 bytes the client random
 *      32 bytes the server random
 *
 *      1 byte the session ID size
 *      x bytes the session ID (32 bytes max)
 *
 *      4 bytes a timestamp
 *            -------------------
 *                MAX: 165 bytes
 *
 *      EXTENSIONS:
 *      2 bytes the record send size
 *      2 bytes the record recv size
 *
 *      1 byte the SRP username size
 *      x bytes the SRP username (MAX_SRP_USERNAME)
 *
 *      2 bytes the number of server name extensions (up to MAX_SERVER_NAME_EXTENSIONS)
 *      1 byte the first name type
 *      2 bytes the size of the first name 
 *      x bytes the first name (MAX_SERVER_NAME_SIZE)
 *       and so on...
 *
 *           --------------------
 *                MAX: 7+MAX_SRP_USERNAME+MAX_SERVER_NAME_EXTENSIONS*(3+MAX_SERVER_NAME_SIZE)
 */
static int
pack_security_parameters (gnutls_session_t session,
                          gnutls_datum_t * packed_session)
{
  int pos = 0;
  size_t len, init, i;

  /* move after the auth info stuff.
   */
  init =
    _gnutls_read_uint32 (&packed_session->data[PACK_HEADER_SIZE]) + 4 +
    PACK_HEADER_SIZE;

  pos = init + 4;               /* make some space to write later the size */

  packed_session->data[pos++] = session->security_parameters.entity;
  packed_session->data[pos++] = session->security_parameters.kx_algorithm;
  packed_session->data[pos++] =
    session->security_parameters.read_bulk_cipher_algorithm;
  packed_session->data[pos++] =
    session->security_parameters.read_mac_algorithm;
  packed_session->data[pos++] =
    session->security_parameters.read_compression_algorithm;
  packed_session->data[pos++] =
    session->security_parameters.write_bulk_cipher_algorithm;
  packed_session->data[pos++] =
    session->security_parameters.write_mac_algorithm;
  packed_session->data[pos++] =
    session->security_parameters.write_compression_algorithm;
  packed_session->data[pos++] =
    session->security_parameters.current_cipher_suite.suite[0];
  packed_session->data[pos++] =
    session->security_parameters.current_cipher_suite.suite[1];

  packed_session->data[pos++] = session->security_parameters.cert_type;
  packed_session->data[pos++] = session->security_parameters.version;

  memcpy (&packed_session->data[pos],
          session->security_parameters.master_secret, TLS_MASTER_SIZE);
  pos += TLS_MASTER_SIZE;

  memcpy (&packed_session->data[pos],
          session->security_parameters.client_random, TLS_RANDOM_SIZE);
  pos += TLS_RANDOM_SIZE;
  memcpy (&packed_session->data[pos],
          session->security_parameters.server_random, TLS_RANDOM_SIZE);
  pos += TLS_RANDOM_SIZE;

  packed_session->data[pos++] = session->security_parameters.session_id_size;
  memcpy (&packed_session->data[pos], session->security_parameters.session_id,
          session->security_parameters.session_id_size);
  pos += session->security_parameters.session_id_size;

  _gnutls_write_uint32 (session->security_parameters.timestamp,
                        &packed_session->data[pos]);
  pos += 4;

  /* Extensions */
  _gnutls_write_uint16 (session->security_parameters.max_record_send_size,
                        &packed_session->data[pos]);
  pos += 2;

  _gnutls_write_uint16 (session->security_parameters.max_record_recv_size,
                        &packed_session->data[pos]);
  pos += 2;

  /* SRP */
  len =
    strlen ((char *) session->security_parameters.extensions.srp_username);
  packed_session->data[pos++] = len;
  memcpy (&packed_session->data[pos],
          session->security_parameters.extensions.srp_username, len);
  pos += len;

  _gnutls_write_uint16 (session->security_parameters.extensions.
                        server_names_size, &packed_session->data[pos]);
  pos += 2;

  for (i = 0; i < session->security_parameters.extensions.server_names_size;
       i++)
    {
      packed_session->data[pos++] =
        session->security_parameters.extensions.server_names[i].type;
      _gnutls_write_uint16 (session->security_parameters.extensions.
                            server_names[i].name_length,
                            &packed_session->data[pos]);
      pos += 2;

      memcpy (&packed_session->data[pos],
              session->security_parameters.extensions.server_names[i].name,
              session->security_parameters.extensions.server_names[i].
              name_length);
      pos +=
        session->security_parameters.extensions.server_names[i].name_length;
    }

  /* write the total size */
  _gnutls_write_uint32 (pos - init - 4, &packed_session->data[init]);
  packed_session->size += pos - init;

  return 0;
}


static int
unpack_security_parameters (gnutls_session_t session,
                            const gnutls_datum_t * packed_session)
{
  size_t pack_size, init, i;
  int pos = 0, len;
  time_t timestamp = time (0);


  /* skip the auth info stuff */
  init =
    _gnutls_read_uint32 (&packed_session->data[PACK_HEADER_SIZE]) + 4 +
    PACK_HEADER_SIZE;

  pos = init;

  pack_size = _gnutls_read_uint32 (&packed_session->data[pos]);
  pos += 4;


  if (pack_size == 0)
    return GNUTLS_E_INVALID_REQUEST;

  /* a simple check for integrity */
  if (pack_size > MAX_SEC_PARAMS)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  session->internals.resumed_security_parameters.entity =
    packed_session->data[pos++];
  session->internals.resumed_security_parameters.kx_algorithm =
    packed_session->data[pos++];
  session->internals.resumed_security_parameters.read_bulk_cipher_algorithm =
    packed_session->data[pos++];
  session->internals.resumed_security_parameters.read_mac_algorithm =
    packed_session->data[pos++];
  session->internals.resumed_security_parameters.read_compression_algorithm =
    packed_session->data[pos++];
  session->internals.resumed_security_parameters.write_bulk_cipher_algorithm =
    packed_session->data[pos++];
  session->internals.resumed_security_parameters.write_mac_algorithm =
    packed_session->data[pos++];
  session->internals.resumed_security_parameters.write_compression_algorithm =
    packed_session->data[pos++];
  session->internals.resumed_security_parameters.current_cipher_suite.
    suite[0] = packed_session->data[pos++];
  session->internals.resumed_security_parameters.current_cipher_suite.
    suite[1] = packed_session->data[pos++];

  session->internals.resumed_security_parameters.cert_type =
    packed_session->data[pos++];
  session->internals.resumed_security_parameters.version =
    packed_session->data[pos++];

  memcpy (session->internals.resumed_security_parameters.master_secret,
          &packed_session->data[pos], TLS_MASTER_SIZE);
  pos += TLS_MASTER_SIZE;

  memcpy (session->internals.resumed_security_parameters.client_random,
          &packed_session->data[pos], TLS_RANDOM_SIZE);
  pos += TLS_RANDOM_SIZE;
  memcpy (session->internals.resumed_security_parameters.server_random,
          &packed_session->data[pos], TLS_RANDOM_SIZE);
  pos += TLS_RANDOM_SIZE;

  session->internals.resumed_security_parameters.session_id_size =
    packed_session->data[pos++];
  memcpy (session->internals.resumed_security_parameters.session_id,
          &packed_session->data[pos],
          session->internals.resumed_security_parameters.session_id_size);
  pos += session->internals.resumed_security_parameters.session_id_size;

  session->internals.resumed_security_parameters.timestamp =
    _gnutls_read_uint32 (&packed_session->data[pos]);
  pos += 4;

  if (timestamp - session->internals.resumed_security_parameters.timestamp >
      session->internals.expire_time
      || session->internals.resumed_security_parameters.timestamp > timestamp)
    {
      gnutls_assert ();
      return GNUTLS_E_EXPIRED;
    }

  /* Extensions */
  session->internals.resumed_security_parameters.max_record_send_size =
    _gnutls_read_uint16 (&packed_session->data[pos]);
  pos += 2;

  session->internals.resumed_security_parameters.max_record_recv_size =
    _gnutls_read_uint16 (&packed_session->data[pos]);
  pos += 2;


  /* SRP */
  len = packed_session->data[pos++];    /* srp username length */
  memcpy (session->internals.resumed_security_parameters.extensions.
          srp_username, &packed_session->data[pos], len);
  session->internals.resumed_security_parameters.extensions.
    srp_username[len] = 0;
  pos += len;

  session->internals.resumed_security_parameters.extensions.
    server_names_size = _gnutls_read_uint16 (&packed_session->data[pos]);
  pos += 2;
  for (i = 0;
       i <
       session->internals.resumed_security_parameters.extensions.
       server_names_size; i++)
    {
      session->internals.resumed_security_parameters.extensions.
        server_names[i].type = packed_session->data[pos++];
      session->internals.resumed_security_parameters.extensions.
        server_names[i].name_length =
        _gnutls_read_uint16 (&packed_session->data[pos]);
      pos += 2;

      memcpy (session->internals.resumed_security_parameters.extensions.
              server_names[i].name, &packed_session->data[pos],
              session->internals.resumed_security_parameters.extensions.
              server_names[i].name_length);
      pos +=
        session->internals.resumed_security_parameters.extensions.
        server_names[i].name_length;
    }
  return 0;
}
