/*
 * Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2007 Free Software Foundation
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

/* The certificate authentication functions which are needed in the handshake,
 * and are common to RSA and DHE key exchange, are in this file.
 */

#include <gnutls_int.h>
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include <gnutls_cert.h>
#include <auth_cert.h>
#include "gnutls_dh.h"
#include "gnutls_num.h"
#include "libtasn1.h"
#include "gnutls_datum.h"
#include <gnutls_pk.h>
#include <gnutls_algorithms.h>
#include <gnutls_global.h>
#include <gnutls_record.h>
#include <gnutls_sig.h>
#include <gnutls_state.h>
#include <gnutls_pk.h>
#include <gnutls_x509.h>
#include <gnutls_extra_hooks.h>
#include "debug.h"

static gnutls_cert *alloc_and_load_x509_certs (gnutls_x509_crt_t * certs,
                                               unsigned);
static gnutls_privkey *alloc_and_load_x509_key (gnutls_x509_privkey_t key);
static gnutls_cert *alloc_and_load_pgp_certs (gnutls_openpgp_crt_t cert);
static gnutls_privkey *alloc_and_load_pgp_key (const gnutls_openpgp_privkey_t
                                               key);


/* Copies data from a internal certificate struct (gnutls_cert) to 
 * exported certificate struct (cert_auth_info_t)
 */
static int
_gnutls_copy_certificate_auth_info (cert_auth_info_t info,
                                    gnutls_cert * cert, int ncerts)
{
  /* Copy peer's information to auth_info_t
   */
  int ret, i, j;

  if (ncerts == 0)
    {
      info->raw_certificate_list = NULL;
      info->ncerts = 0;
      return 0;
    }

  info->raw_certificate_list =
    gnutls_calloc (1, sizeof (gnutls_datum_t) * ncerts);
  if (info->raw_certificate_list == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  for (i = 0; i < ncerts; i++)
    {
      if (cert->raw.size > 0)
        {
          ret =
            _gnutls_set_datum (&info->
                               raw_certificate_list[i],
                               cert[i].raw.data, cert[i].raw.size);
          if (ret < 0)
            {
              gnutls_assert ();
              goto clear;
            }
        }
    }
  info->ncerts = ncerts;

  return 0;

clear:

  for (j = 0; j < i; j++)
    _gnutls_free_datum (&info->raw_certificate_list[j]);

  gnutls_free (info->raw_certificate_list);
  info->raw_certificate_list = NULL;

  return ret;
}




/* returns 0 if the algo_to-check exists in the pk_algos list,
 * -1 otherwise.
 */
inline static int
_gnutls_check_pk_algo_in_list (const gnutls_pk_algorithm_t *
                               pk_algos, int pk_algos_length,
                               gnutls_pk_algorithm_t algo_to_check)
{
  int i;
  for (i = 0; i < pk_algos_length; i++)
    {
      if (algo_to_check == pk_algos[i])
        {
          return 0;
        }
    }
  return -1;
}


/* Returns the issuer's Distinguished name in odn, of the certificate 
 * specified in cert.
 */
static int
_gnutls_cert_get_issuer_dn (gnutls_cert * cert, gnutls_datum_t * odn)
{
  ASN1_TYPE dn;
  int len, result;
  int start, end;

  if ((result = asn1_create_element
       (_gnutls_get_pkix (), "PKIX1.Certificate", &dn)) != ASN1_SUCCESS)
    {
      gnutls_assert ();
      return _gnutls_asn2err (result);
    }

  result = asn1_der_decoding (&dn, cert->raw.data, cert->raw.size, NULL);
  if (result != ASN1_SUCCESS)
    {
      /* couldn't decode DER */
      gnutls_assert ();
      asn1_delete_structure (&dn);
      return _gnutls_asn2err (result);
    }

  result = asn1_der_decoding_startEnd (dn, cert->raw.data, cert->raw.size,
                                       "tbsCertificate.issuer", &start, &end);

  if (result != ASN1_SUCCESS)
    {
      /* couldn't decode DER */
      gnutls_assert ();
      asn1_delete_structure (&dn);
      return _gnutls_asn2err (result);
    }
  asn1_delete_structure (&dn);

  len = end - start + 1;

  odn->size = len;
  odn->data = &cert->raw.data[start];

  return 0;
}


/* Locates the most appropriate x509 certificate using the
 * given DN. If indx == -1 then no certificate was found.
 *
 * That is to guess which certificate to use, based on the 
 * CAs and sign algorithms supported by the peer server.
 */
static int
_find_x509_cert (const gnutls_certificate_credentials_t cred,
                 opaque * _data, size_t _data_size,
                 const gnutls_pk_algorithm_t * pk_algos,
                 int pk_algos_length, int *indx)
{
  unsigned size;
  gnutls_datum_t odn;
  opaque *data = _data;
  ssize_t data_size = _data_size;
  unsigned i, j;
  int result, cert_pk;

  *indx = -1;

  do
    {

      DECR_LENGTH_RET (data_size, 2, 0);
      size = _gnutls_read_uint16 (data);
      DECR_LENGTH_RET (data_size, size, 0);
      data += 2;

      for (i = 0; i < cred->ncerts; i++)
        {
          for (j = 0; j < cred->cert_list_length[i]; j++)
            {
              if ((result =
                   _gnutls_cert_get_issuer_dn (&cred->
                                               cert_list[i][j], &odn)) < 0)
                {
                  gnutls_assert ();
                  return result;
                }

              if (odn.size != size)
                continue;

              /* If the DN matches and
               * the *_SIGN algorithm matches
               * the cert is our cert!
               */
              cert_pk = cred->cert_list[i][0].subject_pk_algorithm;

              if ((memcmp (odn.data, data, size) == 0) &&
                  (_gnutls_check_pk_algo_in_list
                   (pk_algos, pk_algos_length, cert_pk) == 0))
                {
                  *indx = i;
                  break;
                }
            }
          if (*indx != -1)
            break;
        }

      if (*indx != -1)
        break;

      /* move to next record */
      data += size;

    }
  while (1);

  return 0;

}

/* Locates the most appropriate openpgp cert
 */
static int
_find_openpgp_cert (const gnutls_certificate_credentials_t cred,
                    gnutls_pk_algorithm_t * pk_algos,
                    int pk_algos_length, int *indx)
{
  unsigned i, j;

  *indx = -1;

  for (i = 0; i < cred->ncerts; i++)
    {
      for (j = 0; j < cred->cert_list_length[i]; j++)
        {

          /* If the *_SIGN algorithm matches
           * the cert is our cert!
           */
          if ((_gnutls_check_pk_algo_in_list
               (pk_algos, pk_algos_length,
                cred->cert_list[i][0].subject_pk_algorithm) == 0)
              && (cred->cert_list[i][0].cert_type == MHD_GNUTLS_CRT_OPENPGP))
            {
              *indx = i;
              break;
            }
        }
      if (*indx != -1)
        break;
    }

  return 0;
}

/* Returns the number of issuers in the server's
 * certificate request packet.
 */
static int
get_issuers_num (gnutls_session_t session, opaque * data, ssize_t data_size)
{
  int issuers_dn_len = 0, result;
  unsigned size;

  /* Count the number of the given issuers;
   * This is used to allocate the issuers_dn without
   * using realloc().
   */

  if (data_size == 0 || data == NULL)
    return 0;

  if (data_size > 0)
    do
      {
        /* This works like DECR_LEN() 
         */
        result = GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
        DECR_LENGTH_COM (data_size, 2, goto error);
        size = _gnutls_read_uint16 (data);

        result = GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
        DECR_LENGTH_COM (data_size, size, goto error);

        data += 2;

        if (size > 0)
          {
            issuers_dn_len++;
            data += size;
          }

        if (data_size == 0)
          break;

      }
    while (1);

  return issuers_dn_len;

error:
  return result;
}

/* Returns the issuers in the server's certificate request
 * packet.
 */
static int
get_issuers (gnutls_session_t session,
             gnutls_datum_t * issuers_dn, int issuers_len,
             opaque * data, size_t data_size)
{
  int i;
  unsigned size;

  if (gnutls_certificate_type_get (session) != MHD_GNUTLS_CRT_X509)
    return 0;

  /* put the requested DNs to req_dn, only in case
   * of X509 certificates.
   */
  if (issuers_len > 0)
    {

      for (i = 0; i < issuers_len; i++)
        {
          /* The checks here for the buffer boundaries
           * are not needed since the buffer has been
           * parsed above.
           */
          data_size -= 2;

          size = _gnutls_read_uint16 (data);

          data += 2;

          issuers_dn[i].data = data;
          issuers_dn[i].size = size;

          data += size;
        }
    }

  return 0;
}

/* Calls the client get callback.
 */
static int
call_get_cert_callback (gnutls_session_t session,
                        gnutls_datum_t * issuers_dn,
                        int issuers_dn_length,
                        gnutls_pk_algorithm_t * pk_algos, int pk_algos_length)
{
  unsigned i;
  gnutls_cert *local_certs = NULL;
  gnutls_privkey *local_key = NULL;
  gnutls_retr_st st;
  int ret;
  gnutls_certificate_type_t type = gnutls_certificate_type_get (session);
  gnutls_certificate_credentials_t cred;

  cred = (gnutls_certificate_credentials_t)
    _gnutls_get_cred (session->key, MHD_GNUTLS_CRD_CERTIFICATE, NULL);
  if (cred == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  memset (&st, 0, sizeof (st));

  if (session->security_parameters.entity == GNUTLS_SERVER)
    {
      ret = cred->server_get_cert_callback (session, &st);
    }
  else
    {                           /* CLIENT */
      ret =
        cred->client_get_cert_callback (session,
                                        issuers_dn, issuers_dn_length,
                                        pk_algos, pk_algos_length, &st);
    }

  if (ret < 0)
    {
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (st.ncerts == 0)
    return 0;                   /* no certificate was selected */

  if (type != st.type)
    {
      gnutls_assert ();
      ret = GNUTLS_E_INVALID_REQUEST;
      goto cleanup;
    }

  if (type == MHD_GNUTLS_CRT_X509)
    {
      local_certs = alloc_and_load_x509_certs (st.cert.x509, st.ncerts);
      if (local_certs != NULL)
        local_key = alloc_and_load_x509_key (st.key.x509);

    }
  else
    {                           /* PGP */
      if (st.ncerts > 1)
        {
          gnutls_assert ();
          ret = GNUTLS_E_INVALID_REQUEST;
          goto cleanup;
        }

      local_certs = alloc_and_load_pgp_certs (st.cert.pgp);
      if (local_certs != NULL)
        local_key = alloc_and_load_pgp_key (st.key.pgp);

    }

  _gnutls_selected_certs_set (session, local_certs,
                              (local_certs != NULL) ? st.ncerts : 0,
                              local_key, 1);

  ret = 0;

cleanup:

  if (st.type == MHD_GNUTLS_CRT_X509)
    {
      if (st.deinit_all)
        {
          for (i = 0; i < st.ncerts; i++)
            {
              gnutls_x509_crt_deinit (st.cert.x509[i]);
            }
          gnutls_free (st.cert.x509);
          gnutls_x509_privkey_deinit (st.key.x509);
        }
    }
  else
    {
      if (st.deinit_all)
        {
          if (_E_gnutls_openpgp_crt_deinit == NULL ||
              _E_gnutls_openpgp_privkey_deinit == NULL)
            {
              gnutls_assert ();
              return GNUTLS_E_INIT_LIBEXTRA;
            }

          _E_gnutls_openpgp_crt_deinit (st.cert.pgp);
          _E_gnutls_openpgp_privkey_deinit (st.key.pgp);
        }
    }

  return ret;
}

/* Finds the appropriate certificate depending on the cA Distinguished name
 * advertized by the server. If none matches then returns 0 and -1 as index.
 * In case of an error a negative value, is returned.
 *
 * 20020128: added ability to select a certificate depending on the SIGN
 * algorithm (only in automatic mode).
 */
static int
_select_client_cert (gnutls_session_t session,
                     opaque * _data, size_t _data_size,
                     gnutls_pk_algorithm_t * pk_algos, int pk_algos_length)
{
  int result;
  int indx = -1;
  gnutls_certificate_credentials_t cred;
  opaque *data = _data;
  ssize_t data_size = _data_size;
  int issuers_dn_length;
  gnutls_datum_t *issuers_dn = NULL;

  cred = (gnutls_certificate_credentials_t)
    _gnutls_get_cred (session->key, MHD_GNUTLS_CRD_CERTIFICATE, NULL);
  if (cred == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  if (cred->client_get_cert_callback != NULL)
    {

      /* use a callback to get certificate 
       */
      if (session->security_parameters.cert_type != MHD_GNUTLS_CRT_X509)
        issuers_dn_length = 0;
      else
        {
          issuers_dn_length = get_issuers_num (session, data, data_size);
          if (issuers_dn_length < 0)
            {
              gnutls_assert ();
              return issuers_dn_length;
            }

          if (issuers_dn_length > 0)
            {
              issuers_dn =
                gnutls_malloc (sizeof (gnutls_datum_t) * issuers_dn_length);
              if (issuers_dn == NULL)
                {
                  gnutls_assert ();
                  return GNUTLS_E_MEMORY_ERROR;
                }

              result =
                get_issuers (session, issuers_dn, issuers_dn_length,
                             data, data_size);
              if (result < 0)
                {
                  gnutls_assert ();
                  goto cleanup;
                }
            }
        }

      result =
        call_get_cert_callback (session, issuers_dn, issuers_dn_length,
                                pk_algos, pk_algos_length);
      goto cleanup;

    }
  else
    {
      /* If we have no callbacks, try to guess.
       */
      result = 0;

      if (session->security_parameters.cert_type == MHD_GNUTLS_CRT_X509)
        result =
          _find_x509_cert (cred, _data, _data_size,
                           pk_algos, pk_algos_length, &indx);

      if (session->security_parameters.cert_type == MHD_GNUTLS_CRT_OPENPGP)
        result = _find_openpgp_cert (cred, pk_algos, pk_algos_length, &indx);


      if (result < 0)
        {
          gnutls_assert ();
          return result;
        }

      if (indx >= 0)
        {
          _gnutls_selected_certs_set (session,
                                      &cred->cert_list[indx][0],
                                      cred->cert_list_length[indx],
                                      &cred->pkey[indx], 0);
        }
      else
        {
          _gnutls_selected_certs_set (session, NULL, 0, NULL, 0);
        }

      result = 0;
    }

cleanup:
  gnutls_free (issuers_dn);
  return result;

}

/* Generate client certificate
 */

int
_gnutls_gen_x509_crt (gnutls_session_t session, opaque ** data)
{
  int ret, i;
  opaque *pdata;
  gnutls_cert *apr_cert_list;
  gnutls_privkey *apr_pkey;
  int apr_cert_list_length;

  /* find the appropriate certificate 
   */
  if ((ret =
       _gnutls_get_selected_cert (session, &apr_cert_list,
                                  &apr_cert_list_length, &apr_pkey)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = 3;
  for (i = 0; i < apr_cert_list_length; i++)
    {
      ret += apr_cert_list[i].raw.size + 3;
      /* hold size
       * for uint24 */
    }

  /* if no certificates were found then send:
   * 0B 00 00 03 00 00 00    // Certificate with no certs
   * instead of:
   * 0B 00 00 00          // empty certificate handshake
   *
   * ( the above is the whole handshake message, not 
   * the one produced here )
   */

  (*data) = gnutls_malloc (ret);
  pdata = (*data);

  if (pdata == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
  _gnutls_write_uint24 (ret - 3, pdata);
  pdata += 3;
  for (i = 0; i < apr_cert_list_length; i++)
    {
      _gnutls_write_datum24 (pdata, apr_cert_list[i].raw);
      pdata += (3 + apr_cert_list[i].raw.size);
    }

  return ret;
}

enum PGPKeyDescriptorType
{ PGP_KEY_FINGERPRINT, PGP_KEY };

int
_gnutls_gen_openpgp_certificate (gnutls_session_t session, opaque ** data)
{
  int ret;
  opaque *pdata;
  gnutls_cert *apr_cert_list;
  gnutls_privkey *apr_pkey;
  int apr_cert_list_length;

  /* find the appropriate certificate */
  if ((ret =
       _gnutls_get_selected_cert (session, &apr_cert_list,
                                  &apr_cert_list_length, &apr_pkey)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  ret = 3 + 1 + 3;

  if (apr_cert_list_length > 0)
    ret += apr_cert_list[0].raw.size;

  (*data) = gnutls_malloc (ret);
  pdata = (*data);

  if (pdata == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  _gnutls_write_uint24 (ret - 3, pdata);
  pdata += 3;

  *pdata = PGP_KEY;             /* whole key */
  pdata++;

  if (apr_cert_list_length > 0)
    {
      _gnutls_write_datum24 (pdata, apr_cert_list[0].raw);
      pdata += (3 + apr_cert_list[0].raw.size);
    }
  else                          /* empty - no certificate */
    _gnutls_write_uint24 (0, pdata);

  return ret;
}

int
_gnutls_gen_openpgp_certificate_fpr (gnutls_session_t session, opaque ** data)
{
  int ret, packet_size;
  size_t fpr_size;
  opaque *pdata;
  gnutls_cert *apr_cert_list;
  gnutls_privkey *apr_pkey;
  int apr_cert_list_length;

  /* find the appropriate certificate */
  if ((ret =
       _gnutls_get_selected_cert (session, &apr_cert_list,
                                  &apr_cert_list_length, &apr_pkey)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  packet_size = 3 + 1;

  /* Only v4 fingerprints are sent 
   */
  if (apr_cert_list_length > 0 && apr_cert_list[0].version == 4)
    packet_size += 20 + 1;
  else                          /* empty certificate case */
    return _gnutls_gen_openpgp_certificate (session, data);

  (*data) = gnutls_malloc (packet_size);
  pdata = (*data);

  if (pdata == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  _gnutls_write_uint24 (packet_size - 3, pdata);
  pdata += 3;

  *pdata = PGP_KEY_FINGERPRINT; /* key fingerprint */
  pdata++;

  *pdata = 20;
  pdata++;

  fpr_size = 20;

  if (_E_gnutls_openpgp_fingerprint == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INIT_LIBEXTRA;
    }

  if ((ret =
       _E_gnutls_openpgp_fingerprint (&apr_cert_list[0].raw, pdata,
                                      &fpr_size)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  return packet_size;
}



int
_gnutls_gen_cert_client_certificate (gnutls_session_t session, opaque ** data)
{
  switch (session->security_parameters.cert_type)
    {
    case MHD_GNUTLS_CRT_OPENPGP:
      if (_gnutls_openpgp_send_fingerprint (session) == 0)
        return _gnutls_gen_openpgp_certificate (session, data);
      else
        return _gnutls_gen_openpgp_certificate_fpr (session, data);

    case MHD_GNUTLS_CRT_X509:
      return _gnutls_gen_x509_crt (session, data);

    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }
}

int
_gnutls_gen_cert_server_certificate (gnutls_session_t session, opaque ** data)
{
  switch (session->security_parameters.cert_type)
    {
    case MHD_GNUTLS_CRT_OPENPGP:
      return _gnutls_gen_openpgp_certificate (session, data);
    case MHD_GNUTLS_CRT_X509:
      return _gnutls_gen_x509_crt (session, data);
    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }
}

/* Process server certificate
 */

#define CLEAR_CERTS for(x=0;x<peer_certificate_list_size;x++) _gnutls_gcert_deinit(&peer_certificate_list[x])
int
_gnutls_proc_x509_server_certificate (gnutls_session_t session,
                                      opaque * data, size_t data_size)
{
  int size, len, ret;
  opaque *p = data;
  cert_auth_info_t info;
  gnutls_certificate_credentials_t cred;
  ssize_t dsize = data_size;
  int i, j, x;
  gnutls_cert *peer_certificate_list;
  int peer_certificate_list_size = 0;
  gnutls_datum_t tmp;

  cred = (gnutls_certificate_credentials_t)
    _gnutls_get_cred (session->key, MHD_GNUTLS_CRD_CERTIFICATE, NULL);
  if (cred == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }


  if ((ret =
       _gnutls_auth_info_set (session, MHD_GNUTLS_CRD_CERTIFICATE,
                              sizeof (cert_auth_info_st), 1)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  info = _gnutls_get_auth_info (session);

  if (data == NULL || data_size == 0)
    {
      gnutls_assert ();
      /* no certificate was sent */
      return GNUTLS_E_NO_CERTIFICATE_FOUND;
    }

  DECR_LEN (dsize, 3);
  size = _gnutls_read_uint24 (p);
  p += 3;

  /* some implementations send 0B 00 00 06 00 00 03 00 00 00
   * instead of just 0B 00 00 03 00 00 00 as an empty certificate message.
   */
  if (size == 0 || size == 3)
    {
      gnutls_assert ();
      /* no certificate was sent */
      return GNUTLS_E_NO_CERTIFICATE_FOUND;
    }

  i = dsize;
  while (i > 0)
    {
      DECR_LEN (dsize, 3);
      len = _gnutls_read_uint24 (p);
      p += 3;
      DECR_LEN (dsize, len);
      peer_certificate_list_size++;
      p += len;
      i -= len + 3;
    }

  if (peer_certificate_list_size == 0)
    {
      gnutls_assert ();
      return GNUTLS_E_NO_CERTIFICATE_FOUND;
    }

  /* Ok we now allocate the memory to hold the
   * certificate list 
   */

  peer_certificate_list =
    gnutls_malloc (sizeof (gnutls_cert) * (peer_certificate_list_size));

  if (peer_certificate_list == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
  memset (peer_certificate_list, 0, sizeof (gnutls_cert) *
          peer_certificate_list_size);

  p = data + 3;

  /* Now we start parsing the list (again).
   * We don't use DECR_LEN since the list has
   * been parsed before.
   */

  for (j = 0; j < peer_certificate_list_size; j++)
    {
      len = _gnutls_read_uint24 (p);
      p += 3;

      tmp.size = len;
      tmp.data = p;

      if ((ret =
           _gnutls_x509_raw_cert_to_gcert (&peer_certificate_list
                                           [j], &tmp,
                                           CERT_ONLY_EXTENSIONS)) < 0)
        {
          gnutls_assert ();
          goto cleanup;
        }

      p += len;
    }


  if ((ret =
       _gnutls_copy_certificate_auth_info (info,
                                           peer_certificate_list,
                                           peer_certificate_list_size)) < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  if ((ret =
       _gnutls_check_key_usage (&peer_certificate_list[0],
                                gnutls_kx_get (session))) < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = 0;

cleanup:
  CLEAR_CERTS;
  gnutls_free (peer_certificate_list);
  return ret;

}

#define CLEAR_CERTS for(x=0;x<peer_certificate_list_size;x++) _gnutls_gcert_deinit(&peer_certificate_list[x])
int
_gnutls_proc_openpgp_server_certificate (gnutls_session_t session,
                                         opaque * data, size_t data_size)
{
  int size, ret, len;
  opaque *p = data;
  cert_auth_info_t info;
  gnutls_certificate_credentials_t cred;
  ssize_t dsize = data_size;
  int i, x;
  gnutls_cert *peer_certificate_list = NULL;
  int peer_certificate_list_size = 0;
  gnutls_datum_t tmp, akey = { NULL, 0 };

  cred = (gnutls_certificate_credentials_t)
    _gnutls_get_cred (session->key, MHD_GNUTLS_CRD_CERTIFICATE, NULL);
  if (cred == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  if ((ret =
       _gnutls_auth_info_set (session, MHD_GNUTLS_CRD_CERTIFICATE,
                              sizeof (cert_auth_info_st), 1)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  info = _gnutls_get_auth_info (session);

  if (data == NULL || data_size == 0)
    {
      gnutls_assert ();
      return GNUTLS_E_NO_CERTIFICATE_FOUND;
    }

  DECR_LEN (dsize, 3);
  size = _gnutls_read_uint24 (p);
  p += 3;

  if (size == 0)
    {
      gnutls_assert ();
      /* no certificate was sent */
      return GNUTLS_E_NO_CERTIFICATE_FOUND;
    }
  i = dsize;

  /* Read PGPKeyDescriptor */
  DECR_LEN (dsize, 1);
  if (*p == PGP_KEY_FINGERPRINT)
    {                           /* the fingerprint */
      p++;

      DECR_LEN (dsize, 1);
      len = (uint8_t) * p;
      p++;

      if (len != 20)
        {
          gnutls_assert ();
          return GNUTLS_E_OPENPGP_FINGERPRINT_UNSUPPORTED;
        }

      DECR_LEN (dsize, 20);

      /* request the actual key from our database, or
       * a key server or anything.
       */
      if (_E_gnutls_openpgp_request_key == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_INIT_LIBEXTRA;
        }
      if ((ret =
           _E_gnutls_openpgp_request_key (session, &akey, cred, p, 20)) < 0)
        {
          gnutls_assert ();
          return ret;
        }
      tmp = akey;
      peer_certificate_list_size++;

    }
  else if (*p == PGP_KEY)
    {                           /* the whole key */

      p++;

      /* Read the actual certificate */
      DECR_LEN (dsize, 3);
      len = _gnutls_read_uint24 (p);
      p += 3;

      if (len == 0)
        {
          gnutls_assert ();
          /* no certificate was sent */
          return GNUTLS_E_NO_CERTIFICATE_FOUND;
        }

      DECR_LEN (dsize, len);
      peer_certificate_list_size++;

      tmp.size = len;
      tmp.data = p;

    }
  else
    {
      gnutls_assert ();
      return GNUTLS_E_UNSUPPORTED_CERTIFICATE_TYPE;
    }

  /* ok we now have the peer's key in tmp datum
   */

  if (peer_certificate_list_size == 0)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  peer_certificate_list =
    gnutls_alloca (sizeof (gnutls_cert) * (peer_certificate_list_size));
  if (peer_certificate_list == NULL)
    {
      gnutls_assert ();
      ret = GNUTLS_E_MEMORY_ERROR;
      goto cleanup;
    }
  memset (peer_certificate_list, 0, sizeof (gnutls_cert) *
          peer_certificate_list_size);

  if (_E_gnutls_openpgp_raw_key_to_gcert == NULL)
    {
      gnutls_assert ();
      ret = GNUTLS_E_INIT_LIBEXTRA;
      goto cleanup;
    }

  if ((ret =
       _E_gnutls_openpgp_raw_key_to_gcert (&peer_certificate_list[0],
                                           &tmp)) < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  if ((ret =
       _gnutls_copy_certificate_auth_info (info,
                                           peer_certificate_list,
                                           peer_certificate_list_size)) < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  if ((ret =
       _gnutls_check_key_usage (&peer_certificate_list[0],
                                gnutls_kx_get (session))) < 0)
    {
      gnutls_assert ();
      goto cleanup;
    }

  ret = 0;

cleanup:

  _gnutls_free_datum (&akey);
  CLEAR_CERTS;
  gnutls_afree (peer_certificate_list);
  return ret;

}

int
_gnutls_proc_cert_server_certificate (gnutls_session_t session,
                                      opaque * data, size_t data_size)
{
  switch (session->security_parameters.cert_type)
    {
    case MHD_GNUTLS_CRT_OPENPGP:
      return _gnutls_proc_openpgp_server_certificate (session,
                                                      data, data_size);
    case MHD_GNUTLS_CRT_X509:
      return _gnutls_proc_x509_server_certificate (session, data, data_size);
    default:
      gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }
}

#define MAX_SIGN_ALGOS 2
typedef enum CertificateSigType
{ RSA_SIGN = 1, DSA_SIGN
} CertificateSigType;

/* Checks if we support the given signature algorithm 
 * (RSA or DSA). Returns the corresponding gnutls_pk_algorithm_t
 * if true;
 */
inline static int
_gnutls_check_supported_sign_algo (CertificateSigType algo)
{
  switch (algo)
    {
    case RSA_SIGN:
      return MHD_GNUTLS_PK_RSA;
    }

  return -1;
}

int
_gnutls_proc_cert_cert_req (gnutls_session_t session, opaque * data,
                            size_t data_size)
{
  int size, ret;
  opaque *p;
  gnutls_certificate_credentials_t cred;
  cert_auth_info_t info;
  ssize_t dsize;
  int i, j;
  gnutls_pk_algorithm_t pk_algos[MAX_SIGN_ALGOS];
  int pk_algos_length;
  gnutls_protocol_t ver = gnutls_protocol_get_version (session);

  cred = (gnutls_certificate_credentials_t)
    _gnutls_get_cred (session->key, MHD_GNUTLS_CRD_CERTIFICATE, NULL);
  if (cred == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  if ((ret =
       _gnutls_auth_info_set (session, MHD_GNUTLS_CRD_CERTIFICATE,
                              sizeof (cert_auth_info_st), 0)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  info = _gnutls_get_auth_info (session);

  p = data;
  dsize = data_size;

  DECR_LEN (dsize, 1);
  size = p[0];
  p++;
  /* check if the sign algorithm is supported.
   */
  pk_algos_length = j = 0;
  for (i = 0; i < size; i++, p++)
    {
      DECR_LEN (dsize, 1);
      if ((ret = _gnutls_check_supported_sign_algo (*p)) > 0)
        {
          if (j < MAX_SIGN_ALGOS)
            {
              pk_algos[j++] = ret;
              pk_algos_length++;
            }
        }
    }

  if (pk_algos_length == 0)
    {
      gnutls_assert ();
      return GNUTLS_E_UNKNOWN_PK_ALGORITHM;
    }

  if (ver == MHD_GNUTLS_TLS1_2)
    {
      /* read supported hashes */
      int hash_num;
      DECR_LEN (dsize, 1);

      hash_num = p[0] & 0xFF;
      p++;

      DECR_LEN (dsize, hash_num);
      p += hash_num;
    }

  /* read the certificate authorities */
  DECR_LEN (dsize, 2);
  size = _gnutls_read_uint16 (p);
  p += 2;

  if (session->security_parameters.cert_type == MHD_GNUTLS_CRT_OPENPGP
      && size != 0)
    {
      gnutls_assert ();         // size should be zero
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  DECR_LEN (dsize, size);

  /* now we ask the user to tell which one
   * he wants to use.
   */
  if ((ret =
       _select_client_cert (session, p, size, pk_algos, pk_algos_length)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  /* We should reply with a certificate message, 
   * even if we have no certificate to send.
   */
  session->key->certificate_requested = 1;

  return 0;
}

int
_gnutls_gen_cert_client_cert_vrfy (gnutls_session_t session, opaque ** data)
{
  int ret;
  gnutls_cert *apr_cert_list;
  gnutls_privkey *apr_pkey;
  int apr_cert_list_length, size;
  gnutls_datum_t signature;

  *data = NULL;

  /* find the appropriate certificate */
  if ((ret =
       _gnutls_get_selected_cert (session, &apr_cert_list,
                                  &apr_cert_list_length, &apr_pkey)) < 0)
    {
      gnutls_assert ();
      return ret;
    }

  if (apr_cert_list_length > 0)
    {
      if ((ret =
           _gnutls_tls_sign_hdata (session,
                                   &apr_cert_list[0],
                                   apr_pkey, &signature)) < 0)
        {
          gnutls_assert ();
          return ret;
        }
    }
  else
    {
      return 0;
    }

  *data = gnutls_malloc (signature.size + 2);
  if (*data == NULL)
    {
      _gnutls_free_datum (&signature);
      return GNUTLS_E_MEMORY_ERROR;
    }
  size = signature.size;
  _gnutls_write_uint16 (size, *data);

  memcpy (&(*data)[2], signature.data, size);

  _gnutls_free_datum (&signature);

  return size + 2;
}

int
_gnutls_proc_cert_client_cert_vrfy (gnutls_session_t session,
                                    opaque * data, size_t data_size)
{
  int size, ret;
  ssize_t dsize = data_size;
  opaque *pdata = data;
  gnutls_datum_t sig;
  cert_auth_info_t info = _gnutls_get_auth_info (session);
  gnutls_cert peer_cert;

  if (info == NULL || info->ncerts == 0)
    {
      gnutls_assert ();
      /* we need this in order to get peer's certificate */
      return GNUTLS_E_INTERNAL_ERROR;
    }

  DECR_LEN (dsize, 2);
  size = _gnutls_read_uint16 (pdata);
  pdata += 2;

  DECR_LEN (dsize, size);

  sig.data = pdata;
  sig.size = size;

  ret = _gnutls_raw_cert_to_gcert (&peer_cert,
                                   session->security_parameters.cert_type,
                                   &info->raw_certificate_list[0],
                                   CERT_NO_COPY);

  if (ret < 0)
    {
      gnutls_assert ();
      return ret;
    }

  if ((ret = _gnutls_verify_sig_hdata (session, &peer_cert, &sig)) < 0)
    {
      gnutls_assert ();
      _gnutls_gcert_deinit (&peer_cert);
      return ret;
    }
  _gnutls_gcert_deinit (&peer_cert);

  return 0;
}

#define CERTTYPE_SIZE 3
int
_gnutls_gen_cert_server_cert_req (gnutls_session_t session, opaque ** data)
{
  gnutls_certificate_credentials_t cred;
  int size;
  opaque *pdata;
  gnutls_protocol_t ver = gnutls_protocol_get_version (session);

  /* Now we need to generate the RDN sequence. This is
   * already in the CERTIFICATE_CRED structure, to improve
   * performance.
   */

  cred = (gnutls_certificate_credentials_t)
    _gnutls_get_cred (session->key, MHD_GNUTLS_CRD_CERTIFICATE, NULL);
  if (cred == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  size = CERTTYPE_SIZE + 2;     /* 2 for gnutls_certificate_type_t + 2 for size of rdn_seq 
                                 */

  if (session->security_parameters.cert_type == MHD_GNUTLS_CRT_X509 &&
      session->internals.ignore_rdn_sequence == 0)
    size += cred->x509_rdn_sequence.size;

  if (ver == MHD_GNUTLS_TLS1_2)
    /* Need at least one byte to announce the number of supported hash
       functions (see below).  */
    size += 1;

  (*data) = gnutls_malloc (size);
  pdata = (*data);

  if (pdata == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  pdata[0] = CERTTYPE_SIZE - 1;

  pdata[1] = RSA_SIGN;
  pdata[2] = DSA_SIGN;          /* only these for now */
  pdata += CERTTYPE_SIZE;

  if (ver == MHD_GNUTLS_TLS1_2)
    {
      /* Supported hashes (nothing for now -- FIXME). */
      *pdata = 0;
      pdata++;
    }

  if (session->security_parameters.cert_type == MHD_GNUTLS_CRT_X509 &&
      session->internals.ignore_rdn_sequence == 0)
    {
      _gnutls_write_datum16 (pdata, cred->x509_rdn_sequence);
      /* pdata += cred->x509_rdn_sequence.size + 2; */
    }
  else
    {
      _gnutls_write_uint16 (0, pdata);
      /* pdata+=2; */
    }

  return size;
}


/* This function will return the appropriate certificate to use. 
 * Fills in the apr_cert_list, apr_cert_list_length and apr_pkey.
 * The return value is a negative value on error.
 *
 * It is normal to return 0 with no certificates in client side.
 *
 */
int
_gnutls_get_selected_cert (gnutls_session_t session,
                           gnutls_cert ** apr_cert_list,
                           int *apr_cert_list_length,
                           gnutls_privkey ** apr_pkey)
{
  if (session->security_parameters.entity == GNUTLS_SERVER)
    {

      /* select_client_cert() has been called before.
       */

      *apr_cert_list = session->internals.selected_cert_list;
      *apr_pkey = session->internals.selected_key;
      *apr_cert_list_length = session->internals.selected_cert_list_length;

      if (*apr_cert_list_length == 0 || *apr_cert_list == NULL)
        {
          gnutls_assert ();
          return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
        }

    }
  else
    {                           /* CLIENT SIDE 
                                 */

      /* we have already decided which certificate
       * to send.
       */
      *apr_cert_list = session->internals.selected_cert_list;
      *apr_cert_list_length = session->internals.selected_cert_list_length;
      *apr_pkey = session->internals.selected_key;

    }

  return 0;
}

/* converts the given x509 certificate to gnutls_cert* and allocates
 * space for them.
 */
static gnutls_cert *
alloc_and_load_x509_certs (gnutls_x509_crt_t * certs, unsigned ncerts)
{
  gnutls_cert *local_certs;
  int ret = 0;
  unsigned i, j;

  if (certs == NULL)
    return NULL;

  local_certs = gnutls_malloc (sizeof (gnutls_cert) * ncerts);
  if (local_certs == NULL)
    {
      gnutls_assert ();
      return NULL;
    }

  for (i = 0; i < ncerts; i++)
    {
      ret = _gnutls_x509_crt_to_gcert (&local_certs[i], certs[i], 0);
      if (ret < 0)
        break;
    }

  if (ret < 0)
    {
      gnutls_assert ();
      for (j = 0; j < i; j++)
        {
          _gnutls_gcert_deinit (&local_certs[j]);
        }
      gnutls_free (local_certs);
      return NULL;
    }

  return local_certs;
}

/* converts the given x509 key to gnutls_privkey* and allocates
 * space for it.
 */
static gnutls_privkey *
alloc_and_load_x509_key (gnutls_x509_privkey_t key)
{
  gnutls_privkey *local_key;
  int ret = 0;

  if (key == NULL)
    return NULL;

  local_key = gnutls_malloc (sizeof (gnutls_privkey));
  if (local_key == NULL)
    {
      gnutls_assert ();
      return NULL;
    }

  ret = _gnutls_x509_privkey_to_gkey (local_key, key);
  if (ret < 0)
    {
      gnutls_assert ();
      return NULL;
    }

  return local_key;
}

/* converts the given pgp certificate to gnutls_cert* and allocates
 * space for them.
 */
static gnutls_cert *
alloc_and_load_pgp_certs (gnutls_openpgp_crt_t cert)
{
  gnutls_cert *local_certs;
  int ret = 0;

  if (cert == NULL)
    return NULL;

  local_certs = gnutls_malloc (sizeof (gnutls_cert));
  if (local_certs == NULL)
    {
      gnutls_assert ();
      return NULL;
    }

  if (_E_gnutls_openpgp_crt_to_gcert == NULL)
    {
      gnutls_assert ();
      return NULL;
    }

  ret = _E_gnutls_openpgp_crt_to_gcert (local_certs, cert);
  if (ret < 0)
    {
      gnutls_assert ();
      return NULL;
    }

  if (ret < 0)
    {
      gnutls_assert ();
      _gnutls_gcert_deinit (local_certs);
      gnutls_free (local_certs);
      return NULL;
    }

  return local_certs;
}

/* converts the given raw key to gnutls_privkey* and allocates
 * space for it.
 */
static gnutls_privkey *
alloc_and_load_pgp_key (const gnutls_openpgp_privkey_t key)
{
  gnutls_privkey *local_key;
  int ret = 0;

  if (key == NULL)
    return NULL;

  local_key = gnutls_malloc (sizeof (gnutls_privkey));
  if (local_key == NULL)
    {
      gnutls_assert ();
      return NULL;
    }

  if (_E_gnutls_openpgp_privkey_to_gkey == NULL)
    {
      gnutls_assert ();
      return NULL;
    }

  ret = _E_gnutls_openpgp_privkey_to_gkey (local_key, key);
  if (ret < 0)
    {
      gnutls_assert ();
      return NULL;
    }

  return local_key;
}


void
_gnutls_selected_certs_deinit (gnutls_session_t session)
{
  if (session->internals.selected_need_free != 0)
    {
      int i;

      for (i = 0; i < session->internals.selected_cert_list_length; i++)
        {
          _gnutls_gcert_deinit (&session->internals.selected_cert_list[i]);
        }
      gnutls_free (session->internals.selected_cert_list);
      session->internals.selected_cert_list = NULL;
      session->internals.selected_cert_list_length = 0;

      _gnutls_gkey_deinit (session->internals.selected_key);
      if (session->internals.selected_key)
        {
          gnutls_free (session->internals.selected_key);
          session->internals.selected_key = NULL;
        }
    }

  return;
}

void
_gnutls_selected_certs_set (gnutls_session_t session,
                            gnutls_cert * certs, int ncerts,
                            gnutls_privkey * key, int need_free)
{
  _gnutls_selected_certs_deinit (session);

  session->internals.selected_cert_list = certs;
  session->internals.selected_cert_list_length = ncerts;
  session->internals.selected_key = key;
  session->internals.selected_need_free = need_free;

}


/* finds the most appropriate certificate in the cert list.
 * The 'appropriate' is defined by the user.
 *
 * requested_algo holds the parameters required by the peer (RSA, DSA
 * or -1 for any).
 *
 * Returns 0 on success and a negative value on error. The
 * selected certificate will be in session->internals.selected_*.
 *
 */
int
_gnutls_server_select_cert (gnutls_session_t session,
                            gnutls_pk_algorithm_t requested_algo)
{
  unsigned i;
  int idx, ret;
  gnutls_certificate_credentials_t cred;

  cred = (gnutls_certificate_credentials_t)
    _gnutls_get_cred (session->key, MHD_GNUTLS_CRD_CERTIFICATE, NULL);
  if (cred == NULL)
    {
      gnutls_assert ();
      return GNUTLS_E_INSUFFICIENT_CREDENTIALS;
    }

  /* If the callback which retrieves certificate has been set,
   * use it and leave.
   */
  if (cred->server_get_cert_callback != NULL)
    return call_get_cert_callback (session, NULL, 0, NULL, 0);

  /* Otherwise... */

  ret = 0;
  idx = -1;                     /* default is use no certificate */


  for (i = 0; i < cred->ncerts; i++)
    {
      /* find one compatible certificate 
       */
      if (requested_algo == GNUTLS_PK_ANY ||
          requested_algo == cred->cert_list[i][0].subject_pk_algorithm)
        {
          /* if cert type matches 
           */
          if (session->security_parameters.cert_type ==
              cred->cert_list[i][0].cert_type)
            {
              idx = i;
              break;
            }
        }
    }

  /* store the certificate pointer for future use, in the handshake.
   * (This will allow not calling this callback again.)
   */
  if (idx >= 0 && ret == 0)
    {
      _gnutls_selected_certs_set (session,
                                  &cred->cert_list[idx][0],
                                  cred->cert_list_length[idx],
                                  &cred->pkey[idx], 0);
    }
  else
    /* Certificate does not support REQUESTED_ALGO.  */
    ret = GNUTLS_E_INSUFFICIENT_CREDENTIALS;

  return ret;
}

/* Frees the rsa_info_st structure.
 */
void
_gnutls_free_rsa_info (rsa_info_st * rsa)
{
  _gnutls_free_datum (&rsa->modulus);
  _gnutls_free_datum (&rsa->exponent);
}
