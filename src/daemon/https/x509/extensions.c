/*
 * Copyright (C) 2003, 2004, 2005, 2007 Free Software Foundation
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

/* Functions that relate to the X.509 extension parsing.
 */

#include <gnutls_int.h>
#include <gnutls_errors.h>
#include <gnutls_global.h>
#include <mpi.h>
#include <libtasn1.h>
#include <common.h>
#include <x509.h>
#include <extensions.h>
#include <gnutls_datum.h>

/* This function will attempt to return the requested extension found in
 * the given X509v3 certificate. The return value is allocated and stored into
 * ret.
 *
 * Critical will be either 0 or 1.
 *
 * If the extension does not exist, GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will
 * be returned.
 */
int
MHD__gnutls_x509_crt_get_extension (MHD_gnutls_x509_crt_t cert,
                                const char *extension_id, int indx,
                                MHD_gnutls_datum_t * ret, unsigned int *_critical)
{
  int k, result, len;
  char name[MAX_NAME_SIZE], name2[MAX_NAME_SIZE];
  char str[1024];
  char str_critical[10];
  int critical = 0;
  char extnID[128];
  MHD_gnutls_datum_t value;
  int indx_counter = 0;

  ret->data = NULL;
  ret->size = 0;

  k = 0;
  do
    {
      k++;

      snprintf (name, sizeof (name), "tbsCertificate.extensions.?%u", k);

      len = sizeof (str) - 1;
      result = MHD__asn1_read_value (cert->cert, name, str, &len);

      /* move to next
       */

      if (result == ASN1_ELEMENT_NOT_FOUND)
        {
          break;
        }

      do
        {

          MHD_gtls_str_cpy (name2, sizeof (name2), name);
          MHD_gtls_str_cat (name2, sizeof (name2), ".extnID");

          len = sizeof (extnID) - 1;
          result = MHD__asn1_read_value (cert->cert, name2, extnID, &len);

          if (result == ASN1_ELEMENT_NOT_FOUND)
            {
              MHD_gnutls_assert ();
              break;
            }
          else if (result != ASN1_SUCCESS)
            {
              MHD_gnutls_assert ();
              return MHD_gtls_asn2err (result);
            }

          /* Handle Extension
           */
          if (strcmp (extnID, extension_id) == 0 && indx == indx_counter++)
            {
              /* extension was found
               */

              /* read the critical status.
               */
              MHD_gtls_str_cpy (name2, sizeof (name2), name);
              MHD_gtls_str_cat (name2, sizeof (name2), ".critical");

              len = sizeof (str_critical);
              result =
                MHD__asn1_read_value (cert->cert, name2, str_critical, &len);

              if (result == ASN1_ELEMENT_NOT_FOUND)
                {
                  MHD_gnutls_assert ();
                  break;
                }
              else if (result != ASN1_SUCCESS)
                {
                  MHD_gnutls_assert ();
                  return MHD_gtls_asn2err (result);
                }

              if (str_critical[0] == 'T')
                critical = 1;
              else
                critical = 0;

              /* read the value.
               */
              MHD_gtls_str_cpy (name2, sizeof (name2), name);
              MHD_gtls_str_cat (name2, sizeof (name2), ".extnValue");

              result = MHD__gnutls_x509_read_value (cert->cert, name2, &value, 0);
              if (result < 0)
                {
                  MHD_gnutls_assert ();
                  return result;
                }

              ret->data = value.data;
              ret->size = value.size;

              if (_critical)
                *_critical = critical;

              return 0;
            }


        }
      while (0);
    }
  while (1);

  if (result == ASN1_ELEMENT_NOT_FOUND)
    {
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }
  else
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }
}

/* This function will attempt to return the requested extension OID found in
 * the given X509v3 certificate.
 *
 * If you have passed the last extension, GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE will
 * be returned.
 */
int
MHD__gnutls_x509_crt_get_extension_oid (MHD_gnutls_x509_crt_t cert,
                                    int indx, void *oid, size_t * sizeof_oid)
{
  int k, result, len;
  char name[MAX_NAME_SIZE], name2[MAX_NAME_SIZE];
  char str[1024];
  char extnID[128];
  int indx_counter = 0;

  k = 0;
  do
    {
      k++;

      snprintf (name, sizeof (name), "tbsCertificate.extensions.?%u", k);

      len = sizeof (str) - 1;
      result = MHD__asn1_read_value (cert->cert, name, str, &len);

      /* move to next
       */

      if (result == ASN1_ELEMENT_NOT_FOUND)
        {
          break;
        }

      do
        {

          MHD_gtls_str_cpy (name2, sizeof (name2), name);
          MHD_gtls_str_cat (name2, sizeof (name2), ".extnID");

          len = sizeof (extnID) - 1;
          result = MHD__asn1_read_value (cert->cert, name2, extnID, &len);

          if (result == ASN1_ELEMENT_NOT_FOUND)
            {
              MHD_gnutls_assert ();
              break;
            }
          else if (result != ASN1_SUCCESS)
            {
              MHD_gnutls_assert ();
              return MHD_gtls_asn2err (result);
            }

          /* Handle Extension
           */
          if (indx == indx_counter++)
            {
              len = strlen (extnID) + 1;

              if (*sizeof_oid < (unsigned) len)
                {
                  *sizeof_oid = len;
                  MHD_gnutls_assert ();
                  return GNUTLS_E_SHORT_MEMORY_BUFFER;
                }

              memcpy (oid, extnID, len);
              *sizeof_oid = len - 1;

              return 0;
            }


        }
      while (0);
    }
  while (1);

  if (result == ASN1_ELEMENT_NOT_FOUND)
    {
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }
  else
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }
}

/* This function will attempt to set the requested extension in
 * the given X509v3 certificate.
 *
 * Critical will be either 0 or 1.
 */
static int
set_extension (ASN1_TYPE asn, const char *extension_id,
               const MHD_gnutls_datum_t * ext_data, unsigned int critical)
{
  int result;
  const char *str;

  /* Add a new extension in the list.
   */
  result = MHD__asn1_write_value (asn, "tbsCertificate.extensions", "NEW", 1);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  result =
    MHD__asn1_write_value (asn, "tbsCertificate.extensions.?LAST.extnID",
                      extension_id, 1);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  if (critical == 0)
    str = "FALSE";
  else
    str = "TRUE";


  result =
    MHD__asn1_write_value (asn, "tbsCertificate.extensions.?LAST.critical",
                      str, 1);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  result =
    MHD__gnutls_x509_write_value (asn,
                              "tbsCertificate.extensions.?LAST.extnValue",
                              ext_data, 0);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  return 0;
}

/* Overwrite the given extension (using the index)
 * index here starts from one.
 */
static int
overwrite_extension (ASN1_TYPE asn, unsigned int indx,
                     const MHD_gnutls_datum_t * ext_data, unsigned int critical)
{
  char name[MAX_NAME_SIZE], name2[MAX_NAME_SIZE];
  const char *str;
  int result;

  snprintf (name, sizeof (name), "tbsCertificate.extensions.?%u", indx);

  if (critical == 0)
    str = "FALSE";
  else
    str = "TRUE";

  MHD_gtls_str_cpy (name2, sizeof (name2), name);
  MHD_gtls_str_cat (name2, sizeof (name2), ".critical");

  result = MHD__asn1_write_value (asn, name2, str, 1);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  MHD_gtls_str_cpy (name2, sizeof (name2), name);
  MHD_gtls_str_cat (name2, sizeof (name2), ".extnValue");

  result = MHD__gnutls_x509_write_value (asn, name2, ext_data, 0);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  return 0;
}

/* This function will attempt to overwrite the requested extension with
 * the given one.
 *
 * Critical will be either 0 or 1.
 */
int
MHD__gnutls_x509_crt_set_extension (MHD_gnutls_x509_crt_t cert,
                                const char *ext_id,
                                const MHD_gnutls_datum_t * ext_data,
                                unsigned int critical)
{
  int result;
  int k, len;
  char name[MAX_NAME_SIZE], name2[MAX_NAME_SIZE];
  char extnID[128];

  /* Find the index of the given extension.
   */
  k = 0;
  do
    {
      k++;

      snprintf (name, sizeof (name), "tbsCertificate.extensions.?%u", k);

      len = sizeof (extnID) - 1;
      result = MHD__asn1_read_value (cert->cert, name, extnID, &len);

      /* move to next
       */

      if (result == ASN1_ELEMENT_NOT_FOUND)
        {
          break;
        }

      do
        {

          MHD_gtls_str_cpy (name2, sizeof (name2), name);
          MHD_gtls_str_cat (name2, sizeof (name2), ".extnID");

          len = sizeof (extnID) - 1;
          result = MHD__asn1_read_value (cert->cert, name2, extnID, &len);

          if (result == ASN1_ELEMENT_NOT_FOUND)
            {
              MHD_gnutls_assert ();
              break;
            }
          else if (result != ASN1_SUCCESS)
            {
              MHD_gnutls_assert ();
              return MHD_gtls_asn2err (result);
            }

          /* Handle Extension
           */
          if (strcmp (extnID, ext_id) == 0)
            {
              /* extension was found
               */
              return overwrite_extension (cert->cert, k, ext_data, critical);
            }


        }
      while (0);
    }
  while (1);

  if (result == ASN1_ELEMENT_NOT_FOUND)
    {
      return set_extension (cert->cert, ext_id, ext_data, critical);
    }
  else
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }


  return 0;
}


/* Here we only extract the KeyUsage field, from the DER encoded
 * extension.
 */
int
MHD__gnutls_x509_ext_extract_keyUsage (uint16_t * keyUsage,
                                   opaque * extnValue, int extnValueLen)
{
  ASN1_TYPE ext = ASN1_TYPE_EMPTY;
  int len, result;
  uint8_t str[2];

  str[0] = str[1] = 0;
  *keyUsage = 0;

  if ((result = MHD__asn1_create_element
       (MHD__gnutls_get_pkix (), "PKIX1.KeyUsage", &ext)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  result = MHD__asn1_der_decoding (&ext, extnValue, extnValueLen, NULL);

  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&ext);
      return MHD_gtls_asn2err (result);
    }

  len = sizeof (str);
  result = MHD__asn1_read_value (ext, "", str, &len);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&ext);
      return 0;
    }

  *keyUsage = str[0] | (str[1] << 8);

  MHD__asn1_delete_structure (&ext);

  return 0;
}

/* extract the basicConstraints from the DER encoded extension
 */
int
MHD__gnutls_x509_ext_extract_basicConstraints (int *CA,
                                           int *pathLenConstraint,
                                           opaque * extnValue,
                                           int extnValueLen)
{
  ASN1_TYPE ext = ASN1_TYPE_EMPTY;
  char str[128];
  int len, result;

  if ((result = MHD__asn1_create_element
       (MHD__gnutls_get_pkix (), "PKIX1.BasicConstraints", &ext)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  result = MHD__asn1_der_decoding (&ext, extnValue, extnValueLen, NULL);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&ext);
      return MHD_gtls_asn2err (result);
    }

  if (pathLenConstraint)
    {
      result = MHD__gnutls_x509_read_uint (ext, "pathLenConstraint",
                                       pathLenConstraint);
      if (result == GNUTLS_E_ASN1_ELEMENT_NOT_FOUND)
        *pathLenConstraint = -1;
      else if (result != GNUTLS_E_SUCCESS)
        {
          MHD_gnutls_assert ();
          MHD__asn1_delete_structure (&ext);
          return MHD_gtls_asn2err (result);
        }
    }

  /* the default value of cA is false.
   */
  len = sizeof (str) - 1;
  result = MHD__asn1_read_value (ext, "cA", str, &len);
  if (result == ASN1_SUCCESS && strcmp (str, "TRUE") == 0)
    *CA = 1;
  else
    *CA = 0;

  MHD__asn1_delete_structure (&ext);

  return 0;
}

/* generate the basicConstraints in a DER encoded extension
 * Use 0 or 1 (TRUE) for CA.
 * Use negative values for pathLenConstraint to indicate that the field
 * should not be present, >= 0 to indicate set values.
 */
int
MHD__gnutls_x509_ext_gen_basicConstraints (int CA,
                                       int pathLenConstraint,
                                       MHD_gnutls_datum_t * der_ext)
{
  ASN1_TYPE ext = ASN1_TYPE_EMPTY;
  const char *str;
  int result;

  if (CA == 0)
    str = "FALSE";
  else
    str = "TRUE";

  result =
    MHD__asn1_create_element (MHD__gnutls_get_pkix (), "PKIX1.BasicConstraints", &ext);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  result = MHD__asn1_write_value (ext, "cA", str, 1);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&ext);
      return MHD_gtls_asn2err (result);
    }

  if (pathLenConstraint < 0)
    {
      result = MHD__asn1_write_value (ext, "pathLenConstraint", NULL, 0);
      if (result < 0)
        result = MHD_gtls_asn2err (result);
    }
  else
    result = MHD__gnutls_x509_write_uint32 (ext, "pathLenConstraint",
                                        pathLenConstraint);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&ext);
      return result;
    }

  result = MHD__gnutls_x509_der_encode (ext, "", der_ext, 0);

  MHD__asn1_delete_structure (&ext);

  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  return 0;
}

/* generate the keyUsage in a DER encoded extension
 * Use an ORed SEQUENCE of GNUTLS_KEY_* for usage.
 */
int
MHD__gnutls_x509_ext_gen_keyUsage (uint16_t usage, MHD_gnutls_datum_t * der_ext)
{
  ASN1_TYPE ext = ASN1_TYPE_EMPTY;
  int result;
  uint8_t str[2];

  result = MHD__asn1_create_element (MHD__gnutls_get_pkix (), "PKIX1.KeyUsage", &ext);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  str[0] = usage & 0xff;
  str[1] = usage >> 8;

  result = MHD__asn1_write_value (ext, "", str, 9);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&ext);
      return MHD_gtls_asn2err (result);
    }

  result = MHD__gnutls_x509_der_encode (ext, "", der_ext, 0);

  MHD__asn1_delete_structure (&ext);

  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  return 0;
}

static int
write_new_general_name (ASN1_TYPE ext, const char *ext_name,
                        MHD_gnutls_x509_subject_alt_name_t type,
                        const char *data_string)
{
  const char *str;
  int result;
  char name[128];

  result = MHD__asn1_write_value (ext, ext_name, "NEW", 1);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  switch (type)
    {
    case GNUTLS_SAN_DNSNAME:
      str = "dNSName";
      break;
    case GNUTLS_SAN_RFC822NAME:
      str = "rfc822Name";
      break;
    case GNUTLS_SAN_URI:
      str = "uniformResourceIdentifier";
      break;
    case GNUTLS_SAN_IPADDRESS:
      str = "iPAddress";
      break;
    default:
      MHD_gnutls_assert ();
      return GNUTLS_E_INTERNAL_ERROR;
    }

  if (ext_name[0] == 0)
    {                           /* no dot */
      MHD_gtls_str_cpy (name, sizeof (name), "?LAST");
    }
  else
    {
      MHD_gtls_str_cpy (name, sizeof (name), ext_name);
      MHD_gtls_str_cat (name, sizeof (name), ".?LAST");
    }

  result = MHD__asn1_write_value (ext, name, str, 1);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  MHD_gtls_str_cat (name, sizeof (name), ".");
  MHD_gtls_str_cat (name, sizeof (name), str);

  result = MHD__asn1_write_value (ext, name, data_string, strlen (data_string));
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&ext);
      return MHD_gtls_asn2err (result);
    }

  return 0;
}

/* Convert the given name to GeneralNames in a DER encoded extension.
 * This is the same as subject alternative name.
 */
int
MHD__gnutls_x509_ext_gen_subject_alt_name (MHD_gnutls_x509_subject_alt_name_t
                                       type, const char *data_string,
                                       MHD_gnutls_datum_t * der_ext)
{
  ASN1_TYPE ext = ASN1_TYPE_EMPTY;
  int result;

  result =
    MHD__asn1_create_element (MHD__gnutls_get_pkix (), "PKIX1.GeneralNames", &ext);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  result = write_new_general_name (ext, "", type, data_string);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&ext);
      return result;
    }

  result = MHD__gnutls_x509_der_encode (ext, "", der_ext, 0);

  MHD__asn1_delete_structure (&ext);

  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  return 0;
}

/* generate the SubjectKeyID in a DER encoded extension
 */
int
MHD__gnutls_x509_ext_gen_key_id (const void *id, size_t id_size,
                             MHD_gnutls_datum_t * der_ext)
{
  ASN1_TYPE ext = ASN1_TYPE_EMPTY;
  int result;

  result =
    MHD__asn1_create_element (MHD__gnutls_get_pkix (),
                         "PKIX1.SubjectKeyIdentifier", &ext);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  result = MHD__asn1_write_value (ext, "", id, id_size);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&ext);
      return MHD_gtls_asn2err (result);
    }

  result = MHD__gnutls_x509_der_encode (ext, "", der_ext, 0);

  MHD__asn1_delete_structure (&ext);

  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  return 0;
}

/* generate the AuthorityKeyID in a DER encoded extension
 */
int
MHD__gnutls_x509_ext_gen_auth_key_id (const void *id, size_t id_size,
                                  MHD_gnutls_datum_t * der_ext)
{
  ASN1_TYPE ext = ASN1_TYPE_EMPTY;
  int result;

  result =
    MHD__asn1_create_element (MHD__gnutls_get_pkix (),
                         "PKIX1.AuthorityKeyIdentifier", &ext);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  result = MHD__asn1_write_value (ext, "keyIdentifier", id, id_size);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&ext);
      return MHD_gtls_asn2err (result);
    }

  MHD__asn1_write_value (ext, "authorityCertIssuer", NULL, 0);
  MHD__asn1_write_value (ext, "authorityCertSerialNumber", NULL, 0);

  result = MHD__gnutls_x509_der_encode (ext, "", der_ext, 0);

  MHD__asn1_delete_structure (&ext);

  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  return 0;
}


/* Creates and encodes the CRL Distribution points. data_string should be a name
 * and type holds the type of the name.
 * reason_flags should be an or'ed sequence of GNUTLS_CRL_REASON_*.
 *
 */
int
MHD__gnutls_x509_ext_gen_crl_dist_points (MHD_gnutls_x509_subject_alt_name_t
                                      type, const void *data_string,
                                      unsigned int reason_flags,
                                      MHD_gnutls_datum_t * der_ext)
{
  ASN1_TYPE ext = ASN1_TYPE_EMPTY;
  MHD_gnutls_datum_t gnames = { NULL, 0 };
  int result;
  uint8_t reasons[2];

  reasons[0] = reason_flags & 0xff;
  reasons[1] = reason_flags >> 8;

  result =
    MHD__asn1_create_element (MHD__gnutls_get_pkix (),
                         "PKIX1.CRLDistributionPoints", &ext);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  result = MHD__asn1_write_value (ext, "", "NEW", 1);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  if (reason_flags)
    {
      result = MHD__asn1_write_value (ext, "?LAST.reasons", reasons, 9);
      if (result != ASN1_SUCCESS)
        {
          MHD_gnutls_assert ();
          result = MHD_gtls_asn2err (result);
          goto cleanup;
        }
    }
  else
    {
      result = MHD__asn1_write_value (ext, "?LAST.reasons", NULL, 0);
      if (result != ASN1_SUCCESS)
        {
          MHD_gnutls_assert ();
          result = MHD_gtls_asn2err (result);
          goto cleanup;
        }
    }

  result = MHD__asn1_write_value (ext, "?LAST.cRLIssuer", NULL, 0);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

  /* When used as type CHOICE.
   */
  result = MHD__asn1_write_value (ext, "?LAST.distributionPoint", "fullName", 1);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      result = MHD_gtls_asn2err (result);
      goto cleanup;
    }

#if 0
  /* only needed in old code (where defined as SEQUENCE OF) */
  MHD__asn1_write_value (ext,
                    "?LAST.distributionPoint.nameRelativeToCRLIssuer",
                    NULL, 0);
#endif

  result =
    write_new_general_name (ext, "?LAST.distributionPoint.fullName",
                            type, data_string);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      goto cleanup;
    }

  result = MHD__gnutls_x509_der_encode (ext, "", der_ext, 0);

  if (result < 0)
    {
      MHD_gnutls_assert ();
      goto cleanup;
    }

  result = 0;

cleanup:
  MHD__gnutls_free_datum (&gnames);
  MHD__asn1_delete_structure (&ext);

  return result;
}

/* extract the proxyCertInfo from the DER encoded extension
 */
int
MHD__gnutls_x509_ext_extract_proxyCertInfo (int *pathLenConstraint,
                                        char **policyLanguage,
                                        char **policy,
                                        size_t * sizeof_policy,
                                        opaque * extnValue, int extnValueLen)
{
  ASN1_TYPE ext = ASN1_TYPE_EMPTY;
  int result;
  MHD_gnutls_datum_t value;

  if ((result = MHD__asn1_create_element
       (MHD__gnutls_get_pkix (), "PKIX1.ProxyCertInfo", &ext)) != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  result = MHD__asn1_der_decoding (&ext, extnValue, extnValueLen, NULL);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&ext);
      return MHD_gtls_asn2err (result);
    }

  if (pathLenConstraint)
    {
      result = MHD__gnutls_x509_read_uint (ext, "pCPathLenConstraint",
                                       pathLenConstraint);
      if (result == GNUTLS_E_ASN1_ELEMENT_NOT_FOUND)
        *pathLenConstraint = -1;
      else if (result != GNUTLS_E_SUCCESS)
        {
          MHD__asn1_delete_structure (&ext);
          return MHD_gtls_asn2err (result);
        }
    }

  result = MHD__gnutls_x509_read_value (ext, "proxyPolicy.policyLanguage",
                                    &value, 0);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&ext);
      return result;
    }

  if (policyLanguage)
    *policyLanguage = MHD_gnutls_strdup (value.data);

  result = MHD__gnutls_x509_read_value (ext, "proxyPolicy.policy", &value, 0);
  if (result == GNUTLS_E_ASN1_ELEMENT_NOT_FOUND)
    {
      if (policy)
        *policy = NULL;
      if (sizeof_policy)
        *sizeof_policy = 0;
    }
  else if (result < 0)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&ext);
      return result;
    }
  else
    {
      if (policy)
        *policy = value.data;
      if (sizeof_policy)
        *sizeof_policy = value.size;
    }

  MHD__asn1_delete_structure (&ext);

  return 0;
}

/* generate the proxyCertInfo in a DER encoded extension
 */
int
MHD__gnutls_x509_ext_gen_proxyCertInfo (int pathLenConstraint,
                                    const char *policyLanguage,
                                    const char *policy,
                                    size_t sizeof_policy,
                                    MHD_gnutls_datum_t * der_ext)
{
  ASN1_TYPE ext = ASN1_TYPE_EMPTY;
  int result;

  result = MHD__asn1_create_element (MHD__gnutls_get_pkix (),
                                "PKIX1.ProxyCertInfo", &ext);
  if (result != ASN1_SUCCESS)
    {
      MHD_gnutls_assert ();
      return MHD_gtls_asn2err (result);
    }

  if (pathLenConstraint < 0)
    {
      result = MHD__asn1_write_value (ext, "pCPathLenConstraint", NULL, 0);
      if (result < 0)
        result = MHD_gtls_asn2err (result);
    }
  else
    result = MHD__gnutls_x509_write_uint32 (ext, "pCPathLenConstraint",
                                        pathLenConstraint);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&ext);
      return result;
    }

  result = MHD__asn1_write_value (ext, "proxyPolicy.policyLanguage",
                             policyLanguage, 1);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&ext);
      return MHD_gtls_asn2err (result);
    }

  result = MHD__asn1_write_value (ext, "proxyPolicy.policy",
                             policy, sizeof_policy);
  if (result < 0)
    {
      MHD_gnutls_assert ();
      MHD__asn1_delete_structure (&ext);
      return MHD_gtls_asn2err (result);
    }

  result = MHD__gnutls_x509_der_encode (ext, "", der_ext, 0);

  MHD__asn1_delete_structure (&ext);

  if (result < 0)
    {
      MHD_gnutls_assert ();
      return result;
    }

  return 0;
}
