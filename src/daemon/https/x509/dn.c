/*
 * Copyright (C) 2003, 2004, 2005, 2007  Free Software Foundation
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

#include <gnutls_int.h>
#include <libtasn1.h>
#include <gnutls_datum.h>
#include <gnutls_global.h>
#include <gnutls_errors.h>
#include <gnutls_str.h>
#include <common.h>
#include <gnutls_num.h>
#include <dn.h>

/* This file includes all the required to parse an X.509 Distriguished
 * Name (you need a parser just to read a name in the X.509 protoocols!!!)
 */

/* Converts the given OID to an ldap acceptable string or
 * a dotted OID.
 */
static const char *
oid2ldap_string (const char *oid)
{
  const char *ret;

  ret = MHD__gnutls_x509_oid2ldap_string (oid);
  if (ret)
    return ret;

  /* else return the OID in dotted format */
  return oid;
}

/* Escapes a string following the rules from RFC2253.
 */
static char *
str_escape (char *str, char *buffer, unsigned int buffer_size)
{
  int str_length, j, i;

  if (str == NULL || buffer == NULL)
    return NULL;

  str_length = MIN (strlen (str), buffer_size - 1);

  for (i = j = 0; i < str_length; i++)
    {
      if (str[i] == ',' || str[i] == '+' || str[i] == '"'
          || str[i] == '\\' || str[i] == '<' || str[i] == '>'
          || str[i] == ';')
        buffer[j++] = '\\';

      buffer[j++] = str[i];
    }

  /* null terminate the string */
  buffer[j] = 0;

  return buffer;
}

/* Parses an X509 DN in the MHD__asn1_struct, and puts the output into
 * the string buf. The output is an LDAP encoded DN.
 *
 * MHD__asn1_rdn_name must be a string in the form "tbsCertificate.issuer.rdnSequence".
 * That is to point in the rndSequence.
 */
int
MHD__gnutls_x509_parse_dn (ASN1_TYPE MHD__asn1_struct,
                           const char *MHD__asn1_rdn_name, char *buf,
                           size_t * sizeof_buf)
{
  MHD_gtls_string out_str;
  int k2, k1, result;
  char tmpbuffer1[MAX_NAME_SIZE];
  char tmpbuffer2[MAX_NAME_SIZE];
  char tmpbuffer3[MAX_NAME_SIZE];
  opaque value[MAX_STRING_LEN], *value2 = NULL;
  char *escaped = NULL;
  const char *ldap_desc;
  char oid[128];
  int len, printable;
  char *string = NULL;
  size_t sizeof_string, sizeof_escaped;

  if (sizeof_buf == NULL)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (*sizeof_buf > 0 && buf)
    buf[0] = 0;
  else
    *sizeof_buf = 0;

  MHD_gtls_string_init (&out_str, MHD_gnutls_malloc, MHD_gnutls_realloc,
                        MHD_gnutls_free);

  k1 = 0;
  do
    {

      k1++;
      /* create a string like "tbsCertList.issuer.rdnSequence.?1"
       */
      if (MHD__asn1_rdn_name[0] != 0)
        snprintf (tmpbuffer1, sizeof (tmpbuffer1), "%s.?%u",
                  MHD__asn1_rdn_name, k1);
      else
        snprintf (tmpbuffer1, sizeof (tmpbuffer1), "?%u", k1);

      len = sizeof (value) - 1;
      result =
        MHD__asn1_read_value (MHD__asn1_struct, tmpbuffer1, value, &len);

      if (result == ASN1_ELEMENT_NOT_FOUND)
        {
          break;
        }

      if (result != ASN1_VALUE_NOT_FOUND)
        {
          MHD_gnutls_assert ();
          result = MHD_gtls_asn2err (result);
          goto cleanup;
        }

      k2 = 0;

      do
        {                       /* Move to the attibute type and values
                                 */
          k2++;

          if (tmpbuffer1[0] != 0)
            snprintf (tmpbuffer2, sizeof (tmpbuffer2), "%s.?%u", tmpbuffer1,
                      k2);
          else
            snprintf (tmpbuffer2, sizeof (tmpbuffer2), "?%u", k2);

          /* Try to read the RelativeDistinguishedName attributes.
           */

          len = sizeof (value) - 1;
          result =
            MHD__asn1_read_value (MHD__asn1_struct, tmpbuffer2, value, &len);

          if (result == ASN1_ELEMENT_NOT_FOUND)
            break;
          if (result != ASN1_VALUE_NOT_FOUND)
            {
              MHD_gnutls_assert ();
              result = MHD_gtls_asn2err (result);
              goto cleanup;
            }

          /* Read the OID
           */
          MHD_gtls_str_cpy (tmpbuffer3, sizeof (tmpbuffer3), tmpbuffer2);
          MHD_gtls_str_cat (tmpbuffer3, sizeof (tmpbuffer3), ".type");

          len = sizeof (oid) - 1;
          result =
            MHD__asn1_read_value (MHD__asn1_struct, tmpbuffer3, oid, &len);

          if (result == ASN1_ELEMENT_NOT_FOUND)
            break;
          else if (result != ASN1_SUCCESS)
            {
              MHD_gnutls_assert ();
              result = MHD_gtls_asn2err (result);
              goto cleanup;
            }

          /* Read the Value
           */
          MHD_gtls_str_cpy (tmpbuffer3, sizeof (tmpbuffer3), tmpbuffer2);
          MHD_gtls_str_cat (tmpbuffer3, sizeof (tmpbuffer3), ".value");

          len = 0;
          result =
            MHD__asn1_read_value (MHD__asn1_struct, tmpbuffer3, NULL, &len);

          value2 = MHD_gnutls_malloc (len);
          if (value2 == NULL)
            {
              MHD_gnutls_assert ();
              result = GNUTLS_E_MEMORY_ERROR;
              goto cleanup;
            }

          result =
            MHD__asn1_read_value (MHD__asn1_struct, tmpbuffer3, value2, &len);

          if (result != ASN1_SUCCESS)
            {
              MHD_gnutls_assert ();
              result = MHD_gtls_asn2err (result);
              goto cleanup;
            }
#define STR_APPEND(y) if ((result=MHD_gtls_string_append_str( &out_str, y)) < 0) { \
	MHD_gnutls_assert(); \
	goto cleanup; \
}
          /*   The encodings of adjoining RelativeDistinguishedNames are separated
           *   by a comma character (',' ASCII 44).
           */

          /*   Where there is a multi-valued RDN, the outputs from adjoining
           *   AttributeTypeAndValues are separated by a plus ('+' ASCII 43)
           *   character.
           */
          if (k1 != 1)
            {                   /* the first time do not append a comma */
              if (k2 != 1)
                {               /* adjoining multi-value RDN */
                  STR_APPEND ("+");
                }
              else
                {
                  STR_APPEND (",");
                }
            }

          ldap_desc = oid2ldap_string (oid);
          printable = MHD__gnutls_x509_oid_data_printable (oid);

          sizeof_escaped = 2 * len + 1;

          escaped = MHD_gnutls_malloc (sizeof_escaped);
          if (escaped == NULL)
            {
              MHD_gnutls_assert ();
              result = GNUTLS_E_MEMORY_ERROR;
              goto cleanup;
            }

          sizeof_string = 2 * len + 2;  /* in case it is not printable */

          string = MHD_gnutls_malloc (sizeof_string);
          if (string == NULL)
            {
              MHD_gnutls_assert ();
              result = GNUTLS_E_MEMORY_ERROR;
              goto cleanup;
            }

          STR_APPEND (ldap_desc);
          STR_APPEND ("=");
          result = 0;

          if (printable)
            result =
              MHD__gnutls_x509_oid_data2string (oid,
                                                value2, len,
                                                string, &sizeof_string);

          if (!printable || result < 0)
            result =
              MHD__gnutls_x509_data2hex ((const unsigned char *) value2, len,
                                         (unsigned char *) string,
                                         &sizeof_string);

          if (result < 0)
            {
              MHD_gnutls_assert ();
              MHD__gnutls_x509_log
                ("Found OID: '%s' with value '%s'\n",
                 oid, MHD_gtls_bin2hex (value2, len, escaped,
                                        sizeof_escaped));
              goto cleanup;
            }
          STR_APPEND (str_escape (string, escaped, sizeof_escaped));
          MHD_gnutls_free (string);
          string = NULL;

          MHD_gnutls_free (escaped);
          escaped = NULL;
          MHD_gnutls_free (value2);
          value2 = NULL;

        }
      while (1);

    }
  while (1);

  if (out_str.length >= (unsigned int) *sizeof_buf)
    {
      MHD_gnutls_assert ();
      *sizeof_buf = out_str.length + 1;
      result = GNUTLS_E_SHORT_MEMORY_BUFFER;
      goto cleanup;
    }

  if (buf)
    {
      memcpy (buf, out_str.data, out_str.length);
      buf[out_str.length] = 0;
    }
  *sizeof_buf = out_str.length;

  result = 0;

cleanup:
  MHD_gnutls_free (value2);
  MHD_gnutls_free (string);
  MHD_gnutls_free (escaped);
  MHD_gtls_string_clear (&out_str);
  return result;
}

/* Parses an X509 DN in the MHD__asn1_struct, and searches for the
 * given OID in the DN.
 *
 * If raw_flag == 0, the output will be encoded in the LDAP way. (#hex for non printable)
 * Otherwise the raw DER data are returned.
 *
 * MHD__asn1_rdn_name must be a string in the form "tbsCertificate.issuer.rdnSequence".
 * That is to point in the rndSequence.
 *
 * indx specifies which OID to return. Ie 0 means return the first specified
 * OID found, 1 the second etc.
 */
int
MHD__gnutls_x509_parse_dn_oid (ASN1_TYPE MHD__asn1_struct,
                               const char *MHD__asn1_rdn_name,
                               const char *given_oid, int indx,
                               unsigned int raw_flag,
                               void *buf, size_t * sizeof_buf)
{
  int k2, k1, result;
  char tmpbuffer1[MAX_NAME_SIZE];
  char tmpbuffer2[MAX_NAME_SIZE];
  char tmpbuffer3[MAX_NAME_SIZE];
  opaque value[256];
  char oid[128];
  int len, printable;
  int i = 0;
  char *cbuf = buf;

  if (cbuf == NULL)
    *sizeof_buf = 0;
  else
    cbuf[0] = 0;

  k1 = 0;
  do
    {

      k1++;
      /* create a string like "tbsCertList.issuer.rdnSequence.?1"
       */
      if (MHD__asn1_rdn_name[0] != 0)
        snprintf (tmpbuffer1, sizeof (tmpbuffer1), "%s.?%u",
                  MHD__asn1_rdn_name, k1);
      else
        snprintf (tmpbuffer1, sizeof (tmpbuffer1), "?%u", k1);

      len = sizeof (value) - 1;
      result =
        MHD__asn1_read_value (MHD__asn1_struct, tmpbuffer1, value, &len);

      if (result == ASN1_ELEMENT_NOT_FOUND)
        {
          MHD_gnutls_assert ();
          break;
        }

      if (result != ASN1_VALUE_NOT_FOUND)
        {
          MHD_gnutls_assert ();
          result = MHD_gtls_asn2err (result);
          goto cleanup;
        }

      k2 = 0;

      do
        {                       /* Move to the attibute type and values
                                 */
          k2++;

          if (tmpbuffer1[0] != 0)
            snprintf (tmpbuffer2, sizeof (tmpbuffer2), "%s.?%u", tmpbuffer1,
                      k2);
          else
            snprintf (tmpbuffer2, sizeof (tmpbuffer2), "?%u", k2);

          /* Try to read the RelativeDistinguishedName attributes.
           */

          len = sizeof (value) - 1;
          result =
            MHD__asn1_read_value (MHD__asn1_struct, tmpbuffer2, value, &len);

          if (result == ASN1_ELEMENT_NOT_FOUND)
            {
              break;
            }
          if (result != ASN1_VALUE_NOT_FOUND)
            {
              MHD_gnutls_assert ();
              result = MHD_gtls_asn2err (result);
              goto cleanup;
            }

          /* Read the OID
           */
          MHD_gtls_str_cpy (tmpbuffer3, sizeof (tmpbuffer3), tmpbuffer2);
          MHD_gtls_str_cat (tmpbuffer3, sizeof (tmpbuffer3), ".type");

          len = sizeof (oid) - 1;
          result =
            MHD__asn1_read_value (MHD__asn1_struct, tmpbuffer3, oid, &len);

          if (result == ASN1_ELEMENT_NOT_FOUND)
            break;
          else if (result != ASN1_SUCCESS)
            {
              MHD_gnutls_assert ();
              result = MHD_gtls_asn2err (result);
              goto cleanup;
            }

          if (strcmp (oid, given_oid) == 0 && indx == i++)
            {                   /* Found the OID */

              /* Read the Value
               */
              MHD_gtls_str_cpy (tmpbuffer3, sizeof (tmpbuffer3), tmpbuffer2);
              MHD_gtls_str_cat (tmpbuffer3, sizeof (tmpbuffer3), ".value");

              len = *sizeof_buf;
              result =
                MHD__asn1_read_value (MHD__asn1_struct, tmpbuffer3, buf,
                                      &len);

              if (result != ASN1_SUCCESS)
                {
                  MHD_gnutls_assert ();
                  if (result == ASN1_MEM_ERROR)
                    *sizeof_buf = len;
                  result = MHD_gtls_asn2err (result);
                  goto cleanup;
                }

              if (raw_flag != 0)
                {
                  if ((unsigned) len > *sizeof_buf)
                    {
                      *sizeof_buf = len;
                      result = GNUTLS_E_SHORT_MEMORY_BUFFER;
                      goto cleanup;
                    }
                  *sizeof_buf = len;

                  return 0;

                }
              else
                {               /* parse data. raw_flag == 0 */
                  printable = MHD__gnutls_x509_oid_data_printable (oid);

                  if (printable == 1)
                    result =
                      MHD__gnutls_x509_oid_data2string (oid, buf, len,
                                                        cbuf, sizeof_buf);
                  else
                    result =
                      MHD__gnutls_x509_data2hex (buf, len,
                                                 (unsigned char *) cbuf,
                                                 sizeof_buf);

                  if (result < 0)
                    {
                      MHD_gnutls_assert ();
                      goto cleanup;
                    }

                  return 0;

                }               /* raw_flag == 0 */
            }
        }
      while (1);

    }
  while (1);

  MHD_gnutls_assert ();

  result = GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

cleanup:
  return result;
}

/*
 * Compares the DER encoded part of a DN.
 *
 * FIXME: use a real DN comparison algorithm.
 *
 * Returns 1 if the DN's match and zero if they don't match. Otherwise
 * a negative value is returned to indicate error.
 */
int
MHD__gnutls_x509_compare_raw_dn (const MHD_gnutls_datum_t * dn1,
                                 const MHD_gnutls_datum_t * dn2)
{

  if (dn1->size != dn2->size)
    {
      MHD_gnutls_assert ();
      return 0;
    }
  if (memcmp (dn1->data, dn2->data, dn2->size) != 0)
    {
      MHD_gnutls_assert ();
      return 0;
    }
  return 1;                     /* they match */
}
