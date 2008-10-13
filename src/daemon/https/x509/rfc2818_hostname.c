/*
 * Copyright (C) 2003, 2004, 2005, 2007 Free Software Foundation
 * Copyright (C) 2002 Andrew McDonald
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
#include <x509.h>
#include <dn.h>
#include <common.h>
#include <rfc2818.h>
#include <gnutls_errors.h>

/* compare hostname against certificate, taking account of wildcards
 * return 1 on success or 0 on error
 */
int
MHD__gnutls_hostname_compare (const char *certname, const char *hostname)
{
  const char *cmpstr1, *cmpstr2;

  if (strlen (certname) == 0 || strlen (hostname) == 0)
    return 0;

  if (strlen (certname) > 2 && strncmp (certname, "*.", 2) == 0)
    {
      /* a wildcard certificate */

      cmpstr1 = certname + 1;

      /* find the first dot in hostname, compare from there on */
      cmpstr2 = strchr (hostname, '.');

      if (cmpstr2 == NULL)
        {
          /* error, the hostname we're connecting to is only a local part */
          return 0;
        }

      if (strcasecmp (cmpstr1, cmpstr2) == 0)
        {
          return 1;
        }

      return 0;
    }

  if (strcasecmp (certname, hostname) == 0)
    {
      return 1;
    }

  return 0;
}

/**
  * MHD_gnutls_x509_crt_check_hostname - This function compares the given hostname with the hostname in the certificate
  * @cert: should contain an MHD_gnutls_x509_crt_t structure
  * @hostname: A null terminated string that contains a DNS name
  *
  * This function will check if the given certificate's subject
  * matches the given hostname.  This is a basic implementation of the
  * matching described in RFC2818 (HTTPS), which takes into account
  * wildcards, and the DNSName/IPAddress subject alternative name PKIX
  * extension.
  *
  * Returns non zero for a successful match, and zero on failure.
  **/
int
MHD_gnutls_x509_crt_check_hostname (MHD_gnutls_x509_crt_t cert,
                                    const char *hostname)
{

  char dnsname[MAX_CN];
  size_t dnsnamesize;
  int found_dnsname = 0;
  int ret = 0;
  int i = 0;

  /* try matching against:
   *  1) a DNS name as an alternative name (subjectAltName) extension
   *     in the certificate
   *  2) the common name (CN) in the certificate
   *
   *  either of these may be of the form: *.domain.tld
   *
   *  only try (2) if there is no subjectAltName extension of
   *  type dNSName
   */

  /* Check through all included subjectAltName extensions, comparing
   * against all those of type dNSName.
   */
  for (i = 0; !(ret < 0); i++)
    {

      dnsnamesize = sizeof (dnsname);
      ret = MHD_gnutls_x509_crt_get_subject_alt_name (cert, i,
                                                      dnsname, &dnsnamesize,
                                                      NULL);

      if (ret == GNUTLS_SAN_DNSNAME)
        {
          found_dnsname = 1;
          if (MHD__gnutls_hostname_compare (dnsname, hostname))
            {
              return 1;
            }
        }
      else if (ret == GNUTLS_SAN_IPADDRESS)
        {
          found_dnsname = 1;    /* RFC 2818 is unclear whether the CN
                                   should be compared for IP addresses
                                   too, but we won't do it.  */
          if (MHD__gnutls_hostname_compare (dnsname, hostname))
            {
              return 1;
            }
        }
    }

  if (!found_dnsname)
    {
      /* not got the necessary extension, use CN instead
       */
      dnsnamesize = sizeof (dnsname);
      if (MHD_gnutls_x509_crt_get_dn_by_oid (cert, OID_X520_COMMON_NAME, 0,
                                             0, dnsname, &dnsnamesize) < 0)
        {
          /* got an error, can't find a name
           */
          return 0;
        }

      if (MHD__gnutls_hostname_compare (dnsname, hostname))
        {
          return 1;
        }
    }

  /* not found a matching name
   */
  return 0;
}
