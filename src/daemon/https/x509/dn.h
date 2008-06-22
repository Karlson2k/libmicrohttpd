/*
 * Copyright (C) 2003, 2004, 2005 Free Software Foundation
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

#ifndef DN_H
# define DN_H

/* Some OIDs usually found in Distinguished names
 */
#define OID_X520_COUNTRY_NAME		"2.5.4.6"
#define OID_X520_ORGANIZATION_NAME	"2.5.4.10"
#define OID_X520_ORGANIZATIONAL_UNIT_NAME "2.5.4.11"
#define OID_X520_COMMON_NAME 		"2.5.4.3"
#define OID_X520_LOCALITY_NAME 		"2.5.4.7"
#define OID_X520_STATE_OR_PROVINCE_NAME 	"2.5.4.8"
#define OID_LDAP_DC			"0.9.2342.19200300.100.1.25"
#define OID_LDAP_UID			"0.9.2342.19200300.100.1.1"
#define OID_PKCS9_EMAIL 			"1.2.840.113549.1.9.1"

int _gnutls_x509_parse_dn (ASN1_TYPE asn1_struct,
			   const char *asn1_rdn_name, char *buf,
			   size_t * sizeof_buf);

int _gnutls_x509_parse_dn_oid (ASN1_TYPE asn1_struct,
			       const char *asn1_rdn_name, const char *oid,
			       int indx, unsigned int raw_flag, void *buf,
			       size_t * sizeof_buf);

int _gnutls_x509_set_dn_oid (ASN1_TYPE asn1_struct,
			     const char *asn1_rdn_name, const char *oid,
			     int raw_flag, const char *name, int sizeof_name);

int _gnutls_x509_get_dn_oid (ASN1_TYPE asn1_struct,
			     const char *asn1_rdn_name,
			     int indx, void *_oid, size_t * sizeof_oid);


#endif
