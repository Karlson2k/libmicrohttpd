/* packet.h
 *        Copyright (C) 2002, 2003, 2007 Timo Schulz
 *
 * This file is part of OpenCDK.
 *
 * OpenCDK is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * OpenCDK is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#ifndef CDK_PACKET_H
#define CDK_PACKET_H

struct cdk_kbnode_s 
{
  struct cdk_kbnode_s *next;
  cdk_packet_t pkt;
  unsigned int is_deleted:1;
  unsigned int is_cloned:1;
};

/*-- new-packet.c --*/
void _cdk_free_mpibuf (size_t n, gcry_mpi_t *array);
void _cdk_free_userid (cdk_pkt_userid_t uid);
void _cdk_free_signature( cdk_pkt_signature_t sig );
cdk_prefitem_t _cdk_copy_prefs( const cdk_prefitem_t prefs );
int _cdk_copy_userid( cdk_pkt_userid_t *dst, cdk_pkt_userid_t src );
int _cdk_copy_pubkey( cdk_pkt_pubkey_t* dst, cdk_pkt_pubkey_t src );
int _cdk_copy_seckey( cdk_pkt_seckey_t* dst, cdk_pkt_seckey_t src );
int _cdk_copy_pk_to_sk( cdk_pkt_pubkey_t pk, cdk_pkt_seckey_t sk );
int _cdk_copy_signature( cdk_pkt_signature_t* dst, cdk_pkt_signature_t src );
int _cdk_pubkey_compare( cdk_pkt_pubkey_t a, cdk_pkt_pubkey_t b );

#endif /* CDK_PACKET_H */

