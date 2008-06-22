/* pubkey.c - Public key API
 *        Copyright (C) 2007 Free Software Foundation, Inc.
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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <stdio.h>
#include <gcrypt.h>

#include "opencdk.h"
#include "main.h"
#include "packet.h"


/* Convert the given secret key into a gcrypt SEXP object. */
static int
seckey_to_sexp (gcry_sexp_t * r_skey, cdk_seckey_t sk)
{
  gcry_sexp_t sexp = NULL;
  gcry_mpi_t *mpk = NULL, *msk = NULL;
  gcry_error_t err;
  cdk_pubkey_t pk;
  const char *fmt;

  if (!r_skey || !sk || !sk->pk)
    return CDK_Inv_Value;

  pk = sk->pk;
  mpk = pk->mpi;
  msk = sk->mpi;

  *r_skey = NULL;
  if (is_RSA (sk->pubkey_algo))
    {
      fmt = "(private-key(openpgp-rsa(n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))";
      err = gcry_sexp_build (&sexp, NULL, fmt, mpk[0], mpk[1],
                             msk[0], msk[1], msk[2], msk[3]);
    }
  else if (is_ELG (sk->pubkey_algo))
    {
      fmt = "(private-key(openpgp-elg(p%m)(g%m)(y%m)(x%m)))";
      err = gcry_sexp_build (&sexp, NULL, fmt, mpk[0], mpk[1],
                             mpk[2], msk[0]);
    }
  else if (is_DSA (sk->pubkey_algo))
    {
      fmt = "(private-key(openpgp-dsa(p%m)(q%m)(g%m)(y%m)(x%m)))";
      err = gcry_sexp_build (&sexp, NULL, fmt, mpk[0], mpk[1], mpk[2],
                             mpk[3], msk[0]);
    }
  else
    return CDK_Inv_Algo;
  if (err)
    return map_gcry_error (err);
  *r_skey = sexp;
  return 0;
}


/* Convert the given public key to a gcrypt SEXP object. */
static cdk_error_t
pubkey_to_sexp (gcry_sexp_t * r_key_sexp, cdk_pubkey_t pk)
{
  gcry_mpi_t *m;
  gcry_error_t err;
  const char *fmt = NULL;
  cdk_error_t rc = 0;

  if (!r_key_sexp || !pk)
    return CDK_Inv_Value;

  m = pk->mpi;
  if (is_RSA (pk->pubkey_algo))
    {
      fmt = "(public-key(openpgp-rsa(n%m)(e%m)))";
      err = gcry_sexp_build (r_key_sexp, NULL, fmt, m[0], m[1]);
      if (err)
        rc = map_gcry_error (err);
    }
  else if (is_ELG (pk->pubkey_algo))
    {
      fmt = "(public-key(openpgp-elg(p%m)(g%m)(y%m)))";
      err = gcry_sexp_build (r_key_sexp, NULL, fmt, m[0], m[1], m[2]);
      if (err)
        rc = map_gcry_error (err);
    }
  else if (is_DSA (pk->pubkey_algo))
    {
      fmt = "(public-key(openpgp-dsa(p%m)(q%m)(g%m)(y%m)))";
      err = gcry_sexp_build (r_key_sexp, NULL, fmt, m[0], m[1], m[2], m[3]);
      if (err)
        rc = map_gcry_error (err);
    }
  else
    rc = CDK_Inv_Algo;
  return rc;
}


static cdk_error_t
enckey_to_sexp (gcry_sexp_t * r_sexp, gcry_mpi_t esk)
{
  gcry_error_t err;

  if (!r_sexp || !esk)
    return CDK_Inv_Value;
  err = gcry_sexp_build (r_sexp, NULL, "%m", esk);
  if (err)
    return map_gcry_error (err);
  return 0;
}


static cdk_error_t
digest_to_sexp (gcry_sexp_t * r_md_sexp, int digest_algo,
                const byte * md, size_t mdlen)
{
  gcry_mpi_t m;
  gcry_error_t err;

  if (!r_md_sexp || !md)
    return CDK_Inv_Value;

  if (!mdlen)
    mdlen = gcry_md_get_algo_dlen (digest_algo);
  if (!mdlen)
    return CDK_Inv_Algo;

  err = gcry_mpi_scan (&m, GCRYMPI_FMT_USG, md, mdlen, &mdlen);
  if (err)
    return map_gcry_error (err);

  err = gcry_sexp_build (r_md_sexp, NULL, "%m", m);
  gcry_mpi_release (m);
  if (err)
    return map_gcry_error (err);
  return 0;
}


static cdk_error_t
sexp_to_mpi (gcry_sexp_t sexp, const char *val, gcry_mpi_t * ret_buf)
{
  gcry_sexp_t list;

  if (!sexp || !val || !ret_buf)
    return CDK_Inv_Value;

  list = gcry_sexp_find_token (sexp, val, 0);
  if (!list)
    return CDK_Inv_Value;

  *ret_buf = gcry_sexp_nth_mpi (list, 1, 0);
  gcry_sexp_release (list);
  if (!*ret_buf)
    return CDK_Inv_Value;
  return 0;
}


static cdk_error_t
sexp_to_sig (cdk_pkt_signature_t sig, gcry_sexp_t sexp)
{
  if (!sig || !sexp)
    return CDK_Inv_Value;

  /* ElGamal signatures are not supported any longer. */
  if (is_ELG (sig->pubkey_algo))
    {
      _cdk_log_debug ("sexp_to_sig: unsupported signature type (ElGamal)\n");
      return CDK_Not_Implemented;
    }

  if (is_RSA (sig->pubkey_algo))
    return sexp_to_mpi (sexp, "s", &sig->mpi[0]);
  else if (is_DSA (sig->pubkey_algo))
    {
      cdk_error_t rc;

      rc = sexp_to_mpi (sexp, "r", &sig->mpi[0]);
      if (!rc)
        rc = sexp_to_mpi (sexp, "s", &sig->mpi[1]);
      return rc;
    }
  return CDK_Inv_Algo;
}


static cdk_error_t
sig_to_sexp (gcry_sexp_t * r_sig_sexp, cdk_pkt_signature_t sig)
{
  gcry_error_t err;
  cdk_error_t rc;
  const char *fmt;

  if (!r_sig_sexp || !sig)
    return CDK_Inv_Value;
  if (is_ELG (sig->pubkey_algo))
    return CDK_Not_Implemented;

  rc = 0;
  if (is_RSA (sig->pubkey_algo))
    {
      fmt = "(sig-val(openpgp-rsa(s%m)))";
      err = gcry_sexp_build (r_sig_sexp, NULL, fmt, sig->mpi[0]);
      if (err)
        rc = map_gcry_error (err);
    }
  else if (is_DSA (sig->pubkey_algo))
    {
      fmt = "(sig-val(openpgp-dsa(r%m)(s%m)))";
      err = gcry_sexp_build (r_sig_sexp, NULL, fmt, sig->mpi[0], sig->mpi[1]);
      if (err)
        rc = map_gcry_error (err);
    }
  else
    rc = CDK_Inv_Algo;
  return rc;
}


static cdk_error_t
sexp_to_pubenc (cdk_pkt_pubkey_enc_t enc, gcry_sexp_t sexp)
{
  if (!sexp || !enc)
    return CDK_Inv_Value;

  if (is_RSA (enc->pubkey_algo))
    return sexp_to_mpi (sexp, "a", &enc->mpi[0]);
  else if (is_ELG (enc->pubkey_algo))
    {
      cdk_error_t rc = sexp_to_mpi (sexp, "a", &enc->mpi[0]);
      if (!rc)
        rc = sexp_to_mpi (sexp, "b", &enc->mpi[1]);
      return rc;
    }
  return CDK_Inv_Algo;
}


static cdk_error_t
pubenc_to_sexp (gcry_sexp_t * r_sexp, cdk_pkt_pubkey_enc_t enc)
{
  gcry_sexp_t sexp = NULL;
  gcry_error_t err;
  const char *fmt;

  if (!r_sexp || !enc)
    return CDK_Inv_Value;

  *r_sexp = NULL;
  if (is_RSA (enc->pubkey_algo))
    {
      fmt = "(enc-val(openpgp-rsa((a%m))))";
      err = gcry_sexp_build (&sexp, NULL, fmt, enc->mpi[0]);
    }
  else if (is_ELG (enc->pubkey_algo))
    {
      fmt = "(enc-val(openpgp-elg((a%m)(b%m))))";
      err = gcry_sexp_build (&sexp, NULL, fmt, enc->mpi[0], enc->mpi[1]);
    }
  else
    return CDK_Inv_Algo;
  if (err)
    return map_gcry_error (err);
  *r_sexp = sexp;
  return 0;
}


static int
is_unprotected (cdk_seckey_t sk)
{
  if (sk->is_protected && !sk->mpi[0])
    return 0;
  return 1;
}


/**
 * cdk_pk_encrypt:
 * @pk: the public key
 * @pke: the public key encrypted packet
 * @esk: the actual session key
 *
 * Encrypt the session key in @esk and write its encrypted content
 * into the @pke struct.
 **/
cdk_error_t
cdk_pk_encrypt (cdk_pubkey_t pk, cdk_pkt_pubkey_enc_t pke, gcry_mpi_t esk)
{
  gcry_sexp_t s_data = NULL, s_pkey = NULL, s_ciph = NULL;
  gcry_error_t err;
  cdk_error_t rc;

  if (!pk || !esk || !pke)
    return CDK_Inv_Value;

  if (!KEY_CAN_ENCRYPT (pk->pubkey_algo))
    return CDK_Inv_Algo;

  rc = enckey_to_sexp (&s_data, esk);
  if (!rc)
    rc = pubkey_to_sexp (&s_pkey, pk);
  if (!rc)
    {
      err = gcry_pk_encrypt (&s_ciph, s_data, s_pkey);
      if (err)
        return map_gcry_error (err);
    }
  if (!rc)
    rc = sexp_to_pubenc (pke, s_ciph);

  gcry_sexp_release (s_data);
  gcry_sexp_release (s_pkey);
  gcry_sexp_release (s_ciph);
  return rc;
}


/**
 * cdk_pk_decrypt:
 * @sk: the secret key
 * @pke: public key encrypted packet
 * @r_sk: the object to store the plain session key
 *
 * Decrypt the encrypted session key from @pke into @r_sk.
 **/
cdk_error_t
cdk_pk_decrypt (cdk_seckey_t sk, cdk_pkt_pubkey_enc_t pke, gcry_mpi_t * r_sk)
{
  gcry_sexp_t s_data = NULL, s_skey = NULL, s_plain = NULL;
  cdk_error_t rc;
  gcry_error_t err;

  if (!sk || !r_sk || !pke)
    return CDK_Inv_Value;

  if (!is_unprotected (sk))
    return CDK_Inv_Mode;

  *r_sk = NULL;
  rc = seckey_to_sexp (&s_skey, sk);
  if (rc)
    return rc;

  rc = pubenc_to_sexp (&s_data, pke);
  if (rc)
    {
      gcry_sexp_release (s_skey);
      return rc;
    }

  err = gcry_pk_decrypt (&s_plain, s_data, s_skey);
  if (err)
    rc = map_gcry_error (err);
  else
    *r_sk = gcry_sexp_nth_mpi (s_plain, 0, 0);

  gcry_sexp_release (s_data);
  gcry_sexp_release (s_skey);
  gcry_sexp_release (s_plain);
  return rc;
}


/**
 * cdk_pk_sign:
 * @sk: secret key
 * @sig: signature
 * @md: the message digest
 *
 * Sign the message digest from @md and write the result into @sig.
 **/
cdk_error_t
cdk_pk_sign (cdk_seckey_t sk, cdk_pkt_signature_t sig, const byte * md)
{
  gcry_sexp_t s_skey = NULL, s_sig = NULL, s_hash = NULL;
  byte *encmd = NULL;
  size_t enclen = 0;
  int nbits;
  cdk_error_t rc;
  gcry_error_t err;

  if (!sk || !sk->pk || !sig || !md)
    return CDK_Inv_Value;

  if (!is_unprotected (sk))
    return CDK_Inv_Mode;

  if (!KEY_CAN_SIGN (sig->pubkey_algo))
    return CDK_Inv_Algo;

  nbits = cdk_pk_get_nbits (sk->pk);
  rc = _cdk_digest_encode_pkcs1 (&encmd, &enclen, sk->pk->pubkey_algo, md,
                                 sig->digest_algo, nbits);
  if (rc)
    return rc;

  rc = seckey_to_sexp (&s_skey, sk);
  if (!rc)
    rc = digest_to_sexp (&s_hash, sig->digest_algo, encmd, enclen);
  if (rc)
    {
      cdk_free (encmd);
      gcry_sexp_release (s_skey);
      return rc;
    }

  err = gcry_pk_sign (&s_sig, s_hash, s_skey);
  if (err)
    rc = map_gcry_error (err);
  else
    {
      rc = sexp_to_sig (sig, s_sig);
      if (!rc)
        {
          sig->digest_start[0] = md[0];
          sig->digest_start[1] = md[1];
        }
    }

  gcry_sexp_release (s_skey);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_sig);
  cdk_free (encmd);
  return rc;
}


/**
 * cdk_pk_verify:
 * @pk: the public key
 * @sig: signature
 * @md: the message digest
 *
 * Verify the signature in @sig and compare it with the message digest in @md.
 **/
cdk_error_t
cdk_pk_verify (cdk_pubkey_t pk, cdk_pkt_signature_t sig, const byte * md)
{
  gcry_sexp_t s_pkey = NULL, s_sig = NULL, s_hash = NULL;
  byte *encmd = NULL;
  size_t enclen;
  cdk_error_t rc;

  if (!pk || !sig || !md)
    return CDK_Inv_Value;

  rc = pubkey_to_sexp (&s_pkey, pk);
  if (rc)
    return rc;

  rc = sig_to_sexp (&s_sig, sig);
  if (rc)
    goto leave;

  rc = _cdk_digest_encode_pkcs1 (&encmd, &enclen, pk->pubkey_algo, md,
                                 sig->digest_algo, cdk_pk_get_nbits (pk));
  if (rc)
    goto leave;

  rc = digest_to_sexp (&s_hash, sig->digest_algo, encmd, enclen);
  if (rc)
    goto leave;

  if (gcry_pk_verify (s_sig, s_hash, s_pkey))
    rc = CDK_Bad_Sig;

leave:
  gcry_sexp_release (s_sig);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_pkey);
  cdk_free (encmd);
  return rc;
}


/**
 * cdk_pk_get_nbits:
 * @pk: the public key
 * 
 * Return the length of the public key in bits.
 * The meaning of length is actually the size of the 'prime'
 * object in the key. For RSA keys the modulus, for ElG/DSA
 * the size of the public prime.
 **/
int
cdk_pk_get_nbits (cdk_pubkey_t pk)
{
  if (!pk || !pk->mpi[0])
    return 0;
  return gcry_mpi_get_nbits (pk->mpi[0]);
}


/**
 * cdk_pk_get_npkey:
 * @algo: The public key algorithm.
 * 
 * Return the number of multiprecison integer forming an public
 * key with the given algorithm.
 */
int
cdk_pk_get_npkey (int algo)
{
  size_t bytes;

  if (algo == 16)
    algo = 20;                  /* FIXME: libgcrypt returns 0 for 16 */
  if (gcry_pk_algo_info (algo, GCRYCTL_GET_ALGO_NPKEY, NULL, &bytes))
    return 0;
  return bytes;
}


/**
 * cdk_pk_get_nskey:
 * @algo: the public key algorithm
 * 
 * Return the number of multiprecision integers forming an
 * secret key with the given algorithm.
 **/
int
cdk_pk_get_nskey (int algo)
{
  size_t bytes;

  if (gcry_pk_algo_info (algo, GCRYCTL_GET_ALGO_NSKEY, NULL, &bytes))
    return 0;
  bytes -= cdk_pk_get_npkey (algo);
  return bytes;
}


/**
 * cdk_pk_get_nbits:
 * @algo: the public key algorithm
 * 
 * Return the number of MPIs a signature consists of.
 **/
int
cdk_pk_get_nsig (int algo)
{
  size_t bytes;

  if (gcry_pk_algo_info (algo, GCRYCTL_GET_ALGO_NSIGN, NULL, &bytes))
    return 0;
  return bytes;
}


/**
 * cdk_pk_get_nenc: 
 * @algo: the public key algorithm
 * 
 * Return the number of MPI's the encrypted data consists of.
 **/
int
cdk_pk_get_nenc (int algo)
{
  size_t bytes;

  if (gcry_pk_algo_info (algo, GCRYCTL_GET_ALGO_NENCR, NULL, &bytes))
    return 0;
  return bytes;
}


int
_cdk_pk_algo_usage (int algo)
{
  int usage;

  /* The ElGamal sign+encrypt algorithm is not supported any longer. */
  switch (algo)
    {
    case CDK_PK_RSA:
      usage = CDK_KEY_USG_SIGN | CDK_KEY_USG_ENCR;
      break;
    case CDK_PK_RSA_E:
      usage = CDK_KEY_USG_ENCR;
      break;
    case CDK_PK_RSA_S:
      usage = CDK_KEY_USG_SIGN;
      break;
    case CDK_PK_ELG_E:
      usage = CDK_KEY_USG_ENCR;
      break;
    case CDK_PK_DSA:
      usage = CDK_KEY_USG_SIGN;
      break;
    default:
      usage = 0;
    }
  return usage;
}


static cdk_error_t
mpi_to_buffer (gcry_mpi_t a, byte * buf, size_t buflen,
               size_t * r_nwritten, size_t * r_nbits)
{
  size_t nbits;

  if (!a || !buf || !r_nwritten)
    return CDK_Inv_Value;

  nbits = gcry_mpi_get_nbits (a);
  if (r_nbits)
    *r_nbits = nbits;
  if ((nbits + 7) / 8 + 2 > buflen)
    return CDK_Too_Short;
  *r_nwritten = (nbits + 7) / 8 + 2;
  if (gcry_mpi_print (GCRYMPI_FMT_PGP, buf, buflen, r_nwritten, a))
    return CDK_Wrong_Format;
  return 0;
}


/**
 * cdk_pk_get_mpi:
 * @pk: public key
 * @idx: index of the MPI to retrieve
 * @buf: buffer to hold the raw data
 * @r_nwritten: output how large the raw data is
 * @r_nbits: size of the MPI in bits.
 * 
 * Return the MPI with the given index of the public key.
 **/
cdk_error_t
cdk_pk_get_mpi (cdk_pubkey_t pk, size_t idx,
                byte * buf, size_t buflen, size_t * r_nwritten,
                size_t * r_nbits)
{
  if (!pk || !r_nwritten)
    return CDK_Inv_Value;
  if (idx > cdk_pk_get_npkey (pk->pubkey_algo))
    return CDK_Inv_Value;
  return mpi_to_buffer (pk->mpi[idx], buf, buflen, r_nwritten, r_nbits);
}


/**
 * cdk_sk_get_mpi:
 * @sk: secret key
 * @idx: index of the MPI to retrieve
 * @buf: buffer to hold the raw data
 * @r_nwritten: output length of the raw data
 * @r_nbits: length of the MPI data in bits.
 * 
 * Return the MPI of the given secret key with the
 * index @idx. It is important to check if the key
 * is protected and thus no real MPI data will be returned then.
 **/
cdk_error_t
cdk_sk_get_mpi (cdk_pkt_seckey_t sk, size_t idx,
                byte * buf, size_t buflen, size_t * r_nwritten,
                size_t * r_nbits)
{
  if (!sk || !r_nwritten)
    return CDK_Inv_Value;
  if (idx > cdk_pk_get_nskey (sk->pubkey_algo))
    return CDK_Inv_Value;
  return mpi_to_buffer (sk->mpi[idx], buf, buflen, r_nwritten, r_nbits);
}


static u16
checksum_mpi (gcry_mpi_t m)
{
  byte buf[MAX_MPI_BYTES + 2];
  size_t nread;
  int i;
  u16 chksum = 0;

  if (!m)
    return 0;
  if (gcry_mpi_print (GCRYMPI_FMT_PGP, buf, DIM (buf), &nread, m))
    return 0;
  for (i = 0; i < nread; i++)
    chksum += buf[i];
  return chksum;
}


/**
 * cdk_sk_unprotect:
 * @sk: the secret key
 * @pw: the passphrase
 * 
 * Unprotect the given secret key with the passphrase.
 **/
cdk_error_t
cdk_sk_unprotect (cdk_pkt_seckey_t sk, const char *pw)
{
  gcry_cipher_hd_t hd;
  cdk_dek_t dek = NULL;
  byte *data = NULL;
  u16 chksum = 0;
  size_t ndata, nbits, nbytes;
  int i, dlen, pos = 0, nskey;
  cdk_error_t rc;
  gcry_error_t err;

  if (!sk)
    return CDK_Inv_Value;

  nskey = cdk_pk_get_nskey (sk->pubkey_algo);
  if (!sk->is_protected)
    {
      chksum = 0;
      for (i = 0; i < nskey; i++)
        chksum += checksum_mpi (sk->mpi[i]);
      if (chksum != sk->csum)
        return CDK_Chksum_Error;
    }

  rc = cdk_dek_from_passphrase (&dek, sk->protect.algo,
                                sk->protect.s2k, 0, pw);
  if (rc)
    return rc;
  err = gcry_cipher_open (&hd, sk->protect.algo, GCRY_CIPHER_MODE_CFB,
                          GCRY_CIPHER_ENABLE_SYNC);
  if (!err)
    err = gcry_cipher_setiv (hd, sk->protect.iv, sk->protect.ivlen);
  if (!err)
    err = gcry_cipher_setkey (hd, dek->key, dek->keylen);
  if (err)
    {
      cdk_free (dek);
      return map_gcry_error (err);
    }
  cdk_dek_free (dek);
  chksum = 0;
  if (sk->version == 4)
    {
      ndata = sk->enclen;
      data = cdk_salloc (ndata, 1);
      if (!data)
        return CDK_Out_Of_Core;
      gcry_cipher_decrypt (hd, data, ndata, sk->encdata, ndata);
      if (sk->protect.sha1chk)
        {
          /* This is the new SHA1 checksum method to detect tampering
             with the key as used by the Klima/Rosa attack */
          sk->csum = 0;
          chksum = 1;
          dlen = gcry_md_get_algo_dlen (GCRY_MD_SHA1);
          if (ndata < dlen)
            {
              cdk_free (data);
              return CDK_Inv_Packet;
            }
          else
            {
              byte mdcheck[20];

              gcry_md_hash_buffer (GCRY_MD_SHA1, mdcheck, data, ndata - dlen);
              if (!memcmp (mdcheck, data + ndata - dlen, dlen))
                chksum = 0;     /* Digest does match */
            }
        }
      else
        {
          for (i = 0; i < ndata - 2; i++)
            chksum += data[i];
          sk->csum = data[ndata - 2] << 8 | data[ndata - 1];
        }
      if (sk->csum == chksum)
        {
          for (i = 0; i < nskey; i++)
            {
              nbits = data[pos] << 8 | data[pos + 1];

              if (gcry_mpi_scan (&sk->mpi[i], GCRYMPI_FMT_PGP, data,
                                 (nbits + 7) / 8 + 2, &nbytes))
                {
                  wipemem (data, sk->enclen);
                  cdk_free (data);
                  return CDK_Wrong_Format;
                }
              gcry_mpi_set_flag (sk->mpi[i], GCRYMPI_FLAG_SECURE);
              pos += (nbits + 7) / 8 + 2;
            }
        }
      wipemem (data, sk->enclen);
      cdk_free (data);
    }
  else
    {
      byte buf[MAX_MPI_BYTES + 2];

      chksum = 0;
      for (i = 0; i < nskey; i++)
        {
          gcry_cipher_sync (hd);
          gcry_mpi_print (GCRYMPI_FMT_PGP, buf, DIM (buf),
                          &nbytes, sk->mpi[i]);
          gcry_cipher_decrypt (hd, buf + 2, nbytes - 2, NULL, 0);
          gcry_mpi_release (sk->mpi[i]);
          if (gcry_mpi_scan (&sk->mpi[i], GCRYMPI_FMT_PGP,
                             buf, nbytes, &nbytes))
            return CDK_Wrong_Format;
          chksum += checksum_mpi (sk->mpi[i]);
        }
    }
  gcry_cipher_close (hd);
  if (chksum != sk->csum)
    return CDK_Chksum_Error;
  sk->is_protected = 0;
  return 0;
}


/**
 * cdk_sk_protect:
 * @sk: the secret key
 * @pw: the passphrase to use
 * 
 * Protect the given secret key with a passphrase.
 **/
cdk_error_t
cdk_sk_protect (cdk_pkt_seckey_t sk, const char *pw)
{
  gcry_cipher_hd_t hd = NULL;
  cdk_dek_t dek = NULL;
  cdk_s2k_t s2k;
  byte *p = NULL, buf[MAX_MPI_BYTES + 2];
  size_t enclen = 0, nskey, i, nbytes;
  size_t dlen = gcry_md_get_algo_dlen (GCRY_MD_SHA1);
  gcry_error_t err;
  cdk_error_t rc;

  nskey = cdk_pk_get_nskey (sk->pubkey_algo);
  if (!nskey)
    return CDK_Inv_Algo;

  rc = cdk_s2k_new (&s2k, CDK_S2K_ITERSALTED, GCRY_MD_SHA256, NULL);
  if (!rc)
    rc = cdk_dek_from_passphrase (&dek, GCRY_CIPHER_AES, s2k, 1, pw);
  if (rc)
    {
      cdk_s2k_free (s2k);
      return rc;
    }

  for (i = 0; i < nskey; i++)
    {
      enclen += 2;
      enclen += (gcry_mpi_get_nbits (sk->mpi[i]) + 7) / 8;
    }
  p = sk->encdata = cdk_calloc (1, enclen + dlen + 1);
  if (!p)
    {
      cdk_s2k_free (s2k);
      return CDK_Out_Of_Core;
    }

  enclen = 0;
  for (i = 0; i < nskey; i++)
    {
      if (gcry_mpi_print (GCRYMPI_FMT_PGP, buf,
                          DIM (buf), &nbytes, sk->mpi[i]))
        {
          cdk_free (p);
          cdk_s2k_free (s2k);
          return CDK_Wrong_Format;
        }
      memcpy (p + enclen, buf, nbytes);
      enclen += nbytes;
    }

  enclen += dlen;
  sk->enclen = enclen;
  sk->protect.s2k = s2k;
  sk->protect.algo = GCRY_CIPHER_AES;
  sk->protect.ivlen = gcry_cipher_get_algo_blklen (sk->protect.algo);
  gcry_randomize (sk->protect.iv, sk->protect.ivlen, GCRY_STRONG_RANDOM);
  err = gcry_cipher_open (&hd, sk->protect.algo, GCRY_CIPHER_MODE_CFB,
                          GCRY_CIPHER_ENABLE_SYNC);
  if (err)
    {
      cdk_dek_free (dek);
      rc = map_gcry_error (err);
      goto leave;
    }

  err = gcry_cipher_setkey (hd, dek->key, dek->keylen);
  if (!err)
    err = gcry_cipher_setiv (hd, sk->protect.iv, sk->protect.ivlen);
  cdk_dek_free (dek);
  if (err)
    {
      rc = map_gcry_error (err);
      goto leave;
    }

  sk->protect.sha1chk = 1;
  sk->is_protected = 1;
  sk->csum = 0;

  gcry_md_hash_buffer (GCRY_MD_SHA1, buf, p, enclen - dlen);
  memcpy (p + enclen - dlen, buf, dlen);
  gcry_cipher_encrypt (hd, p, enclen, NULL, 0);

  /* FIXME: We should release all MPI's and set the elements to NULL. */

leave:
  gcry_cipher_close (hd);
  return rc;
}


/**
 * cdk_pk_from_secret_key:
 * @sk: the secret key
 * @ret_pk: the new public key
 *
 * Create a new public key from a secret key.
 **/
cdk_error_t
cdk_pk_from_secret_key (cdk_pkt_seckey_t sk, cdk_pubkey_t * ret_pk)
{
  if (!sk)
    return CDK_Inv_Value;
  return _cdk_copy_pubkey (ret_pk, sk->pk);
}


#if 0                           /* FIXME: Code is not finished yet. */
cdk_error_t
cdk_pk_revoke_cert_create (cdk_pkt_seckey_t sk, int code, const char *inf,
                           char **ret_revcert)
{
  gcry_md_hd_t md;
  cdk_subpkt_t node;
  cdk_pkt_signature_t sig;
  char *p = NULL, *dat;
  gcry_error_t err;
  cdk_error_t rc = 0;
  size_t n;

  if (!sk || !ret_revcert)
    return CDK_Inv_Value;
  if (code < 0 || code > 3)
    return CDK_Inv_Value;

  sig = cdk_calloc (1, sizeof *sig);
  if (!sig)
    return CDK_Out_Of_Core;
  _cdk_sig_create (sk->pk, sig);
  n = 1;
  if (inf)
    {
      n += strlen (p);
      p = cdk_utf8_encode (inf);
    }
  dat = cdk_calloc (1, n + 1);
  if (!dat)
    {
      _cdk_free_signature (sig);
      return CDK_Out_Of_Core;
    }
  dat[0] = code;
  if (inf)
    memcpy (dat + 1, p, strlen (p));
  cdk_free (p);

  node = cdk_subpkt_new (n);
  if (node)
    {
      cdk_subpkt_init (node, CDK_SIGSUBPKT_REVOC_REASON, dat, n);
      cdk_subpkt_add (sig->hashed, node);
    }
  cdk_free (dat);

  err = gcry_md_open (&md, GCRY_MD_SHA1, 0);
  if (err)
    rc = map_gcry_error (err);
  else
    _cdk_hash_pubkey (sk->pk, md, 0);
  _cdk_free_signature (sig);

  return rc;
}
#endif

int
_cdk_sk_get_csum (cdk_pkt_seckey_t sk)
{
  u16 csum = 0, i;

  if (!sk)
    return 0;
  for (i = 0; i < cdk_pk_get_nskey (sk->pubkey_algo); i++)
    csum += checksum_mpi (sk->mpi[i]);
  return csum;
}


/**
 * cdk_pk_get_fingerprint:
 * @pk: the public key
 * @fpr: the buffer to hold the fingerprint
 * 
 * Return the fingerprint of the given public key.
 * The buffer must be at least 20 octets.
 * This function should be considered deprecated and
 * the new cdk_pk_to_fingerprint() should be used whenever
 * possible to avoid overflows.
 **/
cdk_error_t
cdk_pk_get_fingerprint (cdk_pubkey_t pk, byte * fpr)
{
  gcry_md_hd_t hd;
  int md_algo;
  int dlen = 0;
  gcry_error_t err;

  if (!pk || !fpr)
    return CDK_Inv_Value;

  if (pk->version < 4 && is_RSA (pk->pubkey_algo))
    md_algo = GCRY_MD_MD5;      /* special */
  else
    md_algo = GCRY_MD_SHA1;
  dlen = gcry_md_get_algo_dlen (md_algo);
  err = gcry_md_open (&hd, md_algo, 0);
  if (err)
    return map_gcry_error (err);
  _cdk_hash_pubkey (pk, hd, 1);
  gcry_md_final (hd);
  memcpy (fpr, gcry_md_read (hd, md_algo), dlen);
  gcry_md_close (hd);
  if (dlen == 16)
    memset (fpr + 16, 0, 4);
  return 0;
}


/**
 * cdk_pk_to_fingerprint:
 * @pk: the public key
 * @fprbuf: buffer to save the fingerprint
 * @fprbuflen: buffer size
 * @r_nout: actual length of the fingerprint.
 * 
 * Calculate a fingerprint of the given key and
 * return it in the given byte array.
 **/
cdk_error_t
cdk_pk_to_fingerprint (cdk_pubkey_t pk,
                       byte * fprbuf, size_t fprbuflen, size_t * r_nout)
{
  size_t key_fprlen;
  cdk_error_t err;

  if (!pk)
    return CDK_Inv_Value;

  if (pk->version < 4)
    key_fprlen = 16;
  else
    key_fprlen = 20;

  /* Only return the required buffer size for the fingerprint. */
  if (!fprbuf && !fprbuflen && r_nout)
    {
      *r_nout = key_fprlen;
      return 0;
    }

  if (!fprbuf || key_fprlen > fprbuflen)
    return CDK_Too_Short;

  err = cdk_pk_get_fingerprint (pk, fprbuf);
  if (r_nout)
    *r_nout = key_fprlen;

  return err;
}


/**
 * cdk_pk_fingerprint_get_keyid:
 * @fpr: the key fingerprint
 * @fprlen: the length of the fingerprint
 * 
 * Derive the key ID from the key fingerprint.
 * For version 3 keys, this is not working.
 **/
u32
cdk_pk_fingerprint_get_keyid (const byte * fpr, size_t fprlen, u32 * keyid)
{
  u32 lowbits = 0;

  /* In this case we say the key is a V3 RSA key and we can't
     use the fingerprint to get the keyid. */
  if (fpr && fprlen == 16)
    {
      keyid[0] = 0;
      keyid[1] = 0;
      return 0;
    }
  else if (keyid && fpr)
    {
      keyid[0] = _cdk_buftou32 (fpr + 12);
      keyid[1] = _cdk_buftou32 (fpr + 16);
      lowbits = keyid[1];
    }
  else if (fpr)
    lowbits = _cdk_buftou32 (fpr + 16);
  return lowbits;
}


/**
 * cdk_pk_get_keyid:
 * @pk: the public key
 * @keyid: buffer to store the key ID
 * 
 * Calculate the key ID of the given public key.
 **/
u32
cdk_pk_get_keyid (cdk_pubkey_t pk, u32 * keyid)
{
  u32 lowbits = 0;
  byte buf[24];

  if (pk && (!pk->keyid[0] || !pk->keyid[1]))
    {
      if (pk->version < 4 && is_RSA (pk->pubkey_algo))
        {
          byte p[MAX_MPI_BYTES];
          size_t n;

          gcry_mpi_print (GCRYMPI_FMT_USG, p, MAX_MPI_BYTES, &n, pk->mpi[0]);
          pk->keyid[0] =
            p[n - 8] << 24 | p[n - 7] << 16 | p[n - 6] << 8 | p[n - 5];
          pk->keyid[1] =
            p[n - 4] << 24 | p[n - 3] << 16 | p[n - 2] << 8 | p[n - 1];
        }
      else if (pk->version == 4)
        {
          cdk_pk_get_fingerprint (pk, buf);
          pk->keyid[0] = _cdk_buftou32 (buf + 12);
          pk->keyid[1] = _cdk_buftou32 (buf + 16);
        }
    }
  lowbits = pk ? pk->keyid[1] : 0;
  if (keyid && pk)
    {
      keyid[0] = pk->keyid[0];
      keyid[1] = pk->keyid[1];
    }

  return lowbits;
}


/**
 * cdk_sk_get_keyid:
 * @sk: the secret key
 * @keyid: buffer to hold the key ID
 * 
 * Calculate the key ID of the secret key, actually the public key.
 **/
u32
cdk_sk_get_keyid (cdk_pkt_seckey_t sk, u32 * keyid)
{
  u32 lowbits = 0;

  if (sk && sk->pk)
    {
      lowbits = cdk_pk_get_keyid (sk->pk, keyid);
      sk->keyid[0] = sk->pk->keyid[0];
      sk->keyid[1] = sk->pk->keyid[1];
    }

  return lowbits;
}


/**
 * cdk_sig_get_keyid:
 * @sig: the signature
 * @keyid: buffer to hold the key ID
 * 
 * Retrieve the key ID from the given signature.
 **/
u32
cdk_sig_get_keyid (cdk_pkt_signature_t sig, u32 * keyid)
{
  u32 lowbits = sig ? sig->keyid[1] : 0;

  if (keyid && sig)
    {
      keyid[0] = sig->keyid[0];
      keyid[1] = sig->keyid[1];
    }
  return lowbits;
}


/* Return the key ID from the given packet.
   If this is not possible, 0 is returned */
u32
_cdk_pkt_get_keyid (cdk_packet_t pkt, u32 * keyid)
{
  u32 lowbits;

  if (!pkt)
    return 0;

  switch (pkt->pkttype)
    {
    case CDK_PKT_PUBLIC_KEY:
    case CDK_PKT_PUBLIC_SUBKEY:
      lowbits = cdk_pk_get_keyid (pkt->pkt.public_key, keyid);
      break;

    case CDK_PKT_SECRET_KEY:
    case CDK_PKT_SECRET_SUBKEY:
      lowbits = cdk_sk_get_keyid (pkt->pkt.secret_key, keyid);
      break;

    case CDK_PKT_SIGNATURE:
      lowbits = cdk_sig_get_keyid (pkt->pkt.signature, keyid);
      break;

    default:
      lowbits = 0;
      break;
    }

  return lowbits;
}


/* Get the fingerprint of the packet if possible. */
int
_cdk_pkt_get_fingerprint (cdk_packet_t pkt, byte * fpr)
{
  if (!pkt || !fpr)
    return CDK_Inv_Value;

  switch (pkt->pkttype)
    {
    case CDK_PKT_PUBLIC_KEY:
    case CDK_PKT_PUBLIC_SUBKEY:
      return cdk_pk_get_fingerprint (pkt->pkt.public_key, fpr);

    case CDK_PKT_SECRET_KEY:
    case CDK_PKT_SECRET_SUBKEY:
      return cdk_pk_get_fingerprint (pkt->pkt.secret_key->pk, fpr);

    default:
      return CDK_Inv_Mode;
    }
  return 0;
}


/**
 * cdk_pubkey_to_sexp:
 * @pk: the public key
 * @sexp: where to store the S-expression
 * @len: the length of sexp
 *
 * Convert a public key to an S-expression. sexp is allocated by this
 * function, but you have to cdk_free() it yourself.  The S-expression
 * is stored in canonical format as used by libgcrypt
 * (GCRYSEXP_FMT_CANON).
 **/
cdk_error_t
cdk_pubkey_to_sexp (cdk_pubkey_t pk, char **sexp, size_t * len)
{
  char *buf;
  size_t sexp_len;
  gcry_sexp_t pk_sexp;
  cdk_error_t rc;

  if (!pk || !sexp)
    return CDK_Inv_Value;

  rc = pubkey_to_sexp (&pk_sexp, pk);
  if (rc)
    return rc;

  sexp_len = gcry_sexp_sprint (pk_sexp, GCRYSEXP_FMT_CANON, NULL, 0);
  if (!sexp_len)
    return CDK_Wrong_Format;

  buf = (char *) cdk_malloc (sexp_len);
  if (!buf)
    {
      gcry_sexp_release (pk_sexp);
      return CDK_Out_Of_Core;
    }

  sexp_len = gcry_sexp_sprint (pk_sexp, GCRYSEXP_FMT_CANON, buf, sexp_len);
  gcry_sexp_release (pk_sexp);
  if (!sexp_len)
    {
      cdk_free (buf);
      return CDK_Wrong_Format;
    }

  if (len)
    *len = sexp_len;
  *sexp = buf;
  return CDK_Success;
}


/**
 * cdk_seckey_to_sexp:
 * @sk: the secret key
 * @sexp: where to store the S-expression
 * @len: the length of sexp
 *
 * Convert a public key to an S-expression. sexp is allocated by this
 * function, but you have to cdk_free() it yourself.  The S-expression
 * is stored in canonical format as used by libgcrypt
 * (GCRYSEXP_FMT_CANON).
 **/
cdk_error_t
cdk_seckey_to_sexp (cdk_pkt_seckey_t sk, char **sexp, size_t * len)
{
  char *buf;
  size_t sexp_len;
  gcry_sexp_t sk_sexp;
  cdk_error_t rc;

  if (!sk || !sexp)
    return CDK_Inv_Value;

  rc = seckey_to_sexp (&sk_sexp, sk);
  if (rc)
    return rc;

  sexp_len = gcry_sexp_sprint (sk_sexp, GCRYSEXP_FMT_CANON, NULL, 0);
  if (!sexp_len)
    return CDK_Wrong_Format;

  buf = (char *) cdk_malloc (sexp_len);
  if (!buf)
    {
      gcry_sexp_release (sk_sexp);
      return CDK_Out_Of_Core;
    }

  sexp_len = gcry_sexp_sprint (sk_sexp, GCRYSEXP_FMT_CANON, buf, sexp_len);
  gcry_sexp_release (sk_sexp);
  if (!sexp_len)
    {
      cdk_free (buf);
      return CDK_Wrong_Format;
    }

  if (len)
    *len = sexp_len;
  *sexp = buf;

  return CDK_Success;
}
