/* verify.c - Verify signatures
 *        Copyright (C) 2001, 2002, 2003, 2007 Timo Schulz
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
# include <config.h>
#endif
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>

#include "opencdk.h"
#include "main.h"
#include "filters.h"
#include "packet.h"


/* Table of all supported digest algorithms and their names. */
struct
{
  const char *name;
  int algo;
} digest_table[] =
{
  {
  "MD5", GCRY_MD_MD5},
  {
  "SHA1", GCRY_MD_SHA1},
  {
  "RIPEMD160", GCRY_MD_RMD160},
  {
  "SHA256", GCRY_MD_SHA256},
  {
  "SHA384", GCRY_MD_SHA384},
  {
  "SHA512", GCRY_MD_SHA512},
  {
  NULL, 0}
};


static int file_verify_clearsign (cdk_ctx_t, const char *, const char *);


/**
 * cdk_stream_verify:
 * @hd: session handle
 * @inp: the input stream
 * @data: for detached signatures, this is the data stream @inp is the sig
 * @out: where the output shall be written.
 */
cdk_error_t
cdk_stream_verify (cdk_ctx_t hd, cdk_stream_t inp, cdk_stream_t data,
                   cdk_stream_t out)
{
  /* FIXME: out is not currently used. */
  if (cdk_armor_filter_use (inp))
    cdk_stream_set_armor_flag (inp, 0);
  return _cdk_proc_packets (hd, inp, data, NULL, NULL, NULL);
}


/**
 * cdk_file_verify:
 * @hd: the session handle
 * @file: the input file
 * @data_file: for detached signature this is the data file and @file is the sig.
 * @output: the output file
 *
 * Verify a signature.
 **/
cdk_error_t
cdk_file_verify (cdk_ctx_t hd, const char *file, const char *data_file,
                 const char *output)
{
  struct stat stbuf;
  cdk_stream_t inp, data;
  char buf[4096];
  int n;
  cdk_error_t rc;

  if (!hd || !file)
    return CDK_Inv_Value;
  if (output && !hd->opt.overwrite && !stat (output, &stbuf))
    return CDK_Inv_Mode;

  rc = cdk_stream_open (file, &inp);
  if (rc)
    return rc;
  if (cdk_armor_filter_use (inp))
    {
      n = cdk_stream_peek (inp, (byte *) buf, DIM (buf) - 1);
      if (!n || n == -1)
        return CDK_EOF;
      buf[n] = '\0';
      if (strstr (buf, "BEGIN PGP SIGNED MESSAGE"))
        {
          cdk_stream_close (inp);
          return file_verify_clearsign (hd, file, output);
        }
      cdk_stream_set_armor_flag (inp, 0);
    }

  if (data_file)
    {
      rc = cdk_stream_open (data_file, &data);
      if (rc)
        {
          cdk_stream_close (inp);
          return rc;
        }
    }
  else
    data = NULL;

  rc = _cdk_proc_packets (hd, inp, data, NULL, NULL, NULL);

  if (data != NULL)
    cdk_stream_close (data);
  cdk_stream_close (inp);
  return rc;
}


void
_cdk_result_verify_free (cdk_verify_result_t res)
{
  if (!res)
    return;
  cdk_free (res->policy_url);
  cdk_free (res->sig_data);
  cdk_free (res);
}


cdk_verify_result_t
_cdk_result_verify_new (void)
{
  cdk_verify_result_t res;

  res = cdk_calloc (1, sizeof *res);
  if (!res)
    return NULL;
  return res;
}


static cdk_error_t
file_verify_clearsign (cdk_ctx_t hd, const char *file, const char *output)
{
  cdk_stream_t inp = NULL, out = NULL, tmp = NULL;
  gcry_md_hd_t md = NULL;
  char buf[512], chk[512];
  const char *s;
  int i, is_signed = 0, nbytes;
  int digest_algo = 0;
  gcry_error_t err;
  cdk_error_t rc;

  if (output)
    {
      rc = cdk_stream_create (output, &out);
      if (rc)
        return rc;
    }

  rc = cdk_stream_open (file, &inp);
  if (rc)
    {
      if (output)
        cdk_stream_close (out);
      return rc;
    }

  s = "-----BEGIN PGP SIGNED MESSAGE-----";
  while (!cdk_stream_eof (inp))
    {
      nbytes = _cdk_stream_gets (inp, buf, DIM (buf) - 1);
      if (!nbytes || nbytes == -1)
        break;
      if (!strncmp (buf, s, strlen (s)))
        {
          is_signed = 1;
          break;
        }
    }

  if (cdk_stream_eof (inp) && !is_signed)
    {
      rc = CDK_Armor_Error;
      goto leave;
    }

  while (!cdk_stream_eof (inp))
    {
      nbytes = _cdk_stream_gets (inp, buf, DIM (buf) - 1);
      if (!nbytes || nbytes == -1)
        break;
      if (nbytes == 1)          /* Empty line */
        break;
      else if (!strncmp (buf, "Hash: ", 6))
        {
          for (i = 0; digest_table[i].name; i++)
            {
              if (!strcmp (buf + 6, digest_table[i].name))
                {
                  digest_algo = digest_table[i].algo;
                  break;
                }
            }
        }
    }

  if (digest_algo && gcry_md_test_algo (digest_algo))
    {
      rc = CDK_Inv_Algo;
      goto leave;
    }

  if (!digest_algo)
    digest_algo = GCRY_MD_MD5;

  err = gcry_md_open (&md, digest_algo, 0);
  if (err)
    {
      rc = map_gcry_error (err);
      goto leave;
    }

  s = "-----BEGIN PGP SIGNATURE-----";
  while (!cdk_stream_eof (inp))
    {
      nbytes = _cdk_stream_gets (inp, buf, DIM (buf) - 1);
      if (!nbytes || nbytes == -1)
        break;
      if (!strncmp (buf, s, strlen (s)))
        break;
      else
        {
          cdk_stream_peek (inp, (byte *) chk, DIM (chk) - 1);
          i = strncmp (chk, s, strlen (s));
          if (strlen (buf) == 0 && i == 0)
            continue;           /* skip last '\n' */
          _cdk_trim_string (buf, i == 0 ? 0 : 1);
          gcry_md_write (md, buf, strlen (buf));
        }
      if (!strncmp (buf, "- ", 2))      /* FIXME: handle it recursive. */
        memmove (buf, buf + 2, nbytes - 2);
      if (out)
        {
          if (strstr (buf, "\r\n"))
            buf[strlen (buf) - 2] = '\0';
          cdk_stream_write (out, buf, strlen (buf));
          _cdk_stream_puts (out, _cdk_armor_get_lineend ());
        }
    }

  /* We create a temporary stream object to store the
     signature data in there. */
  rc = cdk_stream_tmp_new (&tmp);
  if (rc)
    goto leave;

  s = "-----BEGIN PGP SIGNATURE-----\n";
  _cdk_stream_puts (tmp, s);
  while (!cdk_stream_eof (inp))
    {
      nbytes = _cdk_stream_gets (inp, buf, DIM (buf) - 1);
      if (!nbytes || nbytes == -1)
        break;
      if (nbytes < (DIM (buf) - 3))
        {
          buf[nbytes - 1] = '\n';
          buf[nbytes] = '\0';
        }
      cdk_stream_write (tmp, buf, nbytes);
    }

  /* FIXME: This code is not very elegant. */
  cdk_stream_tmp_set_mode (tmp, STREAMCTL_READ);
  cdk_stream_seek (tmp, 0);
  cdk_stream_set_armor_flag (tmp, 0);
  cdk_stream_read (tmp, NULL, 0);

  /* the digest handle will be closed there. */
  rc = _cdk_proc_packets (hd, tmp, NULL, NULL, NULL, md);

leave:
  gcry_md_close (md);
  cdk_stream_close (out);
  cdk_stream_close (tmp);
  cdk_stream_close (inp);
  return rc;
}
