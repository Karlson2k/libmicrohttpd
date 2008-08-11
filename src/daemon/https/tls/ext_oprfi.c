/*
 * Copyright (C) 2007 Free Software Foundation
 *
 * Author: Simon Josefsson
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

/* Implementation of Opaque PRF Input:
 * http://tools.ietf.org/id/draft-rescorla-tls-opaque-prf-input-00.txt
 *
 */

#include <ext_oprfi.h>

#include <gnutls_errors.h>
#include <gnutls_num.h>

int
oprfi_recv_server (mhd_gtls_session_t session,
                   const opaque * data, size_t _data_size)
{
  ssize_t data_size = _data_size;
  uint16_t len;

  if (!session->security_parameters.extensions.oprfi_cb)
    {
      gnutls_assert ();
      return 0;
    }

  DECR_LEN (data_size, 2);
  len = mhd_gtls_read_uint16 (data);
  data += 2;

  if (len != data_size)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  /* Store incoming data. */
  session->security_parameters.extensions.oprfi_client_len = len;
  session->security_parameters.extensions.oprfi_client = gnutls_malloc (len);
  if (!session->security_parameters.extensions.oprfi_client)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
  memcpy (session->security_parameters.extensions.oprfi_client, data, len);

  return 0;
}

int
oprfi_recv_client (mhd_gtls_session_t session,
                   const opaque * data, size_t _data_size)
{
  ssize_t data_size = _data_size;
  uint16_t len;

  if (session->security_parameters.extensions.oprfi_client == NULL)
    {
      gnutls_assert ();
      return 0;
    }

  DECR_LEN (data_size, 2);
  len = mhd_gtls_read_uint16 (data);
  data += 2;

  if (len != data_size)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  if (len != session->security_parameters.extensions.oprfi_client_len)
    {
      gnutls_assert ();
      return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
    }

  /* Store incoming data. */
  session->security_parameters.extensions.oprfi_server_len = len;
  session->security_parameters.extensions.oprfi_server = gnutls_malloc (len);
  if (!session->security_parameters.extensions.oprfi_server)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
  memcpy (session->security_parameters.extensions.oprfi_server, data, len);

  return 0;
}

int
mhd_gtls_oprfi_recv_params (mhd_gtls_session_t session,
                           const opaque * data, size_t data_size)
{
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    return oprfi_recv_client (session, data, data_size);
  else
    return oprfi_recv_server (session, data, data_size);
}

int
oprfi_send_client (mhd_gtls_session_t session, opaque * data, size_t _data_size)
{
  opaque *p = data;
  ssize_t data_size = _data_size;
  int oprf_size = session->security_parameters.extensions.oprfi_client_len;

  if (oprf_size == 0)
    return 0;

  DECR_LENGTH_RET (data_size, 2, GNUTLS_E_SHORT_MEMORY_BUFFER);
  mhd_gtls_write_uint16 (oprf_size, p);
  p += 2;

  DECR_LENGTH_RET (data_size, oprf_size, GNUTLS_E_SHORT_MEMORY_BUFFER);

  memcpy (p, session->security_parameters.extensions.oprfi_client, oprf_size);

  return 2 + oprf_size;
}

int
oprfi_send_server (mhd_gtls_session_t session, opaque * data, size_t _data_size)
{
  opaque *p = data;
  int ret;
  ssize_t data_size = _data_size;

  if (!session->security_parameters.extensions.oprfi_client ||
      !session->security_parameters.extensions.oprfi_cb)
    return 0;

  /* Allocate buffer for outgoing data. */
  session->security_parameters.extensions.oprfi_server_len =
    session->security_parameters.extensions.oprfi_client_len;
  session->security_parameters.extensions.oprfi_server =
    gnutls_malloc (session->security_parameters.extensions.oprfi_server_len);
  if (!session->security_parameters.extensions.oprfi_server)
    {
      gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }

  /* Get outgoing data. */
  ret = session->security_parameters.extensions.oprfi_cb
    (session, session->security_parameters.extensions.oprfi_userdata,
     session->security_parameters.extensions.oprfi_client_len,
     session->security_parameters.extensions.oprfi_client,
     session->security_parameters.extensions.oprfi_server);
  if (ret < 0)
    {
      gnutls_assert ();
      gnutls_free (session->security_parameters.extensions.oprfi_server);
      return ret;
    }

  DECR_LENGTH_RET (data_size, 2, GNUTLS_E_SHORT_MEMORY_BUFFER);
  mhd_gtls_write_uint16 (session->security_parameters.
                        extensions.oprfi_server_len, p);
  p += 2;

  DECR_LENGTH_RET (data_size, session->security_parameters.
                   extensions.oprfi_server_len, GNUTLS_E_SHORT_MEMORY_BUFFER);

  memcpy (p, session->security_parameters.extensions.oprfi_server,
          session->security_parameters.extensions.oprfi_server_len);

  return 2 + session->security_parameters.extensions.oprfi_server_len;
}

int
mhd_gtls_oprfi_send_params (mhd_gtls_session_t session,
                           opaque * data, size_t data_size)
{
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    return oprfi_send_client (session, data, data_size);
  else
    return oprfi_send_server (session, data, data_size);
}

/**
 * MHD_gtls_oprfi_enable_client:
 * @session: is a #mhd_gtls_session_t structure.
 * @len: length of Opaque PRF data to use in client.
 * @data: Opaque PRF data to use in client.
 *
 * Request that the client should attempt to negotiate the Opaque PRF
 * Input TLS extension, using the given data as the client's Opaque
 * PRF input.
 *
 * The data is copied into the session context after this call, so you
 * may de-allocate it immediately after calling this function.
 **/
void
MHD_gtls_oprfi_enable_client (mhd_gtls_session_t session,
                            size_t len, unsigned char *data)
{
  session->security_parameters.extensions.oprfi_client_len = len;
  session->security_parameters.extensions.oprfi_client = data;
}

/**
 * MHD_gtls_oprfi_enable_server:
 * @session: is a #mhd_gtls_session_t structure.
 * @cb: function pointer to Opaque PRF extension server callback.
 * @userdata: hook passed to callback function for passing application state.
 *
 * Request that the server should attempt to accept the Opaque PRF
 * Input TLS extension.  If the client requests the extension, the
 * provided callback @cb will be invoked.  The callback must have the
 * following prototype:
 *
 * int callback (mhd_gtls_session_t session, void *userdata,
 *               size_t oprfi_len, const unsigned char *in_oprfi,
 *               unsigned char *out_oprfi);
 *
 * The callback can inspect the client-provided data in the input
 * parameters, and specify its own opaque prf input data in the output
 * variable.  The function must return 0 on success, otherwise the
 * handshake will be aborted.
 **/
void
MHD_gtls_oprfi_enable_server (mhd_gtls_session_t session,
                            gnutls_oprfi_callback_func cb, void *userdata)
{
  session->security_parameters.extensions.oprfi_cb = cb;
  session->security_parameters.extensions.oprfi_userdata = userdata;
}
