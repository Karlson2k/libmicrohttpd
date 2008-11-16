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

#include "MHD_config.h"
#include <ext_oprfi.h>

#include <gnutls_errors.h>
#include <gnutls_num.h>

static int
oprfi_recv_server (MHD_gtls_session_t session,
                   const opaque * data, size_t _data_size)
{
  ssize_t data_size = _data_size;
  uint16_t len;

  if (!session->security_parameters.extensions.oprfi_cb)
    {
      MHD_gnutls_assert ();
      return 0;
    }

  DECR_LEN (data_size, 2);
  len = MHD_gtls_read_uint16 (data);
  data += 2;

  if (len != data_size)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  /* Store incoming data. */
  session->security_parameters.extensions.oprfi_client_len = len;
  session->security_parameters.extensions.oprfi_client =
    MHD_gnutls_malloc (len);
  if (!session->security_parameters.extensions.oprfi_client)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
  memcpy (session->security_parameters.extensions.oprfi_client, data, len);

  return 0;
}

#if MHD_DEBUG_TLS
static int
oprfi_recv_client (MHD_gtls_session_t session,
                   const opaque * data, size_t _data_size)
{
  ssize_t data_size = _data_size;
  uint16_t len;

  if (session->security_parameters.extensions.oprfi_client == NULL)
    {
      MHD_gnutls_assert ();
      return 0;
    }

  DECR_LEN (data_size, 2);
  len = MHD_gtls_read_uint16 (data);
  data += 2;

  if (len != data_size)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  if (len != session->security_parameters.extensions.oprfi_client_len)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_RECEIVED_ILLEGAL_PARAMETER;
    }

  /* Store incoming data. */
  session->security_parameters.extensions.oprfi_server_len = len;
  session->security_parameters.extensions.oprfi_server =
    MHD_gnutls_malloc (len);
  if (!session->security_parameters.extensions.oprfi_server)
    {
      MHD_gnutls_assert ();
      return GNUTLS_E_MEMORY_ERROR;
    }
  memcpy (session->security_parameters.extensions.oprfi_server, data, len);

  return 0;
}
#endif

int
MHD_gtls_oprfi_recv_params (MHD_gtls_session_t session,
                            const opaque * data, size_t data_size)
{
#if MHD_DEBUG_TLS
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    return oprfi_recv_client (session, data, data_size);
  else
#endif
    return oprfi_recv_server (session, data, data_size);
}

#if MHD_DEBUG_TLS
static int
oprfi_send_client (MHD_gtls_session_t session, opaque * data,
                   size_t _data_size)
{
  opaque *p = data;
  ssize_t data_size = _data_size;
  int oprf_size = session->security_parameters.extensions.oprfi_client_len;

  if (oprf_size == 0)
    return 0;

  DECR_LENGTH_RET (data_size, 2, GNUTLS_E_SHORT_MEMORY_BUFFER);
  MHD_gtls_write_uint16 (oprf_size, p);
  p += 2;

  DECR_LENGTH_RET (data_size, oprf_size, GNUTLS_E_SHORT_MEMORY_BUFFER);

  memcpy (p, session->security_parameters.extensions.oprfi_client, oprf_size);

  return 2 + oprf_size;
}
#endif

static int
oprfi_send_server (MHD_gtls_session_t session, opaque * data,
                   size_t _data_size)
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
    MHD_gnutls_malloc (session->security_parameters.extensions.
                       oprfi_server_len);
  if (!session->security_parameters.extensions.oprfi_server)
    {
      MHD_gnutls_assert ();
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
      MHD_gnutls_assert ();
      MHD_gnutls_free (session->security_parameters.extensions.oprfi_server);
      return ret;
    }

  DECR_LENGTH_RET (data_size, 2, GNUTLS_E_SHORT_MEMORY_BUFFER);
  MHD_gtls_write_uint16 (session->security_parameters.extensions.
                         oprfi_server_len, p);
  p += 2;

  DECR_LENGTH_RET (data_size,
                   session->security_parameters.extensions.oprfi_server_len,
                   GNUTLS_E_SHORT_MEMORY_BUFFER);

  memcpy (p, session->security_parameters.extensions.oprfi_server,
          session->security_parameters.extensions.oprfi_server_len);

  return 2 + session->security_parameters.extensions.oprfi_server_len;
}

int
MHD_gtls_oprfi_send_params (MHD_gtls_session_t session,
                            opaque * data, size_t data_size)
{
#if MHD_DEBUG_TLS
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    return oprfi_send_client (session, data, data_size);
  else
#endif
    return oprfi_send_server (session, data, data_size);
}

