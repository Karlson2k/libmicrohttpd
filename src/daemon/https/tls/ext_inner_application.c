/*
 * Copyright (C) 2005, 2006 Free Software Foundation
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 */

#include "gnutls_int.h"
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_num.h"
#include "ext_inner_application.h"

#define NO 0
#define YES 1

int
mhd_gtls_inner_app_rcv_params (mhd_gtls_session_t session,
                               const opaque * data, size_t data_size)
{
  mhd_gtls_ext_st *ext = &session->security_parameters.extensions;

  if (data_size != 1)
    {
      gnutls_assert ();
      return GNUTLS_E_UNEXPECTED_PACKET_LENGTH;
    }

  ext->gnutls_ia_peer_enable = 1;
  ext->gnutls_ia_peer_allowskip = 0;

  switch ((unsigned char) *data)
    {
    case NO:                   /* Peer's ia_on_resume == no */
      ext->gnutls_ia_peer_allowskip = 1;
      break;

    case YES:
      break;

    default:
      gnutls_assert ();
    }

  return 0;
}


/**
 *  returns data_size or a negative number on failure
 */
int
mhd_gtls_inner_app_send_params (mhd_gtls_session_t session,
                                opaque * data, size_t data_size)
{
  mhd_gtls_ext_st *ext = &session->security_parameters.extensions;

  /* Set ext->gnutls_ia_enable depending on whether we have a TLS/IA
     credential in the session. */
#if MHD_DEBUG_TLS
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {
      gnutls_ia_client_credentials_t cred = (gnutls_ia_client_credentials_t)
        mhd_gtls_get_cred (session->key, MHD_GNUTLS_CRD_IA, NULL);

      if (cred)
        ext->gnutls_ia_enable = 1;
    }
  else
#endif
    {
      struct gnutls_ia_server_credentials_st *cred =
        (struct gnutls_ia_server_credentials_st *)
        mhd_gtls_get_cred (session->key, MHD_GNUTLS_CRD_IA, NULL);

      if (cred)
        ext->gnutls_ia_enable = 1;
    }

  /* If we don't want gnutls_ia locally, or we are a server and the
   * client doesn't want it, don't advertise TLS/IA support at all, as
   * required. */

  if (!ext->gnutls_ia_enable)
    return 0;

  if (session->security_parameters.entity == GNUTLS_SERVER &&
      !ext->gnutls_ia_peer_enable)
    return 0;

  /* We'll advertise. Check if there's room in the hello buffer. */

  if (data_size < 1)
    {
      gnutls_assert ();
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  /* default: require new application phase */

  *data = YES;

#if MHD_DEBUG_TLS
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {

      /* Client: value follows local setting */

      if (ext->gnutls_ia_allowskip)
        *data = NO;
    }
  else
#endif
    {

      /* Server: value follows local setting and client's setting, but only
       * if we are resuming.
       *
       * XXX Can server test for resumption at this stage?
       *
       * Ai! It seems that read_client_hello only calls parse_extensions if
       * we're NOT resuming! That would make us automatically violate the IA
       * draft; if we're resuming, we must first learn what the client wants
       * -- IA or no IA -- and then prepare our response. Right now we'll
       * always skip IA on resumption, because recv_ext isn't even called
       * to record the peer's support for IA at all. Simon? */

      if (ext->gnutls_ia_allowskip &&
          ext->gnutls_ia_peer_allowskip &&
          session->internals.resumed == RESUME_TRUE)
        *data = NO;
    }

  return 1;
}
