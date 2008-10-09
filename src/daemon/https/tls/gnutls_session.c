/*
 * Copyright (C) 2000, 2003, 2004, 2005, 2007 Free Software Foundation
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
#include "gnutls_int.h"
#include "gnutls_errors.h"
#include "debug.h"
#include "gnutls_session_pack.h"
#include <gnutls_datum.h>

/* TODO this file should be removed if session resumption will be abandoned */

/**
  * MHD_gtls_session_get_id - Returns session id.
  * @session: is a #MHD_gtls_session_t structure.
  * @session_id: is a pointer to space to hold the session id.
  * @session_id_size: is the session id's size, or it will be set by the function.
  *
  * Returns the current session id. This can be used if you want to check if
  * the next session you tried to resume was actually resumed.
  * This is because resumed sessions have the same sessionID with the
  * original session.
  *
  * Session id is some data set by the server, that identify the current session.
  * In TLS 1.0 and SSL 3.0 session id is always less than 32 bytes.
  *
  * Returns zero on success.
  **/
int
MHD_gtls_session_get_id (MHD_gtls_session_t session,
                         void *session_id, size_t * session_id_size)
{
  size_t given_session_id_size = *session_id_size;

  *session_id_size = session->security_parameters.session_id_size;

  /* just return the session size */
  if (session_id == NULL)
    {
      return 0;
    }

  if (given_session_id_size < session->security_parameters.session_id_size)
    {
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  memcpy (session_id, &session->security_parameters.session_id,
          *session_id_size);

  return 0;
}

