/*
 * Copyright (C) 2002, 2003, 2004, 2005 Free Software Foundation
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
#include "gnutls_auth_int.h"
#include "gnutls_errors.h"
#include "gnutls_num.h"
#include <ext_server_name.h>

/*
 * In case of a server: if a NAME_DNS extension type is received then it stores
 * into the session the value of NAME_DNS. The server may use gnutls_ext_get_server_name(),
 * in order to access it.
 *
 * In case of a client: If a proper NAME_DNS extension type is found in the session then
 * it sends the extension to the peer.
 *
 */

int
mhd_gtls_server_name_recv_params (mhd_gtls_session_t session,
                                  const opaque * data, size_t _data_size)
{
  int i;
  const unsigned char *p;
  uint16_t len, type;
  ssize_t data_size = _data_size;
  int server_names = 0;

  if (session->security_parameters.entity == GNUTLS_SERVER)
    {
      DECR_LENGTH_RET (data_size, 2, 0);
      len = mhd_gtls_read_uint16 (data);

      if (len != data_size)
        {
          /* This is unexpected packet length, but
           * just ignore it, for now.
           */
          gnutls_assert ();
          return 0;
        }

      p = data + 2;

      /* Count all server_names in the packet. */
      while (data_size > 0)
        {
          DECR_LENGTH_RET (data_size, 1, 0);
          p++;

          DECR_LEN (data_size, 2);
          len = mhd_gtls_read_uint16 (p);
          p += 2;

          DECR_LENGTH_RET (data_size, len, 0);
          server_names++;

          p += len;
        }

      session->security_parameters.extensions.server_names_size =
        server_names;
      if (server_names == 0)
        return 0;               /* no names found */

      /* we cannot accept more server names.
       */
      if (server_names > MAX_SERVER_NAME_EXTENSIONS)
        server_names = MAX_SERVER_NAME_EXTENSIONS;

      p = data + 2;
      for (i = 0; i < server_names; i++)
        {
          type = *p;
          p++;

          len = mhd_gtls_read_uint16 (p);
          p += 2;

          switch (type)
            {
            case 0:            /* NAME_DNS */
              if (len <= MAX_SERVER_NAME_SIZE)
                {
                  memcpy (session->security_parameters.extensions.
                          server_names[i].name, p, len);
                  session->security_parameters.extensions.
                    server_names[i].name_length = len;
                  session->security_parameters.extensions.
                    server_names[i].type = GNUTLS_NAME_DNS;
                  break;
                }
            }

          /* move to next record */
          p += len;
        }
    }
  return 0;
}

/* returns data_size or a negative number on failure
 */
int
mhd_gtls_server_name_send_params (mhd_gtls_session_t session,
                                  opaque * data, size_t _data_size)
{
  int total_size = 0;
#if MHD_DEBUG_TLS
  uint16_t len;
  opaque *p;
  unsigned i;
  ssize_t data_size = _data_size;

  /* this function sends the client extension data (dnsname) */
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {

      if (session->security_parameters.extensions.server_names_size == 0)
        return 0;

      /* uint16_t
       */
      total_size = 2;
      for (i = 0;
           i < session->security_parameters.extensions.server_names_size; i++)
        {
          /* count the total size
           */
          len =
            session->security_parameters.extensions.server_names[i].
            name_length;

          /* uint8_t + uint16_t + size
           */
          total_size += 1 + 2 + len;
        }

      p = data;

      /* UINT16: write total size of all names
       */
      DECR_LENGTH_RET (data_size, 2, GNUTLS_E_SHORT_MEMORY_BUFFER);
      mhd_gtls_write_uint16 (total_size - 2, p);
      p += 2;

      for (i = 0;
           i < session->security_parameters.extensions.server_names_size; i++)
        {

          switch (session->security_parameters.extensions.
                  server_names[i].type)
            {
            case GNUTLS_NAME_DNS:

              len =
                session->security_parameters.extensions.
                server_names[i].name_length;
              if (len == 0)
                break;

              /* UINT8: type of this extension
               * UINT16: size of the first name
               * LEN: the actual server name.
               */
              DECR_LENGTH_RET (data_size, len + 3,
                               GNUTLS_E_SHORT_MEMORY_BUFFER);

              *p = 0;           /* NAME_DNS type */
              p++;

              mhd_gtls_write_uint16 (len, p);
              p += 2;

              memcpy (p,
                      session->security_parameters.extensions.
                      server_names[0].name, len);
              p += len;
              break;
            default:
              gnutls_assert ();
              return GNUTLS_E_INTERNAL_ERROR;
            }
        }
    }
#endif
  return total_size;
}

/**
  * MHD_gnutls_server_name_get - Used to get the server name indicator send by a client
  * @session: is a #mhd_gtls_session_t structure.
  * @data: will hold the data
  * @data_length: will hold the data length. Must hold the maximum size of data.
  * @type: will hold the server name indicator type
  * @indx: is the index of the server_name
  *
  * This function will allow you to get the name indication (if any),
  * a client has sent. The name indication may be any of the enumeration
  * gnutls_server_name_type_t.
  *
  * If @type is GNUTLS_NAME_DNS, then this function is to be used by servers
  * that support virtual hosting, and the data will be a null terminated UTF-8 string.
  *
  * If @data has not enough size to hold the server name GNUTLS_E_SHORT_MEMORY_BUFFER
  * is returned, and @data_length will hold the required size.
  *
  * @index is used to retrieve more than one server names (if sent by the client).
  * The first server name has an index of 0, the second 1 and so on. If no name with the given
  * index exists GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE is returned.
  *
  **/
int
MHD_gnutls_server_name_get (mhd_gtls_session_t session, void *data,
                            size_t * data_length,
                            unsigned int *type, unsigned int indx)
{
  char *_data = data;
#if MHD_DEBUG_TLS
  if (session->security_parameters.entity == GNUTLS_CLIENT)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }
#endif
  if (indx + 1 > session->security_parameters.extensions.server_names_size)
    {
      return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
    }

  *type = session->security_parameters.extensions.server_names[indx].type;

  if (*data_length >            /* greater since we need one extra byte for the null */
      session->security_parameters.extensions.server_names[indx].name_length)
    {
      *data_length =
        session->security_parameters.extensions.server_names[indx].
        name_length;
      memcpy (data,
              session->security_parameters.extensions.server_names[indx].name,
              *data_length);

      if (*type == GNUTLS_NAME_DNS)     /* null terminate */
        _data[(*data_length)] = 0;

    }
  else
    {
      *data_length =
        session->security_parameters.extensions.server_names[indx].
        name_length;
      return GNUTLS_E_SHORT_MEMORY_BUFFER;
    }

  return 0;
}

/**
  * MHD_gnutls_server_name_set - Used to set a name indicator to be sent as an extension
  * @session: is a #mhd_gtls_session_t structure.
  * @type: specifies the indicator type
  * @name: is a string that contains the server name.
  * @name_length: holds the length of name
  *
  * This function is to be used by clients that want to inform
  * (via a TLS extension mechanism) the server of the name they
  * connected to. This should be used by clients that connect
  * to servers that do virtual hosting.
  *
  * The value of @name depends on the @ind type. In case of GNUTLS_NAME_DNS,
  * an ASCII or UTF-8 null terminated string, without the trailing dot, is expected.
  * IPv4 or IPv6 addresses are not permitted.
  *
  **/
int
MHD_gnutls_server_name_set (mhd_gtls_session_t session,
                            gnutls_server_name_type_t type,
                            const void *name, size_t name_length)
{
  int server_names;

  if (session->security_parameters.entity == GNUTLS_SERVER)
    {
      gnutls_assert ();
      return GNUTLS_E_INVALID_REQUEST;
    }

  if (name_length > MAX_SERVER_NAME_SIZE)
    return GNUTLS_E_SHORT_MEMORY_BUFFER;

  server_names =
    session->security_parameters.extensions.server_names_size + 1;

  if (server_names > MAX_SERVER_NAME_EXTENSIONS)
    server_names = MAX_SERVER_NAME_EXTENSIONS;

  session->security_parameters.extensions.server_names[server_names -
                                                       1].type = type;
  memcpy (session->security_parameters.extensions.
          server_names[server_names - 1].name, name, name_length);
  session->security_parameters.extensions.server_names[server_names -
                                                       1].name_length =
    name_length;

  session->security_parameters.extensions.server_names_size++;

  return 0;
}
