/*
  This file is part of GNU libmicrohttpd
  Copyright (C) 2024 Evgeny Grin (Karlson2k)

  GNU libmicrohttpd is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  GNU libmicrohttpd is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

*/

/**
 * @file src/mhd2/daemon_create.c
 * @brief  The implementation of the MHD_daemon_create()
 * @author Karlson2k (Evgeny Grin)
 */

#include "mhd_sys_options.h"

#include "sys_base_types.h"
#include "sys_malloc.h"

#include "mhd_public_api.h"

#include "compat_calloc.h"

#include "mhd_daemon.h"
#include "daemon_options.h"

#include "daemon_logger_default.h"

#include "mhd_lib_init.h"


MHD_FN_MUST_CHECK_RESULT_ MHD_EXTERN_ struct MHD_Daemon *
MHD_daemon_create (MHD_RequestCallback req_cb,
                   void *req_cb_cls)
{
  struct MHD_Daemon *d;
  struct DaemonOptions *s;

  MHD_GLOBAL_INIT_CHECK ();

  if (NULL == req_cb)
    return NULL;

  d = (struct MHD_Daemon *) mhd_calloc (1, sizeof(struct MHD_Daemon));
  if (NULL == d)
    return NULL;

  s = (struct DaemonOptions *) mhd_calloc (1, sizeof(struct DaemonOptions));
  if (NULL == s)
  {
    free (d);
    return NULL;
  }
  /* calloc() does not guarantee that floating point values and pointers
     are initialised to zero and NULL (respectfully). */
  /* Any floating point and pointer members must be initialised manually here */
#ifndef HAVE_NULL_PTR_ALL_ZEROS
  s->bind_sa.v_sa = NULL;
  s->tls_key_cert.v_mem_key = NULL;
  s->tls_key_cert.v_mem_cert = NULL;
  s->tls_key_cert.v_mem_pass = NULL;
  s->tls_client_ca = NULL;
  s->tls_psk_callback.v_psk_cb = NULL;
  s->tls_psk_callback.v_psk_cb_cls = NULL;
  s->accept_policy.v_apc = NULL;
  s->accept_policy.v_apc_cls = NULL;
  s->early_uri_logger.v_cb = NULL;
  s->early_uri_logger.v_cls = NULL;
  s->daemon_ready_callback.v_cb = NULL;
  s->daemon_ready_callback.v_cb_cls = NULL;
  s->notify_connection.v_ncc = NULL;
  s->notify_connection.v_cls = NULL;
  s->notify_stream.v_nsc = NULL;
  s->notify_stream.v_cls = NULL;
  s->random_entropy.v_buf = NULL;

  d->log_params.v_log_cb = NULL; /* optional */
#endif /* !HAVE_NULL_PTR_ALL_ZEROS */

  s->listen_socket = MHD_INVALID_SOCKET;
  s->fd_number_limit = MHD_INVALID_SOCKET;

  d->log_params.v_log_cb = mhd_logger_default;
  d->req_cfg.cb = req_cb;
  d->req_cfg.cb_cls = req_cb_cls;
  d->settings = s;

  return d;
}


/* This is a workaround for GCC/binutils bug.
 * To make sure that initialisation functions are called when MHD is used as
 * a static library, put initialisation functions to the file with function
 * that always referred/used by application/user of the library.
 * If application does not refer any function, the initialiser call could be
 * missed for the static library.
 */
#define MHD_LIB_INIT_IMPL_H_IN_DAEMON_CREATE_C 1
#include "mhd_lib_init_impl.h"
