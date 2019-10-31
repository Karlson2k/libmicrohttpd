enum MHD_Bool
(*handshake)(void *cls,
             struct MHD_TLS_ConnectionState *cs) :


  if (MHD_TLS_CONN_NO_TLS != connection->tls_state)
{     /* HTTPS connection. */
  if (MHD_TLS_CONN_CONNECTED > connection->tls_state)
  {
    if (! MHD_run_tls_handshake_ (connection))
      return MHD_FALSE;
  }
}
return MHD_TRUE;
