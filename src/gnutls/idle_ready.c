enum MHD_Bool
(*idle_ready)(void *cls,
              struct MHD_TLS_ConnectionState *cs);


if (MHD_TLS_CONN_NO_TLS != connection->tls_state)
{         /* HTTPS connection. */
  if ((MHD_TLS_CONN_INIT <= connection->tls_state) &&
      (MHD_TLS_CONN_CONNECTED > connection->tls_state))
    return false;
}
return true;
