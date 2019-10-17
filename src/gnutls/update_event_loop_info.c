enum MHD_Bool
(*update_event_loop_info)(void *cls,
                          struct MHD_TLS_ConnectionState *cs,
                          enum MHD_RequestEventLoopInfo *eli);


switch (connection->tls_state)
{
case MHD_TLS_CONN_INIT:
  *eli = MHD_EVENT_LOOP_INFO_READ;
  return true;
case MHD_TLS_CONN_HANDSHAKING:
  if (0 == gnutls_record_get_direction (connection->tls_session))
    *eli = MHD_EVENT_LOOP_INFO_READ;
  else
    *eli = MHD_EVENT_LOOP_INFO_WRITE;
  return true;
default:
  return false;
}
