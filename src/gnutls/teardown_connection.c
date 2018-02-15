teardown_connection ()
{
  gnutls_deinit (connection->tls_session);
}
