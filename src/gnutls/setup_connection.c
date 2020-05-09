setup_connection ()
{
  connection->tls_state = MHD_TLS_CONN_INIT;
  MHD_set_https_callbacks (connection);
  gnutls_init (&connection->tls_session,
               GNUTLS_SERVER
#if (GNUTLS_VERSION_NUMBER + 0 >= 0x030402)
               | GNUTLS_NO_SIGNAL
#endif /* GNUTLS_VERSION_NUMBER >= 0x030402 */
#if GNUTLS_VERSION_MAJOR >= 3
               | GNUTLS_NONBLOCK
#endif /* GNUTLS_VERSION_MAJOR >= 3*/
               );
  gnutls_priority_set (connection->tls_session,
                       daemon->priority_cache);
  switch (daemon->cred_type)
  {
  /* set needed credentials for certificate authentication. */
  case GNUTLS_CRD_CERTIFICATE:
    gnutls_credentials_set (connection->tls_session,
                            GNUTLS_CRD_CERTIFICATE,
                            daemon->x509_cred);
    break;
  default:
#ifdef HAVE_MESSAGES
    MHD_DLOG (connection->daemon,
              _ (
                "Failed to setup TLS credentials: unknown credential type %d.\n"),
              daemon->cred_type);
#endif
    MHD_socket_close_chk_ (client_socket);
    MHD_ip_limit_del (daemon,
                      addr,
                      addrlen);
    free (connection);
    MHD_PANIC (_ ("Unknown credential type.\n"));
#if EINVAL
    errno = EINVAL;
#endif
    return MHD_NO;
  }
#if (GNUTLS_VERSION_NUMBER + 0 >= 0x030109) && ! defined(_WIN64)
  gnutls_transport_set_int (connection->tls_session, (int) (client_socket));
#else  /* GnuTLS before 3.1.9 or Win x64 */
  gnutls_transport_set_ptr (connection->tls_session,
                            (gnutls_transport_ptr_t) (intptr_t) (client_socket));
#endif /* GnuTLS before 3.1.9 */
#ifdef MHD_TLSLIB_NEED_PUSH_FUNC
  gnutls_transport_set_push_function (connection->tls_session,
                                      MHD_tls_push_func_);
#endif /* MHD_TLSLIB_NEED_PUSH_FUNC */
  if (daemon->https_mem_trust)
    gnutls_certificate_server_set_request (connection->tls_session,
                                           GNUTLS_CERT_REQUEST);
#else  /* ! HTTPS_SUPPORT */
  return NULL;

}
