ssize_t
(*send)(void *cls,
        struct MHD_TLS_ConnectionState *cs,
        const void *buf,
        size_t buf_size);


see:
res = gnutls_record_send (connection->tls_session,
                          urh->out_buffer,
                          data_size);
