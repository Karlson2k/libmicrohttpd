recv :

res = gnutls_record_recv (connection->tls_session,
                          &urh->in_buffer[urh->in_buffer_used],
                          buf_size);
