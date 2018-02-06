
/**
 * Generate option to set a custom timeout for the given connection.
 * Specified as the number of seconds.  Use zero for no timeout.  If
 * timeout was set to zero (or unset) before, setting of a new value
 * by MHD_connection_set_option() will reset timeout timer.
 *
 * @param connection connection to configure timeout for
 * @param timeout_s new timeout in seconds
 */
struct MHD_ConnectionOption
MHD_connection_timeout (struct MHD_Connection *connection,
			unsigned int timeout_s);



