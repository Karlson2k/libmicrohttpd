/**
 * Get all of the headers from the request.
 *
 * @param request request to get values from
 * @param kind types of values to iterate over, can be a bitmask
 * @param iterator callback to call on each header;
 *        maybe NULL (then just count headers)
 * @param iterator_cls extra argument to @a iterator
 * @return number of entries iterated over
 * @ingroup request
 */
_MHD_EXTERN unsigned int
MHD_request_get_values (struct MHD_Request *request,
			enum MHD_ValueKind kind,
			MHD_KeyValueIterator iterator,
			void *iterator_cls);


/**
 * This function can be used to add an entry to the HTTP headers of a
 * request (so that the #MHD_request_get_values function will
 * return them -- and the `struct MHD_PostProcessor` will also see
 * them).  This maybe required in certain situations (see Mantis
 * #1399) where (broken) HTTP implementations fail to supply values
 * needed by the post processor (or other parts of the application).
 *
 * This function MUST only be called from within the
 * request callbacks (otherwise, access maybe improperly
 * synchronized).  Furthermore, the client must guarantee that the key
 * and value arguments are 0-terminated strings that are NOT freed
 * until the connection is closed.  (The easiest way to do this is by
 * passing only arguments to permanently allocated strings.).
 *
 * @param request the request for which a
 *  value should be set
 * @param kind kind of the value
 * @param key key for the value
 * @param value the value itself
 * @return #MHD_NO if the operation could not be
 *         performed due to insufficient memory;
 *         #MHD_YES on success
 * @ingroup request
 */
_MHD_EXTERN enum MHD_Bool
MHD_request_set_value (struct MHD_Request *request,
		       enum MHD_ValueKind kind,
		       const char *key,
		       const char *value);


/**
 * Get a particular header value.  If multiple
 * values match the kind, return any one of them.
 *
 * @param request request to get values from
 * @param kind what kind of value are we looking for
 * @param key the header to look for, NULL to lookup 'trailing' value without a key
 * @return NULL if no such item was found
 * @ingroup request
 */
_MHD_EXTERN const char *
MHD_request_lookup_value (struct MHD_Request *request,
			  enum MHD_ValueKind kind,
			  const char *key);




