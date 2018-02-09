#ifndef MICROHTTPD_TLS_H
#define MICROHTTPD_TLS_H

/**
 * Version of the TLS ABI.
 */
#define MHD_TLS_ABI_VERSION 0

/**
 * Version of the TLS ABI as a string.
 * Must match #MHD_TLS_ABI_VERSION!
 */
#define MHD_TLS_ABI_VERSION_STR "0"


/**
 * Callback functions to use for TLS operations.
 */
struct MHD_TLS_Plugin
{
  /**
   * Closure with plugin's internal state, opaque to MHD.
   */ 
  void *cls;
  
  /**
   * Destroy the plugin, we are done with it.
   */
  void
  (*done)(struct MHD_TLS_Plugin *plugin);

  /**
   * Initialize key and certificate data from memory.
   *
   * @param cls the @e cls of this struct
   * @param mem_key private key (key.pem) to be used by the
   *     HTTPS daemon.  Must be the actual data in-memory, not a filename.
   * @param mem_cert certificate (cert.pem) to be used by the
   *     HTTPS daemon.  Must be the actual data in-memory, not a filename.
   * @param pass passphrase phrase to decrypt 'key.pem', NULL
   *     if @param mem_key is in cleartext already
   * @return #MHD_SC_OK upon success; TODO: define failure modes
   */
  enum MHD_StatusCode
  (*init_kcp)(void *cls,
	      const char *mem_key,
	      const char *mem_cert,
	      const char *pass);


  /**
   * Initialize DH parameters.
   *
   * @param cls the @e cls of this struct
   * @param dh parameters to use
   * @return #MHD_SC_OK upon success; TODO: define failure modes
   */
  enum MHD_StatusCode
  (*init_dhparams)(void *cls,
		   const char *dh);


  /**
   * Initialize certificate to use for client authentication.
   *
   * @param cls the @e cls of this struct
   * @param mem_trust client certificate
   * @return #MHD_SC_OK upon success; TODO: define failure modes
   */
  enum MHD_StatusCode
  (*init_mem_trust)(void *cls,
		    const char *mem_trust);
  
  
  /**
   * TODO: More functions here....
   */
  
};


/**
 * Signature of the initialization function each TLS plugin must
 * export.
 *
 * @param ciphers desired cipher suite
 * @return NULL on errors (in particular, invalid cipher suite)
 */
typedef struct MHD_TLS_Plugin *
MHD_TLS_PluginInit (const char *ciphers);


/**
 * Define function to be exported from the TLS plugin.
 *
 * @a body function body that receives `ciphers` argument
 *    and must return the plugin API, or NULL on error.
 */
#define MHD_TLS_INIT(body) \
  struct MHD_TLS_Plugin * \
  MHD_TLS_init_ ## MHD_TLS_ABI_VERSION (const char *ciphers) \\
  {  body  }

#endif
