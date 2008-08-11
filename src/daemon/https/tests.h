typedef enum
{
  TEST_SUCCEED, TEST_FAILED, TEST_UNSURE, TEST_IGNORE
} test_code_t;

test_code_t test_srp (mhd_gtls_session_t state);
test_code_t test_server (mhd_gtls_session_t state);
test_code_t test_export (mhd_gtls_session_t state);
test_code_t test_export_info (mhd_gtls_session_t state);
test_code_t test_hello_extension (mhd_gtls_session_t state);
test_code_t test_dhe (mhd_gtls_session_t state);
test_code_t test_dhe_group (mhd_gtls_session_t state);
test_code_t test_ssl3 (mhd_gtls_session_t state);
test_code_t test_aes (mhd_gtls_session_t state);
#ifdef	ENABLE_CAMELLIA
test_code_t test_camellia (mhd_gtls_session_t state);
#endif
test_code_t test_md5 (mhd_gtls_session_t state);
test_code_t test_sha (mhd_gtls_session_t state);
test_code_t test_3des (mhd_gtls_session_t state);
test_code_t test_arcfour (mhd_gtls_session_t state);
test_code_t test_arcfour_40 (mhd_gtls_session_t state);
test_code_t test_tls1 (mhd_gtls_session_t state);
test_code_t test_tls1_1 (mhd_gtls_session_t state);
test_code_t test_tls1_1_fallback (mhd_gtls_session_t state);
test_code_t test_tls_disable (mhd_gtls_session_t state);
test_code_t test_rsa_pms (mhd_gtls_session_t state);
test_code_t test_max_record_size (mhd_gtls_session_t state);
test_code_t test_version_rollback (mhd_gtls_session_t state);
test_code_t test_anonymous (mhd_gtls_session_t state);
test_code_t test_unknown_ciphersuites (mhd_gtls_session_t state);
test_code_t test_openpgp1 (mhd_gtls_session_t state);
test_code_t test_bye (mhd_gtls_session_t state);
test_code_t test_certificate (mhd_gtls_session_t state);
test_code_t test_server_cas (mhd_gtls_session_t state);
test_code_t test_session_resume2 (mhd_gtls_session_t state);
test_code_t test_rsa_pms_version_check (mhd_gtls_session_t session);
test_code_t test_version_oob (mhd_gtls_session_t session);
test_code_t test_zlib (mhd_gtls_session_t session);
test_code_t test_lzo (mhd_gtls_session_t session);
int _test_srp_username_callback (mhd_gtls_session_t session,
				 char **username, char **password);
