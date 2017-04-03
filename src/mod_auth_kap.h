/*
 * Copyright (C) 2017 Kapstonellc (http://www.kapstonellc.com)
 *
 * Created by Pavlov <pavlov0123@outlook.com>
 * 
 */

#ifndef MOD_AUTH_KAP_H_
#define MOD_AUTH_KAP_H_

#include <stdint.h>
#include <openssl/evp.h>
#include <apr_uri.h>
#include <apr_uuid.h>
#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <mod_auth.h>

#include "apr_memcache.h"
#include "apr_shm.h"
#include "apr_global_mutex.h"

#include "jose/apr_jose.h"

#include "cache/cache.h"

extern "C" module AP_MODULE_DECLARE_DATA auth_kap_module;

// #ifdef APLOG_USE_MODULE
// APLOG_USE_MODULE(auth_kap_module);
// #endif
#ifdef APLOG_USE_MODULE
static int * const aplog_module_index = &(auth_kap_module.module_index);
#endif

#ifndef KAP_DEBUG
#define KAP_DEBUG APLOG_DEBUG
#endif

#define kap_log(r, level, fmt, ...) ap_log_rerror(APLOG_MARK, level, 0, r,"%s: %s", __FUNCTION__, apr_psprintf(r->pool, fmt, ##__VA_ARGS__))
#define kap_slog(s, level, fmt, ...) ap_log_error(APLOG_MARK, level, 0, s, "%s: %s", __FUNCTION__, apr_psprintf(s->process->pool, fmt, ##__VA_ARGS__))

#define kap_debug(r, fmt, ...) kap_log(r, KAP_DEBUG, fmt, ##__VA_ARGS__)
#define kap_warn(r, fmt, ...) kap_log(r, APLOG_WARNING, fmt, ##__VA_ARGS__)
#define kap_error(r, fmt, ...) kap_log(r, APLOG_ERR, fmt, ##__VA_ARGS__)

#define kap_sdebug(s, fmt, ...) kap_slog(s, KAP_DEBUG, fmt, ##__VA_ARGS__)
#define kap_swarn(s, fmt, ...) kap_slog(s, APLOG_WARNING, fmt, ##__VA_ARGS__)
#define kap_serror(s, fmt, ...) kap_slog(s, APLOG_ERR, fmt, ##__VA_ARGS__)

#ifndef NAMEVER
#define NAMEVERSION "mod_auth_kap-0.0.0"
#else
#define STRINGIFY(x) #x
#define TOSTRING(x) STRINGIFY(x)
#define NAMEVERSION TOSTRING(NAMEVER)
#endif

/* key for storing the claims in the session context */
#define KAP_CLAIMS_SESSION_KEY "claims"
/* key for storing the id_token in the session context */
#define KAP_IDTOKEN_CLAIMS_SESSION_KEY "id_token_claims"
/* key for storing the raw id_token in the session context */
#define KAP_IDTOKEN_SESSION_KEY "id_token"
/* key for storing the access_token in the session context */
#define KAP_ACCESSTOKEN_SESSION_KEY "access_token"
/* key for storing the access_token expiry in the session context */
#define KAP_ACCESSTOKEN_EXPIRES_SESSION_KEY "access_token_expires"
/* key for storing the refresh_token in the session context */
#define KAP_REFRESHTOKEN_SESSION_KEY "refresh_token"
/* key for storing maximum session duration in the session context */
#define KAP_SESSION_EXPIRES_SESSION_KEY "session_expires"

/* key for storing the session_state in the session context */
#define KAP_SESSION_STATE_SESSION_KEY "session_state"
/* key for storing the issuer in the session context */
#define KAP_ISSUER_SESSION_KEY "issuer"
/* key for storing the client_id in the session context */
#define KAP_CLIENTID_SESSION_KEY "client_id"
/* key for storing the check_session_iframe in the session context */
#define KAP_CHECK_IFRAME_SESSION_KEY "check_session_iframe"
/* key for storing the end_session_endpoint in the session context */
#define KAP_LOGOUT_ENDPOINT_SESSION_KEY "end_session_endpoint"

/* parameter name of the callback URL in the discovery response */
#define KAP_DISC_CB_PARAM "kap_callback"
/* parameter name of the OP provider selection in the discovery response */
#define KAP_DISC_OP_PARAM "iss"
/* parameter name of the original URL in the discovery response */
#define KAP_DISC_RT_PARAM "target_link_uri"
/* parameter name of login hint in the discovery response */
#define KAP_DISC_LH_PARAM "login_hint"
/* parameter name of parameters that need to be passed in the authentication request */
#define KAP_DISC_AR_PARAM "auth_request_params"

/* value that indicates to use server-side cache based session tracking */
#define KAP_SESSION_TYPE_22_SERVER_CACHE 0
/* value that indicates to use client cookie based session tracking */
#define KAP_SESSION_TYPE_22_CLIENT_COOKIE 1

/* pass id_token as individual claims in headers (default) */
#define KAP_PASS_IDTOKEN_AS_CLAIMS     1
/* pass id_token payload as JSON object in header*/
#define KAP_PASS_IDTOKEN_AS_PAYLOAD    2
/* pass id_token in compact serialized format in header*/
#define KAP_PASS_IDTOKEN_AS_SERIALIZED 4

/* prefix of the cookie that binds the state in the authorization request/response to the browser */
#define KAPStateCookiePrefix  "mod_auth_kap_state_"

/* default prefix for information passed in HTTP headers */
#define KAP_DEFAULT_HEADER_PREFIX "KAP_"

/* the (global) key for the mod_auth_kap related state that is stored in the request userdata context */
#define KAP_USERDATA_KEY "mod_auth_kap_state"

#define KAP_USERDATA_ENV_KEY "mod_auth_kap_env"

/* input filter hook name */
#define KAP_UTIL_HTTP_SENDSTRING "KAP_UTIL_HTTP_SENDSTRING"

/* the name of the keyword that follows the Require primitive to indicate claims-based authorization */
#define KAP_REQUIRE_NAME "claim"

/* defines for how long provider metadata will be cached */
#define KAP_CACHE_PROVIDER_METADATA_EXPIRY_DEFAULT 86400

/* define the parameter value for the "logout" request that indicates a GET-style logout call from the OP */
#define KAP_GET_STYLE_LOGOUT_PARAM_VALUE "get"

/* cache sections */
#define KAP_CACHE_SECTION_JTI "jti"
#define KAP_CACHE_SECTION_SESSION "session"
#define KAP_CACHE_SECTION_NONCE "nonce"
#define KAP_CACHE_SECTION_JWKS "jwks"
#define KAP_CACHE_SECTION_ACCESS_TOKEN "access_token"
#define KAP_CACHE_SECTION_PROVIDER "provider"

typedef struct kap_jwks_uri_t {
	const char *url;
	int refresh_interval;
	int ssl_validate_server;
} kap_jwks_uri_t;

typedef struct kap_provider_t {
	char *metadata_url;
	char *issuer;
	char *authorization_endpoint_url;
	char *token_endpoint_url;
	char *token_endpoint_auth;
	char *token_endpoint_params;
	char *userinfo_endpoint_url;
	char *registration_endpoint_url;
	char *check_session_iframe;
	char *end_session_endpoint;
	char *jwks_uri;
	char *client_id;
	char *client_secret;

	// the next ones function as global default settings too
	int ssl_validate_server;
	char *client_name;
	char *client_contact;
	char *registration_token;
	char *registration_endpoint_json;
	char *scope;
	char *response_type;
	char *response_mode;
	int jwks_refresh_interval;
	int idtoken_iat_slack;
	char *auth_request_params;
	int session_max_duration;

	char *client_jwks_uri;
	char *id_token_signed_response_alg;
	char *id_token_encrypted_response_alg;
	char *id_token_encrypted_response_enc;
	char *userinfo_signed_response_alg;
	char *userinfo_encrypted_response_alg;
	char *userinfo_encrypted_response_enc;
} kap_provider_t ;

typedef struct kap_remote_user_claim_t {
	const char *claim_name;
	const char *reg_exp;
} kap_remote_user_claim_t;

typedef struct kap_oauth_t {
	int ssl_validate_server;
	char *client_id;
	char *client_secret;
	char *introspection_endpoint_url;
	char *introspection_endpoint_method;
	char *introspection_endpoint_params;
	char *introspection_endpoint_auth;
	char *introspection_token_param_name;
	char *introspection_token_expiry_claim_name;
	char *introspection_token_expiry_claim_format;
	int introspection_token_expiry_claim_required;
	kap_remote_user_claim_t remote_user_claim;
	apr_hash_t *verify_shared_keys;
	char *verify_jwks_uri;
	apr_hash_t *verify_public_keys;
} kap_oauth_t;

typedef struct kap_cfg {
	/* indicates whether this is a derived config, merged from a base one */
	unsigned int merged;

	/* the redirect URI as configured with the OpenID Connect OP's that we talk to */
	char *redirect_uri;
	/* (optional) default URL for 3rd-party initiated SSO */
	char *default_sso_url;
	/* (optional) default URL to go to after logout */
	char *default_slo_url;

	/* public keys in JWK format, used by parters for encrypting JWTs sent to us */
	apr_hash_t *public_keys;
	/* private keys in JWK format used for decrypting encrypted JWTs sent to us */
	apr_hash_t *private_keys;

	/* a pointer to the (single) provider that we connect to */
	/* NB: if metadata_dir is set, these settings will function as defaults for the metadata read from there) */
	kap_provider_t provider;
	/* a pointer to the oauth server settings */
	kap_oauth_t oauth;

	/* directory that holds the provider & client metadata files */
	char *metadata_dir;
	/* type of session management/storage */
	int session_type;

	/* pointer to cache functions */
	kap_cache_t *cache;
	void *cache_cfg;
	/* cache_type = file: directory that holds the cache files (if not set, we'll try and use an OS defined one like "/tmp" */
	char *cache_file_dir;
	/* cache_type = file: clean interval */
	int cache_file_clean_interval;
	/* cache_type= memcache: list of memcache host/port servers to use */
	char *cache_memcache_servers;
	/* cache_type = shm: size of the shared memory segment (cq. max number of cached entries) */
	int cache_shm_size_max;
	/* cache_type = shm: maximum size in bytes of a cache entry */
	int cache_shm_entry_size_max;
#ifdef USE_LIBHIREDIS
	/* cache_type= redis: Redis host/port server to use */
	char *cache_redis_server;
#endif

	/* tell the module to strip any mod_auth_kap related headers that already have been set by the user-agent, normally required for secure operation */
	int scrub_request_headers;

	int http_timeout_long;
	int http_timeout_short;
	int state_timeout;
	int session_inactivity_timeout;

	char *cookie_domain;
	char *claim_delimiter;
	char *claim_prefix;
	kap_remote_user_claim_t remote_user_claim;
	int pass_idtoken_as;
	int cookie_http_only;

	char *outgoing_proxy;

	char *crypto_passphrase;

	EVP_CIPHER_CTX *encrypt_ctx;
	EVP_CIPHER_CTX *decrypt_ctx;
} kap_cfg;

typedef struct kap_dir_cfg {
	/* (optional) external OP discovery page */
	char *discover_url;
	char *cookie_path;
	char *cookie;
	char *authn_header;
	int return401;
	apr_array_header_t *pass_cookies;
	apr_byte_t pass_info_in_headers;
	apr_byte_t pass_info_in_env_vars;
} kap_dir_cfg;

int kap_check_user_id(request_rec *r);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
authz_status kap_authz_checker(request_rec *r, const char *require_args, const void *parsed_require_args);
#else
int kap_auth_checker(request_rec *r);
#endif
void kap_request_state_set(request_rec *r, const char *key, const char *value);
const char*kap_request_state_get(request_rec *r, const char *key);
int kap_handle_jwks(request_rec *r, kap_cfg *c);

// kap_proto.c

int kap_proto_authorization_request(request_rec *r, struct kap_provider_t *provider, const char *login_hint, const char *redirect_uri, const char *state, json_t *proto_state, const char *id_token_hint, const char *auth_request_params);
apr_byte_t kap_proto_is_post_authorization_response(request_rec *r, kap_cfg *cfg);
apr_byte_t kap_proto_is_redirect_authorization_response(request_rec *r, kap_cfg *cfg);
apr_byte_t kap_proto_resolve_code(request_rec *r, kap_cfg *cfg, kap_provider_t *provider, const char *code, char **id_token, char **access_token, char **token_type, int *expires_in, char **refresh_token);
apr_byte_t kap_proto_refresh_request(request_rec *r, kap_cfg *cfg, kap_provider_t *provider, const char *rtoken, char **id_token, char **access_token, char **token_type, int *expires_in, char **refresh_token);
apr_byte_t kap_proto_resolve_userinfo(request_rec *r, kap_cfg *cfg, kap_provider_t *provider, const char *access_token, const char **response);
apr_byte_t kap_proto_account_based_discovery(request_rec *r, kap_cfg *cfg, const char *acct, char **issuer);
apr_byte_t kap_proto_parse_idtoken(request_rec *r, kap_cfg *cfg, kap_provider_t *provider, const char *id_token, const char *nonce, apr_jwt_t **jwt, apr_byte_t is_code_flow);
int kap_proto_javascript_implicit(request_rec *r, kap_cfg *c);
apr_array_header_t *kap_proto_supported_flows(apr_pool_t *pool);
apr_byte_t kap_proto_flow_is_supported(apr_pool_t *pool, const char *flow);
apr_byte_t kap_proto_validate_authorization_response(request_rec *r, const char *response_type, const char *requested_response_mode, char **code, char **id_token, char **access_token, char **token_type, const char *used_response_mode);
apr_byte_t kap_proto_jwt_verify(request_rec *r, kap_cfg *cfg, apr_jwt_t *jwt, const kap_jwks_uri_t *jwks_uri, apr_hash_t *symmetric_keys);
apr_byte_t kap_proto_validate_jwt(request_rec *r, apr_jwt_t *jwt, const char *iss, apr_byte_t exp_is_mandatory, apr_byte_t iat_is_mandatory, int iat_slack);
apr_byte_t kap_proto_generate_nonce(request_rec *r, char **nonce);

apr_byte_t kap_proto_authorization_response_code_idtoken_token(request_rec *r, kap_cfg *c, json_t *proto_state, kap_provider_t *provider, apr_table_t *params, const char *response_mode, apr_jwt_t **jwt);
apr_byte_t kap_proto_authorization_response_code_idtoken(request_rec *r, kap_cfg *c, json_t *proto_state, kap_provider_t *provider, apr_table_t *params, const char *response_mode, apr_jwt_t **jwt);
apr_byte_t kap_proto_handle_authorization_response_code_token(request_rec *r, kap_cfg *c, json_t *proto_state, kap_provider_t *provider, apr_table_t *params, const char *response_mode, apr_jwt_t **jwt);
apr_byte_t kap_proto_handle_authorization_response_code(request_rec *r, kap_cfg *c, json_t *proto_state, kap_provider_t *provider, apr_table_t *params, const char *response_mode, apr_jwt_t **jwt);
apr_byte_t kap_proto_handle_authorization_response_idtoken_token(request_rec *r, kap_cfg *c, json_t *proto_state, kap_provider_t *provider, apr_table_t *params, const char *response_mode, apr_jwt_t **jwt);
apr_byte_t kap_proto_handle_authorization_response_idtoken(request_rec *r, kap_cfg *c, json_t *proto_state, kap_provider_t *provider, apr_table_t *params, const char *response_mode, apr_jwt_t **jwt);

// non-static for test.c
apr_byte_t kap_proto_validate_access_token(request_rec *r, kap_provider_t *provider, apr_jwt_t *jwt, const char *response_type, const char *access_token);
apr_byte_t kap_proto_validate_code(request_rec *r, kap_provider_t *provider, apr_jwt_t *jwt, const char *response_type, const char *code);
apr_byte_t kap_proto_validate_nonce(request_rec *r, kap_cfg *cfg, kap_provider_t *provider, const char *nonce, apr_jwt_t *jwt);

// kap_authz.c
int kap_authz_worker(request_rec *r, const json_t *const claims, const require_line *const reqs, int nelts);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
authz_status kap_authz_worker24(request_rec *r, const json_t * const claims, const char *require_line);
#endif

// kap_config.c
void *kap_create_server_config(apr_pool_t *pool, server_rec *svr);
void *kap_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD);
void *kap_create_dir_config(apr_pool_t *pool, char *path);
void *kap_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD);
void kap_register_hooks(apr_pool_t *pool);

// kap_util.c
int kap_strnenvcmp(const char *a, const char *b, int len);
int kap_base64url_encode(request_rec *r, char **dst, const char *src, int src_len, int remove_padding);
int kap_base64url_decode(request_rec *r, char **dst, const char *src);
int kap_encrypt_base64url_encode_string(request_rec *r, char **dst, const char *src);
int kap_base64url_decode_decrypt_string(request_rec *r, char **dst, const char *src);
char *kap_get_current_url(const request_rec *r, const kap_cfg *c);
char *kap_url_encode(const request_rec *r, const char *str, const char *charsToEncode);
char *kap_normalize_header_name(const request_rec *r, const char *str);

void kap_util_set_cookie(request_rec *r, const char *cookieName, const char *cookieValue, apr_time_t expires);
char *kap_util_get_cookie(request_rec *r, const char *cookieName);
apr_byte_t kap_util_http_get(request_rec *r, const char *url, const apr_table_t *params, const char *basic_auth, const char *bearer_token, int ssl_validate_server, const char **response, int timeout, const char *outgoing_proxy, apr_array_header_t *pass_cookies);
apr_byte_t kap_util_http_post_form(request_rec *r, const char *url, const apr_table_t *params, const char *basic_auth, const char *bearer_token, int ssl_validate_server, const char **response, int timeout, const char *outgoing_proxy, apr_array_header_t *pass_cookies);
apr_byte_t kap_util_http_post_json(request_rec *r, const char *url, const json_t *data, const char *basic_auth, const char *bearer_token, int ssl_validate_server, const char **response, int timeout, const char *outgoing_proxy, apr_array_header_t *pass_cookies);
apr_byte_t kap_util_request_matches_url(request_rec *r, const char *url);
apr_byte_t kap_util_request_has_parameter(request_rec *r, const char* param);
apr_byte_t kap_util_get_request_parameter(request_rec *r, char *name, char **value);
apr_byte_t kap_util_decode_json_and_check_error(request_rec *r, const char *str, json_t **json);
int kap_util_http_send(request_rec *r, const char *data, int data_len, const char *content_type, int success_rvalue);
int kap_util_html_send(request_rec *r, const char *title, const char *html_head, const char *on_load, const char *html_body, int status_code);
char *kap_util_escape_string(const request_rec *r, const char *str);
char *kap_util_unescape_string(const request_rec *r, const char *str);
apr_byte_t kap_util_read_form_encoded_params(request_rec *r, apr_table_t *table, const char *data);
apr_byte_t kap_util_read_post_params(request_rec *r, apr_table_t *table);
apr_byte_t kap_util_file_read(request_rec *r, const char *path, char **result);
apr_byte_t kap_util_issuer_match(const char *a, const char *b);
int kap_util_html_send_error(request_rec *r, const char *error, const char *description, int status_code);
apr_byte_t kap_util_json_array_has_value(request_rec *r, json_t *haystack, const char *needle);
void kap_util_set_app_info(request_rec *r, const char *s_key, const char *s_value, const char *claim_prefix, apr_byte_t as_header, apr_byte_t as_env_var);
void kap_util_set_app_infos(request_rec *r, const json_t *j_attrs, const char *claim_prefix, const char *claim_delimiter, apr_byte_t as_header, apr_byte_t as_env_var);
apr_hash_t *kap_util_spaced_string_to_hashtable(apr_pool_t *pool, const char *str);
apr_byte_t kap_util_spaced_string_equals(apr_pool_t *pool, const char *a, const char *b);
apr_byte_t kap_util_spaced_string_contains(apr_pool_t *pool, const char *response_type, const char *match);
apr_byte_t kap_json_object_get_string(apr_pool_t *pool, json_t *json, const char *name, char **value, const char *default_value);
apr_byte_t kap_json_object_get_int(apr_pool_t *pool, json_t *json, const char *name, int *value, const int default_value);
char *kap_util_html_escape(apr_pool_t *pool, const char *input);
void kap_util_table_add_query_encoded_params(apr_pool_t *pool, apr_table_t *table, const char *params);
apr_hash_t * kap_util_merge_symmetric_key(apr_pool_t *pool, apr_hash_t *private_keys, const char *secret, const char *hash_algo);
apr_hash_t * kap_util_merge_key_sets(apr_pool_t *pool, apr_hash_t *k1, apr_hash_t *k2);
apr_byte_t kap_util_regexp_first_match(apr_pool_t *pool, const char *input, const char *regexp, char **output, char **error_str);
apr_byte_t kap_util_json_merge(json_t *src, json_t *dst);

// kap_crypto.c
unsigned char *kap_crypto_aes_encrypt(request_rec *r, kap_cfg *cfg, unsigned char *plaintext, int *len);
unsigned char *kap_crypto_aes_decrypt(request_rec *r, kap_cfg *cfg, unsigned char *ciphertext, int *len);
apr_byte_t kap_crypto_destroy(kap_cfg *cfg, server_rec *s);

// kap_metadata.c
apr_byte_t kap_metadata_provider_retrieve(request_rec *r, kap_cfg *cfg, const char *issuer, const char *url, json_t **j_metadata, const char **response);
apr_byte_t kap_metadata_provider_parse(request_rec *r, json_t *j_provider, kap_provider_t *provider);
apr_byte_t kap_metadata_list(request_rec *r, kap_cfg *cfg, apr_array_header_t **arr);
apr_byte_t kap_metadata_get(request_rec *r, kap_cfg *cfg, const char *selected, kap_provider_t **provider);
apr_byte_t kap_metadata_jwks_get(request_rec *r, kap_cfg *cfg, const kap_jwks_uri_t *jwks_uri, json_t **j_jwks, apr_byte_t *refresh);

// kap_session.c
#if MODULE_MAGIC_NUMBER_MAJOR_NOT_WORKING_YET >= 20081201
// this stuff should make it easy to migrate to the post 2.3 mod_session infrastructure
#include "mod_session.h"
//#define KAP_SESSION_USE_APACHE_SESSIONS 1
#else
typedef struct {
    apr_pool_t *pool;             /* pool to be used for this session */
    apr_uuid_t *uuid;             /* anonymous uuid of this particular session */
    const char *remote_user;      /* user who owns this particular session */
    apr_table_t *entries;         /* key value pairs */
    const char *encoded;          /* the encoded version of the key value pairs */
    apr_time_t expiry;            /* if > 0, the time of expiry of this session */
    long maxage;                  /* if > 0, the maxage of the session, from
                                   * which expiry is calculated */
    int dirty;                    /* dirty flag */
    int cached;                   /* true if this session was loaded from a
                                   * cache of some kind */
    int written;                  /* true if this session has already been
                                   * written */
} session_rec;
#endif

apr_status_t kap_session_init();
apr_status_t kap_session_load(request_rec *r, session_rec **z);
apr_status_t kap_session_get(request_rec *r, session_rec *z, const char *key, const char **value);
apr_status_t kap_session_set(request_rec *r, session_rec *z, const char *key, const char *value);
apr_status_t kap_session_save(request_rec *r, session_rec *z);
apr_status_t kap_session_kill(request_rec *r, session_rec *z);

#endif /* MOD_AUTH_KAP_H_ */
