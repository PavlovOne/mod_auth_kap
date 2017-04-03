/*
 * Copyright (C) 2017 Kapstonellc (http://www.kapstonellc.com)
 *
 * Created by Pavlov <pavlov0123@outlook.com>
 * 
 */

#include <apr.h>
#include <apr_errno.h>
#include <apr_strings.h>
#include <apr_portable.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>
#include <ap_provider.h>

#include <curl/curl.h>

#include "mod_auth_kap.h"

#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#include <openssl/opensslv.h>
#if (OPENSSL_VERSION_NUMBER < 0x01000000)
#define OPENSSL_NO_THREADID
#endif

/* validate SSL server certificates by default */
#define KAP_DEFAULT_SSL_VALIDATE_SERVER 1
/* default scope requested from the OP */
#define KAP_DEFAULT_SCOPE "openid"
/* default claim delimiter for multi-valued claims passed in a HTTP header */
#define KAP_DEFAULT_CLAIM_DELIMITER ","
/* default prefix for claim names being passed in HTTP headers */
#define KAP_DEFAULT_CLAIM_PREFIX "KAP_CLAIM_"
/* default name for the claim that will contain the REMOTE_USER value for OpenID Connect protected paths */
#define KAP_DEFAULT_CLAIM_REMOTE_USER "sub@"
/* default name for the claim that will contain the REMOTE_USER value for OAuth 2.0 protected paths */
#define KAP_DEFAULT_OAUTH_CLAIM_REMOTE_USER "sub"
/* default name of the session cookie */
#define KAP_DEFAULT_COOKIE "mod_auth_kap_session"
/* default for the HTTP header name in which the remote user name is passed */
#define KAP_DEFAULT_AUTHN_HEADER NULL
/* scrub HTTP headers by default unless overridden (and insecure) */
#define KAP_DEFAULT_SCRUB_REQUEST_HEADERS 1
/* default client_name the client uses for dynamic client registration */
#define KAP_DEFAULT_CLIENT_NAME "OpenID Connect Apache Module (mod_auth_kap)"
/* timeouts in seconds for HTTP calls that may take a long time */
#define KAP_DEFAULT_HTTP_TIMEOUT_LONG  60
/* timeouts in seconds for HTTP calls that should take a short time (registry/discovery related) */
#define KAP_DEFAULT_HTTP_TIMEOUT_SHORT  5
/* default session storage type */
#define KAP_DEFAULT_SESSION_TYPE KAP_SESSION_TYPE_22_SERVER_CACHE
/* timeout in seconds after which state expires */
#define KAP_DEFAULT_STATE_TIMEOUT 300
/* default session inactivity timeout */
#define KAP_DEFAULT_SESSION_INACTIVITY_TIMEOUT 300
/* default session max duration */
#define KAP_DEFAULT_SESSION_MAX_DURATION 3600 * 8
/* default OpenID Connect authorization response type */
#define KAP_DEFAULT_RESPONSE_TYPE "code"
/* default duration in seconds after which retrieved JWS should be refreshed */
#define KAP_DEFAULT_JWKS_REFRESH_INTERVAL 3600
/* default max cache size for shm */
#define KAP_DEFAULT_CACHE_SHM_SIZE 500
/* default max cache entry size for shm: # value + # key + # overhead */
#define KAP_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX 16384 + 512 + 17
/* minimum size of a cache entry */
#define KAP_MINIMUM_CACHE_SHM_ENTRY_SIZE_MAX 8192 + 512 + 17
/* for issued-at timestamp (iat) checking */
#define KAP_DEFAULT_IDTOKEN_IAT_SLACK 600
/* for file-based caching: clean interval in seconds */
#define KAP_DEFAULT_CACHE_FILE_CLEAN_INTERVAL 60
/* set httponly flag on cookies */
#define KAP_DEFAULT_COOKIE_HTTPONLY 1
/* default cookie path */
#define KAP_DEFAULT_COOKIE_PATH "/"
/* default OAuth 2.0 introspection token parameter name */
#define KAP_DEFAULT_OAUTH_TOKEN_PARAM_NAME "token"
/* default OAuth 2.0 introspection call HTTP method */
#define KAP_DEFAULT_OAUTH_ENDPOINT_METHOD "POST"
/* default OAuth 2.0 non-spec compliant introspection expiry claim name */
#define KAP_DEFAULT_OAUTH_EXPIRY_CLAIM_NAME "expires_in"
/* default OAuth 2.0 non-spec compliant introspection expiry claim format */
#define KAP_DEFAULT_OAUTH_EXPIRY_CLAIM_FORMAT "relative"
/* default OAuth 2.0 non-spec compliant introspection expiry claim required */
#define KAP_DEFAULT_OAUTH_EXPIRY_CLAIM_REQUIRED TRUE

/*
 * set a boolean value in the server config
 */
static const char *kap_set_flag_slot(cmd_parms *cmd, void *struct_ptr, int arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);
	return ap_set_flag_slot(cmd, cfg, arg);
}

/*
 * set a string value in the server config
 */
static const char *kap_set_string_slot(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);
	return ap_set_string_slot(cmd, cfg, arg);
}

/*
 * set an integer value in the server config
 */
static const char *kap_set_int_slot(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);
	return ap_set_int_slot(cmd, cfg, arg);
}

/*
 * set a URL value in a config record
 */
static const char *kap_set_url_slot_type(cmd_parms *cmd, void *ptr,
		const char *arg, const char *type) {
	apr_uri_t url;
	if (apr_uri_parse(cmd->pool, arg, &url) != APR_SUCCESS) {
		return apr_psprintf(cmd->pool,
				"kap_set_url_slot_type: configuration value '%s' could not be parsed as a URL!",
				arg);
	}

	if (url.scheme == NULL) {
		return apr_psprintf(cmd->pool,
				"kap_set_url_slot_type: configuration value '%s' could not be parsed as a URL (no scheme set)!",
				arg);
	}

	if (type == NULL) {
		if ((apr_strnatcmp(url.scheme, "http") != 0)
				&& (apr_strnatcmp(url.scheme, "https") != 0)) {
			return apr_psprintf(cmd->pool,
					"kap_set_url_slot_type: configuration value '%s' could not be parsed as a HTTP/HTTPs URL (scheme != http/https)!",
					arg);
		}
	} else if (apr_strnatcmp(url.scheme, type) != 0) {
		return apr_psprintf(cmd->pool,
				"kap_set_url_slot_type: configuration value '%s' could not be parsed as a \"%s\" URL (scheme == %s != \"%s\")!",
				arg, type, url.scheme, type);
	}

	if (url.hostname == NULL) {
		return apr_psprintf(cmd->pool,
				"kap_set_url_slot_type: configuration value '%s' could not be parsed as a HTTP/HTTPs URL (no hostname set, check your slashes)!",
				arg);
	}
	return ap_set_string_slot(cmd, ptr, arg);
}

/*
 * set a HTTPS value in the server config
 */
static const char *kap_set_https_slot(cmd_parms *cmd, void *ptr,
		const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);
	return kap_set_url_slot_type(cmd, cfg, arg, "https");
}

/*
 * set a HTTPS/HTTP value in the server config
 */
static const char *kap_set_url_slot(cmd_parms *cmd, void *ptr, const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);
	return kap_set_url_slot_type(cmd, cfg, arg, NULL);
}

/*
 * set a HTTPS/HTTP value in the directory config
 */
static const char *kap_set_url_slot_dir_cfg(cmd_parms *cmd, void *ptr,
		const char *arg) {
	return kap_set_url_slot_type(cmd, ptr, arg, NULL);
}

/*
 * set a directory value in the server config
 */
// TODO: it's not really a syntax error... (could be fixed at runtime but then we'd have to restart the server)
static const char *kap_set_dir_slot(cmd_parms *cmd, void *ptr, const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);

	char s_err[128];
	apr_dir_t *dir;
	apr_status_t rc = APR_SUCCESS;

	/* ensure the directory exists */
	if ((rc = apr_dir_open(&dir, arg, cmd->pool)) != APR_SUCCESS) {
		return apr_psprintf(cmd->pool,
				"kap_set_dir_slot: could not access directory '%s' (%s)", arg,
				apr_strerror(rc, s_err, sizeof(s_err)));
	}

	/* and cleanup... */
	if ((rc = apr_dir_close(dir)) != APR_SUCCESS) {
		return apr_psprintf(cmd->pool,
				"kap_set_dir_slot: could not close directory '%s' (%s)", arg,
				apr_strerror(rc, s_err, sizeof(s_err)));
	}

	return ap_set_string_slot(cmd, cfg, arg);
}

/*
 * set the cookie domain in the server config and check it syntactically
 */
static const char *kap_set_cookie_domain(cmd_parms *cmd, void *ptr,
		const char *value) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);
	size_t sz, limit;
	char d;
	limit = strlen(value);
	for (sz = 0; sz < limit; sz++) {
		d = value[sz];
		if ((d < '0' || d > '9') && (d < 'a' || d > 'z') && (d < 'A' || d > 'Z')
				&& d != '.' && d != '-') {
			return (apr_psprintf(cmd->pool,
					"kap_set_cookie_domain: invalid character (%c) in %s",
					d, cmd->directive->directive));
		}
	}
	cfg->cookie_domain = apr_pstrdup(cmd->pool, value);
	return NULL;
}

/*
 * set the session storage type
 */
static const char *kap_set_session_type(cmd_parms *cmd, void *ptr,
		const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);

	if (apr_strnatcmp(arg, "server-cache") == 0) {
		cfg->session_type = KAP_SESSION_TYPE_22_SERVER_CACHE;
	} else if (apr_strnatcmp(arg, "client-cookie") == 0) {
		cfg->session_type = KAP_SESSION_TYPE_22_CLIENT_COOKIE;
	} else {
		return (apr_psprintf(cmd->pool,
				"kap_set_session_type: invalid value for %s (%s); must be one of \"server-cache\" or \"client-cookie\"",
				cmd->directive->directive, arg));
	}

	return NULL;
}

/*
 * set the maximum size of a shared memory cache entry and enforces a minimum
 */
static const char *kap_set_cache_shm_entry_size_max(cmd_parms *cmd, void *ptr,
		const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);

	char *endptr;
	int v = strtol(arg, &endptr, 10);
	if ((*arg == '\0') || (*endptr != '\0')) {
		return apr_psprintf(cmd->pool,
				"Invalid value for directive %s, expected integer",
				cmd->directive->directive);
	}
	cfg->cache_shm_entry_size_max =
			v > KAP_MINIMUM_CACHE_SHM_ENTRY_SIZE_MAX ?
					v : KAP_MINIMUM_CACHE_SHM_ENTRY_SIZE_MAX;

	return NULL;
}

/*
 * set the cache type
 */
static const char *kap_set_cache_type(cmd_parms *cmd, void *ptr,
		const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);

	if (apr_strnatcmp(arg, "file") == 0) {
		cfg->cache = &kap_cache_file;
	} else if (apr_strnatcmp(arg, "memcache") == 0) {
		cfg->cache = &kap_cache_memcache;
	} else if (apr_strnatcmp(arg, "shm") == 0) {
		cfg->cache = &kap_cache_shm;
#ifdef USE_LIBHIREDIS
	} else if (apr_strnatcmp(arg, "redis") == 0) {
		cfg->cache = &kap_cache_redis;
#endif
	} else {
		return (apr_psprintf(cmd->pool,
#ifdef USE_LIBHIREDIS
				"kap_set_cache_type: invalid value for %s (%s); must be one of \"shm\", \"memcache\", \"redis\" or \"file\"",
				cmd->directive->directive, arg));
#else
				"kap_set_cache_type: invalid value for %s (%s); must be one of \"shm\", \"memcache\" or \"file\"",
				cmd->directive->directive, arg));
#endif
	}

	return NULL;
}

/*
 * set an authentication method for an endpoint and check it is one that we support
 */
static const char *kap_set_endpoint_auth_slot(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);

	if ((apr_strnatcmp(arg, "client_secret_post") == 0)
			|| (apr_strnatcmp(arg, "client_secret_basic") == 0)) {

		return ap_set_string_slot(cmd, cfg, arg);
	}
	return "parameter must be 'client_secret_post' or 'client_secret_basic'";
}

/*
 * set the response type used
 */
static const char *kap_set_response_type(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);

	if (kap_proto_flow_is_supported(cmd->pool, arg)) {
		return ap_set_string_slot(cmd, cfg, arg);
	}

	return apr_psprintf(cmd->pool, "parameter must be one of %s",
			apr_array_pstrcat(cmd->pool, kap_proto_supported_flows(cmd->pool),
					'|'));
}

/*
 * set the response mode used
 */
static const char *kap_set_response_mode(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);

	if ((apr_strnatcmp(arg, "fragment") == 0)
			|| (apr_strnatcmp(arg, "query") == 0)
			|| (apr_strnatcmp(arg, "form_post") == 0)) {

		return ap_set_string_slot(cmd, cfg, arg);
	}
	return "parameter must be 'fragment', 'query' or 'form_post'";
}

/*
 * set the signing algorithm to be used by the OP (id_token/user_info)
 */
static const char *kap_set_signed_response_alg(cmd_parms *cmd,
		void *struct_ptr, const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);

	if (apr_jws_algorithm_is_supported(cmd->pool, arg)) {
		return ap_set_string_slot(cmd, cfg, arg);
	}

	return apr_psprintf(cmd->pool, "parameter must be one of %s",
			apr_array_pstrcat(cmd->pool,
					apr_jws_supported_algorithms(cmd->pool), '|'));
}

/*
 * set the Content Encryption Key encryption algorithm to be used by the OP (id_token/user_info)
 */
static const char *kap_set_encrypted_response_alg(cmd_parms *cmd,
		void *struct_ptr, const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);

	if (apr_jwe_algorithm_is_supported(cmd->pool, arg)) {
		return ap_set_string_slot(cmd, cfg, arg);
	}

	return apr_psprintf(cmd->pool, "parameter must be one of %s",
			apr_array_pstrcat(cmd->pool,
					apr_jwe_supported_algorithms(cmd->pool), '|'));
}

/*
 * set the content encryption algorithm to be used by the OP (id_token/user_info)
 */
static const char *kap_set_encrypted_response_enc(cmd_parms *cmd,
		void *struct_ptr, const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);

	if (apr_jwe_encryption_is_supported(cmd->pool, arg)) {
		return ap_set_string_slot(cmd, cfg, arg);
	}

	return apr_psprintf(cmd->pool, "parameter must be one of %s",
			apr_array_pstrcat(cmd->pool,
					apr_jwe_supported_encryptions(cmd->pool), '|'));
}

/*
 * set the session inactivity timeout
 */
static const char *kap_set_session_inactivity_timeout(cmd_parms *cmd,
		void *struct_ptr, const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);
	char *endptr = NULL;
	long n = strtol(arg, &endptr, 10);
	if ((*arg == '\0') || (*endptr != '\0')) {
		return apr_psprintf(cmd->pool,
				"Invalid value for directive %s, expected integer",
				cmd->directive->directive);
	}
	if (n < 10) {
		return apr_psprintf(cmd->pool,
				"Invalid value for directive %s, must not be less than 10 seconds",
				cmd->directive->directive);
	}
	if (n > 86400) {
		return apr_psprintf(cmd->pool,
				"Invalid value for directive %s, must not be greater than 86400 seconds (24 hours)",
				cmd->directive->directive);
	}
	cfg->session_inactivity_timeout = n;
	return NULL;
}

/*
 * set the maximum session duration; 0 means take it from the ID token expiry time
 */
static const char *kap_set_session_max_duration(cmd_parms *cmd,
		void *struct_ptr, const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);
	char *endptr = NULL;
	long n = strtol(arg, &endptr, 10);
	if ((*arg == '\0') || (*endptr != '\0')) {
		return apr_psprintf(cmd->pool,
				"Invalid value for directive %s, expected integer",
				cmd->directive->directive);
	}
	if (n == 0) {
		cfg->provider.session_max_duration = 0;
		return NULL;
	}
	if (n < 300) {
		return apr_psprintf(cmd->pool,
				"Invalid value for directive %s, must not be less than 5 minutes (300 seconds)",
				cmd->directive->directive);
	}
	if (n > 86400 * 365) {
		return apr_psprintf(cmd->pool,
				"Invalid value for directive %s, must not be greater than 1 year (31536000 seconds)",
				cmd->directive->directive);
	}
	cfg->provider.session_max_duration = n;
	return NULL;
}

/*
 * add a public key from an X.509 file to our list of JWKs with public keys
 */
static const char *kap_set_public_key_files(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	apr_jwk_t *jwk = NULL;
	apr_jwt_error_t err;

	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);

	int offset = (int) (long) cmd->info;
	apr_hash_t **public_keys = (apr_hash_t **) ((char *) cfg + offset);

	if (apr_jwk_parse_rsa_public_key(cmd->pool, arg, &jwk, &err) == FALSE) {
		return apr_psprintf(cmd->pool,
				"apr_jwk_parse_rsa_public_key failed for \"%s\": %s", arg,
				apr_jwt_e2s(cmd->pool, err));
	}

	if (*public_keys == NULL)
		*public_keys = apr_hash_make(cmd->pool);
	apr_hash_set(*public_keys, jwk->kid, APR_HASH_KEY_STRING, jwk);

	return NULL;
}

/*
 * add a shared key to a list of JWKs with shared keys
 */
static const char *kap_set_shared_keys(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);
	int offset = (int) (long) cmd->info;
	apr_hash_t **shared_keys = (apr_hash_t **) ((char *) cfg + offset);
	*shared_keys = kap_util_merge_symmetric_key(cmd->pool, *shared_keys, arg,
			NULL);
	return NULL;
}

/*
 * add a private key from an RSA private key file to our list of JWKs with private keys
 */
static const char *kap_set_private_key_files_enc(cmd_parms *cmd, void *dummy,
		const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);
	apr_jwk_t *jwk = NULL;
	apr_jwt_error_t err;

	if (apr_jwk_parse_rsa_private_key(cmd->pool, arg, &jwk, &err) == FALSE) {
		return apr_psprintf(cmd->pool,
				"apr_jwk_parse_rsa_private_key failed for \"%s\": %s", arg,
				apr_jwt_e2s(cmd->pool, err));
	}

	if (cfg->private_keys == NULL)
		cfg->private_keys = apr_hash_make(cmd->pool);
	apr_hash_set(cfg->private_keys, jwk->kid, APR_HASH_KEY_STRING, jwk);
	return NULL;
}

static int kap_pass_idtoken_as_str2int(const char *v) {
	if (apr_strnatcmp(v, "claims") == 0)
		return KAP_PASS_IDTOKEN_AS_CLAIMS;
	if (apr_strnatcmp(v, "payload") == 0)
		return KAP_PASS_IDTOKEN_AS_PAYLOAD;
	if (apr_strnatcmp(v, "serialized") == 0)
		return KAP_PASS_IDTOKEN_AS_SERIALIZED;
	return -1;
}

/*
 * define how to pass the id_token/claims in HTTP headers
 */
static const char * kap_set_pass_idtoken_as(cmd_parms *cmd, void *dummy,
		const char *v1, const char *v2, const char *v3) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);

	int b = kap_pass_idtoken_as_str2int(v1);
	if (b != -1) {
		cfg->pass_idtoken_as = b;
	} else {
		return apr_psprintf(cmd->pool, "Invalid value \"%s\" for directive %s",
				v1, cmd->directive->directive);
	}
	if (v2) {
		b = kap_pass_idtoken_as_str2int(v2);
		if (b != -1) {
			cfg->pass_idtoken_as |= b;
		} else {
			return apr_psprintf(cmd->pool,
					"Invalid value \"%s\" for directive %s", v2,
					cmd->directive->directive);
		}
		if (v3) {
			b = kap_pass_idtoken_as_str2int(v3);
			if (b != -1) {
				cfg->pass_idtoken_as |= b;
			} else {
				return apr_psprintf(cmd->pool,
						"Invalid value \"%s\" for directive %s", v3,
						cmd->directive->directive);
			}
		}
	}

	return NULL;
}

/*
 * set the syntax of the token expiry claim in the introspection response
 */
static const char * kap_set_token_expiry_claim(cmd_parms *cmd, void *dummy,
		const char *claim_name, const char *claim_format,
		const char *claim_required) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);

	cfg->oauth.introspection_token_expiry_claim_name = apr_pstrdup(cmd->pool,
			claim_name);

	if (claim_format) {
		if ((apr_strnatcmp(claim_required, "absolute") == 0)
				|| (apr_strnatcmp(claim_required, "relative") == 0)) {
			cfg->oauth.introspection_token_expiry_claim_format = apr_pstrdup(
					cmd->pool, claim_format);
		} else {
			return apr_psprintf(cmd->pool,
					"Invalid value \"%s\" for directive %s; must be either \"absolute\" or \"relative\"",
					claim_required, cmd->directive->directive);
		}
	}

	if (claim_required) {
		if (apr_strnatcmp(claim_required, "mandatory") == 0)
			cfg->oauth.introspection_token_expiry_claim_required = TRUE;
		else if (apr_strnatcmp(claim_required, "optional") == 0) {
			cfg->oauth.introspection_token_expiry_claim_required = FALSE;
		} else {
			return apr_psprintf(cmd->pool,
					"Invalid value \"%s\" for directive %s; must be either \"mandatory\" or \"optional\"",
					claim_required, cmd->directive->directive);
		}
	}

	return NULL;
}

/*
 * specify cookies to pass on to the OP/AS
 */
static const char * kap_set_pass_cookies(cmd_parms *cmd, void *m,
		const char *arg) {
	kap_dir_cfg *dir_cfg = (kap_dir_cfg *) m;
	*(const char**) apr_array_push(dir_cfg->pass_cookies) = arg;
	return NULL;
}

/*
 * set the HTTP method to use in an OAuth 2.0 token introspection/validation call
 */
static const char * kap_set_introspection_method(cmd_parms *cmd, void *m,
		const char *arg) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);

	if ((apr_strnatcmp(arg, "GET") == 0) || (apr_strnatcmp(arg, "POST") == 0)) {
		return ap_set_string_slot(cmd, cfg, arg);
	}

	return "parameter must be 'GET' or 'POST'";
}

/*
 * set the remote user name claims, optionally plus the regular expression applied to it
 */
static const char *kap_set_remote_user_claim(cmd_parms *cmd, void *struct_ptr,
		const char *v1, const char *v2) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(
			cmd->server->module_config, &auth_kap_module);

	int offset = (int) (long) cmd->info;
	kap_remote_user_claim_t *remote_user_claim =
			(kap_remote_user_claim_t *) ((char *) cfg + offset);

	remote_user_claim->claim_name = v1;
	if (v2)
		remote_user_claim->reg_exp = v2;

	return NULL;
}

/*
 * define how to pass claims information to the application: in headers and/or environment variables
 */
static const char * kap_set_pass_claims_as(cmd_parms *cmd, void *m,
		const char *arg) {
	kap_dir_cfg *dir_cfg = (kap_dir_cfg *) m;

	if (apr_strnatcmp(arg, "both") == 0) {
		dir_cfg->pass_info_in_headers = 1;
		dir_cfg->pass_info_in_env_vars = 1;
		return NULL;
	}

	if (apr_strnatcmp(arg, "headers") == 0) {
		dir_cfg->pass_info_in_headers = 1;
		dir_cfg->pass_info_in_env_vars = 0;
		return NULL;
	}

	if (apr_strnatcmp(arg, "environment") == 0) {
		dir_cfg->pass_info_in_headers = 0;
		dir_cfg->pass_info_in_env_vars = 1;
		return NULL;
	}

	if (apr_strnatcmp(arg, "none") == 0) {
		dir_cfg->pass_info_in_headers = 0;
		dir_cfg->pass_info_in_env_vars = 0;
		return NULL;
	}

	return "parameter must be one of 'both', 'headers', 'environment' or 'none";
}

/*
 * create a new server config record with defaults
 */
void *kap_create_server_config(apr_pool_t *pool, server_rec *svr) {
	kap_cfg *c = (kap_cfg *)apr_pcalloc(pool, sizeof(kap_cfg));

	c->merged = FALSE;

	c->redirect_uri = NULL;
	c->default_sso_url = NULL;
	c->default_slo_url = NULL;
	c->public_keys = NULL;
	c->private_keys = NULL;

	c->provider.metadata_url = NULL;
	c->provider.issuer = NULL;
	c->provider.authorization_endpoint_url = NULL;
	c->provider.token_endpoint_url = NULL;
	c->provider.token_endpoint_auth = NULL;
	c->provider.token_endpoint_params = NULL;
	c->provider.userinfo_endpoint_url = NULL;
	c->provider.client_id = NULL;
	c->provider.client_secret = NULL;
	c->provider.registration_endpoint_url = NULL;
	c->provider.registration_endpoint_json = NULL;
	c->provider.check_session_iframe = NULL;
	c->provider.end_session_endpoint = NULL;
	c->provider.jwks_uri = NULL;

	c->provider.ssl_validate_server = KAP_DEFAULT_SSL_VALIDATE_SERVER;
	c->provider.client_name = KAP_DEFAULT_CLIENT_NAME;
	c->provider.client_contact = NULL;
	c->provider.registration_token = NULL;
	c->provider.scope = KAP_DEFAULT_SCOPE;
	c->provider.response_type = KAP_DEFAULT_RESPONSE_TYPE;
	c->provider.response_mode = NULL;
	c->provider.jwks_refresh_interval = KAP_DEFAULT_JWKS_REFRESH_INTERVAL;
	c->provider.idtoken_iat_slack = KAP_DEFAULT_IDTOKEN_IAT_SLACK;
	c->provider.session_max_duration = KAP_DEFAULT_SESSION_MAX_DURATION;
	c->provider.auth_request_params = NULL;

	c->provider.client_jwks_uri = NULL;
	c->provider.id_token_signed_response_alg = NULL;
	c->provider.id_token_encrypted_response_alg = NULL;
	c->provider.id_token_encrypted_response_enc = NULL;
	c->provider.userinfo_signed_response_alg = NULL;
	c->provider.userinfo_encrypted_response_alg = NULL;
	c->provider.userinfo_encrypted_response_enc = NULL;

	c->oauth.ssl_validate_server = KAP_DEFAULT_SSL_VALIDATE_SERVER;
	c->oauth.client_id = NULL;
	c->oauth.client_secret = NULL;
	c->oauth.introspection_endpoint_url = NULL;
	c->oauth.introspection_endpoint_method = KAP_DEFAULT_OAUTH_ENDPOINT_METHOD;
	c->oauth.introspection_endpoint_params = NULL;
	c->oauth.introspection_endpoint_auth = NULL;
	c->oauth.introspection_token_param_name =
			KAP_DEFAULT_OAUTH_TOKEN_PARAM_NAME;

	c->oauth.introspection_token_expiry_claim_name =
			KAP_DEFAULT_OAUTH_EXPIRY_CLAIM_NAME;
	c->oauth.introspection_token_expiry_claim_format =
			KAP_DEFAULT_OAUTH_EXPIRY_CLAIM_FORMAT;
	c->oauth.introspection_token_expiry_claim_required =
			KAP_DEFAULT_OAUTH_EXPIRY_CLAIM_REQUIRED;

	c->oauth.remote_user_claim.claim_name =
			KAP_DEFAULT_OAUTH_CLAIM_REMOTE_USER;
	c->oauth.remote_user_claim.reg_exp = NULL;

	c->oauth.verify_jwks_uri = NULL;
	c->oauth.verify_public_keys = NULL;
	c->oauth.verify_shared_keys = NULL;

	c->cache = &kap_cache_shm;
	c->cache_cfg = NULL;

	c->cache_file_dir = NULL;
	c->cache_file_clean_interval = KAP_DEFAULT_CACHE_FILE_CLEAN_INTERVAL;
	c->cache_memcache_servers = NULL;
	c->cache_shm_size_max = KAP_DEFAULT_CACHE_SHM_SIZE;
	c->cache_shm_entry_size_max = KAP_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX;
#ifdef USE_LIBHIREDIS
	c->cache_redis_server = NULL;
#endif

	c->metadata_dir = NULL;
	c->session_type = KAP_DEFAULT_SESSION_TYPE;

	c->http_timeout_long = KAP_DEFAULT_HTTP_TIMEOUT_LONG;
	c->http_timeout_short = KAP_DEFAULT_HTTP_TIMEOUT_SHORT;
	c->state_timeout = KAP_DEFAULT_STATE_TIMEOUT;
	c->session_inactivity_timeout = KAP_DEFAULT_SESSION_INACTIVITY_TIMEOUT;

	c->cookie_domain = NULL;
	c->claim_delimiter = KAP_DEFAULT_CLAIM_DELIMITER;
	c->claim_prefix = KAP_DEFAULT_CLAIM_PREFIX;
	c->remote_user_claim.claim_name = KAP_DEFAULT_CLAIM_REMOTE_USER;
	c->remote_user_claim.reg_exp = NULL;
	c->pass_idtoken_as = KAP_PASS_IDTOKEN_AS_CLAIMS;
	c->cookie_http_only = KAP_DEFAULT_COOKIE_HTTPONLY;

	c->outgoing_proxy = NULL;
	c->crypto_passphrase = NULL;

	c->scrub_request_headers = KAP_DEFAULT_SCRUB_REQUEST_HEADERS;

	return c;
}

/*
 * merge a new server config with a base one
 */
void *kap_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD) {
	kap_cfg *c = (kap_cfg *)apr_pcalloc(pool, sizeof(kap_cfg));
	kap_cfg *base = (kap_cfg *)BASE;
	kap_cfg *add = (kap_cfg *)ADD;

	c->merged = TRUE;

	c->redirect_uri =
			add->redirect_uri != NULL ? add->redirect_uri : base->redirect_uri;
	c->default_sso_url =
			add->default_sso_url != NULL ?
					add->default_sso_url : base->default_sso_url;
	c->default_slo_url =
			add->default_slo_url != NULL ?
					add->default_slo_url : base->default_slo_url;
	c->public_keys =
			add->public_keys != NULL ? add->public_keys : base->public_keys;
	c->private_keys =
			add->private_keys != NULL ? add->private_keys : base->private_keys;

	c->provider.metadata_url =
			add->provider.metadata_url != NULL ?
					add->provider.metadata_url : base->provider.metadata_url;
	c->provider.issuer =
			add->provider.issuer != NULL ?
					add->provider.issuer : base->provider.issuer;
	c->provider.authorization_endpoint_url =
			add->provider.authorization_endpoint_url != NULL ?
					add->provider.authorization_endpoint_url :
					base->provider.authorization_endpoint_url;
	c->provider.token_endpoint_url =
			add->provider.token_endpoint_url != NULL ?
					add->provider.token_endpoint_url :
					base->provider.token_endpoint_url;
	c->provider.token_endpoint_auth =
			add->provider.token_endpoint_auth != NULL ?
					add->provider.token_endpoint_auth :
					base->provider.token_endpoint_auth;
	c->provider.token_endpoint_params =
			add->provider.token_endpoint_params != NULL ?
					add->provider.token_endpoint_params :
					base->provider.token_endpoint_params;
	c->provider.userinfo_endpoint_url =
			add->provider.userinfo_endpoint_url != NULL ?
					add->provider.userinfo_endpoint_url :
					base->provider.userinfo_endpoint_url;
	c->provider.jwks_uri =
			add->provider.jwks_uri != NULL ?
					add->provider.jwks_uri : base->provider.jwks_uri;
	c->provider.client_id =
			add->provider.client_id != NULL ?
					add->provider.client_id : base->provider.client_id;
	c->provider.client_secret =
			add->provider.client_secret != NULL ?
					add->provider.client_secret : base->provider.client_secret;
	c->provider.registration_endpoint_url =
			add->provider.registration_endpoint_url != NULL ?
					add->provider.registration_endpoint_url :
					base->provider.registration_endpoint_url;
	c->provider.registration_endpoint_json =
			add->provider.registration_endpoint_json != NULL ?
					add->provider.registration_endpoint_json :
					base->provider.registration_endpoint_json;

	c->provider.check_session_iframe =
			add->provider.check_session_iframe != NULL ?
					add->provider.check_session_iframe :
					base->provider.check_session_iframe;
	c->provider.end_session_endpoint =
			add->provider.end_session_endpoint != NULL ?
					add->provider.end_session_endpoint :
					base->provider.end_session_endpoint;

	c->provider.ssl_validate_server =
			add->provider.ssl_validate_server
					!= KAP_DEFAULT_SSL_VALIDATE_SERVER ?
					add->provider.ssl_validate_server :
					base->provider.ssl_validate_server;
	c->provider.client_name =
			apr_strnatcmp(add->provider.client_name, KAP_DEFAULT_CLIENT_NAME)
					!= 0 ?
					add->provider.client_name : base->provider.client_name;
	c->provider.client_contact =
			add->provider.client_contact != NULL ?
					add->provider.client_contact :
					base->provider.client_contact;
	c->provider.registration_token =
			add->provider.registration_token != NULL ?
					add->provider.registration_token :
					base->provider.registration_token;
	c->provider.scope =
			apr_strnatcmp(add->provider.scope, KAP_DEFAULT_SCOPE) != 0 ?
					add->provider.scope : base->provider.scope;
	c->provider.response_type =
			apr_strnatcmp(add->provider.response_type,
					KAP_DEFAULT_RESPONSE_TYPE) != 0 ?
							add->provider.response_type : base->provider.response_type;
	c->provider.response_mode =
			add->provider.response_mode != NULL ?
					add->provider.response_mode : base->provider.response_mode;
	c->provider.jwks_refresh_interval =
			add->provider.jwks_refresh_interval
					!= KAP_DEFAULT_JWKS_REFRESH_INTERVAL ?
					add->provider.jwks_refresh_interval :
					base->provider.jwks_refresh_interval;
	c->provider.idtoken_iat_slack =
			add->provider.idtoken_iat_slack != KAP_DEFAULT_IDTOKEN_IAT_SLACK ?
					add->provider.idtoken_iat_slack :
					base->provider.idtoken_iat_slack;
	c->provider.session_max_duration =
			add->provider.session_max_duration
				!= KAP_DEFAULT_SESSION_MAX_DURATION ?
					add->provider.session_max_duration :
					base->provider.session_max_duration;
	c->provider.auth_request_params =
			add->provider.auth_request_params != NULL ?
					add->provider.auth_request_params :
					base->provider.auth_request_params;

	c->provider.client_jwks_uri =
			add->provider.client_jwks_uri != NULL ?
					add->provider.client_jwks_uri :
					base->provider.client_jwks_uri;
	c->provider.id_token_signed_response_alg =
			add->provider.id_token_signed_response_alg != NULL ?
					add->provider.id_token_signed_response_alg :
					base->provider.id_token_signed_response_alg;
	c->provider.id_token_encrypted_response_alg =
			add->provider.id_token_encrypted_response_alg != NULL ?
					add->provider.id_token_encrypted_response_alg :
					base->provider.id_token_encrypted_response_alg;
	c->provider.id_token_encrypted_response_enc =
			add->provider.id_token_encrypted_response_enc != NULL ?
					add->provider.id_token_encrypted_response_enc :
					base->provider.id_token_encrypted_response_enc;
	c->provider.userinfo_signed_response_alg =
			add->provider.userinfo_signed_response_alg != NULL ?
					add->provider.userinfo_signed_response_alg :
					base->provider.userinfo_signed_response_alg;
	c->provider.userinfo_encrypted_response_alg =
			add->provider.userinfo_encrypted_response_alg != NULL ?
					add->provider.userinfo_encrypted_response_alg :
					base->provider.userinfo_encrypted_response_alg;
	c->provider.userinfo_encrypted_response_enc =
			add->provider.userinfo_encrypted_response_enc != NULL ?
					add->provider.userinfo_encrypted_response_enc :
					base->provider.userinfo_encrypted_response_enc;

	c->oauth.ssl_validate_server =
			add->oauth.ssl_validate_server != KAP_DEFAULT_SSL_VALIDATE_SERVER ?
					add->oauth.ssl_validate_server :
					base->oauth.ssl_validate_server;
	c->oauth.client_id =
			add->oauth.client_id != NULL ?
					add->oauth.client_id : base->oauth.client_id;
	c->oauth.client_secret =
			add->oauth.client_secret != NULL ?
					add->oauth.client_secret : base->oauth.client_secret;
	c->oauth.introspection_endpoint_url =
			add->oauth.introspection_endpoint_url != NULL ?
					add->oauth.introspection_endpoint_url :
					base->oauth.introspection_endpoint_url;
	c->oauth.introspection_endpoint_method =
			apr_strnatcmp(add->oauth.introspection_endpoint_method,
					KAP_DEFAULT_OAUTH_ENDPOINT_METHOD) != 0 ?
							add->oauth.introspection_endpoint_method :
							base->oauth.introspection_endpoint_method;
	c->oauth.introspection_endpoint_params =
			add->oauth.introspection_endpoint_params != NULL ?
					add->oauth.introspection_endpoint_params :
					base->oauth.introspection_endpoint_params;
	c->oauth.introspection_endpoint_auth =
			add->oauth.introspection_endpoint_auth != NULL ?
					add->oauth.introspection_endpoint_auth :
					base->oauth.introspection_endpoint_auth;
	c->oauth.introspection_token_param_name =
			apr_strnatcmp(add->oauth.introspection_token_param_name,
					KAP_DEFAULT_OAUTH_TOKEN_PARAM_NAME) != 0 ?
							add->oauth.introspection_token_param_name :
							base->oauth.introspection_token_param_name;

	c->oauth.introspection_token_expiry_claim_name =
			apr_strnatcmp(add->oauth.introspection_token_expiry_claim_name,
					KAP_DEFAULT_OAUTH_EXPIRY_CLAIM_NAME) != 0 ?
							add->oauth.introspection_token_expiry_claim_name :
							base->oauth.introspection_token_expiry_claim_name;
	c->oauth.introspection_token_expiry_claim_format =
			apr_strnatcmp(add->oauth.introspection_token_expiry_claim_format,
					KAP_DEFAULT_OAUTH_EXPIRY_CLAIM_FORMAT) != 0 ?
							add->oauth.introspection_token_expiry_claim_format :
							base->oauth.introspection_token_expiry_claim_format;
	c->oauth.introspection_token_expiry_claim_required =
			add->oauth.introspection_token_expiry_claim_required
			!= KAP_DEFAULT_OAUTH_EXPIRY_CLAIM_REQUIRED ?
					add->oauth.introspection_token_expiry_claim_required :
					base->oauth.introspection_token_expiry_claim_required;

	c->oauth.remote_user_claim.claim_name =
			apr_strnatcmp(add->oauth.remote_user_claim.claim_name,
					KAP_DEFAULT_OAUTH_CLAIM_REMOTE_USER) != 0 ?
							add->oauth.remote_user_claim.claim_name :
							base->oauth.remote_user_claim.claim_name;
	c->oauth.remote_user_claim.reg_exp =
			add->oauth.remote_user_claim.reg_exp != NULL ?
					add->oauth.remote_user_claim.reg_exp :
					base->oauth.remote_user_claim.reg_exp;

	c->oauth.verify_jwks_uri =
			add->oauth.verify_jwks_uri != NULL ?
					add->oauth.verify_jwks_uri : base->oauth.verify_jwks_uri;
	c->oauth.verify_public_keys =
			add->oauth.verify_public_keys != NULL ?
					add->oauth.verify_public_keys :
					base->oauth.verify_public_keys;
	c->oauth.verify_shared_keys =
			add->oauth.verify_shared_keys != NULL ?
					add->oauth.verify_shared_keys :
					base->oauth.verify_shared_keys;

	c->http_timeout_long =
			add->http_timeout_long != KAP_DEFAULT_HTTP_TIMEOUT_LONG ?
					add->http_timeout_long : base->http_timeout_long;
	c->http_timeout_short =
			add->http_timeout_short != KAP_DEFAULT_HTTP_TIMEOUT_SHORT ?
					add->http_timeout_short : base->http_timeout_short;
	c->state_timeout =
			add->state_timeout != KAP_DEFAULT_STATE_TIMEOUT ?
					add->state_timeout : base->state_timeout;
	c->session_inactivity_timeout =
			add->session_inactivity_timeout
					!= KAP_DEFAULT_SESSION_INACTIVITY_TIMEOUT ?
					add->session_inactivity_timeout :
					base->session_inactivity_timeout;

	if (add->cache != &kap_cache_shm) {
		c->cache = add->cache;
	} else {
		c->cache = base->cache;
	}
	c->cache_cfg = NULL;

	c->cache_file_dir =
			add->cache_file_dir != NULL ?
					add->cache_file_dir : base->cache_file_dir;
	c->cache_file_clean_interval =
			add->cache_file_clean_interval
					!= KAP_DEFAULT_CACHE_FILE_CLEAN_INTERVAL ?
					add->cache_file_clean_interval :
					base->cache_file_clean_interval;

	c->cache_memcache_servers =
			add->cache_memcache_servers != NULL ?
					add->cache_memcache_servers : base->cache_memcache_servers;
	c->cache_shm_size_max =
			add->cache_shm_size_max != KAP_DEFAULT_CACHE_SHM_SIZE ?
					add->cache_shm_size_max : base->cache_shm_size_max;
	c->cache_shm_entry_size_max =
			add->cache_shm_entry_size_max != KAP_DEFAULT_CACHE_SHM_ENTRY_SIZE_MAX ?
					add->cache_shm_entry_size_max : base->cache_shm_entry_size_max;

#ifdef USE_LIBHIREDIS
	c->cache_redis_server =
			add->cache_redis_server != NULL ?
					add->cache_redis_server : base->cache_redis_server;
#endif

	c->metadata_dir =
			add->metadata_dir != NULL ? add->metadata_dir : base->metadata_dir;
	c->session_type =
			add->session_type != KAP_DEFAULT_SESSION_TYPE ?
					add->session_type : base->session_type;

	c->cookie_domain =
			add->cookie_domain != NULL ?
					add->cookie_domain : base->cookie_domain;
	c->claim_delimiter =
			apr_strnatcmp(add->claim_delimiter, KAP_DEFAULT_CLAIM_DELIMITER)
					!= 0 ? add->claim_delimiter : base->claim_delimiter;
	c->claim_prefix =
			apr_strnatcmp(add->claim_prefix, KAP_DEFAULT_CLAIM_PREFIX) != 0 ?
					add->claim_prefix : base->claim_prefix;
	c->remote_user_claim.claim_name =
			apr_strnatcmp(add->remote_user_claim.claim_name,
					KAP_DEFAULT_CLAIM_REMOTE_USER) != 0 ?
							add->remote_user_claim.claim_name :
							base->remote_user_claim.claim_name;
	c->remote_user_claim.reg_exp =
			add->remote_user_claim.reg_exp != NULL ?
					add->remote_user_claim.reg_exp :
					base->remote_user_claim.reg_exp;
	c->pass_idtoken_as =
			add->pass_idtoken_as != KAP_PASS_IDTOKEN_AS_CLAIMS ?
					add->pass_idtoken_as : base->pass_idtoken_as;
	c->cookie_http_only =
			add->cookie_http_only != KAP_DEFAULT_COOKIE_HTTPONLY ?
					add->cookie_http_only : base->cookie_http_only;

	c->outgoing_proxy =
			add->outgoing_proxy != NULL ?
					add->outgoing_proxy : base->outgoing_proxy;

	c->crypto_passphrase =
			add->crypto_passphrase != NULL ?
					add->crypto_passphrase : base->crypto_passphrase;

	c->scrub_request_headers =
			add->scrub_request_headers != KAP_DEFAULT_SCRUB_REQUEST_HEADERS ?
					add->scrub_request_headers : base->scrub_request_headers;

	return c;
}

/*
 * create a new directory config record with defaults
 */
void *kap_create_dir_config(apr_pool_t *pool, char *path) {
	kap_dir_cfg *c = (kap_dir_cfg *)apr_pcalloc(pool, sizeof(kap_dir_cfg));
	c->discover_url = NULL;
	c->cookie = KAP_DEFAULT_COOKIE;
	c->cookie_path = KAP_DEFAULT_COOKIE_PATH;
	c->authn_header = KAP_DEFAULT_AUTHN_HEADER;
	c->return401 = FALSE;
	c->pass_cookies = apr_array_make(pool, 0, sizeof(const char *));
	c->pass_info_in_headers = 1;
	c->pass_info_in_env_vars = 1;
	return (c);
}

/*
 * merge a new directory config with a base one
 */
void *kap_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD) {
	kap_dir_cfg *c = (kap_dir_cfg *)apr_pcalloc(pool, sizeof(kap_dir_cfg));
	kap_dir_cfg *base = (kap_dir_cfg *)BASE;
	kap_dir_cfg *add = (kap_dir_cfg *)ADD;
	c->discover_url =
			add->discover_url != NULL ? add->discover_url : base->discover_url;
	c->cookie = (
			apr_strnatcasecmp(add->cookie, KAP_DEFAULT_COOKIE) != 0 ?
					add->cookie : base->cookie);
	c->cookie_path = (
			apr_strnatcasecmp(add->cookie_path, KAP_DEFAULT_COOKIE_PATH) != 0 ?
					add->cookie_path : base->cookie_path);
	c->authn_header = (
			add->authn_header != KAP_DEFAULT_AUTHN_HEADER ?
					add->authn_header : base->authn_header);
	c->return401 = (add->return401 != FALSE ? add->return401 : base->return401);
	c->pass_cookies = (
			apr_is_empty_array(add->pass_cookies) != 0 ?
					add->pass_cookies : base->pass_cookies);
	c->pass_info_in_headers = (
			add->pass_info_in_headers != 1 ?
					add->pass_info_in_headers : base->pass_info_in_headers);
	c->pass_info_in_env_vars = (
			add->pass_info_in_env_vars != 1 ?
					add->pass_info_in_env_vars : base->pass_info_in_env_vars);
	return (c);
}

/*
 * report a config error
 */
static int kap_check_config_error(server_rec *s, const char *config_str) {
	kap_serror(s, "mandatory parameter '%s' is not set", config_str);
	return HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * check the config required for the OpenID Connect RP role
 */
static int kap_check_config_openid_kap(server_rec *s, kap_cfg *c) {

	apr_uri_t r_uri;

	if ((c->metadata_dir == NULL) && (c->provider.issuer == NULL)
			&& (c->provider.metadata_url == NULL)) {
		kap_serror(s,
				"one of 'KAPProviderIssuer', 'KAPProviderMetadataURL' or 'KAPMetadataDir' must be set");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (c->redirect_uri == NULL)
		return kap_check_config_error(s, "KAPRedirectURI");
	if (c->crypto_passphrase == NULL)
		return kap_check_config_error(s, "KAPCryptoPassphrase");

	if (c->metadata_dir == NULL) {
		if (c->provider.metadata_url == NULL) {
			if (c->provider.issuer == NULL)
				return kap_check_config_error(s, "KAPProviderIssuer");
			if (c->provider.authorization_endpoint_url == NULL)
				return kap_check_config_error(s,
						"KAPProviderAuthorizationEndpoint");
			// TODO: this depends on the configured KAPResponseType now
			//			if (c->provider.token_endpoint_url == NULL)
			//				return kap_check_config_error(s, "KAPProviderTokenEndpoint");
		} else {
			apr_uri_parse(s->process->pconf, c->provider.metadata_url, &r_uri);
			if (apr_strnatcmp(r_uri.scheme, "http") == 0) {
				kap_swarn(s,
						"the URL scheme (%s) of the configured KAPProviderMetadataURL SHOULD be \"https\" for security reasons!",
						r_uri.scheme);
			}
		}
		if (c->provider.client_id == NULL)
			return kap_check_config_error(s, "KAPClientID");
		// TODO: this depends on the configured KAPResponseType now
		if (c->provider.client_secret == NULL)
			return kap_check_config_error(s, "KAPClientSecret");
	} else {
		if (c->provider.metadata_url != NULL) {
			kap_serror(s,
					"only one of 'KAPProviderMetadataURL' or 'KAPMetadataDir' should be set");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	apr_uri_parse(s->process->pconf, c->redirect_uri, &r_uri);
	if (apr_strnatcmp(r_uri.scheme, "https") != 0) {
		kap_swarn(s,
				"the URL scheme (%s) of the configured KAPRedirectURI SHOULD be \"https\" for security reasons (moreover: some Providers may reject non-HTTPS URLs)",
				r_uri.scheme);
	}

	if (c->cookie_domain != NULL) {
		char *p = strstr(r_uri.hostname, c->cookie_domain);
		if ((p == NULL) || (apr_strnatcmp(c->cookie_domain, p) != 0)) {
			kap_serror(s,
					"the domain (%s) configured in KAPCookieDomain does not match the URL hostname (%s) of the configured KAPRedirectURI (%s): setting \"state\" and \"session\" cookies will not work!",
					c->cookie_domain, r_uri.hostname, c->redirect_uri);
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	return OK;
}

/*
 * check the config required for the OAuth 2.0 RS role
 */
static int kap_check_config_oauth(server_rec *s, kap_cfg *c) {

	if (c->oauth.introspection_endpoint_url == NULL) {

		if ((c->oauth.verify_jwks_uri == NULL)
				&& (c->oauth.verify_public_keys == NULL)
				&& (c->oauth.verify_shared_keys == NULL)) {
			kap_serror(s,
					"one of 'KAPOAuthIntrospectionEndpoint', 'KAPOAuthVerifyJwksUri', 'KAPOAuthVerifySharedKeys' or 'KAPOAuthVerifyCertFiles' must be set");
			return HTTP_INTERNAL_SERVER_ERROR;
		}

	} else if ((c->oauth.verify_jwks_uri != NULL)
			|| (c->oauth.verify_public_keys != NULL)
			|| (c->oauth.verify_shared_keys != NULL)) {
		kap_serror(s,
				"only 'KAPOAuthIntrospectionEndpoint' OR one (or more) out of ('KAPOAuthVerifyJwksUri', 'KAPOAuthVerifySharedKeys' or 'KAPOAuthVerifyCertFiles') must be set");
		return HTTP_INTERNAL_SERVER_ERROR;

	}

	return OK;
}

/*
 * check the config of a vhost
 */
static int kap_config_check_vhost_config(apr_pool_t *pool, server_rec *s) {
	kap_cfg *cfg = (kap_cfg *)ap_get_module_config(s->module_config,
			&auth_kap_module);

	kap_sdebug(s, "enter");

	if ((cfg->metadata_dir != NULL) || (cfg->provider.issuer != NULL)
			|| (cfg->provider.metadata_url != NULL)
			|| (cfg->redirect_uri != NULL)
			|| (cfg->crypto_passphrase != NULL)) {
		if (kap_check_config_openid_kap(s, cfg) != OK)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((cfg->oauth.client_id != NULL) || (cfg->oauth.client_secret != NULL)
			|| (cfg->oauth.introspection_endpoint_url != NULL)
			|| (cfg->oauth.verify_jwks_uri != NULL)
			|| (cfg->oauth.verify_public_keys != NULL)
			|| (cfg->oauth.verify_shared_keys != NULL)) {
		if (kap_check_config_oauth(s, cfg) != OK)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

/*
 * check the config of a merged vhost
 */
static int kap_config_check_merged_vhost_configs(apr_pool_t *pool,
		server_rec *s) {
	int status = OK;
	while (s != NULL && status == OK) {
		kap_cfg *cfg = (kap_cfg *)ap_get_module_config(s->module_config,
				&auth_kap_module);
		if (cfg->merged) {
			status = kap_config_check_vhost_config(pool, s);
		}
		s = s->next;
	}
	return status;
}

/*
 * check if any merged vhost configs exist
 */
static int kap_config_merged_vhost_configs_exist(server_rec *s) {
	while (s != NULL) {
		kap_cfg *cfg = (kap_cfg *)ap_get_module_config(s->module_config,
				&auth_kap_module);
		if (cfg->merged) {
			return TRUE;
		}
		s = s->next;
	}
	return FALSE;
}

/*
 * SSL initialization magic copied from mod_auth_cas
 */
#if defined(OPENSSL_THREADS) && APR_HAS_THREADS

static apr_thread_mutex_t **ssl_locks;
static int ssl_num_locks;

static void kap_ssl_locking_callback(int mode, int type, const char *file,
		int line) {
	if (type < ssl_num_locks) {
		if (mode & CRYPTO_LOCK)
			apr_thread_mutex_lock(ssl_locks[type]);
		else
			apr_thread_mutex_unlock(ssl_locks[type]);
	}
}

#ifdef OPENSSL_NO_THREADID
static unsigned long kap_ssl_id_callback(void) {
	return (unsigned long) apr_os_thread_current();
}
#else
static void kap_ssl_id_callback(CRYPTO_THREADID *id) {
	CRYPTO_THREADID_set_numeric(id, (unsigned long) apr_os_thread_current());
}
#endif /* OPENSSL_NO_THREADID */

#endif /* defined(OPENSSL_THREADS) && APR_HAS_THREADS */

static apr_status_t kap_cleanup(void *data) {

	server_rec *sp = (server_rec *) data;
	while (sp != NULL) {
		kap_cfg *cfg = (kap_cfg *) ap_get_module_config(sp->module_config,
				&auth_kap_module);
		kap_crypto_destroy(cfg, sp);
		if (cfg->cache->destroy != NULL) {
			if (cfg->cache->destroy(sp) != APR_SUCCESS) {
				kap_serror(sp, "cache destroy function failed");
			}
		}
		sp = sp->next;
	}

#if (defined (OPENSSL_THREADS) && APR_HAS_THREADS)
	if (CRYPTO_get_locking_callback() == kap_ssl_locking_callback)
		CRYPTO_set_locking_callback(NULL);
#ifdef OPENSSL_NO_THREADID
	if (CRYPTO_get_id_callback() == kap_ssl_id_callback)
		CRYPTO_set_id_callback(NULL);
#else
	if (CRYPTO_THREADID_get_callback() == kap_ssl_id_callback)
		CRYPTO_THREADID_set_callback(NULL);
#endif /* OPENSSL_NO_THREADID */

#endif /* defined(OPENSSL_THREADS) && APR_HAS_THREADS */
	EVP_cleanup();
	curl_global_cleanup();

	ap_log_error(APLOG_MARK, APLOG_INFO, 0, (server_rec *) data,
			"%s - shutdown", NAMEVERSION);

	return APR_SUCCESS;
}

/*
 * handler that is called (twice) after the configuration phase; check if everything is OK
 */
static int kap_post_config(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2,
		server_rec *s) {
	const char *userdata_key = "kap_post_config";
	void *data = NULL;
	int i;

	/* Since the post_config hook is invoked twice (once
	 * for 'sanity checking' of the config and once for
	 * the actual server launch, we have to use a hack
	 * to not run twice
	 */
	apr_pool_userdata_get(&data, userdata_key, s->process->pool);
	if (data == NULL) {
		apr_pool_userdata_set((const void *) 1, userdata_key,
				apr_pool_cleanup_null, s->process->pool);
		return OK;
	}

	ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, "%s - init", NAMEVERSION);

	curl_global_init(CURL_GLOBAL_ALL);
	OpenSSL_add_all_digests();

#if (defined(OPENSSL_THREADS) && APR_HAS_THREADS)
	ssl_num_locks = CRYPTO_num_locks();
	ssl_locks = (apr_thread_mutex_t **)apr_pcalloc(s->process->pool,
			ssl_num_locks * sizeof(*ssl_locks));

	for (i = 0; i < ssl_num_locks; i++)
		apr_thread_mutex_create(&(ssl_locks[i]), APR_THREAD_MUTEX_DEFAULT,
				s->process->pool);

#ifdef OPENSSL_NO_THREADID
	if (CRYPTO_get_locking_callback() == NULL && CRYPTO_get_id_callback() == NULL) {
		CRYPTO_set_locking_callback(kap_ssl_locking_callback);
		CRYPTO_set_id_callback(kap_ssl_id_callback);
	}
#else
	if (CRYPTO_get_locking_callback() == NULL
			&& CRYPTO_THREADID_get_callback() == NULL) {
		CRYPTO_set_locking_callback(kap_ssl_locking_callback);
		CRYPTO_THREADID_set_callback(kap_ssl_id_callback);
	}
#endif /* OPENSSL_NO_THREADID */
#endif /* defined(OPENSSL_THREADS) && APR_HAS_THREADS */
	apr_pool_cleanup_register(pool, s, kap_cleanup, apr_pool_cleanup_null);

	kap_session_init();

	server_rec *sp = s;
	while (sp != NULL) {
		kap_cfg *cfg = (kap_cfg *) ap_get_module_config(sp->module_config,
				&auth_kap_module);
		if (cfg->cache->post_config != NULL) {
			if (cfg->cache->post_config(sp) != OK)
				return HTTP_INTERNAL_SERVER_ERROR;
		}
		sp = sp->next;
	}

	/*
	 * Apache has a base vhost that true vhosts derive from.
	 * There are two startup scenarios:
	 *
	 * 1. Only the base vhost contains KAP settings.
	 *    No server configs have been merged.
	 *    Only the base vhost needs to be checked.
	 *
	 * 2. The base vhost contains zero or more KAP settings.
	 *    One or more vhosts override these.
	 *    These vhosts have a merged config.
	 *    All merged configs need to be checked.
	 */
	if (!kap_config_merged_vhost_configs_exist(s)) {
		/* nothing merged, only check the base vhost */
		return kap_config_check_vhost_config(pool, s);
	}
	return kap_config_check_merged_vhost_configs(pool, s);
}

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
static const authz_provider authz_kap_provider = {
		&kap_authz_checker,
		NULL,
};
#endif

/*
 * initialize cache context in child process if required
 */
static void kap_child_init(apr_pool_t *p, server_rec *s) {
	while (s != NULL) {
		kap_cfg *cfg = (kap_cfg *) ap_get_module_config(s->module_config,
				&auth_kap_module);
		if (cfg->cache->child_init != NULL) {
			if (cfg->cache->child_init(p, s) != APR_SUCCESS) {
				kap_serror(s, "cfg->cache->child_init failed");
			}
		}
		s = s->next;
	}
}

/*
 * fixup handler: be authoritative for environment variables at late processing
 */
static int kap_auth_fixups(request_rec *r) {
	apr_table_t *env = NULL;
	apr_pool_userdata_get((void **) &env, KAP_USERDATA_ENV_KEY, r->pool);
	if ((env == NULL) || apr_is_empty_table(env))
		return DECLINED;

	kap_debug(r, "overlaying env with %d elements",
			apr_table_elts(env)->nelts);

	r->subprocess_env = apr_table_overlay(r->pool, r->subprocess_env, env);

	return OK;
}

/*
 * register our authentication and authorization functions
 */
void kap_register_hooks(apr_pool_t *pool) {
	ap_hook_post_config(kap_post_config, NULL, NULL, APR_HOOK_LAST);
	ap_hook_child_init(kap_child_init, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_fixups(kap_auth_fixups, NULL, NULL, APR_HOOK_MIDDLE);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
	ap_hook_check_authn(kap_check_user_id, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(pool, AUTHZ_PROVIDER_GROUP, KAP_REQUIRE_NAME, "0", &authz_kap_provider, AP_AUTH_INTERNAL_PER_CONF);
#else
	static const char * const authzSucc[] = { "mod_authz_user.c", NULL };
	ap_hook_check_user_id(kap_check_user_id, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_auth_checker(kap_auth_checker, NULL, authzSucc, APR_HOOK_MIDDLE);
#endif
}

/*
 * set of configuration primitives
 */
command_rec kap_config_cmds[] = {

		AP_INIT_TAKE1("KAPProviderMetadataURL", (cmd_func)kap_set_string_slot,
				(void*)APR_OFFSETOF(kap_cfg, provider.metadata_url),
				RSRC_CONF,
				"OpenID Connect OP configuration metadata URL."),
		AP_INIT_TAKE1("KAPProviderIssuer", (cmd_func)kap_set_string_slot,
				(void*)APR_OFFSETOF(kap_cfg, provider.issuer),
				RSRC_CONF,
				"OpenID Connect OP issuer identifier."),
		AP_INIT_TAKE1("KAPProviderAuthorizationEndpoint",
				(cmd_func)kap_set_https_slot,
				(void *)APR_OFFSETOF(kap_cfg, provider.authorization_endpoint_url),
				RSRC_CONF,
				"Define the OpenID OP Authorization Endpoint URL (e.g.: https://localhost:9031/as/authorization.oauth2)"),
		AP_INIT_TAKE1("KAPProviderTokenEndpoint",
				(cmd_func)kap_set_https_slot,
				(void *)APR_OFFSETOF(kap_cfg, provider.token_endpoint_url),
				RSRC_CONF,
				"Define the OpenID OP Token Endpoint URL (e.g.: https://localhost:9031/as/token.oauth2)"),
		AP_INIT_TAKE1("KAPProviderTokenEndpointAuth",
				(cmd_func)kap_set_endpoint_auth_slot,
				(void *)APR_OFFSETOF(kap_cfg, provider.token_endpoint_auth),
				RSRC_CONF,
				"Specify an authentication method for the OpenID OP Token Endpoint (e.g.: client_secret_basic)"),
		AP_INIT_TAKE1("KAPProviderTokenEndpointParams",
				(cmd_func)kap_set_string_slot,
				(void *)APR_OFFSETOF(kap_cfg, provider.token_endpoint_params),
				RSRC_CONF,
				"Define extra parameters that will be posted to the OpenID OP Token Endpoint (e.g.: param1=value1&param2=value2, all urlencoded)."),
		AP_INIT_TAKE1("KAPProviderRegistrationEndpointJson",
				(cmd_func)kap_set_string_slot,
				(void *)APR_OFFSETOF(kap_cfg, provider.registration_endpoint_json),
				RSRC_CONF,
				"Define a JSON object with parameters that will be merged into the client registration request to the OpenID OP Registration Endpoint (e.g.: { \"request_uris\" : [ \"https://example.com/uri\"] })."),
		AP_INIT_TAKE1("KAPProviderUserInfoEndpoint",
				(cmd_func)kap_set_https_slot,
				(void *)APR_OFFSETOF(kap_cfg, provider.userinfo_endpoint_url),
				RSRC_CONF,
				"Define the OpenID OP UserInfo Endpoint URL (e.g.: https://localhost:9031/idp/userinfo.openid)"),
		AP_INIT_TAKE1("KAPProviderCheckSessionIFrame",
				(cmd_func)kap_set_url_slot,
				(void *)APR_OFFSETOF(kap_cfg, provider.check_session_iframe),
				RSRC_CONF,
				"Define the OpenID OP Check Session iFrame URL."),
		AP_INIT_TAKE1("KAPProviderEndSessionEndpoint",
				(cmd_func)kap_set_url_slot,
				(void *)APR_OFFSETOF(kap_cfg, provider.end_session_endpoint),
				RSRC_CONF,
				"Define the OpenID OP End Session Endpoint URL."),
		AP_INIT_TAKE1("KAPProviderJwksUri",
				(cmd_func)kap_set_https_slot,
				(void *)APR_OFFSETOF(kap_cfg, provider.jwks_uri),
				RSRC_CONF,
				"Define the OpenID OP JWKS URL (e.g.: https://localhost:9031/pf/JWKS)"),
		AP_INIT_TAKE1("KAPResponseType",
				(cmd_func)kap_set_response_type,
				(void *)APR_OFFSETOF(kap_cfg, provider.response_type),
				RSRC_CONF,
				"The response type (or OpenID Connect Flow) used; must be one of \"code\", \"id_token\", \"id_token token\", \"code id_token\", \"code token\" or \"code id_token token\" (serves as default value for discovered OPs too)"),
		AP_INIT_TAKE1("KAPResponseMode",
				(cmd_func)kap_set_response_mode,
				(void *)APR_OFFSETOF(kap_cfg, provider.response_mode),
				RSRC_CONF,
				"The response mode used; must be one of \"fragment\", \"query\" or \"form_post\" (serves as default value for discovered OPs too)"),

		AP_INIT_ITERATE("KAPPublicKeyFiles",
				(cmd_func)kap_set_public_key_files,
				(void *)APR_OFFSETOF(kap_cfg, public_keys),
				RSRC_CONF,
				"The fully qualified names of the files that contain the X.509 certificates that contains the RSA public keys that can be used for encryption by the OP."),
		AP_INIT_ITERATE("KAPPrivateKeyFiles", (cmd_func)kap_set_private_key_files_enc,
				NULL,
				RSRC_CONF,
				"The fully qualified names of the files that contain the RSA private keys that can be used to decrypt content sent to us by the OP."),

		AP_INIT_TAKE1("KAPClientJwksUri",
				(cmd_func)kap_set_https_slot,
				(void *)APR_OFFSETOF(kap_cfg, provider.client_jwks_uri),
				RSRC_CONF,
				"Define the Client JWKS URL (e.g.: https://localhost/protected/?jwks=rsa)"),
		AP_INIT_TAKE1("KAPIDTokenSignedResponseAlg",
				(cmd_func)kap_set_signed_response_alg,
				(void *)APR_OFFSETOF(kap_cfg, provider.id_token_signed_response_alg),
				RSRC_CONF,
				"The algorithm that the OP should use to sign the id_token (used only in dynamic client registration); must be one of [RS256|RS384|RS512|PS256|PS384|PS512|HS256|HS384|HS512]"),
		AP_INIT_TAKE1("KAPIDTokenEncryptedResponseAlg",
				(cmd_func)kap_set_encrypted_response_alg,
				(void *)APR_OFFSETOF(kap_cfg, provider.id_token_encrypted_response_alg),
				RSRC_CONF,
				"The algorithm that the OP should use to encrypt the Content Encryption Key that is used to encrypt the id_token (used only in dynamic client registration); must be one of [RSA1_5|A128KW|A256KW]"),
		AP_INIT_TAKE1("KAPIDTokenEncryptedResponseEnc",
				(cmd_func)kap_set_encrypted_response_enc,
				(void *)APR_OFFSETOF(kap_cfg, provider.id_token_encrypted_response_enc),
				RSRC_CONF,
				"The algorithm that the OP should use to encrypt to the id_token with the Content Encryption Key (used only in dynamic client registration); must be one of [A128CBC-HS256|A256CBC-HS512]"),
		AP_INIT_TAKE1("KAPUserInfoSignedResponseAlg",
				(cmd_func)kap_set_signed_response_alg,
				(void *)APR_OFFSETOF(kap_cfg, provider.userinfo_signed_response_alg),
				RSRC_CONF,
				"The algorithm that the OP should use to sign the UserInfo response (used only in dynamic client registration); must be one of [RS256|RS384|RS512|PS256|PS384|PS512|HS256|HS384|HS512]"),
		AP_INIT_TAKE1("KAPUserInfoEncryptedResponseAlg",
				(cmd_func)kap_set_encrypted_response_alg,
				(void *)APR_OFFSETOF(kap_cfg, provider.userinfo_encrypted_response_alg),
				RSRC_CONF,
				"The algorithm that the OP should use to encrypt the Content Encryption Key that is used to encrypt the UserInfo response (used only in dynamic client registration); must be one of [RSA1_5|A128KW|A256KW]"),
		AP_INIT_TAKE1("KAPUserInfoEncryptedResponseEnc",
				(cmd_func)kap_set_encrypted_response_enc,
				(void *)APR_OFFSETOF(kap_cfg, provider.userinfo_encrypted_response_enc),
				RSRC_CONF,
				"The algorithm that the OP should use to encrypt to encrypt the UserInfo response with the Content Encryption Key (used only in dynamic client registration); must be one of [A128CBC-HS256|A256CBC-HS512]"),

		AP_INIT_FLAG("KAPSSLValidateServer",
				(cmd_func)kap_set_flag_slot,
				(void*)APR_OFFSETOF(kap_cfg, provider.ssl_validate_server),
				RSRC_CONF,
				"Require validation of the OpenID Connect OP SSL server certificate for successful authentication (On or Off)"),
		AP_INIT_TAKE1("KAPClientName",
				(cmd_func)kap_set_string_slot,
				(void *) APR_OFFSETOF(kap_cfg, provider.client_name),
				RSRC_CONF,
				"Define the (client_name) name that the client uses for dynamic registration to the OP."),
		AP_INIT_TAKE1("KAPClientContact",
				(cmd_func)kap_set_string_slot,
				(void *) APR_OFFSETOF(kap_cfg, provider.client_contact),
				RSRC_CONF,
				"Define the contact that the client registers in dynamic registration with the OP."),
		AP_INIT_TAKE1("KAPScope", (cmd_func)kap_set_string_slot,
				(void *) APR_OFFSETOF(kap_cfg, provider.scope),
				RSRC_CONF,
				"Define the OpenID Connect scope that is requested from the OP."),
		AP_INIT_TAKE1("KAPJWKSRefreshInterval",
				(cmd_func)kap_set_int_slot,
				(void*)APR_OFFSETOF(kap_cfg, provider.jwks_refresh_interval),
				RSRC_CONF,
				"Duration in seconds after which retrieved JWS should be refreshed."),
		AP_INIT_TAKE1("KAPIDTokenIatSlack",
				(cmd_func)kap_set_int_slot,
				(void*)APR_OFFSETOF(kap_cfg, provider.idtoken_iat_slack),
				RSRC_CONF,
				"Acceptable offset (both before and after) for checking the \"iat\" (= issued at) timestamp in the id_token."),
		AP_INIT_TAKE1("KAPSessionMaxDuration",
				(cmd_func)kap_set_session_max_duration,
				(void*)APR_OFFSETOF(kap_cfg, provider.session_max_duration),
				RSRC_CONF,
				"Maximum duration of a session in seconds."),
		AP_INIT_TAKE1("KAPAuthRequestParams",
				(cmd_func)kap_set_string_slot,
				(void*)APR_OFFSETOF(kap_cfg, provider.auth_request_params),
				RSRC_CONF,
				"Extra parameters that need to be sent in the Authorization Request (must be query-encoded like \"display=popup&prompt=consent\"."),

		AP_INIT_TAKE1("KAPClientID", (cmd_func)kap_set_string_slot,
				(void*)APR_OFFSETOF(kap_cfg, provider.client_id),
				RSRC_CONF,
				"Client identifier used in calls to OpenID Connect OP."),
		AP_INIT_TAKE1("KAPClientSecret", (cmd_func)kap_set_string_slot,
				(void*)APR_OFFSETOF(kap_cfg, provider.client_secret),
				RSRC_CONF,
				"Client secret used in calls to OpenID Connect OP."),

		AP_INIT_TAKE1("KAPRedirectURI", (cmd_func)kap_set_url_slot,
				(void *)APR_OFFSETOF(kap_cfg, redirect_uri),
				RSRC_CONF,
				"Define the Redirect URI (e.g.: https://localhost:9031/protected/example/)"),
		AP_INIT_TAKE1("KAPDefaultURL", (cmd_func)kap_set_url_slot,
				(void *)APR_OFFSETOF(kap_cfg, default_sso_url),
				RSRC_CONF,
				"Defines the default URL where the user is directed to in case of 3rd-party initiated SSO."),
		AP_INIT_TAKE1("KAPDefaultLoggedOutURL", (cmd_func)kap_set_url_slot,
				(void *)APR_OFFSETOF(kap_cfg, default_slo_url),
				RSRC_CONF,
				"Defines the default URL where the user is directed to after logout."),
		AP_INIT_TAKE1("KAPCookieDomain",
				(cmd_func)kap_set_cookie_domain, NULL, RSRC_CONF,
				"Specify domain element for KAP session cookie."),
		AP_INIT_FLAG("KAPCookieHTTPOnly",
				(cmd_func)kap_set_flag_slot,
				(void *) APR_OFFSETOF(kap_cfg, cookie_http_only),
				RSRC_CONF,
				"Defines whether or not the cookie httponly flag is set on cookies."),
		AP_INIT_TAKE1("KAPOutgoingProxy",
				(cmd_func)kap_set_string_slot,
				(void*)APR_OFFSETOF(kap_cfg, outgoing_proxy),
				RSRC_CONF,
				"Specify an outgoing proxy for your network (<host>[:<port>]."),
		AP_INIT_TAKE1("KAPCryptoPassphrase",
				(cmd_func)kap_set_string_slot,
				(void*)APR_OFFSETOF(kap_cfg, crypto_passphrase),
				RSRC_CONF,
				"Passphrase used for AES crypto on cookies and state."),
		AP_INIT_TAKE1("KAPClaimDelimiter",
				(cmd_func)kap_set_string_slot,
				(void*)APR_OFFSETOF(kap_cfg, claim_delimiter),
				RSRC_CONF,
				"The delimiter to use when setting multi-valued claims in the HTTP headers."),
		AP_INIT_TAKE1("KAPClaimPrefix", (cmd_func)kap_set_string_slot,
				(void*)APR_OFFSETOF(kap_cfg, claim_prefix),
				RSRC_CONF,
				"The prefix to use when setting claims in the HTTP headers."),
		AP_INIT_TAKE12("KAPRemoteUserClaim",
				(cmd_func)kap_set_remote_user_claim,
				(void*)APR_OFFSETOF(kap_cfg, remote_user_claim),
				RSRC_CONF,
				"The claim that is used when setting the REMOTE_USER variable for OpenID Connect protected paths."),
		AP_INIT_TAKE123("KAPPassIDTokenAs",
				(cmd_func)kap_set_pass_idtoken_as,
				NULL,
				RSRC_CONF,
				"The format in which the id_token is passed in (a) header(s); must be one or more of: claims|payload|serialized"),

		AP_INIT_TAKE1("KAPOAuthClientID", (cmd_func)kap_set_string_slot,
				(void*)APR_OFFSETOF(kap_cfg, oauth.client_id),
				RSRC_CONF,
				"Client identifier used in calls to OAuth 2.0 Authorization server validation calls."),
		AP_INIT_TAKE1("KAPOAuthClientSecret",
				(cmd_func)kap_set_string_slot,
				(void*)APR_OFFSETOF(kap_cfg, oauth.client_secret),
				RSRC_CONF,
				"Client secret used in calls to OAuth 2.0 Authorization server validation calls."),
		AP_INIT_TAKE1("KAPOAuthIntrospectionEndpoint",
				(cmd_func)kap_set_https_slot,
				(void *)APR_OFFSETOF(kap_cfg, oauth.introspection_endpoint_url),
				RSRC_CONF,
				"Define the OAuth AS Introspection Endpoint URL (e.g.: https://localhost:9031/as/token.oauth2)"),
		AP_INIT_TAKE1("KAPOAuthIntrospectionEndpointMethod",
				(cmd_func)kap_set_introspection_method,
				(void *)APR_OFFSETOF(kap_cfg, oauth.introspection_endpoint_method),
				RSRC_CONF,
				"Define the HTTP method to use for the introspection call: one of \"GET\" or \"POST\" (default)"),
		AP_INIT_TAKE1("KAPOAuthIntrospectionEndpointParams",
				(cmd_func)kap_set_string_slot,
				(void*)APR_OFFSETOF(kap_cfg, oauth.introspection_endpoint_params),
				RSRC_CONF,
				"Extra parameters that need to be sent in the token introspection request (must be query-encoded like \"grant_type=urn%3Apingidentity.com%3Aoauth2%3Agrant_type%3Avalidate_bearer\"."),
		AP_INIT_TAKE1("KAPOAuthIntrospectionEndpointAuth",
				(cmd_func)kap_set_endpoint_auth_slot,
				(void *)APR_OFFSETOF(kap_cfg, oauth.introspection_endpoint_auth),
				RSRC_CONF,
				"Specify an authentication method for the OAuth AS Introspection Endpoint (e.g.: client_auth_basic)"),
		AP_INIT_TAKE1("KAPOAuthIntrospectionTokenParamName",
				(cmd_func)kap_set_string_slot,
				(void*)APR_OFFSETOF(kap_cfg, oauth.introspection_token_param_name),
				RSRC_CONF,
				"Name of the parameter whose value carries the access token value in an validation request to the token introspection endpoint."),
		AP_INIT_TAKE123("KAPOAuthTokenExpiryClaim",
				(cmd_func)kap_set_token_expiry_claim,
				NULL,
				RSRC_CONF,
				"Name of the claim that carries the token expiry value in the introspection result, optionally followed by absolute|relative, optionally followed by optional|mandatory"),
		AP_INIT_FLAG("KAPOAuthSSLValidateServer",
				(cmd_func)kap_set_flag_slot,
				(void*)APR_OFFSETOF(kap_cfg, oauth.ssl_validate_server),
				RSRC_CONF,
				"Require validation of the OAuth 2.0 AS Validation Endpoint SSL server certificate for successful authentication (On or Off)"),
		AP_INIT_TAKE12("KAPOAuthRemoteUserClaim",
				(cmd_func)kap_set_remote_user_claim,
				(void*)APR_OFFSETOF(kap_cfg, oauth.remote_user_claim),
				RSRC_CONF,
				"The claim that is used when setting the REMOTE_USER variable for OAuth 2.0 protected paths."),
		AP_INIT_ITERATE("KAPOAuthVerifyCertFiles",
				(cmd_func)kap_set_public_key_files,
				(void*)APR_OFFSETOF(kap_cfg, oauth.verify_public_keys),
				RSRC_CONF,
				"The fully qualified names of the files that contain the X.509 certificates that contains the RSA public keys that can be used for access token validation."),
		AP_INIT_ITERATE("KAPOAuthVerifySharedKeys",
				(cmd_func)kap_set_shared_keys,
				(void*)APR_OFFSETOF(kap_cfg, oauth.verify_shared_keys),
				RSRC_CONF,
				"Shared secret(s) that is/are used to verify signed JWT access tokens locally."),
		AP_INIT_TAKE1("KAPOAuthVerifyJwksUri",
				(cmd_func)kap_set_https_slot,
				(void *)APR_OFFSETOF(kap_cfg, oauth.verify_jwks_uri),
				RSRC_CONF,
				"The JWKs URL on which the Authorization publishes the keys used to sign its JWT access tokens."),

		AP_INIT_TAKE1("KAPHTTPTimeoutLong", (cmd_func)kap_set_int_slot,
				(void*)APR_OFFSETOF(kap_cfg, http_timeout_long),
				RSRC_CONF,
				"Timeout for long duration HTTP calls (default)."),
		AP_INIT_TAKE1("KAPHTTPTimeoutShort", (cmd_func)kap_set_int_slot,
				(void*)APR_OFFSETOF(kap_cfg, http_timeout_short),
				RSRC_CONF,
				"Timeout for short duration HTTP calls (registry/discovery)."),
		AP_INIT_TAKE1("KAPStateTimeout", (cmd_func)kap_set_int_slot,
				(void*)APR_OFFSETOF(kap_cfg, state_timeout),
				RSRC_CONF,
				"Time to live in seconds for state parameter (cq. interval in which the authorization request and the corresponding response need to be completed)."),
		AP_INIT_TAKE1("KAPSessionInactivityTimeout",
				(cmd_func)kap_set_session_inactivity_timeout,
				(void*)APR_OFFSETOF(kap_cfg, session_inactivity_timeout),
				RSRC_CONF,
				"Inactivity interval after which the session is invalidated when no interaction has occurred."),

		AP_INIT_TAKE1("KAPMetadataDir", (cmd_func)kap_set_dir_slot,
				(void*)APR_OFFSETOF(kap_cfg, metadata_dir),
				RSRC_CONF,
				"Directory that contains provider and client metadata files."),
		AP_INIT_TAKE1("KAPSessionType", (cmd_func)kap_set_session_type,
				(void*)APR_OFFSETOF(kap_cfg, session_type),
				RSRC_CONF,
				"OpenID Connect session storage type (Apache 2.0/2.2 only). Must be one of \"server-cache\" or \"client-cookie\"."),
		AP_INIT_FLAG("KAPScrubRequestHeaders",
				(cmd_func)kap_set_flag_slot,
				(void *) APR_OFFSETOF(kap_cfg, scrub_request_headers),
				RSRC_CONF,
				"Scrub user name and claim headers from the user's request."),

		AP_INIT_TAKE1("KAPCacheType", (cmd_func)kap_set_cache_type,
				(void*)APR_OFFSETOF(kap_cfg, cache), RSRC_CONF,
				"Cache type; must be one of \"file\", \"memcache\" or \"shm\"."),

		AP_INIT_TAKE1("KAPCacheDir", (cmd_func)kap_set_dir_slot,
				(void*)APR_OFFSETOF(kap_cfg, cache_file_dir),
				RSRC_CONF,
				"Directory used for file-based caching."),
		AP_INIT_TAKE1("KAPCacheFileCleanInterval",
				(cmd_func)kap_set_int_slot,
				(void*)APR_OFFSETOF(kap_cfg, cache_file_clean_interval),
				RSRC_CONF,
				"Cache file clean interval in seconds."),
		AP_INIT_TAKE1("KAPMemCacheServers",
				(cmd_func)kap_set_string_slot,
				(void*)APR_OFFSETOF(kap_cfg, cache_memcache_servers),
				RSRC_CONF,
				"Memcache servers used for caching (space separated list of <hostname>[:<port>] tuples)"),
		AP_INIT_TAKE1("KAPCacheShmMax", (cmd_func)kap_set_int_slot,
				(void*)APR_OFFSETOF(kap_cfg, cache_shm_size_max),
				RSRC_CONF,
				"Maximum number of cache entries to use for \"shm\" caching."),
		AP_INIT_TAKE1("KAPCacheShmEntrySizeMax", (cmd_func)kap_set_cache_shm_entry_size_max,
				(void*)APR_OFFSETOF(kap_cfg, cache_shm_entry_size_max),
				RSRC_CONF,
				"Maximum size of a single cache entry used for \"shm\" caching."),
#ifdef USE_LIBHIREDIS
		AP_INIT_TAKE1("KAPRedisCacheServer",
				(cmd_func)kap_set_string_slot,
				(void*)APR_OFFSETOF(kap_cfg, cache_redis_server),
				RSRC_CONF,
				"Redis server used for caching (<hostname>[:<port>])"),
#endif

		AP_INIT_TAKE1("KAPDiscoverURL", (cmd_func)kap_set_url_slot_dir_cfg,
				(void *)APR_OFFSETOF(kap_dir_cfg, discover_url),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Defines an external IDP Discovery page"),
		AP_INIT_ITERATE("KAPPassCookies",
				(cmd_func)kap_set_pass_cookies,
				(void *) APR_OFFSETOF(kap_dir_cfg, pass_cookies),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Specify cookies that need to be passed from the browser on to the backend to the OP/AS."),
		AP_INIT_TAKE1("KAPAuthNHeader", (cmd_func)ap_set_string_slot,
				(void *) APR_OFFSETOF(kap_dir_cfg, authn_header),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Specify the HTTP header variable to set with the name of the authenticated user. By default no explicit header is added but Apache's default REMOTE_USER will be set."),
		AP_INIT_TAKE1("KAPCookiePath", (cmd_func)ap_set_string_slot,
				(void *) APR_OFFSETOF(kap_dir_cfg, cookie_path),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Define the cookie path for the session cookie."),
		AP_INIT_TAKE1("KAPCookie", (cmd_func)ap_set_string_slot,
				(void *) APR_OFFSETOF(kap_dir_cfg, cookie),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Define the cookie name for the session cookie."),
		AP_INIT_FLAG("KAPReturn401", (cmd_func)ap_set_flag_slot,
				(void *) APR_OFFSETOF(kap_dir_cfg, return401),
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Indicates whether a user will be redirected to the Provider when not authenticated (Off) or a 401 will be returned (On)."),
		AP_INIT_TAKE1("KAPPassClaimsAs",
				(cmd_func)kap_set_pass_claims_as, NULL,
				RSRC_CONF|ACCESS_CONF|OR_AUTHCFG,
				"Specify how claims are passed to the application(s); must be one of \"none\", \"headers\", \"environment\" or \"both\" (default)."),
		{ NULL }
};