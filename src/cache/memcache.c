/*
 * Copyright (C) 2017 Kapstonellc (http://www.kapstonellc.com)
 *
 * Created by Pavlov <pavlov0123@outlook.com>
 * 
 */

#include "apr_general.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_memcache.h"

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include "../mod_auth_kap.h"

// TODO: proper memcache error reporting (server unreachable etc.)

extern module AP_MODULE_DECLARE_DATA auth_kap_module;

typedef struct kap_cache_cfg_memcache_t {
	/* cache_type = memcache: memcache ptr */
	apr_memcache_t *cache_memcache;
} kap_cache_cfg_memcache_t;

/* create the cache context */
static void *kap_cache_memcache_cfg_create(apr_pool_t *pool) {
	kap_cache_cfg_memcache_t *context = (kap_cache_cfg_memcache_t *)apr_pcalloc(pool,
			sizeof(kap_cache_cfg_memcache_t));
	context->cache_memcache = NULL;
	return context;
}

/*
 * initialize the memcache struct to a number of memcache servers
 */
static int kap_cache_memcache_post_config(server_rec *s) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(s->module_config,
			&auth_kap_module);

	if (cfg->cache_cfg != NULL)
		return APR_SUCCESS;
	kap_cache_cfg_memcache_t *context = (kap_cache_cfg_memcache_t *)kap_cache_memcache_cfg_create(
			s->process->pool);
	cfg->cache_cfg = context;

	apr_status_t rv = APR_SUCCESS;
	int nservers = 0;
	char* split;
	char* tok;
	apr_pool_t *p = s->process->pool;

	if (cfg->cache_memcache_servers == NULL) {
		kap_serror(s,
				"cache type is set to \"memcache\", but no valid KAPMemCacheServers setting was found");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* loop over the provided memcache servers to find out the number of servers configured */
	char *cache_config = apr_pstrdup(p, cfg->cache_memcache_servers);
	split = apr_strtok(cache_config, " ", &tok);
	while (split) {
		nservers++;
		split = apr_strtok(NULL, " ", &tok);
	}

	/* allocated space for the number of servers */
	rv = apr_memcache_create(p, nservers, 0, &context->cache_memcache);
	if (rv != APR_SUCCESS) {
		kap_serror(s, "failed to create memcache object of '%d' size",
				nservers);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* loop again over the provided servers */
	cache_config = apr_pstrdup(p, cfg->cache_memcache_servers);
	split = apr_strtok(cache_config, " ", &tok);
	while (split) {
		apr_memcache_server_t* st;
		char* host_str;
		char* scope_id;
		apr_port_t port;

		/* parse out host and port */
		rv = apr_parse_addr_port(&host_str, &scope_id, &port, split, p);
		if (rv != APR_SUCCESS) {
			kap_serror(s, "failed to parse cache server: '%s'", split);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		if (host_str == NULL) {
			kap_serror(s,
					"failed to parse cache server, no hostname specified: '%s'",
					split);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		if (port == 0)
			port = 11211;

		/* create the memcache server struct */
		// TODO: tune this
		rv = apr_memcache_server_create(p, host_str, port, 0, 1, 1, 60, &st);
		if (rv != APR_SUCCESS) {
			kap_serror(s, "failed to create cache server: %s:%d", host_str,
					port);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		/* add the memcache server struct to the list */
		rv = apr_memcache_add_server(context->cache_memcache, st);
		if (rv != APR_SUCCESS) {
			kap_serror(s, "failed to add cache server: %s:%d", host_str, port);
			return HTTP_INTERNAL_SERVER_ERROR;
		}

		/* go to the next entry */
		split = apr_strtok(NULL, " ", &tok);
	}

	return OK;
}

/*
 * assemble single key name based on section/key input
 */
static char *kap_cache_memcache_get_key(apr_pool_t *pool, const char *section,
		const char *key) {
	return apr_psprintf(pool, "%s:%s", section, key);
}

/*
 * get a name/value pair from memcache
 */
static apr_byte_t kap_cache_memcache_get(request_rec *r, const char *section,
		const char *key, const char **value) {

	kap_debug(r, "enter, section=\"%s\", key=\"%s\"", section, key);

	kap_cfg *cfg = (kap_cfg *)ap_get_module_config(r->server->module_config,
			&auth_kap_module);
	kap_cache_cfg_memcache_t *context =
			(kap_cache_cfg_memcache_t *) cfg->cache_cfg;

	apr_size_t len = 0;

	/* get it */
	apr_status_t rv = apr_memcache_getp(context->cache_memcache, r->pool,
			kap_cache_memcache_get_key(r->pool, section, key), (char **) value,
			&len, NULL);

	if (rv == APR_NOTFOUND) {
		kap_debug(r, "apr_memcache_getp: key %s not found in cache",
				kap_cache_memcache_get_key(r->pool, section, key));
		return FALSE;
	} else if (rv != APR_SUCCESS) {
		// TODO: error strings ?
		kap_error(r, "apr_memcache_getp returned an error; perhaps your memcache server is not available?");
		return FALSE;
	}

	/* do sanity checking on the string value */
	if ((*value) && (strlen(*value) != len)) {
		kap_error(r,
				"apr_memcache_getp returned less bytes than expected: strlen(value) [%zu] != len [%" APR_SIZE_T_FMT "]",
				strlen(*value), len);
		return FALSE;
	}

	return TRUE;
}

/*
 * store a name/value pair in memcache
 */
static apr_byte_t kap_cache_memcache_set(request_rec *r, const char *section,
		const char *key, const char *value, apr_time_t expiry) {

	kap_debug(r, "enter, section=\"%s\", key=\"%s\"", section, key);

	kap_cfg *cfg = (kap_cfg *)ap_get_module_config(r->server->module_config,
			&auth_kap_module);
	kap_cache_cfg_memcache_t *context =
			(kap_cache_cfg_memcache_t *) cfg->cache_cfg;

	apr_status_t rv = APR_SUCCESS;

	/* see if we should be clearing this entry */
	if (value == NULL) {

		rv = apr_memcache_delete(context->cache_memcache,
				kap_cache_memcache_get_key(r->pool, section, key), 0);

		if (rv == APR_NOTFOUND) {
			kap_debug(r, "apr_memcache_delete: key %s not found in cache",
					kap_cache_memcache_get_key(r->pool, section, key));
		} else if (rv != APR_SUCCESS) {
			// TODO: error strings ?
			kap_error(r,
					"apr_memcache_delete returned an error; perhaps your memcache server is not available?");
		}

	} else {

		/* calculate the timeout from now */
		apr_uint32_t timeout = (apr_uint32_t)apr_time_sec(expiry - apr_time_now());

		/* store it */
		rv = apr_memcache_set(context->cache_memcache,
				kap_cache_memcache_get_key(r->pool, section, key),
				(char *) value, strlen(value), timeout, 0);

		// TODO: error strings ?
		if (rv != APR_SUCCESS) {
			kap_error(r, "apr_memcache_set returned an error; perhaps your memcache server is not available?");
		}
	}

	return (rv == APR_SUCCESS);
}

kap_cache_t kap_cache_memcache = {
		kap_cache_memcache_cfg_create,
		kap_cache_memcache_post_config,
		NULL,
		kap_cache_memcache_get,
		kap_cache_memcache_set,
		NULL
};
