/*
 * Copyright (C) 2017 Kapstonellc (http://www.kapstonellc.com)
 *
 * Created by Pavlov <pavlov0123@outlook.com>
 * 
 */

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include "../mod_auth_kap.h"

extern module AP_MODULE_DECLARE_DATA auth_kap_module;

typedef struct kap_cache_cfg_shm_t {
	apr_shm_t *shm;
	kap_cache_mutex_t *mutex;
} kap_cache_cfg_shm_t;

/* size of key in cached key/value pairs */
#define KAP_CACHE_SHM_KEY_MAX 512
#define KAP_CACHE_SHM_VALUE_MAX 2048

/* represents one (fixed size) cache entry, cq. name/value string pair */
typedef struct kap_cache_shm_entry_t {
	/* name of the cache entry */
	char section_key[KAP_CACHE_SHM_KEY_MAX];
	/* last (read) access timestamp */
	apr_time_t access;
	/* expiry timestamp */
	apr_time_t expires;
	/* value of the cache entry */
	char value[KAP_CACHE_SHM_VALUE_MAX];
} kap_cache_shm_entry_t;

/* create the cache context */
static void *kap_cache_shm_cfg_create(apr_pool_t *pool) {
	kap_cache_cfg_shm_t *context = (kap_cache_cfg_shm_t *)apr_pcalloc(pool,
			sizeof(kap_cache_cfg_shm_t));
	context->shm = NULL;
	context->mutex = kap_cache_mutex_create(pool);
	return context;
}

#define KAP_CACHE_SHM_ADD_OFFSET(t, size) t = (kap_cache_shm_entry_t *)((uint8_t *)t + size)

/*
 * initialized the shared memory block in the parent process
 */
int kap_cache_shm_post_config(server_rec *s) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(s->module_config,
			&auth_kap_module);

	if (cfg->cache_cfg != NULL)
		return APR_SUCCESS;
	kap_cache_cfg_shm_t *context = (kap_cache_cfg_shm_t *)kap_cache_shm_cfg_create(s->process->pool);
	cfg->cache_cfg = context;

	/* create the shared memory segment */
	apr_status_t rv = apr_shm_create(&context->shm,
			cfg->cache_shm_entry_size_max * cfg->cache_shm_size_max,
			NULL, s->process->pool);
	if (rv != APR_SUCCESS) {
		kap_serror(s, "apr_shm_create failed to create shared memory segment");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* initialize the whole segment to '/0' */
	int i;
	kap_cache_shm_entry_t *t = (kap_cache_shm_entry_t *)apr_shm_baseaddr_get(context->shm);
	for (i = 0; i < cfg->cache_shm_size_max; i++, KAP_CACHE_SHM_ADD_OFFSET(t, cfg->cache_shm_entry_size_max)) {
		t->section_key[0] = '\0';
		t->access = 0;
	}

	if (kap_cache_mutex_post_config(s, context->mutex, "shm") == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	kap_sdebug(s, "initialized shared memory with a cache size (# entries) of: %d, and a max (single) entry size of: %d", cfg->cache_shm_size_max, cfg->cache_shm_entry_size_max);

	return OK;
}

/*
 * initialize the shared memory segment in a child process
 */
int kap_cache_shm_child_init(apr_pool_t *p, server_rec *s) {
	kap_cfg *cfg = (kap_cfg *)ap_get_module_config(s->module_config,
			&auth_kap_module);
	kap_cache_cfg_shm_t *context = (kap_cache_cfg_shm_t *) cfg->cache_cfg;

	/* initialize the lock for the child process */
	return kap_cache_mutex_child_init(p, s, context->mutex);
}

/*
 * assemble single key name based on section/key input
 */
static char *kap_cache_shm_get_key(apr_pool_t *pool, const char *section,
		const char *key) {
	return apr_psprintf(pool, "%s:%s", section, key);
}

/*
 * get a value from the shared memory cache
 */
static apr_byte_t kap_cache_shm_get(request_rec *r, const char *section,
		const char *key, const char **value) {

	kap_debug(r, "enter, section=\"%s\", key=\"%s\"", section, key);

	kap_cfg *cfg = (kap_cfg *)ap_get_module_config(r->server->module_config,
			&auth_kap_module);
	kap_cache_cfg_shm_t *context = (kap_cache_cfg_shm_t *) cfg->cache_cfg;

	int i;
	const char *section_key = kap_cache_shm_get_key(r->pool, section, key);

	*value = NULL;

	/* grab the global lock */
	if (kap_cache_mutex_lock(r, context->mutex) == FALSE)
		return FALSE;

	/* get the pointer to the start of the shared memory block */
	kap_cache_shm_entry_t *t = (kap_cache_shm_entry_t *)apr_shm_baseaddr_get(context->shm);

	/* loop over the block, looking for the key */
	for (i = 0; i < cfg->cache_shm_size_max; i++, KAP_CACHE_SHM_ADD_OFFSET(t, cfg->cache_shm_entry_size_max)) {
		const char *tablekey = t->section_key;

		if ( (tablekey != NULL) && (apr_strnatcmp(tablekey, section_key) == 0) ) {

			/* found a match, check if it has expired */
			if (t->expires > apr_time_now()) {

				/* update access timestamp */
				t->access = apr_time_now();
				*value = t->value;

			} else {

				/* clear the expired entry */
				t->section_key[0] = '\0';
				t->access = 0;

			}

			/* we safely can break now since we would not have found an expired match twice */
			break;
		}
	}

	/* release the global lock */
	kap_cache_mutex_unlock(r, context->mutex);

	return (*value == NULL) ? FALSE : TRUE;
}

/*
 * store a value in the shared memory cache
 */
static apr_byte_t kap_cache_shm_set(request_rec *r, const char *section,
		const char *key, const char *value, apr_time_t expiry) {

	kap_debug(r, "enter, section=\"%s\", key=\"%s\", value size=%llu", section,
			key, value ? (unsigned long long )strlen(value) : 0);

	kap_cfg *cfg = (kap_cfg *)ap_get_module_config(r->server->module_config,
			&auth_kap_module);
	kap_cache_cfg_shm_t *context = (kap_cache_cfg_shm_t *) cfg->cache_cfg;

	kap_cache_shm_entry_t *match, *free, *lru;
	kap_cache_shm_entry_t *t;
	apr_time_t current_time;
	int i;
	apr_time_t age;

	const char *section_key = kap_cache_shm_get_key(r->pool, section, key);

	/* check that the passed in key is valid */
	if (strlen(section_key) > KAP_CACHE_SHM_KEY_MAX) {
		kap_error(r, "could not store value since key size is too large (%s)",
				section_key);
		return FALSE;
	}

	/* check that the passed in value is valid */
	if ((value != NULL) && (strlen(value) > (cfg->cache_shm_entry_size_max - sizeof(kap_cache_shm_entry_t)))) {
		kap_error(r, "could not store value since value size is too large (%llu > %lu); consider increasing KAPCacheShmEntrySizeMax",
				(unsigned long long)strlen(value), (unsigned long)(cfg->cache_shm_entry_size_max - sizeof(kap_cache_shm_entry_t)));
		return FALSE;
	}

	/* grab the global lock */
	if (kap_cache_mutex_lock(r, context->mutex) == FALSE)
		return FALSE;

	/* get a pointer to the shared memory block */
	t = (kap_cache_shm_entry_t *)apr_shm_baseaddr_get(context->shm);

	/* get the current time */
	current_time = apr_time_now();

	/* loop over the block, looking for the key */
	match = NULL;
	free = NULL;
	lru = t;
	for (i = 0; i < cfg->cache_shm_size_max; i++, KAP_CACHE_SHM_ADD_OFFSET(t, cfg->cache_shm_entry_size_max)) {

		/* see if this slot is free */
		if (t->section_key[0] == '\0') {
			if (free == NULL)
				free = t;
			continue;
		}

		/* see if a value already exists for this key */
		if (apr_strnatcmp(t->section_key, section_key) == 0) {
			match = t;
			break;
		}

		/* see if this slot has expired */
		if (t->expires <= current_time) {
			if (free == NULL)
				free = t;
			continue;
		}

		/* see if this slot was less recently used than the current pointer */
		if (t->access < lru->access) {
			lru = t;
		}

	}

	/* if we have no free slots, issue a warning about the LRU entry */
	if (match == NULL && free == NULL) {
		age = (current_time - lru->access) / 1000000;
		if (age < 3600) {
			kap_warn(r,
					"dropping LRU entry with age = %" APR_TIME_T_FMT "s, which is less than one hour; consider increasing the shared memory caching space (which is %d now) with the (global) KAPCacheShmMax setting.",
					age, cfg->cache_shm_size_max);
		}
	}

	/* pick the best slot: choose one with a matching key over a free slot, over a least-recently-used one */
	t = match ? match : (free ? free : lru);

	/* see if we need to clear or set the value */
	if (value != NULL) {

		/* fill out the entry with the provided data */
		strcpy(t->section_key, section_key);
		strcpy(t->value, value);
		t->expires = expiry;
		t->access = current_time;

	} else {

		t->section_key[0] = '\0';
		t->access = 0;

	}

	/* release the global lock */
	kap_cache_mutex_unlock(r, context->mutex);

	return TRUE;
}

static int kap_cache_shm_destroy(server_rec *s) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(s->module_config,
			&auth_kap_module);
	kap_cache_cfg_shm_t *context = (kap_cache_cfg_shm_t *) cfg->cache_cfg;
	apr_status_t rv = APR_SUCCESS;

	if (context->shm) {
		rv = apr_shm_destroy(context->shm);
		kap_sdebug(s, "apr_shm_destroy returned: %d", rv);
		context->shm = NULL;
	}

	kap_cache_mutex_destroy(s, context->mutex);

	return rv;
}

kap_cache_t kap_cache_shm = {
		kap_cache_shm_cfg_create,
		kap_cache_shm_post_config,
		kap_cache_shm_child_init,
		kap_cache_shm_get,
		kap_cache_shm_set,
		kap_cache_shm_destroy
};
