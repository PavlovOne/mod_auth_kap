/*
 * Copyright (C) 2017 Kapstonellc (http://www.kapstonellc.com)
 *
 * Created by Pavlov <pavlov0123@outlook.com>
 * 
 */

#ifndef WIN32
#include <unistd.h>
#endif

#include "apr_general.h"

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

#include "../mod_auth_kap.h"

/* create the cache lock context */
kap_cache_mutex_t *kap_cache_mutex_create(apr_pool_t *pool) {
	kap_cache_mutex_t *ctx = (kap_cache_mutex_t *)apr_pcalloc(pool, sizeof(kap_cache_mutex_t));
	ctx->mutex = NULL;
	ctx->mutex_filename = NULL;
	return ctx;
}

apr_byte_t kap_cache_mutex_post_config(server_rec *s, kap_cache_mutex_t *m,
		const char *type) {

	apr_status_t rv = APR_SUCCESS;
	const char *dir;

	/* construct the mutex filename */
	apr_temp_dir_get(&dir, s->process->pool);
	m->mutex_filename = apr_psprintf(s->process->pool,
			"%s/mod_auth_kap_%s_mutex.%ld.%pp", dir, type,
			(long int) getpid(), s);

	/* create the mutex lock */
	rv = apr_global_mutex_create(&m->mutex, (const char *) m->mutex_filename,
			APR_LOCK_DEFAULT, s->process->pool);
	if (rv != APR_SUCCESS) {
		kap_serror(s,
				"apr_global_mutex_create failed to create mutex on file %s",
				m->mutex_filename);
		return FALSE;
	}

	/* need this on Linux */
#ifdef AP_NEED_SET_MUTEX_PERMS
#if MODULE_MAGIC_NUMBER_MAJOR >= 20081201
	rv = ap_unixd_set_global_mutex_perms(m->mutex);
#else
	rv = unixd_set_global_mutex_perms(m->mutex);
#endif
	if (rv != APR_SUCCESS) {
		kap_serror(s,
				"unixd_set_global_mutex_perms failed; could not set permissions ");
		return FALSE;
	}
#endif

	return TRUE;
}

/*
 * initialize the cache lock in a child process
 */
apr_status_t kap_cache_mutex_child_init(apr_pool_t *p, server_rec *s,
		kap_cache_mutex_t *m) {

	/* initialize the lock for the child process */
	apr_status_t rv = apr_global_mutex_child_init(&m->mutex,
			(const char *) m->mutex_filename, p);

	if (rv != APR_SUCCESS) {
		kap_serror(s,
				"apr_global_mutex_child_init failed to reopen mutex on file %s",
				m->mutex_filename);
	}

	return rv;
}

/*
 * global lock
 */
apr_byte_t kap_cache_mutex_lock(request_rec *r, kap_cache_mutex_t *m) {

	apr_status_t rv = apr_global_mutex_lock(m->mutex);

	if (rv != APR_SUCCESS) {
		kap_error(r, "apr_global_mutex_lock() failed [%d]", rv);
		return FALSE;
	}

	return TRUE;
}

/*
 * global unlock
 */
apr_byte_t kap_cache_mutex_unlock(request_rec *r, kap_cache_mutex_t *m) {

	apr_status_t rv = apr_global_mutex_unlock(m->mutex);

	if (rv != APR_SUCCESS) {
		kap_error(r, "apr_global_mutex_unlock() failed [%d]", rv);
		return FALSE;
	}

	return TRUE;
}

/*
 * destroy mutex
 */
apr_byte_t kap_cache_mutex_destroy(server_rec *s, kap_cache_mutex_t *m) {

	apr_status_t rv = APR_SUCCESS;

	if (m->mutex != NULL) {
		rv = apr_global_mutex_destroy(m->mutex);
		if (rv != APR_SUCCESS) {
			kap_swarn(s, "apr_global_mutex_destroy failed: [%d]", rv);
		}
		m->mutex = NULL;
	}

	return rv;
}
