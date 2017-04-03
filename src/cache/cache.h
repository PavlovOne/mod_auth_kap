/*
 * Copyright (C) 2017 Kapstonellc (http://www.kapstonellc.com)
 *
 * Created by Pavlov <pavlov0123@outlook.com>
 * 
 */

#ifndef _MOD_AUTH_KAP_CACHE_H_
#define _MOD_AUTH_KAP_CACHE_H_

typedef void * (*kap_cache_cfg_create)(apr_pool_t *pool);
typedef int (*kap_cache_post_config_function)(server_rec *s);
typedef int (*kap_cache_child_init_function)(apr_pool_t *p, server_rec *s);
typedef apr_byte_t (*kap_cache_get_function)(request_rec *r,
		const char *section, const char *key, const char **value);
typedef apr_byte_t (*kap_cache_set_function)(request_rec *r,
		const char *section, const char *key, const char *value,
		apr_time_t expiry);
typedef int (*kap_cache_destroy_function)(server_rec *s);

typedef struct kap_cache_t {
	kap_cache_cfg_create create_config;
	kap_cache_post_config_function post_config;
	kap_cache_child_init_function child_init;
	kap_cache_get_function get;
	kap_cache_set_function set;
	kap_cache_destroy_function destroy;
} kap_cache_t;

typedef struct kap_cache_mutex_t {
	apr_global_mutex_t *mutex;
	char *mutex_filename;
} kap_cache_mutex_t;

kap_cache_mutex_t *kap_cache_mutex_create(apr_pool_t *pool);
apr_byte_t kap_cache_mutex_post_config(server_rec *s, kap_cache_mutex_t *m,
		const char *type);
apr_status_t kap_cache_mutex_child_init(apr_pool_t *p, server_rec *s,
		kap_cache_mutex_t *m);
apr_byte_t kap_cache_mutex_lock(request_rec *r, kap_cache_mutex_t *m);
apr_byte_t kap_cache_mutex_unlock(request_rec *r, kap_cache_mutex_t *m);
apr_byte_t kap_cache_mutex_destroy(server_rec *s, kap_cache_mutex_t *m);

extern kap_cache_t kap_cache_file;
extern kap_cache_t kap_cache_memcache;
extern kap_cache_t kap_cache_shm;

#ifdef USE_LIBHIREDIS
extern kap_cache_t kap_cache_redis;
#endif

#endif /* _MOD_AUTH_KAP_CACHE_H_ */
