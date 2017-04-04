/*
 * Copyright (C) 2017 Kapstonellc (http://www.kapstonellc.com)
 *
 * Created by Pavlov <pavlov0123@outlook.com>
 * 
 */

#include <apr_hash.h>
#include <apr_time.h>
#include <apr_strings.h>
#include <apr_pools.h>

#include <httpd.h>
#include <http_log.h>

#include "../mod_auth_kap.h"

extern module AP_MODULE_DECLARE_DATA auth_kap_module;

/*
 * header structure that holds the metadata info for a cache file entry
 */
typedef struct {
	/* length of the cached data */
	apr_size_t len;
	/* cache expiry timestamp */
	apr_time_t expire;
} kap_cache_file_info_t;

/*
 * prefix that distinguishes mod_auth_kap cache files from other files in the same directory (/tmp)
 */
#define KAP_CACHE_FILE_PREFIX "mod-auth-connect-"

/* post config routine */
int kap_cache_file_post_config(server_rec *s) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(s->module_config,
			&auth_kap_module);
	if (cfg->cache_file_dir == NULL) {
		/* by default we'll use the OS specified /tmp dir for cache files */
		apr_temp_dir_get((const char **) &cfg->cache_file_dir,
				s->process->pool);
	}
	return OK;
}

/*
 * return the cache file name for a specified key
 */
static const char *kap_cache_file_name(request_rec *r, const char *section,
		const char *key) {
	return apr_psprintf(r->pool, "%s%s-%s", KAP_CACHE_FILE_PREFIX, section,
			key);
}

/*
 * return the fully qualified path name to a cache file for a specified key
 */
static const char *kap_cache_file_path(request_rec *r, const char *section,
		const char *key) {
	kap_cfg *cfg = (kap_cfg *)ap_get_module_config(r->server->module_config,
			&auth_kap_module);
	return apr_psprintf(r->pool, "%s/%s", cfg->cache_file_dir,
			kap_cache_file_name(r, section, key));
}

/*
 * read a specified number of bytes from a cache file in to a preallocated buffer
 */
static apr_status_t kap_cache_file_read(request_rec *r, const char *path,
		apr_file_t *fd, void *buf, const apr_size_t len) {

	apr_status_t rc = APR_SUCCESS;
	apr_size_t bytes_read = 0;
	char s_err[128];

	/* (blocking) read the requested number of bytes */
	rc = apr_file_read_full(fd, buf, len, &bytes_read);

	/* test for system errors */
	if (rc != APR_SUCCESS) {
		kap_error(r, "could not read from: %s (%s)", path,
				apr_strerror(rc, s_err, sizeof(s_err)));
	}

	/* ensure that we've got the requested number of bytes */
	if (bytes_read != len) {
		kap_error(r,
				"could not read enough bytes from: \"%s\", bytes_read (%" APR_SIZE_T_FMT ") != len (%" APR_SIZE_T_FMT ")",
				path, bytes_read, len);
		rc = APR_EGENERAL;
	}

	return rc;
}

/*
 * write a specified number of bytes from a buffer to a cache file
 */
static apr_status_t kap_cache_file_write(request_rec *r, const char *path,
		apr_file_t *fd, void *buf, const apr_size_t len) {

	apr_status_t rc = APR_SUCCESS;
	apr_size_t bytes_written = 0;
	char s_err[128];

	/* (blocking) write the number of bytes in the buffer */
	rc = apr_file_write_full(fd, buf, len, &bytes_written);

	/* check for a system error */
	if (rc != APR_SUCCESS) {
		kap_error(r, "could not write to: \"%s\" (%s)", path,
				apr_strerror(rc, s_err, sizeof(s_err)));
		return rc;
	}

	/* check that all bytes from the header were written */
	if (bytes_written != len) {
		kap_error(r,
				"could not write enough bytes to: \"%s\", bytes_written (%" APR_SIZE_T_FMT ") != len (%" APR_SIZE_T_FMT ")",
				path, bytes_written, len);
		return APR_EGENERAL;
	}

	return rc;
}

/*
 * get a value for the specified key from the cache
 */
static apr_byte_t kap_cache_file_get(request_rec *r, const char *section,
		const char *key, const char **value) {
	apr_file_t *fd = NULL;
	apr_status_t rc = APR_SUCCESS;
	char s_err[128];

	/* get the fully qualified path to the cache file based on the key name */
	const char *path = kap_cache_file_path(r, section, key);

	/* open the cache file if it exists, otherwise we just have a "regular" cache miss */
	if (apr_file_open(&fd, path, APR_FOPEN_READ | APR_FOPEN_BUFFERED,
	APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
		kap_debug(r, "cache miss for key \"%s\"", key);
		return TRUE;
	}

	/* the file exists, now lock it */
	apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);

	/* move the read pointer to the very start of the cache file */
	apr_off_t begin = 0;
	apr_file_seek(fd, APR_SET, &begin);

	/* read a header with metadata */
	kap_cache_file_info_t info;
	if ((rc = kap_cache_file_read(r, path, fd, &info,
			sizeof(kap_cache_file_info_t))) != APR_SUCCESS)
		goto error_close;

	/* check if this cache entry has already expired */
	if (apr_time_now() >= info.expire) {

		/* yep, expired: unlock and close before deleting the cache file */
		apr_file_unlock(fd);
		apr_file_close(fd);

		/* log this event */
		kap_debug(r, "cache entry \"%s\" expired, removing file \"%s\"", key,
				path);

		/* and kill it */
		if ((rc = apr_file_remove(path, r->pool)) != APR_SUCCESS) {
			kap_error(r, "could not delete cache file \"%s\" (%s)", path,
					apr_strerror(rc, s_err, sizeof(s_err)));
		}

		/* nothing strange happened really */
		return TRUE;
	}

	/* allocate space for the actual value based on the data size info in the header (+1 for \0 termination) */
	*value = (const char *)apr_palloc(r->pool, info.len);

	/* (blocking) read the requested data in to the buffer */
	rc = kap_cache_file_read(r, path, fd, (void *) *value, info.len);

	/* barf on failure */
	if (rc != APR_SUCCESS) {
		kap_error(r, "could not read cache value from \"%s\"", path);
		goto error_close;
	}

	/* we're done, unlock and close the file */
	apr_file_unlock(fd);
	apr_file_close(fd);

	/* log a successful cache hit */
	kap_debug(r,
			"cache hit for key \"%s\" (%" APR_SIZE_T_FMT " bytes, expiring in: %" APR_TIME_T_FMT ")",
			key, info.len, apr_time_sec(info.expire - apr_time_now()));

	return TRUE;

error_close:

	apr_file_unlock(fd);
	apr_file_close(fd);

	kap_error(r, "return error status %d (%s)", rc,
			apr_strerror(rc, s_err, sizeof(s_err)));

	return FALSE;
}

// TODO: make these configurable?
#define KAP_CACHE_FILE_LAST_CLEANED "last-cleaned"

/*
 * delete all expired entries from the cache directory
 */
static apr_status_t kap_cache_file_clean(request_rec *r) {
	apr_status_t rc = APR_SUCCESS;
	apr_dir_t *dir = NULL;
	apr_file_t *fd = NULL;
	apr_status_t i;
	apr_finfo_t fi;
	kap_cache_file_info_t info;
	char s_err[128];

	kap_cfg *cfg = (kap_cfg *)ap_get_module_config(r->server->module_config,
			&auth_kap_module);

	/* get the path to the metadata file that holds "last cleaned" metadata info */
	const char *metadata_path = kap_cache_file_path(r, "cache-file",
			KAP_CACHE_FILE_LAST_CLEANED);

	/* open the metadata file if it exists */
	if ((rc = apr_stat(&fi, metadata_path, APR_FINFO_MTIME, r->pool))
			== APR_SUCCESS) {

		/* really only clean once per so much time, check that we haven not recently run */
		if (apr_time_now() < fi.mtime + apr_time_from_sec(cfg->cache_file_clean_interval)) {
			kap_debug(r,
					"last cleanup call was less than %d seconds ago (next one as early as in %" APR_TIME_T_FMT " secs)",
					cfg->cache_file_clean_interval,
					apr_time_sec( fi.mtime + apr_time_from_sec(cfg->cache_file_clean_interval) - apr_time_now()));
			return APR_SUCCESS;
		}

		/* time to clean, reset the modification time of the metadata file to reflect the timestamp of this cleaning cycle */
		apr_file_mtime_set(metadata_path, apr_time_now(), r->pool);

	} else {

		/* no metadata file exists yet, create one (and open it) */
		if ((rc = apr_file_open(&fd, metadata_path,
				(APR_FOPEN_WRITE | APR_FOPEN_CREATE), APR_OS_DEFAULT, r->pool))
				!= APR_SUCCESS) {
			kap_error(r, "error creating cache timestamp file '%s' (%s)",
					metadata_path, apr_strerror(rc, s_err, sizeof(s_err)));
			return rc;
		}

		/* and cleanup... */
		if ((rc = apr_file_close(fd)) != APR_SUCCESS) {
			kap_error(r, "error closing cache timestamp file '%s' (%s)",
					metadata_path, apr_strerror(rc, s_err, sizeof(s_err)));
		}
	}

	/* time to clean, open the cache directory */
	if ((rc = apr_dir_open(&dir, cfg->cache_file_dir, r->pool)) != APR_SUCCESS) {
		kap_error(r, "error opening cache directory '%s' for cleaning (%s)",
				cfg->cache_file_dir, apr_strerror(rc, s_err, sizeof(s_err)));
		return rc;
	}

	/* loop trough the cache file entries */
	do {

		/* read the next entry from the directory */
		i = apr_dir_read(&fi, APR_FINFO_NAME, dir);

		if (i == APR_SUCCESS) {

			/* skip non-cache entries, cq. the ".", ".." and the metadata file */
			if ((fi.name[0] == '.')
					|| (strstr(fi.name, KAP_CACHE_FILE_PREFIX) != fi.name)
					|| ((apr_strnatcmp(fi.name,
							kap_cache_file_name(r, "cache-file",
									KAP_CACHE_FILE_LAST_CLEANED)) == 0)))
				continue;

			/* get the fully qualified path to the cache file and open it */
			const char *path = apr_psprintf(r->pool, "%s/%s",
					cfg->cache_file_dir, fi.name);
			if ((rc = apr_file_open(&fd, path, APR_FOPEN_READ, APR_OS_DEFAULT,
					r->pool)) != APR_SUCCESS) {
				kap_error(r, "unable to open cache entry \"%s\" (%s)", path,
						apr_strerror(rc, s_err, sizeof(s_err)));
				continue;
			}

			/* read the header with cache metadata info */
			rc = kap_cache_file_read(r, path, fd, &info,
					sizeof(kap_cache_file_info_t));
			apr_file_close(fd);

			if (rc == APR_SUCCESS) {

				/* check if this entry expired, if not just continue to the next entry */
				if (apr_time_now() < info.expire)
					continue;

				/* the cache entry expired, we're going to remove it so log that event */
				kap_debug(r, "cache entry (%s) expired, removing file \"%s\")",
						fi.name, path);

			} else {

				/* file open returned an error, log that */
				kap_error(r,
						"cache entry (%s) corrupted (%s), removing file \"%s\"",
						fi.name, apr_strerror(rc, s_err, sizeof(s_err)), path);

			}

			/* delete the cache file */
			if ((rc = apr_file_remove(path, r->pool)) != APR_SUCCESS) {

				/* hrm, this will most probably happen again on the next run... */
				kap_error(r, "could not delete cache file \"%s\" (%s)", path,
						apr_strerror(rc, s_err, sizeof(s_err)));
			}

		}

	} while (i == APR_SUCCESS);

	apr_dir_close(dir);

	return APR_SUCCESS;
}

/*
 * write a value for the specified key to the cache
 */
static apr_byte_t kap_cache_file_set(request_rec *r, const char *section,
		const char *key, const char *value, apr_time_t expiry) {
	apr_file_t *fd = NULL;
	apr_status_t rc = APR_SUCCESS;
	char s_err[128];

	/* get the fully qualified path to the cache file based on the key name */
	const char *path = kap_cache_file_path(r, section, key);

	/* only on writes (not on reads) we clean the cache first (if not done recently) */
	kap_cache_file_clean(r);

	/* just remove cache file if value is NULL */
	if (value == NULL) {
		if ((rc = apr_file_remove(path, r->pool)) != APR_SUCCESS) {
			kap_error(r, "could not delete cache file \"%s\" (%s)", path,
					apr_strerror(rc, s_err, sizeof(s_err)));
		}
		return TRUE;
	}

	/* try to open the cache file for writing, creating it if it does not exist */
	if ((rc = apr_file_open(&fd, path, (APR_FOPEN_WRITE | APR_FOPEN_CREATE),
	APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) {
		kap_error(r, "cache file \"%s\" could not be opened (%s)", path,
				apr_strerror(rc, s_err, sizeof(s_err)));
		return FALSE;
	}

	/* lock the file and move the write pointer to the start of it */
	apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);
	apr_off_t begin = 0;
	apr_file_seek(fd, APR_SET, &begin);

	/* construct the metadata for this cache entry in the header info */
	kap_cache_file_info_t info;
	info.expire = expiry;
	info.len = strlen(value) + 1;

	/* write the header */
	if ((rc = kap_cache_file_write(r, path, fd, &info,
			sizeof(kap_cache_file_info_t))) != APR_SUCCESS)
		return FALSE;

	/* next write the value */
	if ((rc = kap_cache_file_write(r, path, fd, (void *) value, info.len))
			!= APR_SUCCESS)
		return FALSE;

	/* unlock and close the written file */
	apr_file_unlock(fd);
	apr_file_close(fd);

	/* log our success */
	kap_debug(r,
			"set entry for key \"%s\" (%" APR_SIZE_T_FMT " bytes, expires in: %" APR_TIME_T_FMT ")",
			key, info.len, apr_time_sec(expiry - apr_time_now()));

	return TRUE;
}

kap_cache_t kap_cache_file = {
		NULL,
		kap_cache_file_post_config,
		NULL,
		kap_cache_file_get,
		kap_cache_file_set,
		NULL
};
