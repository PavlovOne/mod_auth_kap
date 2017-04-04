/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/***************************************************************************
 * Copyright (C) 2013-2015 Ping Identity Corporation
 * All rights reserved.
 *
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
 *
 * DISCLAIMER OF WARRANTIES:
 *
 * THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
 * ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
 * WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
 * WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
 * USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
 * YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
 * WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * caching using a Redis backend
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include "apr_general.h"
#include "apr_strings.h"

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include "../mod_auth_kap.h"

#include "hiredis/hiredis.h"

// TODO: proper Redis error reporting (server unreachable etc.)

extern module AP_MODULE_DECLARE_DATA auth_kap_module;

typedef struct kap_cache_cfg_redis_t {
	/* cache_type = redis: Redis ptr */
	kap_cache_mutex_t *mutex;
	char *host_str;
	apr_port_t port;
} kap_cache_cfg_redis_t;

/* create the cache context */
static void *kap_cache_redis_cfg_create(apr_pool_t *pool) {
	kap_cache_cfg_redis_t *context = apr_pcalloc(pool,
			sizeof(kap_cache_cfg_redis_t));
	context->mutex = kap_cache_mutex_create(pool);
	return context;
}

/*
 * initialize the Redis struct the specified Redis server
 */
static int kap_cache_redis_post_config(server_rec *s) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(s->module_config,
			&auth_kap_module);

	if (cfg->cache_cfg != NULL)
		return APR_SUCCESS;
	kap_cache_cfg_redis_t *context = kap_cache_redis_cfg_create(
			s->process->pool);
	cfg->cache_cfg = context;

	apr_status_t rv = APR_SUCCESS;

	/* parse the host:post tuple from the configuration */
	if (cfg->cache_redis_server == NULL) {
		kap_serror(s,
				"cache type is set to \"redis\", but no valid KAPRedisCacheServer setting was found");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	char* scope_id;
	rv = apr_parse_addr_port(&context->host_str, &scope_id, &context->port,
			cfg->cache_redis_server, s->process->pool);
	if (rv != APR_SUCCESS) {
		kap_serror(s, "failed to parse cache server: '%s'",
				cfg->cache_redis_server);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (context->host_str == NULL) {
		kap_serror(s,
				"failed to parse cache server, no hostname specified: '%s'",
				cfg->cache_redis_server);
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (context->port == 0)
		context->port = 6379;

	if (kap_cache_mutex_post_config(s, context->mutex, "redis") == FALSE)
		return HTTP_INTERNAL_SERVER_ERROR;

	return OK;
}

/*
 * initialize the Redis cache in a child process
 */
int kap_cache_redis_child_init(apr_pool_t *p, server_rec *s) {
	kap_cfg *cfg = ap_get_module_config(s->module_config,
			&auth_kap_module);
	kap_cache_cfg_redis_t *context = (kap_cache_cfg_redis_t *) cfg->cache_cfg;

	/* initialize the lock for the child process */
	return kap_cache_mutex_child_init(p, s, context->mutex);
}

/*
 * assemble single key name based on section/key input
 */
static char *kap_cache_redis_get_key(apr_pool_t *pool, const char *section,
		const char *key) {
	return apr_psprintf(pool, "%s:%s", section, key);
}

/* key for storing data in the process pool */
#define KAP_CACHE_REDIS_CONTEXT "kap_cache_redis_context"

/*
 * connect to Redis server
 */
static redisContext * kap_cache_redis_connect(request_rec *r,
		kap_cache_cfg_redis_t *context) {

	/* see if we already have a connection by looking it up in the process context */
	redisContext *ctx = NULL;
	apr_pool_userdata_get((void **) &ctx, KAP_CACHE_REDIS_CONTEXT,
			r->server->process->pool);

	if (ctx == NULL) {

		/* no connection, connect to the configured Redis server */
		ctx = redisConnect(context->host_str, context->port);

		/* check for errors */
		if ((ctx == NULL) || (ctx->err != 0)) {
			kap_error(r, "failed to connect to Redis server (%s:%d): '%s'",
					context->host_str, context->port, ctx->errstr);
			return NULL;
		}

		/* store the connection in the process context */
		apr_pool_userdata_set(ctx, KAP_CACHE_REDIS_CONTEXT,
				(apr_status_t (*)(void *)) redisFree, r->server->process->pool);

		/* log the connection */
		kap_debug(r, "successfully connected to Redis server (%s:%d)",
				context->host_str, context->port);
	}

	return ctx;
}

/*
 * execute Redis command and deal with return value
 */
static redisReply* kap_cache_redis_command(request_rec *r,
		kap_cache_cfg_redis_t *context, const char *format, ...) {

	redisContext *ctx = NULL;
	redisReply *reply = NULL;
	int i = 0;

	/* try to execute a command at max 2 times while reconnecting */
	for (i = 0; i < 2; i++) {

		/* connect */
		ctx = kap_cache_redis_connect(r, context);
		if (ctx == NULL)
			break;

		/* execute the command */
		va_list args;
		va_start(args, format);
		reply = redisvCommand(ctx, format, args);
		va_end(args);

		/* errors will result in an empty reply */
		if (reply != NULL)
			break;

		/* something went wrong, log it */
		kap_error(r, "redisvCommand (%d) failed, disconnecting: '%s'", i, ctx->errstr);

		/* cleanup, we may try again (once) after reconnecting */
		redisFree(ctx);
		apr_pool_userdata_set(NULL, KAP_CACHE_REDIS_CONTEXT,
				apr_pool_cleanup_null, r->server->process->pool);
	}

	return reply;
}

/*
 * get a name/value pair from Redis
 */
static apr_byte_t kap_cache_redis_get(request_rec *r, const char *section,
		const char *key, const char **value) {

	kap_debug(r, "enter, section=\"%s\", key=\"%s\"", section, key);

	kap_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_kap_module);
	kap_cache_cfg_redis_t *context = (kap_cache_cfg_redis_t *) cfg->cache_cfg;
	redisReply *reply = NULL;

	/* grab the global lock */
	if (kap_cache_mutex_lock(r, context->mutex) == FALSE)
		return FALSE;

	/* get */
	reply = kap_cache_redis_command(r, context, "GET %s",
			kap_cache_redis_get_key(r->pool, section, key));
	if (reply == NULL) {
		kap_cache_mutex_unlock(r, context->mutex);
		return FALSE;
	}

	/* check that we got a string back */
	if (reply->type != REDIS_REPLY_STRING) {
		freeReplyObject(reply);
		/* this is a normal cache miss, so we'll return OK */
		kap_cache_mutex_unlock(r, context->mutex);
		return TRUE;
	}

	/* do a sanity check on the returned value */
	if (reply->len != strlen(reply->str)) {
		kap_error(r, "redisCommand reply->len != strlen(reply->str): '%s'",
				reply->str);
		freeReplyObject(reply);
		kap_cache_mutex_unlock(r, context->mutex);
		return FALSE;
	}

	/* copy it in to the request memory pool */
	*value = apr_pstrdup(r->pool, reply->str);
	freeReplyObject(reply);

	/* release the global lock */
	kap_cache_mutex_unlock(r, context->mutex);

	return TRUE;
}

/*
 * store a name/value pair in Redis
 */
static apr_byte_t kap_cache_redis_set(request_rec *r, const char *section,
		const char *key, const char *value, apr_time_t expiry) {

	kap_debug(r, "enter, section=\"%s\", key=\"%s\"", section, key);

	kap_cfg *cfg = ap_get_module_config(r->server->module_config,
			&auth_kap_module);
	kap_cache_cfg_redis_t *context = (kap_cache_cfg_redis_t *) cfg->cache_cfg;
	redisReply *reply = NULL;

	/* grab the global lock */
	if (kap_cache_mutex_lock(r, context->mutex) == FALSE)
		return FALSE;

	/* see if we should be clearing this entry */
	if (value == NULL) {

		/* delete it */
		reply = kap_cache_redis_command(r, context, "DEL %s",
				kap_cache_redis_get_key(r->pool, section, key));
		if (reply == NULL) {
			kap_cache_mutex_unlock(r, context->mutex);
			return FALSE;
		}

		freeReplyObject(reply);

	} else {

		/* calculate the timeout from now */
		apr_uint32_t timeout = apr_time_sec(expiry - apr_time_now());

		/* store it */
		reply = kap_cache_redis_command(r, context, "SETEX %s %d %s",
				kap_cache_redis_get_key(r->pool, section, key), timeout,
				value);
		if (reply == NULL) {
			kap_cache_mutex_unlock(r, context->mutex);
			return FALSE;
		}

		freeReplyObject(reply);

	}

	/* release the global lock */
	kap_cache_mutex_unlock(r, context->mutex);

	return TRUE;
}

static int kap_cache_redis_destroy(server_rec *s) {
	kap_cfg *cfg = (kap_cfg *) ap_get_module_config(s->module_config,
			&auth_kap_module);
	kap_cache_cfg_redis_t *context = (kap_cache_cfg_redis_t *) cfg->cache_cfg;

	kap_cache_mutex_destroy(s, context->mutex);

	return APR_SUCCESS;
}

kap_cache_t kap_cache_redis = {
		kap_cache_redis_cfg_create,
		kap_cache_redis_post_config,
		kap_cache_redis_child_init,
		kap_cache_redis_get,
		kap_cache_redis_set,
		kap_cache_redis_destroy
};
