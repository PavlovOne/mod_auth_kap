/*
 * Copyright (C) 2017 Kapstonellc (http://www.kapstonellc.com)
 *
 * Created by Pavlov <pavlov0123@outlook.com>
 * 
 */

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>

#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

#include "mod_auth_kap.h"

/*
 * initialize the crypto context in the server configuration record; the passphrase is set already
 */
static apr_byte_t kap_crypto_init(kap_cfg *cfg, server_rec *s) {

	if (cfg->encrypt_ctx != NULL)
		return TRUE;

	unsigned char *key_data = (unsigned char *) cfg->crypto_passphrase;
	int key_data_len = (int)strlen(cfg->crypto_passphrase);

	unsigned int s_salt[] = { 41892, 72930 };
	unsigned char *salt = (unsigned char *) &s_salt;

	int i, nrounds = 5;
	unsigned char key[32], iv[32];

	/*
	 * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
	 * nrounds is the number of times the we hash the material. More rounds are more secure but
	 * slower.
	 */
	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data,
			key_data_len, nrounds, key, iv);
	if (i != 32) {
		kap_serror(s, "key size must be 256 bits!");
		return FALSE;
	}

	cfg->encrypt_ctx = (EVP_CIPHER_CTX *)apr_palloc(s->process->pool, sizeof(EVP_CIPHER_CTX));
	cfg->decrypt_ctx = (EVP_CIPHER_CTX *)apr_palloc(s->process->pool, sizeof(EVP_CIPHER_CTX));

	/* initialize the encoding context */
	EVP_CIPHER_CTX_init(cfg->encrypt_ctx);
	if (!EVP_EncryptInit_ex(cfg->encrypt_ctx, EVP_aes_256_cbc(), NULL, key,
			iv)) {
		kap_serror(s, "EVP_EncryptInit_ex on the encrypt context failed: %s",
				ERR_error_string(ERR_get_error(), NULL));
		return FALSE;
	}

	/* initialize the decoding context */
	EVP_CIPHER_CTX_init(cfg->decrypt_ctx);
	if (!EVP_DecryptInit_ex(cfg->decrypt_ctx, EVP_aes_256_cbc(), NULL, key,
			iv)) {
		kap_serror(s, "EVP_DecryptInit_ex on the decrypt context failed: %s",
				ERR_error_string(ERR_get_error(), NULL));
		return FALSE;
	}

	return TRUE;
}

/*
 * AES encrypt plaintext
 */
unsigned char *kap_crypto_aes_encrypt(request_rec *r, kap_cfg *cfg,
		unsigned char *plaintext, int *len) {

	if (kap_crypto_init(cfg, r->server) == FALSE)
		return NULL;

	/* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	unsigned char *ciphertext = (unsigned char *)apr_palloc(r->pool, c_len);

	/* allows reusing of 'e' for multiple encryption cycles */
	if (!EVP_EncryptInit_ex(cfg->encrypt_ctx, NULL, NULL, NULL, NULL)) {
		kap_error(r, "EVP_EncryptInit_ex failed: %s",
				ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	/* update ciphertext, c_len is filled with the length of ciphertext generated, len is the size of plaintext in bytes */
	if (!EVP_EncryptUpdate(cfg->encrypt_ctx, ciphertext, &c_len, plaintext,
			*len)) {
		kap_error(r, "EVP_EncryptUpdate failed: %s",
				ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	/* update ciphertext with the final remaining bytes */
	if (!EVP_EncryptFinal_ex(cfg->encrypt_ctx, ciphertext + c_len, &f_len)) {
		kap_error(r, "EVP_EncryptFinal_ex failed: %s",
				ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	*len = c_len + f_len;

	return ciphertext;
}

/*
 * AES decrypt ciphertext
 */
unsigned char *kap_crypto_aes_decrypt(request_rec *r, kap_cfg *cfg,
		unsigned char *ciphertext, int *len) {

	if (kap_crypto_init(cfg, r->server) == FALSE)
		return NULL;

	/* because we have padding ON, we must allocate an extra cipher block size of memory */
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = (unsigned char *)apr_palloc(r->pool, p_len + AES_BLOCK_SIZE);

	/* allows reusing of 'e' for multiple encryption cycles */
	if (!EVP_DecryptInit_ex(cfg->decrypt_ctx, NULL, NULL, NULL, NULL)) {
		kap_error(r, "EVP_DecryptInit_ex failed: %s",
				ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	/* update plaintext, p_len is filled with the length of plaintext generated, len is the size of ciphertext in bytes */
	if (!EVP_DecryptUpdate(cfg->decrypt_ctx, plaintext, &p_len, ciphertext,
			*len)) {
		kap_error(r, "EVP_DecryptUpdate failed: %s",
				ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	/* update plaintext with the final remaining bytes */
	if (!EVP_DecryptFinal_ex(cfg->decrypt_ctx, plaintext + p_len, &f_len)) {
		kap_error(r, "EVP_DecryptFinal_ex failed: %s",
				ERR_error_string(ERR_get_error(), NULL));
		return NULL;
	}

	*len = p_len + f_len;

	return plaintext;
}

/*
 * cleanup the crypto context in the server configuration record
 */
apr_byte_t kap_crypto_destroy(kap_cfg *cfg, server_rec *s) {

	if (cfg->encrypt_ctx == NULL)
		return TRUE;

	EVP_CIPHER_CTX_cleanup(cfg->encrypt_ctx);
	EVP_CIPHER_CTX_cleanup(cfg->decrypt_ctx);

	cfg->encrypt_ctx = NULL;
	cfg->decrypt_ctx = NULL;

	return TRUE;
}
