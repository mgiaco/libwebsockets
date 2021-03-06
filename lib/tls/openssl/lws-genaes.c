/*
 * libwebsockets - generic AES api hiding the backend
 *
 * Copyright (C) 2017 - 2018 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 *
 *  lws_genaes provides an AES abstraction api in lws that works the
 *  same whether you are using openssl or mbedtls hash functions underneath.
 */
#include "core/private.h"
#include "../../jose/private.h"

/*
 * Care: many openssl apis return 1 for success.  These are translated to the
 * lws convention of 0 for success.
 */

LWS_VISIBLE int
lws_genaes_create(struct lws_genaes_ctx *ctx, enum enum_aes_operation op,
		  enum enum_aes_modes mode, struct lws_gencrypto_keyelem *el,
		  int padding, void *engine)
{
	int n;

	ctx->ctx = EVP_CIPHER_CTX_new();
	if (!ctx->ctx)
		return -1;

	ctx->mode = mode;
	ctx->k = el;
	ctx->engine = engine;
	ctx->init = 0;
	ctx->op = op;

	switch (ctx->k->len) {
	case 128 / 8:
		switch (mode) {
		case LWS_GAESM_CBC:
			ctx->cipher = EVP_aes_128_cbc();
			break;
		case LWS_GAESM_CFB128:
			ctx->cipher = EVP_aes_128_cfb128();
			break;
		case LWS_GAESM_CFB8:
			ctx->cipher = EVP_aes_128_cfb8();
			break;
		case LWS_GAESM_CTR:
			ctx->cipher = EVP_aes_128_ctr();
			break;
		case LWS_GAESM_ECB:
			ctx->cipher = EVP_aes_128_ecb();
			break;
		case LWS_GAESM_OFB:
			ctx->cipher = EVP_aes_128_ofb();
			break;
		case LWS_GAESM_XTS:
			lwsl_err("%s: AES XTS requires double-length key\n",
				 __func__);
			break;
		case LWS_GAESM_GCM:
			ctx->cipher = EVP_aes_128_gcm();
			break;
		default:
			return -1;
		}
		break;

	case 192 / 8:
		switch (mode) {
		case LWS_GAESM_CBC:
			ctx->cipher = EVP_aes_192_cbc();
			break;
		case LWS_GAESM_CFB128:
			ctx->cipher = EVP_aes_192_cfb128();
			break;
		case LWS_GAESM_CFB8:
			ctx->cipher = EVP_aes_192_cfb8();
			break;
		case LWS_GAESM_CTR:
			ctx->cipher = EVP_aes_192_ctr();
			break;
		case LWS_GAESM_ECB:
			ctx->cipher = EVP_aes_192_ecb();
			break;
		case LWS_GAESM_OFB:
			ctx->cipher = EVP_aes_192_ofb();
			break;
		case LWS_GAESM_XTS:
			lwsl_err("%s: AES XTS 192 invalid\n", __func__);
			return -1;
		case LWS_GAESM_GCM:
			ctx->cipher = EVP_aes_192_gcm();
			break;
		default:
			return -1;
		}
		break;

	case 256 / 8:
		switch (mode) {
		case LWS_GAESM_CBC:
			ctx->cipher = EVP_aes_256_cbc();
			break;
		case LWS_GAESM_CFB128:
			ctx->cipher = EVP_aes_256_cfb128();
			break;
		case LWS_GAESM_CFB8:
			ctx->cipher = EVP_aes_256_cfb8();
			break;
		case LWS_GAESM_CTR:
			ctx->cipher = EVP_aes_256_ctr();
			break;
		case LWS_GAESM_ECB:
			ctx->cipher = EVP_aes_256_ecb();
			break;
		case LWS_GAESM_OFB:
			ctx->cipher = EVP_aes_256_ofb();
			break;
		case LWS_GAESM_XTS:
			ctx->cipher = EVP_aes_128_xts();
			break;
		case LWS_GAESM_GCM:
			ctx->cipher = EVP_aes_256_gcm();
			break;
		default:
			return -1;
		}
		break;

	case 512 / 8:
		switch (mode) {
		case LWS_GAESM_XTS:
			ctx->cipher = EVP_aes_256_xts();
			break;
		default:
			return -1;
		}
	break;

	default:
		lwsl_err("%s: unsupported AES size %d bits\n", __func__,
			 ctx->k->len * 8);
		return -1;
	}

	switch (ctx->op) {
	case LWS_GAESO_ENC:
		n = EVP_EncryptInit_ex(ctx->ctx, ctx->cipher, ctx->engine,
				       NULL, NULL);
		EVP_CIPHER_CTX_set_padding(ctx->ctx, padding);
		break;
	case LWS_GAESO_DEC:
		n = EVP_DecryptInit_ex(ctx->ctx, ctx->cipher, ctx->engine,
				       NULL, NULL);
		EVP_CIPHER_CTX_set_padding(ctx->ctx, padding);
		break;
	}
	if (!n) {
		lwsl_err("%s: cipher init failed (cipher %p)\n", __func__,
			 ctx->cipher);

		return -1;
	}

	return 0;
}

LWS_VISIBLE int
lws_genaes_destroy(struct lws_genaes_ctx *ctx, unsigned char *tag, size_t tlen)
{
	int outl = 0, n = 0;
	uint8_t buf[256];

	if (!ctx->ctx)
		return 0;

	if (ctx->init) {
		switch (ctx->op) {
		case LWS_GAESO_ENC:

			if (EVP_EncryptFinal_ex(ctx->ctx, buf, &outl) != 1) {
				lwsl_err("%s: enc final failed\n", __func__);
				n = -1;
			}
			if (ctx->mode == LWS_GAESM_GCM) {
				memset(tag, 0, tlen);
				if (EVP_CIPHER_CTX_ctrl(ctx->ctx,
						EVP_CTRL_GCM_GET_TAG,
						    ctx->taglen, tag) != 1) {
					lwsl_err("get tag ctrl failed\n");
					//lws_tls_err_describe();
					n = 1;
				} else
				if (memcmp(tag, ctx->tag, ctx->taglen)) {
					lwsl_err("%s: tag mismatch "
						 "(bad first)\n", __func__);
					//lws_tls_err_describe();
					lwsl_hexdump_notice(tag, tlen);
					lwsl_hexdump_notice(ctx->tag, ctx->taglen);
					n = -1;
				}
			}
			break;
		case LWS_GAESO_DEC:
			if (EVP_DecryptFinal_ex(ctx->ctx, buf, &outl) != 1) {
				lwsl_err("%s: dec final failed\n", __func__);
				//lws_tls_err_describe();
				n = -1;
			}
			break;
		}
		if (outl)
			lwsl_debug("%s: final len %d\n", __func__, outl);
	}

	ctx->k = NULL;
	EVP_CIPHER_CTX_free(ctx->ctx);
	ctx->ctx = NULL;

	return n;
}

LWS_VISIBLE int
lws_genaes_crypt(struct lws_genaes_ctx *ctx,
		 const uint8_t *in, size_t len, uint8_t *out,
		 uint8_t *iv_or_nonce_ctr_or_data_unit_16,
		 uint8_t *stream_block_16, size_t *nc_or_iv_off, int taglen)
{
	int n, outl, olen;

	if (!ctx->init) {

		EVP_CIPHER_CTX_set_key_length(ctx->ctx, ctx->k->len);

		if (ctx->mode == LWS_GAESM_GCM) {
			EVP_CIPHER_CTX_ctrl(ctx->ctx, EVP_CTRL_GCM_SET_IVLEN,
					    *nc_or_iv_off, NULL);
			memcpy(ctx->tag, stream_block_16, taglen);
			ctx->taglen = taglen;
		}

		switch (ctx->op) {
		case LWS_GAESO_ENC:
			n = EVP_EncryptInit_ex(ctx->ctx, NULL, NULL,
					       ctx->k->buf,
					       iv_or_nonce_ctr_or_data_unit_16);
			break;
		case LWS_GAESO_DEC:
			if (ctx->mode == LWS_GAESM_GCM)
				EVP_CIPHER_CTX_ctrl(ctx->ctx,
						    EVP_CTRL_CCM_SET_TAG,
						    ctx->taglen, ctx->tag);
			n = EVP_DecryptInit_ex(ctx->ctx, NULL, NULL,
					       ctx->k->buf,
					       iv_or_nonce_ctr_or_data_unit_16);
			break;
		}

		if (!n) {
			lwsl_err("%s: init failed (cipher %p)\n",
				 __func__, ctx->cipher);

			return -1;
		}
		ctx->init = 1;
		if (ctx->mode == LWS_GAESM_GCM) {
			/* AAD */
			if (len)
				if (EVP_EncryptUpdate(ctx->ctx, NULL, &olen,
						      in, len) != 1) {
					lwsl_err("%s: set aad failed\n",
						 __func__);

					return -1;
				}

			return 0;
		}
	}

	switch (ctx->op) {
	case LWS_GAESO_ENC:
		n = EVP_EncryptUpdate(ctx->ctx, out, &outl, in, len);
		break;
	case LWS_GAESO_DEC:
		n = EVP_DecryptUpdate(ctx->ctx, out, &outl, in, len);
		break;
	}

	// lwsl_notice("discarding outl %d\n", (int)outl);

	if (!n) {
		lwsl_notice("%s: update failed\n", __func__);

		return -1;
	}

	return 0;
}
