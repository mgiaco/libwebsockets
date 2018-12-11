/*
 * libwebsockets - JSON Web Encryption support
 *
 * Copyright (C) 2018 Andy Green <andy@warmcat.com>
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
 *
 * This supports RFC7516 JSON Web Encryption
 *
 */
#include "core/private.h"

struct lws_jwe_ctx {
	union {
		struct lws_genrsa_ctx ctx_rsa;
		struct lws_genaes_ctx ctx_aes;
		struct lws_genec_ctx ctx_ec;
	} ue;
	union {
		struct lws_genhash_ctx ctx_hash;
		struct lws_genhmac_ctx ctx_hmac;
	} uh;
	uint8_t digest[LWS_GENHASH_LARGEST];
	const struct lws_jose_jwe_alg *jose_alg;
	enum enum_jwe_crypt_type type;

};

LWS_VISIBLE struct lws_jwe_ctx *
lws_jwe_crypt_init(struct lws_jwk *jwk, const struct lws_jose_jwe_alg *jose_alg,
		   struct lws_context *context, enum enum_jwe_crypt_type type)
{
	struct lws_jwe_ctx *jwe_ctx = NULL;
	enum enum_genrsa_mode rmode = LGRSAM_PKCS1_1_5;

	jwe_ctx = lws_malloc(sizeof(*jwe_ctx), __func__);
	if (!jwe_ctx)
		return NULL;
	jwe_ctx->jose_alg = jose_alg;
	jwe_ctx->type = type;

	/* digest part */

//	if (lws_genhash_init(&hctx, LWS_GENHASH_TYPE_SHA256))
//		return -1;



	/* encryption part */

	switch (jose_alg->algtype_crypto) {
	default:
	case LWS_JOSE_ENCTYPE_NONE:
		goto bail;

	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_OAEP:
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_PSS:
		rmode = LGRSAM_PKCS1_OAEP_PSS;
		/* fallthru */
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_1_5:
		if (type == LEJCT_ENC && !jwk->private_key)
			goto bail;
		if (lws_genrsa_create(&jwe_ctx->ue.ctx_rsa, jwk->e, context, rmode))
			goto bail;
		break;

	case LWS_JOSE_ENCTYPE_ECDHES:
		lwsl_err("%s: ECDH-ES not supported yet\n", __func__);
		goto bail;

	case LWS_JOSE_ENCTYPE_ECDSA:
		if (type == LEJCT_ENC && !jwk->private_key)
			goto bail;
		if (lws_genecdh_create(&jwe_ctx->ue.ctx_ec, context, NULL))
			goto bail;

		if (lws_genecdh_set_key(&jwe_ctx->ue.ctx_ec, jwk->e, LDHS_OURS))
			goto bail;
		break;

	case LWS_JOSE_ENCTYPE_AES_CBC:
	case LWS_JOSE_ENCTYPE_AES_CFB128:
	case LWS_JOSE_ENCTYPE_AES_CFB8:
	case LWS_JOSE_ENCTYPE_AES_CTR:
	case LWS_JOSE_ENCTYPE_AES_ECB:
	case LWS_JOSE_ENCTYPE_AES_OFB:
	case LWS_JOSE_ENCTYPE_AES_XTS:	/* care... requires double-length key */
	case LWS_JOSE_ENCTYPE_AES_GCM:
		if (lws_genaes_create(&jwe_ctx->ue.ctx_aes, LWS_GAESO_ENC,
				      jose_alg->algtype_crypto -
					      LWS_JOSE_ENCTYPE_AES_CBC,
				      jwk->e, 0, NULL))
			goto bail;

		break;
	}

	return jwe_ctx;

bail:
	lws_free_set_NULL(jwe_ctx);

	return NULL;
}

LWS_VISIBLE int
lws_jwe_crypt_update(struct lws_jwe_ctx *jwe_ctx, const uint8_t *in,
		     size_t in_len, uint8_t *out)
{
	switch (jwe_ctx->jose_alg->algtype_crypto) {
	default:
	case LWS_JOSE_ENCTYPE_NONE:
		goto bail;

	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_OAEP:
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_PSS:
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_1_5:
		if (lws_genrsa_public_encrypt(&jwe_ctx->ue.ctx_rsa, in, in_len, out))
			goto bail;
		break;

	case LWS_JOSE_ENCTYPE_ECDHES:
		lwsl_err("%s: ECDH-ES not supported yet\n", __func__);
		goto bail;

	case LWS_JOSE_ENCTYPE_ECDSA:
		lwsl_err("%s: ECDSA not supported yet\n", __func__);
		goto bail;


	case LWS_JOSE_ENCTYPE_AES_CBC:
	case LWS_JOSE_ENCTYPE_AES_CFB128:
	case LWS_JOSE_ENCTYPE_AES_CFB8:
	case LWS_JOSE_ENCTYPE_AES_CTR:
	case LWS_JOSE_ENCTYPE_AES_ECB:
	case LWS_JOSE_ENCTYPE_AES_OFB:
	case LWS_JOSE_ENCTYPE_AES_XTS:	/* care... requires double-length key */
	case LWS_JOSE_ENCTYPE_AES_GCM:
		lwsl_err("%s: AES not supported yet\n", __func__);
		goto bail;
	}

	return 0;

bail:
	return -1;
}

LWS_VISIBLE void
lws_jwe_crypt_free(struct lws_jwe_ctx **pjwe_ctx)
{
	struct lws_jwe_ctx *jwe_ctx = *pjwe_ctx;

	switch (jwe_ctx->jose_alg->algtype_crypto) {
	default:
	case LWS_JOSE_ENCTYPE_NONE:
		return;

	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_OAEP:
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_PSS:
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_1_5:
		lws_genrsa_destroy(&jwe_ctx->ue.ctx_rsa);
		break;

	case LWS_JOSE_ENCTYPE_ECDHES:
	case LWS_JOSE_ENCTYPE_ECDSA:
		lws_genec_destroy(&jwe_ctx->ue.ctx_ec);
		break;

	case LWS_JOSE_ENCTYPE_AES_CBC:
	case LWS_JOSE_ENCTYPE_AES_CFB128:
	case LWS_JOSE_ENCTYPE_AES_CFB8:
	case LWS_JOSE_ENCTYPE_AES_CTR:
	case LWS_JOSE_ENCTYPE_AES_ECB:
	case LWS_JOSE_ENCTYPE_AES_OFB:
	case LWS_JOSE_ENCTYPE_AES_XTS:	/* care... requires double-length key */
	case LWS_JOSE_ENCTYPE_AES_GCM:
		lws_genaes_destroy(&jwe_ctx->ue.ctx_aes, NULL, 0);
		break;
	}

	lws_free_set_NULL(jwe_ctx);
	*pjwe_ctx = NULL;
}

LWS_VISIBLE int
lws_jwe_create_packet(struct lws_jwk *jwk,
		      const struct lws_jose_jwe_alg *jose_alg,
		      const char *payload, size_t len,
		      const char *nonce, char *out, size_t out_len,
		      struct lws_context *context)
{
	char *buf, *start, *p, *end, *p1, *end1;
	struct lws_jws jws;
	int n;

	memset(&jws, 0, sizeof(jws));
	jws.args = jose_alg;
	jws.jwk = jwk;
	jws.context = context;

	/*
	 * This buffer is local to the function, the actual output
	 * is prepared into vhd->buf.  Only the plaintext protected header
	 * (which contains the public key, 512 bytes for 4096b) goes in
	 * here temporarily.
	 */
	n = LWS_PRE + 2048;
	buf = malloc(n);
	if (!buf) {
		lwsl_notice("%s: malloc %d failed\n", __func__, n);
		return -1;
	}

	p = start = buf + LWS_PRE;
	end = buf + n - LWS_PRE - 1;

	/*
	 * temporary JWS protected header plaintext
	 */

	if (!jose_alg || !jose_alg->alg)
		goto bail;

	p += lws_snprintf(p, end - p, "{\"alg\":\"%s\",\"jwk\":",
			  jose_alg->alg);
	n = lws_jwk_export(jwk, 0, p, end - p);
	if (n < 0) {
		lwsl_notice("failed to export jwk\n");

		goto bail;
	}
	p += n;
	p += lws_snprintf(p, end - p, ",\"nonce\":\"%s\"}", nonce);

	/*
	 * prepare the signed outer JSON with all the parts in
	 */

	p1 = out;
	end1 = out + out_len - 1;

	p1 += lws_snprintf(p1, end1 - p1, "{\"protected\":\"");
	jws.map_b64.buf[LJWS_JOSE] = p1;
	n = lws_jws_base64_enc(start, p - start, p1, end1 - p1);
	if (n < 0) {
		lwsl_notice("%s: failed to encode protected\n", __func__);
		goto bail;
	}
	jws.map_b64.len[LJWS_JOSE] = n;
	p1 += n;

	p1 += lws_snprintf(p1, end1 - p1, "\",\"payload\":\"");
	jws.map_b64.buf[LJWS_PYLD] = p1;
	n = lws_jws_base64_enc(payload, len, p1, end1 - p1);
	if (n < 0) {
		lwsl_notice("%s: failed to encode payload\n", __func__);
		goto bail;
	}
	jws.map_b64.len[LJWS_PYLD] = n;
	p1 += n;

	p1 += lws_snprintf(p1, end1 - p1, "\",\"header\":\"");
	jws.map_b64.buf[LJWS_UHDR] = p1;
	n = lws_jws_base64_enc(payload, len, p1, end1 - p1);
	if (n < 0) {
		lwsl_notice("%s: failed to encode payload\n", __func__);
		goto bail;
	}
	jws.map_b64.len[LJWS_UHDR] = n;

	p1 += n;
	p1 += lws_snprintf(p1, end1 - p1, "\",\"signature\":\"");

	/*
	 * taking the b64 protected header and the b64 payload, sign them
	 * and place the signature into the packet
	 */
	n = lws_jws_sign_from_b64(&jws, p1, end1 - p1);
	if (n < 0) {
		lwsl_notice("sig gen failed\n");

		goto bail;
	}
	jws.map_b64.buf[LJWS_SIG] = p1;
	jws.map_b64.len[LJWS_SIG] = n;

	p1 += n;
	p1 += lws_snprintf(p1, end1 - p1, "\"}");

	free(buf);

	return p1 - out;

bail:
	free(buf);

	return -1;
}
