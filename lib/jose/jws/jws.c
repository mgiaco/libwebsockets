/*
 * libwebsockets - JSON Web Signature support
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
 */

#include "core/private.h"
#include "private.h"

LWS_VISIBLE int
lws_jws_base64_enc(const char *in, size_t in_len, char *out, size_t out_max)
{
	int n;

	n = lws_b64_encode_string_url(in, in_len, out, out_max - 1);
	if (n < 0) {
		lwsl_notice("%s: in len %d too large for %d out buf\n",
				__func__, (int)in_len, (int)out_max);
		return n; /* too large for output buffer */
	}

	/* trim the terminal = */
	while (n && out[n - 1] == '=')
		n--;

	out[n] = '\0';

	return n;
}

LWS_VISIBLE int
lws_jws_b64_concat_map(const char *in, int len, struct lws_jws_concat_map *map)
{
	int me = 0;

	memset(map, 0, sizeof(*map));

	map->buf[me] = (char *)in;
	map->len[me] = 0;

	while (len--) {
		if (*in++ == '.') {
			if (++me == LWS_JWS_MAX_CONCAT_BLOCKS)
				return -1;
			map->buf[me] = (char *)in;
			map->len[me] = 0;
			continue;
		}
		map->len[me]++;
	}

	return me + 1;
}

/* b64 in, map contains decoded elements, if non-NULL,
 * map_b64 set to b64 elements
 */

LWS_VISIBLE int
lws_jws_compact_decode(const char *in, int len, struct lws_jws_concat_map *map,
		struct lws_jws_concat_map *map_b64, char *out, int out_len)
{
	int blocks, n, m = 0;

	if (!map_b64)
		map_b64 = map;

	memset(map_b64, 0, sizeof(*map_b64));
	memset(map, 0, sizeof(*map));

	blocks = lws_jws_b64_concat_map(in, len, map_b64);

	/* compact serialization must have 2 ("none") or 3 blocks */

	if (blocks != 2 && blocks != 3)
		return -1;

	while (m < blocks) {
		n = lws_b64_decode_string_len(map_b64->buf[m],
					      map_b64->len[m], out, out_len);
		if (n < 0) {
			lwsl_err("%s: b64 decode failed\n", __func__);
			return -1;
		}
		/* replace the map entry with the decoded content */
		map->buf[m] = out;
		map->len[m++] = n;
		out += n;
		out_len -= n;

		if (out_len < 1)
			return -1;
	}

	return blocks;
}

static int
lws_jws_compact_decode_map(struct lws_jws_concat_map *map_b64,
			   struct lws_jws_concat_map *map, char *out, int out_len)
{
	int n, m = 0;



	for (n = 0; n < LWS_JWS_MAX_CONCAT_BLOCKS; n++) {
		n = lws_b64_decode_string_len(map_b64->buf[m],
					      map_b64->len[m], out, out_len);
		if (n < 0) {
			lwsl_err("%s: b64 decode failed\n", __func__);
			return -1;
		}
		/* replace the map entry with the decoded content */
		map->buf[m] = out;
		map->len[m++] = n;
		out += n;
		out_len -= n;

		if (out_len < 1)
			return -1;
	}

	return 0;
}

LWS_VISIBLE int
lws_jws_encode_section(const char *in, size_t in_len, int first, char **p,
		       char *end)
{
	int n, len = (end - *p) - 1;
	char *p_entry = *p;

	if (len < 3)
		return -1;

	if (!first)
		*(*p)++ = '.';

	n = lws_jws_base64_enc(in, in_len, *p, len - 1);
	if (n < 0)
		return -1;

	*p += n;

	return (*p) - p_entry;
}

LWS_VISIBLE int
lws_jws_compact_encode(struct lws_jws_concat_map *map_b64, /* b64-encoded */
		       const struct lws_jws_concat_map *map,	/* non-b64 */
		       char *buf, int len)
{
	int n, m;

	for (n = 0; n < LWS_JWS_MAX_CONCAT_BLOCKS; n++) {
		if (!map->buf[n]) {
			map_b64->buf[n] = NULL;
			map_b64->len[n] = 0;
			continue;
		}
		m = lws_jws_base64_enc(map->buf[n], map->len[n], buf, len);
		if (m < 0)
			return -1;
		buf += m;
		len -= m;
		if (len < 1)
			return -1;
	}

	return 0;
}

/*
 * This takes both a base64 -encoded map and a plaintext map.
 *
 * JWS demands base-64 encoded elements for hash computation and at least for
 * the JOSE header and signature, decoded versions too.
 */

LWS_VISIBLE int
lws_jws_sig_confirm(struct lws_jws_concat_map *map_b64, /* b64-encoded */
		    struct lws_jws_concat_map *map,	/* non-b64 */
		    struct lws_jwk *jwk, struct lws_context *context)
{
	enum enum_genrsa_mode padding = LGRSAM_PKCS1_1_5;
	const struct lws_jose_jwe_alg *args = NULL;
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx hash_ctx;
	struct lws_genec_ctx ecdsactx;
	struct lws_genrsa_ctx rsactx;
	struct lws_genhmac_ctx ctx;
	int n, h_len, b = 3;

	/* only valid if no signature or key */
	if (!map_b64->buf[LJWS_SIG] && !map->buf[LJWS_UHDR])
		b = 2;

	if (lws_jws_parse_jose(&args, map->buf[LJWS_JOSE],
				      map->len[LJWS_JOSE]) < 0) {
		lwsl_notice("%s: parse failed\n", __func__);
		return -1;
	}

	if (!strcmp(args->alg, "none")) {
		/* "none" compact serialization has 2 blocks: jose.payload */
		if (b != 2 || jwk)
			return -1;

		/* the lack of a key matches the lack of a signature */
		return 0;
	}

	/* all other have 3 blocks: jose.payload.sig */
	if (b != 3 || !jwk) {
		lwsl_notice("%s: %d blocks\n", __func__, b);
		return -1;
	}

	switch (args->algtype_signing) {
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_PSS:
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_OAEP:
		padding = LGRSAM_PKCS1_OAEP_PSS;
		/* fallthru */
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_1_5:

		/* RSASSA-PKCS1-v1_5 or OAEP using SHA-256/384/512 */

		if (jwk->kty != LWS_GENCRYPTO_KTY_RSA)
			return -1;

		/* 6(RSA): compute the hash of the payload into "digest" */

		if (lws_genhash_init(&hash_ctx, args->hash_type))
			return -1;

		/*
		 * JWS Signing Input value:
		 *
		 * BASE64URL(UTF8(JWS Protected Header)) || '.' ||
		 * 	BASE64URL(JWS Payload)
		 */

		if (lws_genhash_update(&hash_ctx, map_b64->buf[LJWS_JOSE],
						  map_b64->len[LJWS_JOSE]) ||
		    lws_genhash_update(&hash_ctx, ".", 1) ||
		    lws_genhash_update(&hash_ctx, map_b64->buf[LJWS_PYLD],
						  map_b64->len[LJWS_PYLD]) ||
		    lws_genhash_destroy(&hash_ctx, digest)) {
			lws_genhash_destroy(&hash_ctx, NULL);

			return -1;
		}
		h_len = lws_genhash_size(args->hash_type);

		if (lws_genrsa_create(&rsactx, jwk->e, context, padding)) {
			lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
				    __func__);
			return -1;
		}

		n = lws_genrsa_hash_sig_verify(&rsactx, digest, args->hash_type,
					       (uint8_t *)map->buf[LJWS_SIG],
					       map->len[LJWS_SIG]);

		lws_genrsa_destroy(&rsactx);
		if (n < 0) {
			lwsl_notice("decrypt fail\n");
			return -1;
		}

		break;

	case LWS_JOSE_ENCTYPE_NONE: /* HSxxx */

		/* SHA256/384/512 HMAC */

		h_len = lws_genhmac_size(args->hmac_type);

		/* 6) compute HMAC over payload */

		if (lws_genhmac_init(&ctx, args->hmac_type,
				     jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].buf,
				     jwk->e[LWS_GENCRYPTO_RSA_KEYEL_E].len))
			return -1;

		/*
		 * JWS Signing Input value:
		 *
		 * BASE64URL(UTF8(JWS Protected Header)) || '.' ||
		 *   BASE64URL(JWS Payload)
		 */

		if (lws_genhmac_update(&ctx, map_b64->buf[LJWS_JOSE],
					     map_b64->len[LJWS_JOSE]) ||
		    lws_genhmac_update(&ctx, ".", 1) ||
		    lws_genhmac_update(&ctx, map_b64->buf[LJWS_PYLD],
					     map_b64->len[LJWS_PYLD]) ||
		    lws_genhmac_destroy(&ctx, digest)) {
			lws_genhmac_destroy(&ctx, NULL);

			return -1;
		}

		/* 7) Compare the computed and decoded hashes */

		if (memcmp(digest, map->buf[2], h_len)) {
			lwsl_notice("digest mismatch\n");

			return -1;
		}

		break;

	case LWS_JOSE_ENCTYPE_ECDSA:

		/* ECDSA using SHA-256/384/512 */

		/* Confirm the key coming in with this makes sense */

		/* has to be an EC key :-) */
		if (jwk->kty != LWS_GENCRYPTO_KTY_EC)
			return -1;

		/* key must state its curve */
		if (!jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf)
			return -1;

		/* key must match the selected alg curve */
		if (strcmp((const char *)jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf,
			   args->curve_name))
			return -1;

		/*
		 * JWS Signing Input value:
		 *
		 * BASE64URL(UTF8(JWS Protected Header)) || '.' ||
		 * 	BASE64URL(JWS Payload)
		 *
		 * Validating the JWS Signature is a bit different from the
		 * previous examples.  We need to split the 64 member octet
		 * sequence of the JWS Signature (which is base64url decoded
		 * from the value encoded in the JWS representation) into two
		 * 32 octet sequences, the first representing R and the second
		 * S.  We then pass the public key (x, y), the signature (R, S),
		 * and the JWS Signing Input (which is the initial substring of
		 * the JWS Compact Serialization representation up until but not
		 * including the second period character) to an ECDSA signature
		 * verifier that has been configured to use the P-256 curve with
		 * the SHA-256 hash function.
		 */

		if (lws_genhash_init(&hash_ctx, args->hash_type) ||
		    lws_genhash_update(&hash_ctx, map_b64->buf[LJWS_JOSE],
						  map_b64->len[LJWS_JOSE]) ||
		    lws_genhash_update(&hash_ctx, ".", 1) ||
		    lws_genhash_update(&hash_ctx, map_b64->buf[LJWS_PYLD],
						  map_b64->len[LJWS_PYLD]) ||
		    lws_genhash_destroy(&hash_ctx, digest)) {
			lws_genhash_destroy(&hash_ctx, NULL);

			return -1;
		}

		h_len = lws_genhash_size(args->hash_type);

		if (lws_genecdsa_create(&ecdsactx, context, NULL)) {
			lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
				    __func__);
			return -1;
		}

		if (lws_genecdsa_set_key(&ecdsactx, jwk->e)) {
			lws_genec_destroy(&ecdsactx);
			lwsl_notice("%s: ec key import fail\n", __func__);
			return -1;
		}

		n = lws_genecdsa_hash_sig_verify_jws(&ecdsactx, digest,
						     args->hash_type,
						     args->keybits_fixed,
						  (uint8_t *)map->buf[LJWS_SIG],
						     map->len[LJWS_SIG]);
		lws_genec_destroy(&ecdsactx);
		if (n < 0) {
			lwsl_notice("%s: verify fail\n", __func__);
			return -1;
		}

		break;

	default:
		lwsl_err("%s: unknown alg from jose\n", __func__);
		return -1;
	}

	return 0;
}

/* it's already a b64 map, we will make a temp plain version */

LWS_VISIBLE int
lws_jws_sig_confirm_compact_b64_map(struct lws_jws_concat_map *map_b64,
				    struct lws_jwk *jwk,
			            struct lws_context *context)
{
	struct lws_jws_concat_map map;
	char buf[2048];

	if (lws_jws_compact_decode_map(map_b64, &map, buf, sizeof(buf)) < 0)
		return -1;

	return lws_jws_sig_confirm(map_b64, &map, jwk, context);
}

/* it's already a concatenated b64 string, we will make a temp plain version */

LWS_VISIBLE int
lws_jws_sig_confirm_compact_b64(const char *in, size_t len, struct lws_jwk *jwk,
			        struct lws_context *context)
{
	struct lws_jws_concat_map map_b64, map;
	char buf[2048];

	if (lws_jws_b64_concat_map(in, len, &map_b64) < 0)
		return -1;

	if (lws_jws_compact_decode(in, len, &map, &map_b64, buf,
				   sizeof(buf)) < 0)
		return -1;

	return lws_jws_sig_confirm(&map_b64, &map, jwk, context);
}

/* it's already plain, we will make a temp b64 version */

LWS_VISIBLE int
lws_jws_sig_confirm_compact(struct lws_jws_concat_map *map, struct lws_jwk *jwk,
			    struct lws_context *context)
{
	struct lws_jws_concat_map map_b64;
	char buf[2048];

	if (lws_jws_compact_encode(map, &map_b64, buf, sizeof(buf)) < 0)
		return -1;

	return lws_jws_sig_confirm(&map_b64, map, jwk, context);
}


LWS_VISIBLE int
lws_jws_sign_from_b64(struct lws_jws *jws, char *b64_sig, size_t sig_len)
{
	enum enum_genrsa_mode pad = LGRSAM_PKCS1_1_5;
	uint8_t digest[LWS_GENHASH_LARGEST];
	struct lws_genhash_ctx hash_ctx;
	struct lws_genec_ctx ecdsactx;
	struct lws_genrsa_ctx rsactx;
	uint8_t *buf;
	int n, m;

	if (jws->args->hash_type == LWS_GENHASH_TYPE_UNKNOWN &&
	    jws->args->hmac_type == LWS_GENHMAC_TYPE_UNKNOWN &&
	    !strcmp(jws->args->alg, "none"))
		return 0;

	if (lws_genhash_init(&hash_ctx, jws->args->hash_type) ||
	    lws_genhash_update(&hash_ctx, jws->map_b64.buf[LJWS_JOSE],
					  jws->map_b64.len[LJWS_JOSE]) ||
	    lws_genhash_update(&hash_ctx, ".", 1) ||
	    lws_genhash_update(&hash_ctx, jws->map_b64.buf[LJWS_PYLD],
					  jws->map_b64.len[LJWS_PYLD]) ||
	    lws_genhash_destroy(&hash_ctx, digest)) {
		lws_genhash_destroy(&hash_ctx, NULL);

		return -1;
	}

	switch (jws->args->algtype_signing) {
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_PSS:
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_OAEP:
		pad = LGRSAM_PKCS1_OAEP_PSS;
		/* fallthru */
	case LWS_JOSE_ENCTYPE_RSASSA_PKCS1_1_5:

		if (jws->jwk->kty != LWS_GENCRYPTO_KTY_RSA)
			return -1;

		if (lws_genrsa_create(&rsactx, jws->jwk->e, jws->context,
				      pad)) {
			lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
				    __func__);
			return -1;
		}

		n = jws->jwk->e[LWS_GENCRYPTO_RSA_KEYEL_N].len;
		buf = lws_malloc(n, "jws sign");
		if (!buf)
			return -1;

		n = lws_genrsa_hash_sign(&rsactx, digest, jws->args->hash_type,
					 buf, n);
		lws_genrsa_destroy(&rsactx);
		if (n < 0) {
			lwsl_err("%s: lws_genrsa_hash_sign failed\n", __func__);
			lws_free(buf);

			return -1;
		}

		n = lws_jws_base64_enc((char *)buf, n, b64_sig, sig_len);
		lws_free(buf);
		if (n < 0) {
			lwsl_err("%s: lws_jws_base64_enc failed\n", __func__);
		}

		return n;

	case LWS_JOSE_ENCTYPE_NONE:
		return lws_jws_base64_enc((char *)digest,
					 lws_genhash_size(jws->args->hash_type),
					  b64_sig, sig_len);
	case LWS_JOSE_ENCTYPE_ECDSA:
		/* ECDSA using SHA-256/384/512 */

		/* the key coming in with this makes sense, right? */

		/* has to be an EC key :-) */
		if (jws->jwk->kty != LWS_GENCRYPTO_KTY_EC)
			return -1;

		/* key must state its curve */
		if (!jws->jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf)
			return -1;

		/* must have all his pieces for a private key */
		if (!jws->jwk->e[LWS_GENCRYPTO_EC_KEYEL_X].buf ||
		    !jws->jwk->e[LWS_GENCRYPTO_EC_KEYEL_Y].buf ||
		    !jws->jwk->e[LWS_GENCRYPTO_EC_KEYEL_D].buf)
			return -1;

		/* key must match the selected alg curve */
		if (strcmp((const char *)
				jws->jwk->e[LWS_GENCRYPTO_EC_KEYEL_CRV].buf,
			    jws->args->curve_name))
			return -1;

		if (lws_genecdsa_create(&ecdsactx, jws->context, NULL)) {
			lwsl_notice("%s: lws_genrsa_public_decrypt_create\n",
				    __func__);
			return -1;
		}

		if (lws_genecdsa_set_key(&ecdsactx, jws->jwk->e)) {
			lws_genec_destroy(&ecdsactx);
			lwsl_notice("%s: ec key import fail\n", __func__);
			return -1;
		}
		m = lwsl_gencrypto_bits_to_bytes(jws->args->keybits_fixed) * 2;
		buf = lws_malloc(m, "jws sign");
		if (!buf)
			return -1;

		n = lws_genecdsa_hash_sign_jws(&ecdsactx, digest,
					       jws->args->hash_type,
					       jws->args->keybits_fixed,
					       (uint8_t *)buf, m);
		lws_genec_destroy(&ecdsactx);
		if (n < 0) {
			lws_free(buf);
			lwsl_notice("%s: lws_genecdsa_hash_sign_jws fail\n",
					__func__);
			return -1;
		}
		n = lws_jws_base64_enc((char *)buf, m, b64_sig, sig_len);
		lws_free(buf);

		return n;

	default:
		break;
	}

	/* unknown key type */

	return -1;
}

/*
 * Flattened JWS JSON:
 *
 *  {
 *    "payload":   "<payload contents>",
 *    "protected": "<integrity-protected header contents>",
 *    "header":    <non-integrity-protected header contents>,
 *    "signature": "<signature contents>"
 *   }
 */

LWS_VISIBLE int
lws_jws_write_flattened_json(struct lws_jws *jws, char *flattened, size_t len)
{
	size_t n = 0;

	n += lws_snprintf(flattened + n, len - n , "{\"payload\": \"%s\",\n",
			  jws->map_b64.buf[LJWS_PYLD]);

	n += lws_snprintf(flattened + n, len - n , " \"protected\": \"%s\",\n",
			jws->map_b64.buf[LJWS_JOSE]);

	if (jws->map_b64.buf[LJWS_UHDR])
		n += lws_snprintf(flattened + n, len - n , " \"header\": %s,\n",
				jws->map_b64.buf[LJWS_UHDR]);

	n += lws_snprintf(flattened + n, len - n , " \"signature\": \"%s\"}\n",
			jws->map_b64.buf[LJWS_SIG]);

	return n >= len - 1;
}

