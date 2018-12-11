/*
 * libwebsockets - small server side websockets and web server implementation
 *
 * Copyright (C) 2010-2018 Andy Green <andy@warmcat.com>
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
 * included from libwebsockets.h
 */

/*! \defgroup jws JSON Web Signature
 * ## JSON Web Signature API
 *
 * Lws provides an API to check and create RFC7515 JSON Web Signatures
 *
 * SHA256/384/512 HMAC, and RSA 256/384/512 are supported.
 *
 * The API uses your TLS library crypto, but works exactly the same no matter
 * what you TLS backend is.
 */
///@{

enum enum_jws_sig_elements {

	LJWS_JOSE,
	LJWS_PYLD,
	LJWS_SIG,
	LJWS_UHDR,

	LWS_JWS_MAX_CONCAT_BLOCKS
};

struct lws_jws_concat_map {
	const char *buf[LWS_JWS_MAX_CONCAT_BLOCKS];
	uint16_t len[LWS_JWS_MAX_CONCAT_BLOCKS];
};

struct lws_jws {
	const struct lws_jose_jwe_alg *args; /* algorithm info used for sig */
	struct lws_jwk *jwk; /* the struct lws_jwk containing the signing key */
	struct lws_context *context; /* the lws context (used to get random) */
	struct lws_jws_concat_map map, map_b64;

//	const char *b64_hdr; /* protected header encoded in b64, may be NULL */
//	const char *b64_pay; /* payload encoded in b64 */
//	char *b64_sig; /* buffer to write the b64 encoded signature into */
//	const char *b64_unprot_hdr; /* unprotected header in b64, may be NULL */
//	size_t hdr_len; /* bytes in b64 coding of protected header */
//	size_t pay_len; /* bytes in b64 coding of payload */
//	size_t sig_len; /* max bytes we can write at b64_sig */
//	size_t b64_unprot_hdr_len; /* bytes in unprotected JSON hdr */
};

/* jws EC signatures do not have ASN.1 in them, meaning they're incompatible
 * with generic signatures.
 */

/**
 * lws_jws_sig_confirm_compact() - check signature
 *
 * \param map: pointers and lengths for each of the unencoded JWS elements
 * \param jwk: public key
 * \param content: lws_context
 *
 * Confirms the signature on a JWS.  Use if you have non-b64 plain JWS elements
 * in a map... it'll make a temp b64 version needed for comparison.  See below
 * for other variants.
 *
 * Returns 0 on match.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_sig_confirm_compact(struct lws_jws_concat_map *map, struct lws_jwk *jwk,
			    struct lws_context *context);

LWS_VISIBLE LWS_EXTERN int
lws_jws_sig_confirm_compact_b64_map(struct lws_jws_concat_map *map_b64,
				    struct lws_jwk *jwk,
			            struct lws_context *context);

/**
 * lws_jws_sig_confirm_compact_b64() - check signature on b64 compact JWS
 *
 * \param in: pointer to b64 jose.payload[.hdr].sig
 * \param len: bytes available at \p in
 * \param jwk: public key
 * \param content: lws_context
 *
 * Confirms the signature on a JWS.  Use if you have you have b64 compact layout
 * (jose.payload.hdr.sig) as an aggregated string... it'll make a temp plain
 * version needed for comparison.
 *
 * Returns 0 on match.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_sig_confirm_compact_b64(const char *in, size_t len, struct lws_jwk *jwk,
			        struct lws_context *context);

/**
 * lws_jws_sig_confirm() - check signature on plain + b64 JWS elements
 *
 * \param map_b64: pointers and lengths for each of the b64-encoded JWS elements
 * \param map: pointers and lengths for each of the unencoded JWS elements
 * \param jwk: public key
 * \param content: lws_context
 *
 * Confirms the signature on a JWS.  Use if you have you already have both b64
 * compact layout (jose.payload.hdr.sig) and decoded JWS elements in maps.
 *
 * If you had the b64 string and called lws_jws_compact_decode() on it, you
 * will end up with both maps, and can use this api version, saving needlessly
 * regenerating any temp map.
 *
 * Returns 0 on match.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_sig_confirm(struct lws_jws_concat_map *map_b64, /* b64-encoded */
		    struct lws_jws_concat_map *map,	/* non-b64 */
		    struct lws_jwk *jwk, struct lws_context *context);

/**
 * lws_jws_b64_concat_map() - find block starts and lengths in compact b64
 *
 * \param in: pointer to b64 jose.payload[.hdr].sig
 * \param len: bytes available at \p in
 * \param map: output struct with pointers and lengths for each JWS element
 *
 * Scans a jose.payload[.hdr].sig b64 string and notes where the blocks start
 * and their length into \p map.
 *
 * Returns number of blocks if OK.  May return <0 if malformed.
 * May not fill all map entries.
 */

LWS_VISIBLE LWS_EXTERN int
lws_jws_b64_concat_map(const char *in, int len, struct lws_jws_concat_map *map);

/**
 * lws_jws_sign_from_b64() - add b64 sig to b64 hdr + payload
 *
 * \param jws: information to include in the signature
 * \param b64_sig: output buffer for b64 signature
 * \param sig_len: size of \p b64_sig output buffer
 *
 * This adds a b64-coded JWS signature of the b64-encoded protected header
 * and b64-encoded payload, at \p b64_sig.  The signature will be as large
 * as the N element of the RSA key when the RSA key is used, eg, 512 bytes for
 * a 4096-bit key, and then b64-encoding on top.
 *
 * In some special cases, there is only payload to sign and no header, in that
 * case \p b64_hdr may be NULL, and only the payload will be hashed before
 * signing.
 *
 * Returns the length of the encoded signature written to \p b64_sig, or -1.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_sign_from_b64(struct lws_jws *jws, char *b64_sig, size_t sig_len);

/**
 * lws_jws_write_flattened_json() - create flattened JSON sig
 *
 * \param jws: information to include in the signature
 * \param flattened: output buffer for JSON
 * \param len: size of \p flattened output buffer
 *
 */

LWS_VISIBLE LWS_EXTERN int
lws_jws_write_flattened_json(struct lws_jws *jws, char *flattened, size_t len);


/**
 * lws_jws_compact_decode() - converts and maps compact serialization b64 sections
 *
 * \param in: the incoming compact serialized b64
 * \param len: the length of the incoming compact serialized b64
 * \param map: pointer to the results structure
 * \param map_b64: NULL, or pointer to a second results structure taking block
 *		   information about the undecoded b64
 * \param out: buffer to hold decoded results
 * \param out_len: size of out in bytes
 *
 * Returns number of sections (2 if "none", else 3), or -1 if illegal.
 *
 * map is set to point to the start and hold the length of each decoded block.
 * If map_b64 is non-NULL, then it's set with information about the input b64
 * blocks.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_compact_decode(const char *in, int len, struct lws_jws_concat_map *map,
		struct lws_jws_concat_map *map_b64, char *out, int out_len);

/**
 * lws_jws_base64_enc() - encode input data into b64url data
 *
 * \param in: the incoming plaintext
 * \param in_len: the length of the incoming plaintext in bytes
 * \param out: the buffer to store the b64url encoded data to
 * \param out_max: the length of \p out in bytes
 *
 * Returns either -1 if problems, or the number of bytes written to \p out.
 */
LWS_VISIBLE LWS_EXTERN int
lws_jws_base64_enc(const char *in, size_t in_len, char *out, size_t out_max);

/**
 * lws_jws_encode_section() - encode input data into b64url data, prepending . if not first
 *
 * \param in: the incoming plaintext
 * \param in_len: the length of the incoming plaintext in bytes
 * \param first: nonzero if the first section
 * \param out: the buffer to store the b64url encoded data to
 * \param out_max: the length of \p out in bytes
 *
 * Returns either -1 if problems, or the number of bytes written to \p out.
 * If the section is not the first one, '.' is prepended.
 */

LWS_VISIBLE LWS_EXTERN int
lws_jws_encode_section(const char *in, size_t in_len, int first, char **p,
		       char *end);
///@}
