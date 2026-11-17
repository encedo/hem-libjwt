/* Copyright (C) 2015-2017 Ben Collins <ben@cyphre.com>
   This file is part of the JWT C Library

   This Source Code Form is subject to the terms of the Mozilla Public
   License, v. 2.0. If a copy of the MPL was not distributed with this
   file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/curve25519.h>

#include "jwt.h"
// #include "base64.h" - reuse wolfCrypt functions

#include "jwt-private.h"
#include "main.h"
#include <wolfssl/wolfcrypt/coding.h> //DEV-446 (A7)

// DEV-432: libjwt link symbols, shims over b64_* - libjwt contract: coded_dst holds the base64 string + NUL (B64_ENC_SIZE),
// plain_dst holds the decoded bytes (B64_DEC_MAX of the padded input); 0 on error. Our own code uses b64_* directly.
int jwt_Base64encode(char *coded_dst, const char *plain_src, int len_plain_src)
{
    int ret = b64_encode((const uint8_t *)plain_src, (size_t)len_plain_src, coded_dst, B64_ENC_SIZE(len_plain_src));

    return (ret < 0) ? 0 : ret;
}

int jwt_Base64decode(char *plain_dst, const char *coded_src)
{
    int ret = b64_decode(coded_src, 0, (uint8_t *)plain_dst, B64_DEC_MAX(strlen(coded_src)), B64_F_ALLOW_WS); // DEV-432

    return (ret < 0) ? 0 : ret;
}

/* Routines to support crypto in LibJWT using WolfSSL. */

int jwt_sign_sha_hmac(jwt_t *jwt, char **out, unsigned int *len,
                      const char *str)
{
    int alg, ret = 0;
    Hmac *hmac;

    switch (jwt->alg)
    {
    case JWT_ALG_HS256:
        alg = WC_SHA256;
        break;
    case JWT_ALG_HS384:
        alg = WC_SHA384;
        break;
    case JWT_ALG_HS512:
        alg = WC_SHA512;
        break;
    default:
        return EINVAL;
    }

    *len = wc_HmacSizeByType(alg);
    *out = jwt_malloc(*len);
    if (*out == NULL)
        return ENOMEM;

    hmac = jwt_malloc(sizeof(Hmac));
    if (hmac == NULL)
    {
        jwt_freemem(*out);
        return ENOMEM;
    }

    ret = wc_HmacInit(hmac, NULL, INVALID_DEVID);
    if (ret == 0)
    {
        ret = wc_HmacSetKey(hmac, alg, (const byte *)jwt->key, jwt->key_len);
        if (ret == 0)
            ret = wc_HmacUpdate(hmac, (const byte *)str, strlen(str));
        if (ret == 0)
            ret = wc_HmacFinal(hmac, (byte *)*out);
        wc_HmacFree(hmac);
    }

    jwt_freemem(hmac);

    if (ret != 0)
        jwt_freemem(*out);

    return ret;
}

int jwt_verify_sha_hmac(jwt_t *jwt, const char *head, const char *sig)
{
    int alg, len, ret = 0;
    Hmac *hmac;
    byte *res, *buf;

    switch (jwt->alg)
    {
    case JWT_ALG_HS256:
        alg = WC_SHA256;
        break;
    case JWT_ALG_HS384:
        alg = WC_SHA384;
        break;
    case JWT_ALG_HS512:
        alg = WC_SHA512;
        break;
    default:
        return EINVAL;
    }

    len = wc_HmacSizeByType(alg);

    hmac = jwt_malloc(sizeof(Hmac));
    if (hmac == NULL)
        return ENOMEM;

    res = jwt_malloc(len);
    if (res == NULL)
    { // DEV-463 (E7): was 'hmac == NULL'
        jwt_freemem(hmac);
        return ENOMEM;
    }

    buf = jwt_malloc(B64_ENC_SIZE(len)); // DEV-432: was len*2
    if (buf == NULL)
    { // DEV-463 (E7): was 'hmac == NULL'
        jwt_freemem(hmac);
        jwt_freemem(res);
        return ENOMEM;
    }

    const char *ecdh_x25519 = jwt_get_header(jwt, "ecdh");
    if ((ecdh_x25519) && (strcmp(ecdh_x25519, "x25519") == 0) && (jwt->key_len == CURVE25519_KEYSIZE))
    {
        // gen HMACkey
        curve25519_key prvkey = {0}, pubkey = {0};
        word32 outlen = CURVE25519_KEYSIZE + 8;
        byte shared[CURVE25519_KEYSIZE + 8];

        const char *iss = jwt_get_grant(jwt, "iss");

        if (!iss || (b64_decode_exact(iss, shared, CURVE25519_KEYSIZE) != 0))
        { // DEV-438 (R3): bounded by shared, missing/invalid iss rejected; DEV-432: b64_decode_exact
            jwt_freemem(hmac);
            jwt_freemem(res);
            return EINVAL;
        }
        outlen = CURVE25519_KEYSIZE + 8; // reused below for the shared secret

        wc_curve25519_init(&prvkey);
        wc_curve25519_init(&pubkey);

        wc_curve25519_import_private_ex((const byte *)jwt->key, jwt->key_len, &prvkey, EC25519_LITTLE_ENDIAN);
        wc_curve25519_import_public_ex(shared, CURVE25519_KEYSIZE, &pubkey, EC25519_LITTLE_ENDIAN);
        wc_curve25519_shared_secret_ex(&prvkey, &pubkey, shared, &outlen, EC25519_LITTLE_ENDIAN);

        wc_curve25519_free(&prvkey);
        wc_curve25519_free(&pubkey);

        memcpy(jwt->key, shared, jwt->key_len);
    }

    ret = wc_HmacInit(hmac, NULL, INVALID_DEVID);
    if (ret == 0)
    {
        ret = wc_HmacSetKey(hmac, alg, (const byte *)jwt->key, jwt->key_len);
        if (ret == 0)
            ret = wc_HmacUpdate(hmac, (const byte *)head, strlen(head));
        if (ret == 0)
            ret = wc_HmacFinal(hmac, res);
        wc_HmacFree(hmac);
    }

    jwt_freemem(hmac);

    if (ret == 0)
    {
        // now compare 'res' (binary) with 'sig' (base64)
        ret = b64url_encode(res, len, (char *)buf, B64_ENC_SIZE(len)); // DEV-432: was jwt_Base64encode + jwt_base64uri_encode, result unchecked
        if (ret < 0)
            buf[0] = '\0'; // no match below
        // And now...
        ret = strcmp((const char *)buf, sig) ? EINVAL : 0;
    }

    jwt_freemem(res);
    jwt_freemem(buf);

    return ret;
}

int jwt_sign_sha_pem(jwt_t *jwt, char **out, unsigned int *len,
                     const char *str)
{
    int ret = EINVAL;

    // TBD

    return ret;
}

int jwt_verify_sha_pem(jwt_t *jwt, const char *head, const char *sig_b64)
{
    int ret = EINVAL;

    // TBD

    return ret;
}
