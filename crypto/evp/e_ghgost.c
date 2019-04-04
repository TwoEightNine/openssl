//
// Created by msnthrp on 16/03/19.
//
#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/modes.h>

#ifndef OPENSSL_NO_GHGOST

# include <openssl/evp.h>
# include <openssl/objects.h>
# include <openssl/ghgost.h>

# include "internal/evp_int.h"

typedef struct {
    GHGOST_KEY key;
} EVP_GHGOST_KEY;

# define data(ctx) ((EVP_GHGOST_KEY *)EVP_CIPHER_CTX_get_cipher_data(ctx))

static int ghgost_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                     const unsigned char *iv, int enc);

static int ghgost_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                      const unsigned char *in, size_t inl);

static const EVP_CIPHER ghgost_cipher = {
        NID_ghgost,
        GHGOST_BLOCK_SIZE,
        GHGOST_BLOCK_SIZE * 2,
        GHGOST_BLOCK_SIZE,
        EVP_CIPH_CBC_MODE,
        ghgost_init_key,
        ghgost_do_cipher,
        NULL,
        sizeof(EVP_GHGOST_KEY),
        NULL,
        NULL,
        NULL,
        NULL
};

static int ghgost_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                     const unsigned char *iv, int enc) {
    int ret;
    int mode = EVP_CIPHER_CTX_mode(ctx);
    if (mode == EVP_CIPH_CFB_MODE || mode == EVP_CIPH_OFB_MODE || enc)
        ret = GHGOST_set_encrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                     EVP_CIPHER_CTX_get_cipher_data(ctx));
    else
        ret = GHGOST_set_decrypt_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8,
                                     EVP_CIPHER_CTX_get_cipher_data(ctx));
    return 1;
}

static int ghgost_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                      const unsigned char *in, size_t inl) {
    EVP_GHGOST_KEY *d = data(ctx);
    if (EVP_CIPHER_CTX_encrypting(ctx))
        CRYPTO_cbc128_encrypt(in, out, inl, &d->key,
                              EVP_CIPHER_CTX_iv_noconst(ctx), (block128_f) GHGOST_encrypt);
    else
        CRYPTO_cbc128_decrypt(in, out, inl, &d->key,
                              EVP_CIPHER_CTX_iv_noconst(ctx), (block128_f) GHGOST_decrypt);
    return 1;
}

const EVP_CIPHER *EVP_ghgost(void) {
    return (&ghgost_cipher);
}
#endif