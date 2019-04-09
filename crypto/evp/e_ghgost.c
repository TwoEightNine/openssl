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
# include <string.h>

# include "internal/evp_int.h"

typedef struct {
    GHGOST_KEY key;
} EVP_GHGOST_KEY;

# define data(ctx) ((EVP_GHGOST_KEY *)EVP_CIPHER_CTX_get_cipher_data(ctx))

static int ghgost_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                           const unsigned char *iv, int enc);

static int ghgost_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t inl);

static const EVP_CIPHER ghgost_ecb = {
        NID_ghgost_ecb,
        GHGOST_BLOCK_SIZE,
        GHGOST_BLOCK_SIZE * 2,
        GHGOST_BLOCK_SIZE,
        EVP_CIPH_ECB_MODE,
        ghgost_init_key,
        ghgost_do_cipher,
        NULL,
        sizeof(EVP_GHGOST_KEY),
        NULL, NULL,
        NULL, NULL
};

static const EVP_CIPHER ghgost_cbc = {
        NID_ghgost_cbc,
        GHGOST_BLOCK_SIZE,
        GHGOST_BLOCK_SIZE * 2,
        GHGOST_BLOCK_SIZE,
        EVP_CIPH_CBC_MODE,
        ghgost_init_key,
        ghgost_do_cipher,
        NULL,
        sizeof(EVP_GHGOST_KEY),
        NULL, NULL,
        NULL, NULL
};

static const EVP_CIPHER ghgost_ofb = {
        NID_ghgost_ofb,
        GHGOST_BLOCK_SIZE,
        GHGOST_BLOCK_SIZE * 2,
        GHGOST_BLOCK_SIZE,
        EVP_CIPH_OFB_MODE,
        ghgost_init_key,
        ghgost_do_cipher,
        NULL,
        sizeof(EVP_GHGOST_KEY),
        NULL, NULL,
        NULL, NULL
};

static const EVP_CIPHER ghgost_cfb = {
        NID_ghgost_cfb,
        GHGOST_BLOCK_SIZE,
        GHGOST_BLOCK_SIZE * 2,
        GHGOST_BLOCK_SIZE,
        EVP_CIPH_CFB_MODE,
        ghgost_init_key,
        ghgost_do_cipher,
        NULL,
        sizeof(EVP_GHGOST_KEY),
        NULL, NULL,
        NULL, NULL
};

static const EVP_CIPHER ghgost_ctr = {
        NID_ghgost_ctr,
        GHGOST_BLOCK_SIZE,
        GHGOST_BLOCK_SIZE * 2,
        GHGOST_BLOCK_SIZE,
        EVP_CIPH_CTR_MODE,
        ghgost_init_key,
        ghgost_do_cipher,
        NULL,
        sizeof(EVP_GHGOST_KEY),
        NULL, NULL,
        NULL, NULL
};

void print_block_2(ghgost_block_t b) {
    for (int i = GHGOST_BLOCK_SIZE - 1; i >= 0; i--) {
        printf("%02x", b[i]);
    }
}

void print_ghgost_key_2(GHGOST_KEY key) {
    printf("\nGHGOST2 key:");
    for (int i = 0; i < GHGOST_ROUNDS_COUNT; i++) {
        printf("\n%d: ", i + 1);
        print_block_2(key[i]);
    }
    printf("\n");
}

static int ghgost_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                           const unsigned char *iv, int enc) {
    EVP_GHGOST_KEY *d = data(ctx);
    GHGOST_KEY ghgost_key;
    GHGOST_set_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8, ghgost_key);

    memcpy(d->key, ghgost_key, GHGOST_ROUNDS_COUNT * GHGOST_BLOCK_SIZE);
    return 1;
}

static int ghgost_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t inl) {
    EVP_GHGOST_KEY *d = data(ctx);
    int mode = EVP_CIPHER_CTX_mode(ctx);
    int num;
    int i;
    switch (mode) {

        case EVP_CIPH_ECB_MODE:
            if (inl < GHGOST_BLOCK_SIZE) return 1;

            for (i = 0, inl -= GHGOST_BLOCK_SIZE; i <= inl; i += GHGOST_BLOCK_SIZE) {
                if (EVP_CIPHER_CTX_encrypting(ctx)) {
                    GHGOST_encrypt(in + i, out + i, &d->key);
                } else {
                    GHGOST_decrypt(in + i, out + i, &d->key);
                }
            }
            return 1;

        case EVP_CIPH_CBC_MODE:
            if (EVP_CIPHER_CTX_encrypting(ctx)) {
                CRYPTO_cbc128_encrypt(in, out, inl, &d->key,
                                      EVP_CIPHER_CTX_iv_noconst(ctx), (block128_f) GHGOST_encrypt);
            } else {
                CRYPTO_cbc128_decrypt(in, out, inl, &d->key,
                                      EVP_CIPHER_CTX_iv_noconst(ctx), (block128_f) GHGOST_decrypt);
            }
            return 1;

        case EVP_CIPH_OFB_MODE:
            num = EVP_CIPHER_CTX_num(ctx);
            CRYPTO_ofb128_encrypt(in, out, inl, &d->key,
                                  EVP_CIPHER_CTX_iv_noconst(ctx), &num,
                                  (block128_f) GHGOST_encrypt);
            EVP_CIPHER_CTX_set_num(ctx, num);
            return 1;

        case EVP_CIPH_CFB_MODE:
            num = EVP_CIPHER_CTX_num(ctx);
            CRYPTO_cfb128_encrypt(in, out, inl, &d->key,
                                  EVP_CIPHER_CTX_iv_noconst(ctx), &num,
                                  EVP_CIPHER_CTX_encrypting(ctx),
                                  (block128_f) GHGOST_encrypt);
            EVP_CIPHER_CTX_set_num(ctx, num);
            return 1;

        case EVP_CIPH_CTR_MODE:
            num = EVP_CIPHER_CTX_num(ctx);
            CRYPTO_ctr128_encrypt(in, out, inl, &d->key,
                                  EVP_CIPHER_CTX_iv_noconst(ctx),
                                  EVP_CIPHER_CTX_buf_noconst(ctx), &num,
                                  (block128_f) GHGOST_encrypt);
            EVP_CIPHER_CTX_set_num(ctx, num);
            return 1;

        default:
            return 0;
    }
}

const EVP_CIPHER *EVP_ghgost_ecb(void) {
    return (&ghgost_ecb);
}

const EVP_CIPHER *EVP_ghgost_cbc(void) {
    return (&ghgost_cbc);
}

const EVP_CIPHER *EVP_ghgost_ofb(void) {
    return (&ghgost_ofb);
}

const EVP_CIPHER *EVP_ghgost_cfb(void) {
    return (&ghgost_cfb);
}

const EVP_CIPHER *EVP_ghgost_ctr(void) {
    return (&ghgost_ctr);
}

#endif