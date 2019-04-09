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

static int ghgost_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static int ghgost_sign(const unsigned char *data, const GHGOST_KEY *key,
        unsigned char *tag, size_t len);

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

static const EVP_CIPHER ghgost_ae = {
        NID_ghgost_ae,
        GHGOST_BLOCK_SIZE,
        GHGOST_BLOCK_SIZE * 2,
        GHGOST_BLOCK_SIZE,
        EVP_CIPH_ECB_MODE | EVP_CIPH_FLAG_AEAD_CIPHER,
        ghgost_init_key,
        ghgost_do_cipher,
        NULL,
        sizeof(EVP_GHGOST_KEY),
        NULL, NULL,
        ghgost_ctrl,
        NULL
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
    GHGOST_set_key(key, EVP_CIPHER_CTX_key_length(ctx) * 8, d->key);
    return 1;
}

static int ghgost_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t inl) {
    EVP_GHGOST_KEY *d = data(ctx);
    size_t const_len = inl;
    int cipher_mode = EVP_CIPHER_CTX_mode(ctx) & 0x07;
    int aead = EVP_CIPHER_CTX_flags(ctx) & EVP_CIPH_FLAG_AEAD_CIPHER;
    int encr = EVP_CIPHER_CTX_encrypting(ctx);
    int num;
    int i;
    switch (cipher_mode) {

        case EVP_CIPH_ECB_MODE:
            if (inl < GHGOST_BLOCK_SIZE) return 1;

            for (i = 0, inl -= GHGOST_BLOCK_SIZE; i <= inl; i += GHGOST_BLOCK_SIZE) {
                if (encr) {
                    GHGOST_encrypt(in + i, out + i, &d->key);
                } else {
                    GHGOST_decrypt(in + i, out + i, &d->key);
                }
            }
            if (aead) {
                unsigned char tag[GHGOST_BLOCK_SIZE];
                if (encr) {
                    ghgost_sign(out, &d->key, tag, const_len);
                    memcpy(EVP_CIPHER_CTX_buf_noconst(ctx), tag, GHGOST_BLOCK_SIZE);
                } else {
                    ghgost_sign(in, &d->key, tag, const_len);
                    if (memcmp(tag, EVP_CIPHER_CTX_buf_noconst(ctx), GHGOST_BLOCK_SIZE)) {
                        return 0;
                    }
                }
            }
            return 1;

        case EVP_CIPH_CBC_MODE:
            if (encr) {
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

static int ghgost_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) {

    switch (type) {

        /**
         * here we copy tag from #EVP_CIPHER_CTX_buf_noconst(ctx) into @param ptr
         * so decryptor can check it
         */
        case EVP_CTRL_AEAD_SET_TAG:
            if (arg != GHGOST_BLOCK_SIZE || EVP_CIPHER_CTX_encrypting(ctx)) return 0;
            memcpy(EVP_CIPHER_CTX_buf_noconst(ctx), ptr, arg);
            break;

            /**
             * here we must put authentication tag into @param ptr
             * so encryptor must put it into #EVP_CIPHER_CTX_buf_noconst(ctx)
             */
        case EVP_CTRL_AEAD_GET_TAG:
            if (arg != GHGOST_BLOCK_SIZE || !EVP_CIPHER_CTX_encrypting(ctx)) return 0;
            memcpy(ptr, EVP_CIPHER_CTX_buf_noconst(ctx), arg);
            break;
    }
    return 1;
}

/**
 * uses ghgost-cbc-mac for create an authentication tag
 * @param data input message
 * @param key GHGOST_KEY for deriving the MAC key
 * @param tag result
 * @param len length of @param data
 * @return tag for @param data
 */
static int ghgost_sign(const unsigned char *data, const GHGOST_KEY *key,
        unsigned char *tag, size_t len) {

    unsigned char iv[GHGOST_BLOCK_SIZE];
    memset(iv, 0, GHGOST_BLOCK_SIZE);

    if (len >= 2 * GHGOST_BLOCK_SIZE) {
        /**
         * encrypt and take block[-2]
         */
        unsigned char *out = (unsigned char *) malloc(len);
        memset(out, 0, len);

        CRYPTO_cbc128_encrypt(data, out, len, key, iv, (block128_f) GHGOST_encrypt);
        memcpy(tag, &out[len - 2 * GHGOST_BLOCK_SIZE], GHGOST_BLOCK_SIZE);
        free(out);
    } else {
        /**
         * just take iv
         */
        memcpy(tag, iv, GHGOST_BLOCK_SIZE);
    }

    unsigned char mac_key[GHGOST_BLOCK_SIZE];
    GHGOST_get_mac_key(key, mac_key);
    for (int i = 0; i < GHGOST_BLOCK_SIZE; i++) {
        tag[i] = data[len - GHGOST_BLOCK_SIZE + i] ^ tag[i] ^ mac_key[i];
    }
    GHGOST_encrypt(tag, tag, key);
    return 1;
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

const EVP_CIPHER *EVP_ghgost_ae(void) {
    return (&ghgost_ae);
}

#endif