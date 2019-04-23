//
// Created by msnthrp on 22/04/19.
//
#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/modes.h>

#ifndef OPENSSL_NO_MGMGOST

# include <openssl/evp.h>
# include <openssl/objects.h>
# include <openssl/mgmgost.h>
# include <string.h>

# include "internal/evp_int.h"

typedef struct {
    uint8_t key[32];
} EVP_MGMGOST_KEY;

# define data(ctx) ((EVP_MGMGOST_KEY *)EVP_CIPHER_CTX_get_cipher_data(ctx))

static int mgmgost_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc);

static int mgmgost_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t inl);

static int mgmgost_do_eax_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 const unsigned char *in, size_t inl);

static int mgmgost_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static int mgmgost_sign(const unsigned char *data, const uint8_t *key,
                        unsigned char *tag, size_t len);

static int mgmgost_encrypt_128(const unsigned char *in, unsigned char *out,
                               const uint8_t *key);

static int mgmgost_decrypt_128(const unsigned char *in, unsigned char *out,
                               const uint8_t *key);

static const EVP_CIPHER mgmgost_ecb = {
        NID_mgmgost_ecb,
        16, 32, 16,
        EVP_CIPH_ECB_MODE,
        mgmgost_init_key,
        mgmgost_do_cipher,
        NULL,
        sizeof(EVP_MGMGOST_KEY),
        NULL, NULL,
        NULL, NULL
};

static const EVP_CIPHER mgmgost_cbc = {
        NID_mgmgost_cbc,
        16, 32, 16,
        EVP_CIPH_CBC_MODE,
        mgmgost_init_key,
        mgmgost_do_cipher,
        NULL,
        sizeof(EVP_MGMGOST_KEY),
        NULL, NULL,
        NULL, NULL
};

static const EVP_CIPHER mgmgost_ofb = {
        NID_mgmgost_ofb,
        16, 32, 16,
        EVP_CIPH_OFB_MODE,
        mgmgost_init_key,
        mgmgost_do_cipher,
        NULL,
        sizeof(EVP_MGMGOST_KEY),
        NULL, NULL,
        NULL, NULL
};

static const EVP_CIPHER mgmgost_cfb = {
        NID_mgmgost_cfb,
        16, 32, 16,
        EVP_CIPH_CFB_MODE,
        mgmgost_init_key,
        mgmgost_do_cipher,
        NULL,
        sizeof(EVP_MGMGOST_KEY),
        NULL, NULL,
        NULL, NULL
};

static const EVP_CIPHER mgmgost_ctr = {
        NID_mgmgost_ctr,
        16, 32, 16,
        EVP_CIPH_CTR_MODE,
        mgmgost_init_key,
        mgmgost_do_cipher,
        NULL,
        sizeof(EVP_MGMGOST_KEY),
        NULL, NULL,
        NULL, NULL
};

static const EVP_CIPHER mgmgost_ae = {
        NID_mgmgost_ae,
        16, 32, 16,
        EVP_CIPH_ECB_MODE | EVP_CIPH_FLAG_AEAD_CIPHER,
        mgmgost_init_key,
        mgmgost_do_cipher,
        NULL,
        sizeof(EVP_MGMGOST_KEY),
        NULL, NULL,
        mgmgost_ctrl,
        NULL
};

static const EVP_CIPHER mgmgost_eax = {
        NID_mgmgost_eax,
        16, 32, 16,
        EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_AEAD_CIPHER,
        mgmgost_init_key,
        mgmgost_do_eax_cipher,
        NULL,
        sizeof(EVP_MGMGOST_KEY),
        NULL, NULL,
        mgmgost_ctrl,
        NULL
};

static int mgmgost_encrypt_128(const unsigned char *in, unsigned char *out,
                               const uint8_t *key) {
    MGMGOST_encrypt(key, in, out);
    MGMGOST_encrypt(key, in + 8, out + 8);
}

static int mgmgost_decrypt_128(const unsigned char *in, unsigned char *out,
                               const uint8_t *key) {
    MGMGOST_decrypt(key, in, out);
    MGMGOST_decrypt(key, in + 8, out + 8);
}

static int mgmgost_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                            const unsigned char *iv, int enc) {
    EVP_MGMGOST_KEY *d = data(ctx);
    memcpy(&d->key, key, 32);
    return 1;
}

static int mgmgost_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                             const unsigned char *in, size_t inl) {
    EVP_MGMGOST_KEY *d = data(ctx);
    size_t const_len = inl;
    int cipher_mode = EVP_CIPHER_CTX_mode(ctx) & 0x07;
    int aead = EVP_CIPHER_CTX_flags(ctx) & EVP_CIPH_FLAG_AEAD_CIPHER;
    int encr = EVP_CIPHER_CTX_encrypting(ctx);
    int num;
    int i;
    switch (cipher_mode) {

        case EVP_CIPH_ECB_MODE:
            if (inl < 16) return 1;

            for (i = 0, inl -= 16; i <= inl; i += 16) {
                if (encr) {
                    mgmgost_encrypt_128(in + i, out + i, &d->key);
                } else {
                    mgmgost_decrypt_128(in + i, out + i, &d->key);
                }
            }
            if (aead) {
                if (encr) {
                    mgmgost_sign(out, &d->key, EVP_CIPHER_CTX_buf_noconst(ctx), const_len);
                } else {
                    unsigned char tag[16];
                    mgmgost_sign(in, &d->key, tag, const_len);
                    if (memcmp(tag, EVP_CIPHER_CTX_buf_noconst(ctx), 16)) {
                        return 0;
                    }
                }
            }
            return 1;

        case EVP_CIPH_CBC_MODE:
            if (encr) {
                CRYPTO_cbc128_encrypt(in, out, inl, &d->key,
                                      EVP_CIPHER_CTX_iv_noconst(ctx), (block128_f) mgmgost_encrypt_128);
            } else {
                CRYPTO_cbc128_decrypt(in, out, inl, &d->key,
                                      EVP_CIPHER_CTX_iv_noconst(ctx), (block128_f) mgmgost_decrypt_128);
            }
            return 1;

        case EVP_CIPH_OFB_MODE:
            num = EVP_CIPHER_CTX_num(ctx);
            CRYPTO_ofb128_encrypt(in, out, inl, &d->key,
                                  EVP_CIPHER_CTX_iv_noconst(ctx), &num,
                                  (block128_f) mgmgost_encrypt_128);
            EVP_CIPHER_CTX_set_num(ctx, num);
            return 1;

        case EVP_CIPH_CFB_MODE:
            num = EVP_CIPHER_CTX_num(ctx);
            CRYPTO_cfb128_encrypt(in, out, inl, &d->key,
                                  EVP_CIPHER_CTX_iv_noconst(ctx), &num,
                                  EVP_CIPHER_CTX_encrypting(ctx),
                                  (block128_f) mgmgost_encrypt_128);
            EVP_CIPHER_CTX_set_num(ctx, num);
            return 1;

        case EVP_CIPH_CTR_MODE:
            num = EVP_CIPHER_CTX_num(ctx);
            CRYPTO_ctr128_encrypt(in, out, inl, &d->key,
                                  EVP_CIPHER_CTX_iv_noconst(ctx),
                                  EVP_CIPHER_CTX_buf_noconst(ctx), &num,
                                  (block128_f) mgmgost_encrypt_128);
            EVP_CIPHER_CTX_set_num(ctx, num);
            return 1;

        default:
            return 0;
    }
}

static int mgmgost_do_eax_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                 const unsigned char *in, size_t inl) {
    EVP_MGMGOST_KEY *d = data(ctx);
    int encr = EVP_CIPHER_CTX_encrypting(ctx);
    unsigned char h[3];
    memset(h, 0, 3);
    if (encr) {
        CRYPTO_eax128_encrypt(EVP_CIPHER_CTX_iv(ctx), h, 3,
                              &d->key, in, inl, out,
                              EVP_CIPHER_CTX_buf_noconst(ctx), (block128_f) mgmgost_encrypt_128);
    } else {
        return CRYPTO_eax128_decrypt(EVP_CIPHER_CTX_iv(ctx), h, 3,
                                     &d->key, in, EVP_CIPHER_CTX_buf_noconst(ctx),
                                     inl, out, (block128_f) mgmgost_encrypt_128);
    }
    return 1;
}

static int mgmgost_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) {

    switch (type) {

        /**
         * here we copy tag from #EVP_CIPHER_CTX_buf_noconst(ctx) into @param ptr
         * so decryptor can check it
         */
        case EVP_CTRL_AEAD_SET_TAG:
            if (arg != 16 || EVP_CIPHER_CTX_encrypting(ctx)) return 0;
            memcpy(EVP_CIPHER_CTX_buf_noconst(ctx), ptr, arg);
            break;

            /**
             * here we must put authentication tag into @param ptr
             * so encryptor must put it into #EVP_CIPHER_CTX_buf_noconst(ctx)
             */
        case EVP_CTRL_AEAD_GET_TAG:
            if (arg != 16 || !EVP_CIPHER_CTX_encrypting(ctx)) return 0;
            memcpy(ptr, EVP_CIPHER_CTX_buf_noconst(ctx), arg);
            break;
    }
    return 1;
}

/**
 * uses mgmgost-cbc-mac for create an authentication tag
 * @param data input message
 * @param key for deriving the MAC key
 * @param tag result
 * @param len length of @param data
 * @return tag for @param data
 *
 * block cipher calls: [len / BLOCK_SIZE] + 1
 */
static int mgmgost_sign(const unsigned char *data, const uint8_t *key,
                        unsigned char *tag, size_t len) {

    unsigned char iv[16];
    memset(iv, 0, 16);

    if (len >= 2 * 16) {
        /**
         * encrypt and take block[-2]
         */
        unsigned char *out = (unsigned char *) malloc(len);
        memset(out, 0, len);

        CRYPTO_cbc128_encrypt(data, out, len, key, iv, (block128_f) mgmgost_encrypt_128);
        memcpy(tag, &out[len - 2 * 16], 16);
        free(out);
    } else {
        /**
         * just take iv
         */
        memcpy(tag, iv, 16);
    }

    /**
     * encrypt zeros to obtain mac_key
     */
    unsigned char mac_key[16];
    memset(mac_key, 0, 16);
    mgmgost_encrypt_128(mac_key, mac_key, key);

    for (int i = 0; i < 16; i++) {
        tag[i] = data[len - 16 + i] ^ tag[i] ^ mac_key[i];
    }
    mgmgost_encrypt_128(tag, tag, key);
    return 1;
}

const EVP_CIPHER *EVP_mgmgost_ecb(void) {
    return (&mgmgost_ecb);
}

const EVP_CIPHER *EVP_mgmgost_cbc(void) {
    return (&mgmgost_cbc);
}

const EVP_CIPHER *EVP_mgmgost_ofb(void) {
    return (&mgmgost_ofb);
}

const EVP_CIPHER *EVP_mgmgost_cfb(void) {
    return (&mgmgost_cfb);
}

const EVP_CIPHER *EVP_mgmgost_ctr(void) {
    return (&mgmgost_ctr);
}

const EVP_CIPHER *EVP_mgmgost_ae(void) {
    return (&mgmgost_ae);
}

const EVP_CIPHER *EVP_mgmgost_eax(void) {
    return (&mgmgost_eax);
}

#endif