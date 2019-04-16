//
// Created by msnthrp on 16/04/19.
//
#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/modes.h>

#ifndef OPENSSL_NO_AEGIS

# include <openssl/evp.h>
# include <openssl/objects.h>
# include <openssl/aegis.h>
# include <string.h>

# include "internal/evp_int.h"

typedef struct {
    uint8_t key[16];
    uint8_t iv[16];
} EVP_AEGIS_KEY;

# define data(ctx) ((EVP_AEGIS_KEY *)EVP_CIPHER_CTX_get_cipher_data(ctx))

static int aegis_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                           const unsigned char *iv, int enc);

static int aegis_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                            const unsigned char *in, size_t inl);

static int aegis_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

static const EVP_CIPHER aegis_128l = {
        NID_aegis_128l,
        1, 16, 16,
        EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_VARIABLE_LENGTH,
        aegis_init_key,
        aegis_do_cipher,
        NULL,
        sizeof(EVP_AEGIS_KEY),
        NULL, NULL,
        aegis_ctrl,
        NULL
};

const EVP_CIPHER *EVP_aegis_128l(void) {
    return &aegis_128l;
}

static int aegis_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                          const unsigned char *iv, int enc) {
    EVP_AEGIS_KEY *d = data(ctx);
    memcpy(&d->key, key, 16);
    memcpy(&d->iv, iv, 16);
}

static int aegis_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                           const unsigned char *in, size_t inl) {
    EVP_AEGIS_KEY *d = data(ctx);
    int encr = EVP_CIPHER_CTX_encrypting(ctx);
    uint8_t ad[0];
    if (encr) {
        AEGIS_encrypt(&d->key, &d->iv, in, inl,
                ad, 0, out, EVP_CIPHER_CTX_buf_noconst(ctx));
        return 1;
    } else {
        return AEGIS_decrypt(&d->key, &d->iv, in, inl,
                ad, 0, EVP_CIPHER_CTX_buf_noconst(ctx), out);
    }
}

static int aegis_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr) {
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

#endif
