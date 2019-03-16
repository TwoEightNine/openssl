//
// Created by msnthrp on 16/03/19.
//
# include <openssl/evp.h>

# include <openssl/objects.h>
# include <openssl/gost_grasshopper.h>

typedef struct {
    GHGOST_KEY key;
} EVP_GHGOST_KEY;

# define data(ctx) ((EVP_GHGOST_KEY *)EVP_CIPHER_CTX_get_cipher_data(ctx))

static int gost_grasshopper_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                                     const unsigned char *iv, int enc);

static int gost_grasshopper_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                      const unsigned char *in, size_t inl);

static const EVP_CIPHER gost_grasshopper_cipher = {
        NID_gost_grasshopper,
        1, 16, 0,
        EVP_CIPH_CBC_MODE,
        gost_grasshopper_init_key,
        gost_grasshopper_do_cipher,
        NULL,
        sizeof(EVP_GHGOST_KEY),
        NULL,
        NULL,
        NULL,
        NULL
};

static int gost_grasshopper_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
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

static int gost_grasshopper_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                      const unsigned char *in, size_t inl) {
    EVP_GHGOST_KEY *d = data(ctx);
    if (EVP_CIPHER_CTX_encrypting(ctx))
        CRYPTO_cbc128_encrypt(in, out, len, &d->key,
                              EVP_CIPHER_CTX_iv_noconst(ctx), (block128_t) GHGOST_encrypt);
    else
        CRYPTO_cbc128_decrypt(in, out, len, &d->key,
                              EVP_CIPHER_CTX_iv_noconst(ctx), (block128_t) GHGOST_decrypt);
    return 1;
}

const EVP_CIPHER *EVP_gost_grasshopper(void) {
    return (&gost_grasshopper_cipher);
}