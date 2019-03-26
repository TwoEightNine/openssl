//
// Created by msnthrp on 16/03/19.
//

#ifndef OPENSSL_GHGOST_H
# define OPENSSL_GHGOST_H

# include <openssl/opensslconf.h>

# ifdef OPENSSL_NO_GHGOST
#  error GHGOST is disabled.
# endif

# define GHGOST_BLOCK_SIZE 16
# define GHGOST_ROUNDS_COUNT 10

typedef struct {
    unsigned long key[GHGOST_ROUNDS_COUNT];
} GHGOST_KEY;

void GHGOST_encrypt(const unsigned char *in, unsigned char *out,
                    const GHGOST_KEY *key);

void GHGOST_decrypt(const unsigned char *in, unsigned char *out,
                    const GHGOST_KEY *key);

int GHGOST_set_encrypt_key(const unsigned char *userKey, const int bits,
                           GHGOST_KEY *key);

int GHGOST_set_decrypt_key(const unsigned char *userKey, const int bits,
                           GHGOST_KEY *key);

#endif //OPENSSL_GHGOST_H
