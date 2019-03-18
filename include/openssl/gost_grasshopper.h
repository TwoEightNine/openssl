//
// Created by msnthrp on 16/03/19.
//

#ifndef OPENSSL_GOST_GRASSHOPPER_H
# define OPENSSL_GOST_GRASSHOPPER_H

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

#endif //OPENSSL_GOST_GRASSHOPPER_H
