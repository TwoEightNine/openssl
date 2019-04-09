//
// Created by msnthrp on 16/03/19.
//

#ifndef OPENSSL_GHGOST_H
# define OPENSSL_GHGOST_H

# include <openssl/opensslconf.h>
# include <stdint.h>

# ifdef OPENSSL_NO_GHGOST
#  error GHGOST is disabled.
# endif

# define GHGOST_BLOCK_SIZE 16
# define GHGOST_ROUNDS_COUNT 10

typedef uint8_t ghgost_block_t[GHGOST_BLOCK_SIZE];

typedef ghgost_block_t GHGOST_KEY[GHGOST_ROUNDS_COUNT];

void GHGOST_encrypt(const unsigned char *in, unsigned char *out,
                    const GHGOST_KEY *key);

void GHGOST_decrypt(const unsigned char *in, unsigned char *out,
                    const GHGOST_KEY *key);

void GHGOST_set_key(const unsigned char *userKey, const int bits,
                           GHGOST_KEY *key);

void GHGOST_get_mac_key(const GHGOST_KEY *key, unsigned char *mac_key);

#endif //OPENSSL_GHGOST_H
