//
// Created by msnthrp on 16/04/19.
//

#ifndef OPENSSL_AEGIS_H
#define OPENSSL_AEGIS_H

# include <stdint.h>
# include <stdlib.h>

/**
 * encrypt using AEGIS-128L
 * INPUT:
 * @param key 128bit
 * @param iv 128bit
 * @param msg, len = @param msglen * 8
 * @param msglen
 * @param ad, len = @param adlen * 8
 * @param adlen
 * OUTPUT:
 * @param cipher, len = @param msglen
 * @param tag 128bit
 */
void AEGIS_encrypt(const uint8_t *key, const uint8_t *iv,
                   const uint8_t *msg, size_t msglen,
                   const uint8_t *ad, size_t adlen,
                   uint8_t *cipher, uint8_t *tag);

/**
 * encrypt using AEGIS-128L
 * INPUT:
 * @param key 128bit
 * @param iv 128bit
 * @param cipher, len = @param cipherlen * 8
 * @param cipherlen
 * @param ad, len = @param adlen * 8
 * @param adlen
 * @param tag 128bit
 * OUTPUT:
 * @param msg, len = @param cipherlen
 * @return 1 if tag is valid, 0 otherwise
 */
uint8_t AEGIS_decrypt(const uint8_t *key, const uint8_t *iv,
                  const uint8_t *cipher, size_t cipherlen,
                  const uint8_t *ad, size_t adlen,
                  const uint8_t *tag, uint8_t *msg);

/**
 * encrypt using AEGIS-256
 *
 * INPUT:
 * @param key 256bit
 * @param iv 256bit
 * @param msg, len = @param msglen * 8
 * @param msglen
 * @param ad, len = @param adlen * 8
 * @param adlen
 * OUTPUT:
 * @param tag 128bit
 * @param cipher, len = @param msglen
 */
void AEGIS_256_encrypt(
        const uint8_t *key, const uint8_t *iv,
        const uint8_t *msg, size_t msglen,
        const uint8_t *ad, size_t adlen,
        uint8_t *tag, uint8_t *cipher
);

/**
 * decrypt using AEGIS-256
 *
 * INPUT:
 * @param key 256bit
 * @param iv 256bit
 * @param cipher, len = @param cipherlen * 8
 * @param cipherlen
 * @param ad, len = @param adlen * 8
 * @param adlen
 * @param tag 128bit
 * OUTPUT:
 * @param msg, len = @param cipherlen
 * @return 1 if tag is valid, 0 otherwise
 */
uint8_t AEGIS_256_decrypt(
        const uint8_t *key, const uint8_t *iv,
        const uint8_t *cipher, size_t cipherlen,
        const uint8_t *ad, size_t adlen,
        const uint8_t *tag, uint8_t *msg
);

/**
 * encrypt using AEGIS-128
 *
 * INPUT:
 * @param key 128bit
 * @param iv 128bit
 * @param msg, len = @param msglen * 8
 * @param msglen
 * @param ad, len = @param adlen * 8
 * @param adlen
 * OUTPUT:
 * @param tag 128bit
 * @param cipher, len = @param msglen
 */
void AEGIS_128_encrypt(
        const uint8_t *key, const uint8_t *iv,
        const uint8_t *msg, size_t msglen,
        const uint8_t *ad, size_t adlen,
        uint8_t *tag, uint8_t *cipher
);

/**
 * decrypt using AEGIS-128
 *
 * INPUT:
 * @param key 128bit
 * @param iv 128bit
 * @param cipher, len = @param cipherlen * 8
 * @param cipherlen
 * @param ad, len = @param adlen * 8
 * @param adlen
 * @param tag 128bit
 * OUTPUT:
 * @param msg, len = @param cipherlen
 * @return 1 if tag is valid, 0 otherwise
 */
uint8_t AEGIS_128_decrypt(
        const uint8_t *key, const uint8_t *iv,
        const uint8_t *cipher, size_t cipherlen,
        const uint8_t *ad, size_t adlen,
        const uint8_t *tag, uint8_t *msg
);

#endif //OPENSSL_AEGIS_H
