//
// Created by msnthrp on 11/04/19.
//

#include <openssl/modes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BLOCK_SIZE 16

void print_b(const unsigned char *b) {
    for (int i = 0; i < BLOCK_SIZE; i++) {
        printf("%02x", b[i]);
    }
    printf("\n");
}

/**
 * increase block by one
 * @param block: len = BLOCK_SIZE
 */
void inc(unsigned char *block) {
    uint8_t i = BLOCK_SIZE;
    while (i--) {
        block[i]++;
        if (block[i] != 0) return;
    }
}

/**
 * shift block to left
 * @param block: len = BLOCK_SIZE
 */
void shift_left(unsigned char *block) {
    uint8_t last = BLOCK_SIZE - 1;
    for (uint8_t i = 0; i < last; i++) {
        block[i] <<= 1;
        block[i] += (block[i + 1] & 0x80) >> 7;
    }
    block[last] <<= 1;
}

/**
 * multiply block by 2 in GF(2^128) a.k.a.
 * shift left and xor 0x87 if msb = 1
 * @param block, len = BLOCK_SIZE
 */
void mul_2(unsigned char *block) {
    uint8_t msb = block[0] & 0x80;
    shift_left(block);
    if (msb) {
        block[BLOCK_SIZE - 1] ^= 0x87;
    }
}

/**
 * perform encryption in CBC mode with IV = {0}^n
 * INPUT:
 * @param message to be encrypted, len = @param len
 * @param key for function @param encrypt
 * @param len of message
 * @param encrypt, function (block128_f)
 * OUTPUT:
 * @param out, last block of cipher, len = BLOCK_SIZE
 *
 * block cipher calls: [len / BLOCK_SIZE]
 */
void eax_cbc(const unsigned char *message, const void *key,
             size_t len, unsigned char *out, block128_f encrypt) {
    memset(out, 0, BLOCK_SIZE);
    uint8_t i;
    size_t l = 0;
    while (l < len) {
        i = BLOCK_SIZE;
        while (i--) {
            out[i] = out[i] ^ message[l + i];
        }
        (*encrypt)(out, out, key);
        l += BLOCK_SIZE;
    }
}

/**
 * perform encryption in CTR mode
 * INPUT:
 * @param n, nonce, len = BLOCK_SIZE
 * @param key for @param encrypt
 * @param message to be encrypted, len = @param len
 * @param len of message
 * @param encrypt, function (block128_t)
 * OUTPUT:
 * @param out, ciphertext, len = @param len
 *
 * block cipher calls: [len / BLOCK_SIZE]
 */
void eax_ctr(const unsigned char *n, const void *key,
             const unsigned char *message, size_t len,
             unsigned char *out, block128_f encrypt) {

    uint8_t nonce[BLOCK_SIZE];
    memcpy(nonce, n, BLOCK_SIZE);

    size_t l = 0;
    uint8_t i;
    while (l < len) {
        (*encrypt) (nonce, out + l, key);
        i = BLOCK_SIZE;
        while (i--) {
            out[l + i] ^= message[l + i];
        }
        inc(nonce);
        l += BLOCK_SIZE;
    }
}

/**
 * pad message, xor with last block, output len = BLOCK_SIZE
 * @param b, len = BLOCK_SIZE
 * @param p, len = BLOCK_SIZE
 * @param message, len = @param len
 * @param len of message
 * OUTPUT:
 * @param padded_message result, len = @param plen
 * @param plen, len of padded_message (>= len)
 */
void eax_pad(const uint8_t *b, const uint8_t *p,
             const uint8_t *message, size_t len,
             uint8_t *padded_message, size_t *plen) {

    memcpy(padded_message, message, len);

    uint8_t over_len = len % BLOCK_SIZE;
    size_t new_len = len;
    if (over_len) {
        uint8_t offset = BLOCK_SIZE - over_len;
        new_len += offset;

        padded_message[len] = 0x80;
        memset(padded_message + len + 1, 0, offset - 1);
    }

    uint8_t i = 0;
    size_t offset = new_len - BLOCK_SIZE;

    if (over_len) {
        for (; i < BLOCK_SIZE; i++) {
            padded_message[offset + i] ^= p[i];
        }
    } else {
        for (; i < BLOCK_SIZE; i++) {
            padded_message[offset + i] ^= b[i];
        }
    }
    *plen = new_len;
}

/**
 * perfomr OMAC with key
 * INPUT:
 * @param key for @param encrypt
 * @param message, len = @param len
 * @param len of message
 * @param encrypt, function
 * OUTPUT:
 * @param out, len = BLOCK_SIZE
 *
 * block cipher calls: 1 + [len / BLOCK_SIZE] //(1 explicit + in eax_cbc)
 */
void eax_omac(const void *key, const uint8_t *message,
              size_t len, uint8_t *out, block128_f encrypt) {

    uint8_t b[BLOCK_SIZE];
    memset(b, 0, BLOCK_SIZE);
    (*encrypt) (b, b, key);
    mul_2(b);

    uint8_t p[BLOCK_SIZE];
    memcpy(p, b, BLOCK_SIZE);
    mul_2(p);

    uint8_t *padded = (uint8_t *) malloc(len + BLOCK_SIZE);
    size_t plen = 0;
    eax_pad(b, p, message, len, padded, &plen);
    eax_cbc(padded, key, plen, out, encrypt);
    free(padded);
}

/**
 * perform OMAC with prepadding 0..0 + t
 * INPUT:
 * @param key for @param encrypt
 * @param message, len = @param len
 * @param len of message
 * @param t, value fr prepadding
 * @param encrypt, function
 * OUTPUT:
 * @param out, len = BLOCK_SIZE
 *
 * block cipher calls: 1 + [len / BLOCK_SIZE] //(all in eax_omac)
 */
void eax_omac_n(const void *key, const unsigned char *message,
                size_t len, unsigned char *out, uint8_t t, block128_f encrypt) {

    size_t new_len = len + BLOCK_SIZE;
    unsigned char *expanded = (unsigned char *) malloc(new_len);
    memcpy(expanded + BLOCK_SIZE, message, len);
    memset(expanded, 0, BLOCK_SIZE);
    expanded[BLOCK_SIZE - 1] = t;
    eax_omac(key, expanded, new_len, out, encrypt);
    free(expanded);
}

/**
 * sign @param cipher with @param nonce and @param h
 * INPUT:
 * @param nonce (!!) OMAC[1](n), len = BLOCK_SIZE
 * @param h, header, len = @param hlen
 * @param hlen, length of header (@param h)
 * @param key for @param encrypt
 * @param cipher, len = @param len
 * @param len of cipher text
 * @param encrypt, function
 * OUTPUT:
 * @param tag, len = BLOCK_SIZE
 *
 * block cipher calls: 2 + [hlen / BLOCK_SIZE] //(from eax_omac_n of @param h)
 *                      + [len / BLOCK_SIZE] //(from eax_omac_n of @param cipher)
 */
void CRYPTO_eax128_sign(const unsigned char *nonce, const unsigned char *h, size_t hlen,
                        const void *key, const unsigned char *cipher, size_t len,
                        unsigned char *tag, block128_f encrypt) {

    uint8_t header[BLOCK_SIZE];
    eax_omac_n(key, h, hlen, header, 1, encrypt);

    eax_omac_n(key, cipher, len, tag, 2, encrypt);

    uint8_t i = BLOCK_SIZE;
    while (i--) {
        tag[i] ^= nonce[i] ^ header[i];
    }
}

/**
 * encrypt @param message with nonce @param n and header @param h
 * INPUT:
 * @param n, nonce, len = BLOCK_SIZE
 * @param h, header, len = @param hlen
 * @param hlen, len of header
 * @param key for @param encrypt
 * @param message, len = @param len
 * @param len of message
 * @param encrypt, function
 * OUTPUT:
 * @param out, ciphertext, len = @param len
 * @param tag, len = BLOCK_SIZE
 *
 * block cipher calls: 2 //(eax_omac_n of @param n)
 *                      + [len / BLOCK_SIZE] //(eax_ctr)
 *                      + 2 + [hlen / BLOCK_SIZE] + [len / BLOCK_SIZE] //(sign)
 *                      = 4 + [hlen / BLOCK_SIZE] + 2 * [len / BLOCK_SIZE]
 */
void CRYPTO_eax128_encrypt(const unsigned char *n, const unsigned char *h, size_t hlen,
                           const void *key, const unsigned char *message, size_t len,
                           unsigned char *out, unsigned  char *tag, block128_f encrypt) {

    uint8_t nonce[BLOCK_SIZE];
    eax_omac_n(key, n, BLOCK_SIZE, nonce, 0, encrypt);

    eax_ctr(nonce, key, message, len, out, encrypt);

    CRYPTO_eax128_sign(nonce, h, hlen, key, out, len, tag, encrypt);
}

/**
 * check tag and decrypt
 * @param n, nonce, len = BLOCK_SIZE
 * @param h, header, len = @param hlen
 * @param hlen, len of header @param h
 * @param key for @param encrypt
 * @param cipher, len = @param len
 * @param len of cipher
 * @param tag to verify, len = @param BLOCK_SIZE
 * @param encrypt, function
 * OUTPUT:
 * @param out, plaintext if @return 1, len = @param len
 * @return 1 if @param tag is valid and @param cipher is decrypted into @param out
 *          0 otherwise
 *
 * block cipher calls:
 *      - min: 2 + //(eax_omac_n of @param n)
 *               + 2 + [hlen / BLOCK_SIZE] + [len / BLOCK_SIZE] //(sign)
 *               = 4 + [hlen / BLOCK_SIZE] + [len / BLOCK_SIZE]
 *      - max: min +
 *                 + [len / BLOCK_SIZE] //(eax_ctr of @param cipher)
 *                 = 4 + [hlen / BLOCK_SIZE] + 2 * [len / BLOCK_SIZE]
 */
int CRYPTO_eax128_decrypt(const unsigned char *n, const unsigned char *h, size_t hlen,
                          const void *key, const unsigned char *cipher, const unsigned char *tag,
                          size_t len, unsigned char *out, block128_f encrypt) {

    uint8_t nonce[BLOCK_SIZE];
    eax_omac_n(key, n, BLOCK_SIZE, nonce, 0, encrypt);

    uint8_t t[BLOCK_SIZE];
    CRYPTO_eax128_sign(nonce, h, hlen, key, cipher, len, t, encrypt);

    if (memcmp(t, tag, BLOCK_SIZE)) return 0;

    eax_ctr(nonce, key, cipher, len, out, encrypt);
    return 1;
}


