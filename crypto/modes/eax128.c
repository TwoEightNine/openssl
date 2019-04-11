//
// Created by msnthrp on 11/04/19.
//

#include <openssl/modes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BLOCK_SIZE 16

//void print_block(const uint8_t* b) {
//    for (int i = 0; i < BLOCK_SIZE; i++) {
//        printf("%02x", b[i]);
//    }
//    printf("\n");
//}

void inc(uint8_t *block) {
    uint8_t i = BLOCK_SIZE;
    while (i--) {
        block[i]++;
        if (block[i] != 0) return;
    }
}

void shift_left(uint8_t *block) {
    for (uint8_t i = 0; i < BLOCK_SIZE; i++) {
        block[i] = block[i] << 1;
        if (i + 1 != BLOCK_SIZE && block[i + 1] & 0x80) {
            block[i]++;
        }
    }
}

void mul_2(uint8_t *block) {
    uint8_t msb = block[0] & 0x80;
    shift_left(block);
    if (msb) {
        block[BLOCK_SIZE - 1] ^= 0x87;
    }
}

void eax_cbc(const uint8_t *message, const void *key,
        uint8_t len, uint8_t *out, block128_f encrypt) {
    memset(out, 0, BLOCK_SIZE);
    uint8_t i;
    uint8_t l = 0;
    while(l != len) {
        i = BLOCK_SIZE;
        while(i--) {
            out[i] = out[i] ^ message[l + i];
        }
        (*encrypt) (out, key, out);
        l += BLOCK_SIZE;
    }
}

void eax_ctr(const uint8_t *n, const void *key,
             const uint8_t *message, uint8_t len,
             uint8_t *out, block128_f encrypt) {

    uint8_t nonce[BLOCK_SIZE];
    memcpy(nonce, n, BLOCK_SIZE);

    uint8_t l = 0;
    uint8_t i;
    while (l != len) {
        (*encrypt) (nonce, key, out + l);
        i = BLOCK_SIZE;
        while(i--) {
            out[l + i] ^= message[l + i];
        }
        inc(nonce);
        l += BLOCK_SIZE;
    }
}

void eax_pad(const uint8_t *b, const uint8_t *p, uint8_t *message, uint8_t len) {
    if (len % BLOCK_SIZE) {
        //
    } else {
        uint8_t i = BLOCK_SIZE;
        while (--i) {
            message[len - BLOCK_SIZE + i] ^= b[i];
        }
    }
}

void eax_omac(const void *key, const uint8_t *message,
              uint8_t len, uint8_t *out, block128_f encrypt) {

    uint8_t b[BLOCK_SIZE];
    memset(b, 0, BLOCK_SIZE);
    (*encrypt) (b, key, b);
    mul_2(b);

    uint8_t p[BLOCK_SIZE];
    memcpy(p, b, BLOCK_SIZE);
    mul_2(p);

    uint8_t pad[BLOCK_SIZE];
    memcpy(pad, message + len - BLOCK_SIZE, BLOCK_SIZE);
    eax_pad(b, p, pad, BLOCK_SIZE);
    eax_cbc(pad, key, BLOCK_SIZE, out, encrypt);
}

void eax_omac_n(const void *key, const uint8_t *message,
                uint8_t len, uint8_t *out, uint8_t t, block128_f encrypt) {

    uint8_t new_len = len + BLOCK_SIZE;
    uint8_t *expanded = (uint8_t *) malloc(new_len);
    memcpy(expanded + BLOCK_SIZE, message, len);
    memset(expanded, 0, BLOCK_SIZE);
    expanded[BLOCK_SIZE - 1] = t;
    eax_omac(key, expanded, new_len, out, encrypt);
    free(expanded);
}

void CRYPTO_eax128_sign(const uint8_t *n, const uint8_t *h,
              const void *key, const uint8_t *cipher,
              uint8_t *tag, block128_f encrypt) {

    uint8_t nonce[BLOCK_SIZE];
    memcpy(nonce, n, BLOCK_SIZE);
    eax_omac_n(key, nonce, BLOCK_SIZE, nonce, 0, encrypt);

    uint8_t header[BLOCK_SIZE];
    memcpy(header, h, BLOCK_SIZE);
    eax_omac_n(key, header, BLOCK_SIZE, header, 1, encrypt);

    eax_omac_n(key, cipher, BLOCK_SIZE, tag, 2, encrypt);

    uint8_t i = BLOCK_SIZE;
    while (i--) {
        tag[i] = tag[i] ^ nonce[i] ^ header[i];
    }
}

void CRYPTO_eax128_encrypt(const uint8_t *n, const uint8_t *h,
                 const void *key, const uint8_t *message, uint8_t len,
                 uint8_t *out, uint8_t *tag, block128_f encrypt) {

    uint8_t *nonce = (uint8_t *) malloc(BLOCK_SIZE);
    memcpy(nonce, n, BLOCK_SIZE);
    eax_omac_n(key, nonce, BLOCK_SIZE, nonce, 0, encrypt);

    eax_ctr(nonce, key, message, len, out, encrypt);

    CRYPTO_eax128_sign(n, h, key, out, tag, encrypt);
}

int CRYPTO_eax128_decrypt(const uint8_t *n, const uint8_t *h,
                const void *key, const uint8_t *cipher, const uint8_t *tag,
                uint8_t len, uint8_t *out, block128_f encrypt) {

    uint8_t t[BLOCK_SIZE];
    CRYPTO_eax128_sign(n, h, key, cipher, t, encrypt);

    if (memcmp(t, tag, BLOCK_SIZE)) return 0;

    uint8_t *nonce = (uint8_t *) malloc(BLOCK_SIZE);
    memcpy(nonce, n, BLOCK_SIZE);
    eax_omac_n(key, nonce, BLOCK_SIZE, nonce, 0, encrypt);

    eax_ctr(nonce, key, cipher, len, out, encrypt);
    return 1;
}


