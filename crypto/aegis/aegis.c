//
// Created by msnthrp on 16/04/19.
//

#include <openssl/aegis.h>
#include <stdint.h>     //for int8_t
#include <stdio.h>     //for printf
#include <string.h>     //for memcmp
#include <wmmintrin.h>  //for intrinsics for AES-NI

#define STATE_128_COUNT 8 // 8 * 128 bit = 1024 bit

#define UPDSTATE(state, m_a, m_b) \
    __m128i tmp = _mm_aesenc_si128(state[7], _mm_xor_si128(state[0], m_a)); \
    state[7] = _mm_aesenc_si128(state[6], state[7]); \
    state[6] = _mm_aesenc_si128(state[5], state[6]); \
    state[5] = _mm_aesenc_si128(state[4], state[5]); \
    state[4] = _mm_aesenc_si128(state[3], _mm_xor_si128(state[4], m_b)); \
    state[3] = _mm_aesenc_si128(state[2], state[3]); \
    state[2] = _mm_aesenc_si128(state[1], state[2]); \
    state[1] = _mm_aesenc_si128(state[0], state[1]); \
    state[0] = tmp;

static const uint8_t CONST[32] = {
        0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
        0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd
};

__m128i xor_state_0(__m128i *state, uint8_t *state_out) {
    __m128i xor_state = _mm_xor_si128(state[1], _mm_xor_si128(state[6], _mm_and_si128(state[2], state[3])));
    memcpy(state_out, &xor_state, 16);
}

__m128i xor_state_1(__m128i *state, uint8_t *state_out) {
    __m128i xor_state = _mm_xor_si128(state[2], _mm_xor_si128(state[5], _mm_and_si128(state[6], state[7])));
    memcpy(state_out, &xor_state, 16);
}

void init_state(__m128i *state, __m128i key, __m128i iv) {
    __m128i xor_key_iv = _mm_xor_si128(key, iv);
    __m128i const_0 = _mm_loadu_si128((__m128i *) CONST);
    __m128i const_1 = _mm_loadu_si128((__m128i *) (CONST + 16));
    __m128i xor_key_const_0 = _mm_xor_si128(key, const_0);
    __m128i xor_key_const_1 = _mm_xor_si128(key, const_1);

    state[0] = xor_key_iv;
    state[1] = const_1;
    state[2] = const_0;
    state[3] = const_1;
    state[4] = xor_key_iv;
    state[5] = xor_key_const_0;
    state[6] = xor_key_const_1;
    state[7] = xor_key_const_0;

    uint8_t i = 10;
    while (i--) {
        UPDSTATE(state, iv, key);
    }
}

void process_ad(__m128i *state, const uint8_t *ad, size_t len) {
    size_t l = 0;
    size_t full_block_len = (len >> 5) << 5;
    while (l != full_block_len) {
        UPDSTATE(state,
                 _mm_loadu_si128((__m128i *) (ad + l)),
                 _mm_loadu_si128((__m128i *) (ad + l + 16))
        );
        l += 32;
    }
    size_t diff = len - full_block_len;
    if (diff) {
        uint8_t last_block[32];
        memcpy(last_block, ad + full_block_len, diff);
        memset(last_block + diff, 0, 32 - diff);
        UPDSTATE(state,
                 _mm_loadu_si128((__m128i *) last_block),
                 _mm_loadu_si128((__m128i *) (last_block + 16))
        );
    }
}

void encrypt(__m128i *state, const uint8_t *plain, size_t plain_len, uint8_t *cipher) {
    size_t l = 0;
    size_t full_block_len = (plain_len >> 5) << 5;

    uint8_t state_0[16];
    uint8_t state_1[16];
    uint8_t i;
    while (l != full_block_len) {
        xor_state_0(state, state_0);
        xor_state_1(state, state_1);
        i = 16;
        while(i--) {
            cipher[l + i] = plain[l + i] ^ state_0[i];
            cipher[l + i + 16] = plain[l + i + 16] ^ state_1[i];
        }
        UPDSTATE(state,
                 _mm_loadu_si128((__m128i *) (plain + l)),
                 _mm_loadu_si128((__m128i *) (plain + l + 16))
        );
        l += 32;
    }
    size_t diff = plain_len - full_block_len;
    if (diff) {
        uint8_t last_block[32];
        memcpy(last_block, plain + full_block_len, diff);
        memset(last_block + diff, 0, 32 - diff);

        xor_state_0(state, state_0);
        xor_state_1(state, state_1);
        i = 16;
        while(i--) {
            cipher[l + i] = last_block[i] ^ state_0[i];
            cipher[l + i + 16] = last_block[i + 16] ^ state_1[i];
        }

        UPDSTATE(state,
                 _mm_loadu_si128((__m128i *) last_block),
                 _mm_loadu_si128((__m128i *) (last_block + 16))
        );
    }
}

void decrypt(__m128i *state, const uint8_t *cipher, size_t cipher_len, uint8_t *plain) {
    size_t l = 0;
    size_t full_block_len = (cipher_len >> 5) << 5;

    uint8_t state_0[16];
    uint8_t state_1[16];
    uint8_t i;
    while (l != full_block_len) {
        xor_state_0(state, state_0);
        xor_state_1(state, state_1);
        i = 16;
        while(i--) {
            plain[l + i] = cipher[l + i] ^ state_0[i];
            plain[l + i + 16] = cipher[l + i + 16] ^ state_1[i];
        }
        UPDSTATE(state,
                 _mm_loadu_si128((__m128i *) (plain + l)),
                 _mm_loadu_si128((__m128i *) (plain + l + 16))
        );
        l += 32;
    }
    size_t diff = cipher_len - full_block_len;
    if (diff) {
        uint8_t last_block[32];
        memcpy(last_block, cipher + full_block_len, diff);
        memset(last_block + diff, 0, 32 - diff);

        xor_state_0(state, state_0);
        xor_state_1(state, state_1);
        i = 16;
        while(i--) {
            plain[l + i] = last_block[i] ^ state_0[i];
            plain[l + i + 16] = last_block[i + 16] ^ state_1[i];
        }
        memset(plain + l + diff, 0, 32 - diff);

        UPDSTATE(state,
                 _mm_loadu_si128((__m128i *) (plain + l)),
                 _mm_loadu_si128((__m128i *) (plain + l + 16))
        );
    }
}

void finalize(__m128i *state, uint64_t ad_len, uint64_t plain_len, uint8_t *tag) {
    __m128i  msgtmp;
    uint8_t tmp[16];
    memset(tmp, 0, 16);

    ((unsigned long long *) tmp)[0] = ad_len << 3;
    ((unsigned long long *) tmp)[1] = plain_len << 3;
    msgtmp = _mm_load_si128((__m128i *) tmp);
    msgtmp = _mm_xor_si128(msgtmp, state[2]);

    uint8_t i;
    i = 7;
    while (i--) {
        UPDSTATE(state, msgtmp, msgtmp);
    }

    uint8_t j;
    memset(tag, 0, 16);
    i = 7;
    while (i--) {
        uint8_t *st = (uint8_t *) &state[i];
        j = 16;
        while (j--) {
            tag[j] ^= st[j];
        }
    }
}

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
                   uint8_t *cipher, uint8_t *tag) {
    init_state(state, _mm_loadu_si128((__m128i *) key), _mm_loadu_si128((__m128i *) iv));
    process_ad(state, ad, adlen);
    encrypt(state, msg, msglen, cipher);
    finalize(state, adlen, msglen, tag);
}

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
int AEGIS_decrypt(const uint8_t *key, const uint8_t *iv,
                  const uint8_t *cipher, size_t cipherlen,
                  const uint8_t *ad, size_t adlen,
                  const uint8_t *tag, uint8_t *msg) {
    init_state(state, _mm_loadu_si128((__m128i *) key), _mm_loadu_si128((__m128i *) iv));
    process_ad(state, ad, adlen);
    decrypt(state, cipher, cipherlen, msg);

    uint8_t tag_internal[16];
    finalize(state, adlen, cipherlen, tag_internal);

    return !memcmp(tag, tag_internal, 16);
}