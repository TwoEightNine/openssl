#include <stdint.h>     //for int8_t
#include <stdio.h>     //for printf
#include <string.h>     //for memcmp
#include <wmmintrin.h>  //for intrinsics for AES-NI

static const uint8_t CONST[32] = {
        0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
        0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd
};

void print_data(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

__m128i xor_state_128l_0(__m128i *state, uint8_t *state_out) {
    __m128i xor_state = _mm_xor_si128(state[1], _mm_xor_si128(state[6], _mm_and_si128(state[2], state[3])));
    memcpy(state_out, &xor_state, 16);
}

__m128i xor_state_128l_1(__m128i *state, uint8_t *state_out) {
    __m128i xor_state = _mm_xor_si128(state[2], _mm_xor_si128(state[5], _mm_and_si128(state[6], state[7])));
    memcpy(state_out, &xor_state, 16);
}

__m128i xor_state_128(__m128i *state, uint8_t *state_out) {
    __m128i xor_state = _mm_xor_si128(state[1], _mm_xor_si128(state[4], _mm_and_si128(state[2], state[3])));
    memcpy(state_out, &xor_state, 16);
}

__m128i xor_state_256(__m128i *state, uint8_t *state_out) {
    __m128i xor_state = _mm_xor_si128(state[1], _mm_xor_si128(state[4], _mm_xor_si128(state[5], _mm_and_si128(state[2],
                                                                                                              state[3]))));
    memcpy(state_out, &xor_state, 16);
}

void update_state_128(__m128i *state, __m128i m) {
    __m128i tmp = _mm_aesenc_si128(state[4], _mm_xor_si128(state[0], m));
    state[4] = _mm_aesenc_si128(state[3], state[4]);
    state[3] = _mm_aesenc_si128(state[2], state[3]);
    state[2] = _mm_aesenc_si128(state[1], state[2]);
    state[1] = _mm_aesenc_si128(state[0], state[1]);
    state[0] = tmp;
}

inline void update_state_128l(__m128i *state, __m128i m_a, __m128i m_b) {
    __m128i tmp = _mm_aesenc_si128(state[7], _mm_xor_si128(state[0], m_a));
    state[7] = _mm_aesenc_si128(state[6], state[7]);
    state[6] = _mm_aesenc_si128(state[5], state[6]);
    state[5] = _mm_aesenc_si128(state[4], state[5]);
    state[4] = _mm_aesenc_si128(state[3], _mm_xor_si128(state[4], m_b));
    state[3] = _mm_aesenc_si128(state[2], state[3]);
    state[2] = _mm_aesenc_si128(state[1], state[2]);
    state[1] = _mm_aesenc_si128(state[0], state[1]);
    state[0] = tmp;
}

void update_state_256(__m128i *state, __m128i m) {
    __m128i tmp = _mm_aesenc_si128(state[5], _mm_xor_si128(state[0], m));
    state[5] = _mm_aesenc_si128(state[4], state[5]);
    state[4] = _mm_aesenc_si128(state[3], state[4]);
    state[3] = _mm_aesenc_si128(state[2], state[3]);
    state[2] = _mm_aesenc_si128(state[1], state[2]);
    state[1] = _mm_aesenc_si128(state[0], state[1]);
    state[0] = tmp;
}

void init_state_128(__m128i *state, __m128i key, __m128i iv) {
    __m128i xor_key_iv = _mm_xor_si128(key, iv);
    __m128i const_0 = _mm_loadu_si128((__m128i *) CONST);
    __m128i const_1 = _mm_loadu_si128((__m128i * )(CONST + 16));

    state[0] = xor_key_iv;
    state[1] = const_1;
    state[2] = const_0;
    state[3] = _mm_xor_si128(key, const_0);
    state[4] = _mm_xor_si128(key, const_1);

    uint8_t i = 5;
    while (i--) {
        update_state_128(state, key);
        update_state_128(state, xor_key_iv);
    }
}

void init_128l(const uint8_t *key, const uint8_t *iv, __m128i *state) {
    int i;
    __m128i tmp;
    __m128i keytmp = _mm_load_si128((__m128i *) key);
    __m128i ivtmp = _mm_load_si128((__m128i *) iv);

    state[0] = _mm_xor_si128(keytmp, ivtmp);
    state[1] = _mm_set_epi8(0xdd, 0x28, 0xb5, 0x73, 0x42, 0x31, 0x11, 0x20, 0xf1, 0x2f, 0xc2, 0x6d, 0x55, 0x18, 0x3d,
                            0xdb);
    state[2] = _mm_set_epi8(0x62, 0x79, 0xe9, 0x90, 0x59, 0x37, 0x22, 0x15, 0x0d, 0x08, 0x05, 0x03, 0x02, 0x01, 0x1,
                            0x0);
    state[3] = _mm_set_epi8(0xdd, 0x28, 0xb5, 0x73, 0x42, 0x31, 0x11, 0x20, 0xf1, 0x2f, 0xc2, 0x6d, 0x55, 0x18, 0x3d,
                            0xdb);
    state[4] = _mm_xor_si128(keytmp, ivtmp);
    state[5] = _mm_xor_si128(keytmp,
                             _mm_set_epi8(0x62, 0x79, 0xe9, 0x90, 0x59, 0x37, 0x22, 0x15, 0x0d, 0x08, 0x05, 0x03, 0x02,
                                          0x01, 0x1, 0x0));
    state[6] = _mm_xor_si128(keytmp,
                             _mm_set_epi8(0xdd, 0x28, 0xb5, 0x73, 0x42, 0x31, 0x11, 0x20, 0xf1, 0x2f, 0xc2, 0x6d, 0x55,
                                          0x18, 0x3d, 0xdb));
    state[7] = _mm_xor_si128(keytmp,
                             _mm_set_epi8(0x62, 0x79, 0xe9, 0x90, 0x59, 0x37, 0x22, 0x15, 0x0d, 0x08, 0x05, 0x03, 0x02,
                                          0x01, 0x1, 0x0));

    for (i = 0; i < 10; i++) {
        //state update function;
        tmp = state[7];
        state[7] = _mm_aesenc_si128(state[6], state[7]);
        state[6] = _mm_aesenc_si128(state[5], state[6]);
        state[5] = _mm_aesenc_si128(state[4], state[5]);
        state[4] = _mm_aesenc_si128(state[3], state[4]);
        state[3] = _mm_aesenc_si128(state[2], state[3]);
        state[2] = _mm_aesenc_si128(state[1], state[2]);
        state[1] = _mm_aesenc_si128(state[0], state[1]);
        state[0] = _mm_aesenc_si128(tmp, state[0]);

        //message is used to update the state.
        state[0] = _mm_xor_si128(state[0], ivtmp);
        state[4] = _mm_xor_si128(state[4], keytmp);
    }
}

void init_state_256(__m128i *state, __m128i key_0, __m128i key_1, __m128i iv_0, __m128i iv_1) {
    __m128i xor_key_0_iv_0 = _mm_xor_si128(key_0, iv_0);
    __m128i xor_key_1_iv_1 = _mm_xor_si128(key_1, iv_1);
    __m128i const_0 = _mm_loadu_si128((__m128i *) CONST);
    __m128i const_1 = _mm_loadu_si128((__m128i * )(CONST + 16));

    state[0] = xor_key_0_iv_0;
    state[1] = xor_key_1_iv_1;
    state[2] = const_1;
    state[3] = const_0;
    state[4] = _mm_xor_si128(key_0, const_0);
    state[5] = _mm_xor_si128(key_1, const_1);

    uint8_t i = 4;
    while (i--) {
        update_state_256(state, key_0);
        update_state_256(state, key_1);
        update_state_256(state, xor_key_0_iv_0);
        update_state_256(state, xor_key_1_iv_1);
    }
}

void process_ad_128(__m128i *state, const uint8_t *ad, size_t len) {
    size_t l = 0;
    size_t full_block_len = (len >> 4) << 4;
    while (l != full_block_len) {
        update_state_128(state, _mm_loadu_si128((__m128i * )(ad + l)));
        l += 16;
    }

    size_t diff = len - full_block_len;
    if (diff) {
        uint8_t last_block[16];
        memcpy(last_block, ad + full_block_len, diff);
        memset(last_block + diff, 0, 16 - diff);
        update_state_128(state, _mm_loadu_si128((__m128i *) last_block));
    }
}

inline void process_ad_128l(__m128i *state, const uint8_t *ad, size_t len) {
    size_t l = 0;
    size_t full_block_len = (len >> 5) << 5;
    uint8_t *ad_ptr = &ad;
    while (l != full_block_len) {
        update_state_128l(state,
                          _mm_loadu_si128((__m128i * )(ad_ptr)),
                          _mm_loadu_si128((__m128i * )(ad_ptr + 16))
        );
        ad_ptr += 32;
        l += 32;
    }

    size_t diff = len - full_block_len;
    if (diff) {
        uint8_t last_block[32];
        memcpy(last_block, ad + full_block_len, diff);
        memset(last_block + diff, 0, 32 - diff);
        update_state_128l(state,
                          _mm_loadu_si128((__m128i *) last_block),
                          _mm_loadu_si128((__m128i * )(last_block + 16))
        );
    }
}

void process_ad_256(__m128i *state, const uint8_t *ad, size_t len) {
    size_t l = 0;
    size_t full_block_len = (len >> 4) << 4;
    while (l != full_block_len) {
        update_state_256(state, _mm_loadu_si128((__m128i * )(ad + l)));
        l += 16;
    }

    size_t diff = len - full_block_len;
    if (diff) {
        uint8_t last_block[16];
        memcpy(last_block, ad + full_block_len, diff);
        memset(last_block + diff, 0, 16 - diff);
        update_state_256(state, _mm_loadu_si128((__m128i *) last_block));
    }
}

void encrypt_128(__m128i *state, const uint8_t *plain, size_t plain_len, uint8_t *cipher) {
    size_t l = 0;
    size_t full_block_len = (plain_len >> 4) << 4;

    uint8_t state_0[16];
    uint8_t i;
    while (l != full_block_len) {
        xor_state_128(state, state_0);
        i = 16;
        while (i--) {
            cipher[l + i] = plain[l + i] ^ state_0[i];
        }
        update_state_128(state, _mm_loadu_si128((__m128i * )(plain + l)));
        l += 16;
    }

    size_t diff = plain_len - full_block_len;
    if (diff) {
        uint8_t last_block[16];
        memcpy(last_block, plain + full_block_len, diff);
        memset(last_block + diff, 0, 16 - diff);

        xor_state_128(state, state_0);
        i = 16;
        while (i--) {
            cipher[l + i] = last_block[i] ^ state_0[i];
        }

        update_state_128(state, _mm_loadu_si128((__m128i *) last_block));
    }
}

void encrypt_128l(const uint8_t *plaintextblk, uint8_t *ciphertextblk, __m128i *state) {
    __m128i ct0, ct1;
    __m128i tmp;
    uint8_t t[32];
    for (uint8_t i=0; i < 32; i++) t[i] = plaintextblk[i];
    __m128i msg0 = _mm_load_si128((__m128i *) t);
    __m128i msg1 = _mm_load_si128((__m128i *) (t + 16));

    //encryption
    ct0 = _mm_xor_si128(msg0, state[6]);
    ct0 = _mm_xor_si128(ct0, state[1]);
    ct1 = _mm_xor_si128(msg1, state[2]);
    ct1 = _mm_xor_si128(ct1, state[5]);
    ct0 = _mm_xor_si128(ct0, _mm_and_si128(state[2], state[3]));
    ct1 = _mm_xor_si128(ct1, _mm_and_si128(state[6], state[7]));
    _mm_store_si128((__m128i *) ciphertextblk, ct0);
    _mm_store_si128((__m128i * )(ciphertextblk + 16), ct1);

    //state update function
    tmp = state[7];
    state[7] = _mm_aesenc_si128(state[6], state[7]);
    state[6] = _mm_aesenc_si128(state[5], state[6]);
    state[5] = _mm_aesenc_si128(state[4], state[5]);
    state[4] = _mm_aesenc_si128(state[3], state[4]);
    state[3] = _mm_aesenc_si128(state[2], state[3]);
    state[2] = _mm_aesenc_si128(state[1], state[2]);
    state[1] = _mm_aesenc_si128(state[0], state[1]);
    state[0] = _mm_aesenc_si128(tmp, state[0]);

    //message is used to update the state.
    state[0] = _mm_xor_si128(state[0], msg0);
    state[4] = _mm_xor_si128(state[4], msg1);
}

void encrypt_256(__m128i *state, const uint8_t *plain, size_t plain_len, uint8_t *cipher) {
    size_t l = 0;
    size_t full_block_len = (plain_len >> 4) << 4;

    uint8_t state_0[16];
    uint8_t i;
    while (l != full_block_len) {
        xor_state_256(state, state_0);
        i = 16;
        while (i--) {
            cipher[l + i] = plain[l + i] ^ state_0[i];
        }
        update_state_256(state, _mm_loadu_si128((__m128i * )(plain + l)));
        l += 16;
    }

    size_t diff = plain_len - full_block_len;
    if (diff) {
        uint8_t last_block[16];
        memcpy(last_block, plain + full_block_len, diff);
        memset(last_block + diff, 0, 16 - diff);

        xor_state_256(state, state_0);
        i = 16;
        while (i--) {
            cipher[l + i] = last_block[i] ^ state_0[i];
        }

        update_state_256(state, _mm_loadu_si128((__m128i *) last_block));
    }
}

void decrypt_128(__m128i *state, const uint8_t *cipher, size_t cipher_len, uint8_t *plain) {
    size_t l = 0;
    size_t full_block_len = (cipher_len >> 4) << 4;

    uint8_t state_0[16];
    uint8_t i;
    while (l != full_block_len) {
        xor_state_128(state, state_0);
        i = 16;
        while (i--) {
            plain[l + i] = cipher[l + i] ^ state_0[i];
        }
        update_state_128(state, _mm_loadu_si128((__m128i * )(plain + l)));
        l += 16;
    }

    size_t diff = cipher_len - full_block_len;
    if (diff) {
        uint8_t last_block[16];
        memcpy(last_block, cipher + full_block_len, diff);
        memset(last_block + diff, 0, 16 - diff);

        xor_state_128(state, state_0);
        i = 16;
        while (i--) {
            plain[l + i] = last_block[i] ^ state_0[i];
        }
        memset(plain + l + diff, 0, 16 - diff);

        update_state_128(state, _mm_loadu_si128((__m128i * )(plain + l)));
    }
}

void decrypt_128l(uint8_t *plaintextblk, const uint8_t *ciphertextblk, __m128i *state) {
    __m128i msg0 = _mm_load_si128((__m128i *) ciphertextblk);
    __m128i msg1 = _mm_load_si128((__m128i * )(ciphertextblk + 16));
    __m128i tmp;

    //decryption
    msg0 = _mm_xor_si128(msg0, state[6]);
    msg0 = _mm_xor_si128(msg0, state[1]);
    msg1 = _mm_xor_si128(msg1, state[2]);
    msg1 = _mm_xor_si128(msg1, state[5]);
    msg0 = _mm_xor_si128(msg0, _mm_and_si128(state[2], state[3]));
    msg1 = _mm_xor_si128(msg1, _mm_and_si128(state[6], state[7]));
    _mm_store_si128((__m128i *) plaintextblk, msg0);
    _mm_store_si128((__m128i * )(plaintextblk + 16), msg1);

    //state update function
    tmp = state[7];
    state[7] = _mm_aesenc_si128(state[6], state[7]);
    state[6] = _mm_aesenc_si128(state[5], state[6]);
    state[5] = _mm_aesenc_si128(state[4], state[5]);
    state[4] = _mm_aesenc_si128(state[3], state[4]);
    state[3] = _mm_aesenc_si128(state[2], state[3]);
    state[2] = _mm_aesenc_si128(state[1], state[2]);
    state[1] = _mm_aesenc_si128(state[0], state[1]);
    state[0] = _mm_aesenc_si128(tmp, state[0]);

    //message is used to update the state.
    state[0] = _mm_xor_si128(state[0], msg0);
    state[4] = _mm_xor_si128(state[4], msg1);
}

void decrypt_256(__m128i *state, const uint8_t *cipher, size_t cipher_len, uint8_t *plain) {
    size_t l = 0;
    size_t full_block_len = (cipher_len >> 4) << 4;

    uint8_t state_0[16];
    uint8_t i;
    while (l != full_block_len) {
        xor_state_256(state, state_0);
        i = 16;
        while (i--) {
            plain[l + i] = cipher[l + i] ^ state_0[i];
        }
        update_state_256(state, _mm_loadu_si128((__m128i * )(plain + l)));
        l += 16;
    }

    size_t diff = cipher_len - full_block_len;
    if (diff) {
        uint8_t last_block[16];
        memcpy(last_block, cipher + full_block_len, diff);
        memset(last_block + diff, 0, 16 - diff);

        xor_state_256(state, state_0);
        i = 16;
        while (i--) {
            plain[l + i] = last_block[i] ^ state_0[i];
        }
        memset(plain + l + diff, 0, 16 - diff);

        update_state_256(state, _mm_loadu_si128((__m128i * )(plain + l)));
    }
}

void finalize_128(__m128i *state, uint64_t ad_len, uint64_t plain_len, uint8_t *tag) {
    __m128i msgtmp;
    uint8_t tmp[16];
    memset(tmp, 0, 16);

    ((unsigned long long *) tmp)[0] = ad_len << 3;
    ((unsigned long long *) tmp)[1] = plain_len << 3;
    msgtmp = _mm_load_si128((__m128i *) tmp);
    msgtmp = _mm_xor_si128(msgtmp, state[3]);

    uint8_t i;
    i = 7;
    while (i--) {
        update_state_128(state, msgtmp);
    }

    uint8_t j;
    memset(tag, 0, 16);
    i = 5;
    while (i--) {
        uint8_t *st = (uint8_t * ) & state[i];
        j = 16;
        while (j--) {
            tag[j] ^= st[j];
        }
    }
}

void finalize_128l(size_t msglen, size_t adlen, uint8_t *mac, __m128i *state) {
    int i;

    __m128i tmp;
    __m128i msgtmp;
    unsigned char t[16], tt[16];


    for (i = 0; i < 16; i++) tt[i] = 0;


    ((unsigned long long *) tt)[0] = adlen << 3;
    ((unsigned long long *) tt)[1] = msglen << 3;
    msgtmp = _mm_load_si128((__m128i *) tt);

    msgtmp = _mm_xor_si128(msgtmp, state[2]);   //note the change

    for (i = 0; i < 7; i++) {
        //state update function
        tmp = state[7];
        state[7] = _mm_aesenc_si128(state[6], state[7]);
        state[6] = _mm_aesenc_si128(state[5], state[6]);
        state[5] = _mm_aesenc_si128(state[4], state[5]);
        state[4] = _mm_aesenc_si128(state[3], state[4]);
        state[3] = _mm_aesenc_si128(state[2], state[3]);
        state[2] = _mm_aesenc_si128(state[1], state[2]);
        state[1] = _mm_aesenc_si128(state[0], state[1]);
        state[0] = _mm_aesenc_si128(tmp, state[0]);

        //message is used to update the state.
        state[0] = _mm_xor_si128(state[0], msgtmp);
        state[4] = _mm_xor_si128(state[4], msgtmp);
    }

    state[6] = _mm_xor_si128(state[6], state[5]);
    state[6] = _mm_xor_si128(state[6], state[4]);
    state[6] = _mm_xor_si128(state[6], state[3]);
    state[6] = _mm_xor_si128(state[6], state[2]);
    state[6] = _mm_xor_si128(state[6], state[1]);
    state[6] = _mm_xor_si128(state[6], state[0]);

    _mm_store_si128((__m128i *) t, state[6]);
    //in this program, the mac length is assumed to be multiple of bytes
    memcpy(mac, t, 16);
}

void finalize_256(__m128i *state, uint64_t ad_len, uint64_t plain_len, uint8_t *tag) {
    __m128i msgtmp;
    uint8_t tmp[16];
    memset(tmp, 0, 16);

    ((unsigned long long *) tmp)[0] = ad_len << 3;
    ((unsigned long long *) tmp)[1] = plain_len << 3;
    msgtmp = _mm_load_si128((__m128i *) tmp);
    msgtmp = _mm_xor_si128(msgtmp, state[3]);

    uint8_t i;
    i = 7;
    while (i--) {
        update_state_256(state, msgtmp);
    }

    uint8_t j;
    memset(tag, 0, 16);
    i = 6;
    while (i--) {
        uint8_t *st = (uint8_t * ) & state[i];
        j = 16;
        while (j--) {
            tag[j] ^= st[j];
        }
    }
}

/**
 * encrypt using AEGIS-128L
 *
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
    unsigned long i;
    uint8_t plaintextblock[32], ciphertextblock[32];
    __m128i aegis128L_state[8];

    //initialization stage
    init_128l(key, iv, aegis128L_state);

    //process the associated data
    for (i = 0; (i + 32) <= adlen; i += 32) {
        encrypt_128l(ad + i, ciphertextblock, aegis128L_state);
    }

    //deal with the partial block of associated data
    //in this program, we assume that the message length is multiple of bytes.
    if ((adlen & 0x1f) != 0) {
        memset(plaintextblock, 0, 32);
        memcpy(plaintextblock, ad + i, adlen & 0x1f);
        encrypt_128l(plaintextblock, ciphertextblock, aegis128L_state);
    }

    //encrypt the plaintext
    for (i = 0; (i + 32) <= msglen; i += 32) {
        encrypt_128l(msg + i, cipher + i, aegis128L_state);
    }

    // Deal with the partial block
    // In this program, we assume that the message length is multiple of bytes.
    if ((msglen & 0x1f) != 0) {
        memset(plaintextblock, 0, 32);
        memcpy(plaintextblock, msg + i, msglen & 0x1f);
        encrypt_128l(plaintextblock, ciphertextblock, aegis128L_state);
        memcpy(cipher + i, ciphertextblock, msglen & 0x1f);
    }

    // finalization stage, we assume that the tag length is multiple of bytes
    finalize_128l(msglen, adlen, tag, aegis128L_state);

    return 0;
}

/**
 * decrypt using AEGIS-128L
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
uint8_t AEGIS_decrypt(const uint8_t *key, const uint8_t *iv,
                      const uint8_t *cipher, size_t cipherlen,
                      const uint8_t *ad, size_t adlen,
                      const uint8_t *tag, uint8_t *msg) {
    unsigned long i;
    unsigned char plaintextblock[32], ciphertextblock[32];
    unsigned char check = 0;
    __m128i aegis128L_state[8];

    init_128l(key, iv, aegis128L_state);

    //process the associated data
    for (i = 0; i + 32 <= adlen; i += 32) {
        encrypt_128l(ad + i, ciphertextblock, aegis128L_state);
    }

    //deal with the partial block of associated data
    //in this program, we assume that the message length is multiple of bytes.
    if ((adlen & 0x1f) != 0) {
        memset(plaintextblock, 0, 32);
        memcpy(plaintextblock, ad + i, adlen & 0x1f);
        encrypt_128l(plaintextblock, ciphertextblock, aegis128L_state);
    }

    //decrypt the ciphertext
    for (i = 0; (i + 32) <= cipherlen; i += 32) {
        decrypt_128l(msg + i, cipher + i, aegis128L_state);
    }

    // Deal with the partial block
    // In this program, we assume that the message length is multiple of bytes.

    if ((cipherlen & 0x1f) != 0) {
        memset(ciphertextblock, 0, 32);
        memcpy(ciphertextblock, cipher + i, cipherlen & 0x1f);
        decrypt_128l(plaintextblock, ciphertextblock, aegis128L_state);
        memcpy(msg + i, plaintextblock, cipherlen & 0x1f);

        //need to modify the state here (because in the last block, keystream is wrongly used to update the state)
        memset(plaintextblock, 0, cipherlen & 0x1f);
        aegis128L_state[0] = _mm_xor_si128(aegis128L_state[0], _mm_load_si128((__m128i *) plaintextblock));
        aegis128L_state[4] = _mm_xor_si128(aegis128L_state[4], _mm_load_si128((__m128i * )(plaintextblock + 16)));
    }

    //we assume that the tag length is multiple of bytes
    uint8_t tag_internal[16];
    finalize_128l(cipherlen, adlen, tag_internal, aegis128L_state);

    //verification
    for (i = 0; i < 16; i++) check |= (tag[i] ^ tag_internal[i]);
    return !check;
}

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
) {
    __m128i state[6];
    init_state_256(state,
                   _mm_loadu_si128((__m128i *) key), _mm_loadu_si128((__m128i * )(key + 16)),
                   _mm_loadu_si128((__m128i *) iv), _mm_loadu_si128((__m128i * )(iv + 16))
    );
    process_ad_256(state, ad, adlen);
    encrypt_256(state, msg, msglen, cipher);
    finalize_256(state, adlen, msglen, tag);
}

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
) {
    __m128i state[6];
    init_state_256(state,
                   _mm_loadu_si128((__m128i *) key), _mm_loadu_si128((__m128i * )(key + 16)),
                   _mm_loadu_si128((__m128i *) iv), _mm_loadu_si128((__m128i * )(iv + 16))
    );
    process_ad_256(state, ad, adlen);
    decrypt_256(state, cipher, cipherlen, msg);

    uint8_t tag_internal[16];
    finalize_256(state, adlen, cipherlen, tag_internal);
    return !memcmp(tag, tag_internal, 16);
}

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
) {
    __m128i state[5];
    init_state_128(state, _mm_loadu_si128((__m128i *) key), _mm_loadu_si128((__m128i *) iv));
    process_ad_128(state, ad, adlen);
    encrypt_128(state, msg, msglen, cipher);
    finalize_128(state, adlen, msglen, tag);
}

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
) {
    __m128i state[5];
    init_state_128(state, _mm_loadu_si128((__m128i *) key), _mm_loadu_si128((__m128i *) iv));
    process_ad_128(state, ad, adlen);
    decrypt_128(state, cipher, cipherlen, msg);

    uint8_t tag_internal[16];
    finalize_128(state, adlen, cipherlen, tag_internal);
    return !memcmp(tag, tag_internal, 16);
}