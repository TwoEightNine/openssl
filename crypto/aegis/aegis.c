#include <stdint.h>     //for int8_t
#include <stdio.h>     //for printf
#include <string.h>     //for memcmp
#include <wmmintrin.h>  //for intrinsics for AES-NI


void init_128(const unsigned char *key, const unsigned char *iv, __m128i *state) {
    int i;

    __m128i tmp;
    __m128i keytmp = _mm_load_si128((__m128i *) key);
    __m128i ivtmp = _mm_load_si128((__m128i *) iv);

    state[0] = ivtmp;
    state[1] = _mm_set_epi8(0xdd, 0x28, 0xb5, 0x73, 0x42, 0x31, 0x11, 0x20, 0xf1, 0x2f, 0xc2, 0x6d, 0x55, 0x18, 0x3d,
                            0xdb);
    state[2] = _mm_set_epi8(0x62, 0x79, 0xe9, 0x90, 0x59, 0x37, 0x22, 0x15, 0x0d, 0x08, 0x05, 0x03, 0x02, 0x01, 0x1,
                            0x0);
    state[3] = _mm_xor_si128(keytmp,
                             _mm_set_epi8(0x62, 0x79, 0xe9, 0x90, 0x59, 0x37, 0x22, 0x15, 0x0d, 0x08, 0x05, 0x03, 0x02,
                                          0x01, 0x1, 0x0));
    state[4] = _mm_xor_si128(keytmp,
                             _mm_set_epi8(0xdd, 0x28, 0xb5, 0x73, 0x42, 0x31, 0x11, 0x20, 0xf1, 0x2f, 0xc2, 0x6d, 0x55,
                                          0x18, 0x3d, 0xdb));
    state[0] = _mm_xor_si128(state[0], keytmp);

    keytmp = _mm_xor_si128(keytmp, ivtmp);
    for (i = 0; i < 10; i++) {
        //state update function
        tmp = state[4];
        state[4] = _mm_aesenc_si128(state[3], state[4]);
        state[3] = _mm_aesenc_si128(state[2], state[3]);
        state[2] = _mm_aesenc_si128(state[1], state[2]);
        state[1] = _mm_aesenc_si128(state[0], state[1]);
        state[0] = _mm_aesenc_si128(tmp, state[0]);

        //xor msg with state[0]
        keytmp = _mm_xor_si128(keytmp, ivtmp);
        state[0] = _mm_xor_si128(state[0], keytmp);
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

void init_256(const unsigned char *key,
              const unsigned char *iv, __m128i *state)
{
    int i;

    __m128i  tmp;
    __m128i  keytmp1 = _mm_load_si128((__m128i*)key);
    __m128i  keytmp2 = _mm_load_si128((__m128i*)(key+16));
    __m128i  ivtmp1  = _mm_load_si128((__m128i*)iv);
    __m128i  ivtmp2  = _mm_load_si128((__m128i*)(iv+16));


    state[0] = ivtmp1;
    state[1] = ivtmp2;
    state[2] = _mm_set_epi8(0xdd,0x28,0xb5,0x73,0x42,0x31,0x11,0x20,0xf1,0x2f,0xc2,0x6d,0x55,0x18,0x3d,0xdb);
    state[3] = _mm_set_epi8(0x62,0x79,0xe9,0x90,0x59,0x37,0x22,0x15,0x0d,0x08,0x05,0x03,0x02,0x01,0x1, 0x0);
    state[4] = _mm_xor_si128(keytmp1, _mm_set_epi8(0x62,0x79,0xe9,0x90,0x59,0x37,0x22,0x15,0x0d,0x08,0x05,0x03,0x02,0x01,0x1,0x0));
    state[5] = _mm_xor_si128(keytmp2, _mm_set_epi8(0xdd,0x28,0xb5,0x73,0x42,0x31,0x11,0x20,0xf1,0x2f,0xc2,0x6d,0x55,0x18,0x3d,0xdb));


    state[0] = _mm_xor_si128(state[0], keytmp1);
    state[1] = _mm_xor_si128(state[1], keytmp2);

    keytmp1 = _mm_xor_si128(keytmp1,ivtmp1);
    keytmp2 = _mm_xor_si128(keytmp2,ivtmp2);

    for (i = 0; i < 8; i++) {
        //state update function
        tmp = state[5];
        state[5] = _mm_aesenc_si128(state[4],state[5]);
        state[4] = _mm_aesenc_si128(state[3],state[4]);
        state[3] = _mm_aesenc_si128(state[2],state[3]);
        state[2] = _mm_aesenc_si128(state[1],state[2]);
        state[1] = _mm_aesenc_si128(state[0],state[1]);
        state[0] = _mm_aesenc_si128(tmp,state[0]);

        //xor msg with state[0]
        keytmp1  = _mm_xor_si128(keytmp1,ivtmp1);
        state[0] = _mm_xor_si128(state[0], keytmp1);


        //state update function
        tmp = state[5];
        state[5] = _mm_aesenc_si128(state[4],state[5]);
        state[4] = _mm_aesenc_si128(state[3],state[4]);
        state[3] = _mm_aesenc_si128(state[2],state[3]);
        state[2] = _mm_aesenc_si128(state[1],state[2]);
        state[1] = _mm_aesenc_si128(state[0],state[1]);
        state[0] = _mm_aesenc_si128(tmp,state[0]);

        //xor msg with state[0]
        keytmp2  = _mm_xor_si128(keytmp2, ivtmp2);
        state[0] = _mm_xor_si128(state[0], keytmp2);
    }
}

inline void encrypt_128(const unsigned char *plaintextblk,
                        unsigned char *ciphertextblk, __m128i *state) {
    __m128i t, ct;
    uint8_t tt[16];
    for (uint8_t i=0; i < 16; i++) tt[i] = plaintextblk[i];
    __m128i msg = _mm_load_si128((__m128i *) tt);
    __m128i tmp = state[4];

    //encryption
    t = _mm_and_si128(state[2], state[3]);
    ct = _mm_xor_si128(msg, state[4]);
    ct = _mm_xor_si128(ct, state[1]);
    ct = _mm_xor_si128(ct, t);
    _mm_store_si128((__m128i *) ciphertextblk, ct);

    //state update function
    state[4] = _mm_aesenc_si128(state[3], state[4]);
    state[3] = _mm_aesenc_si128(state[2], state[3]);
    state[2] = _mm_aesenc_si128(state[1], state[2]);
    state[1] = _mm_aesenc_si128(state[0], state[1]);
    state[0] = _mm_aesenc_si128(tmp, state[0]);

    //message is used to update the state.
    state[0] = _mm_xor_si128(state[0], msg);
}

void encrypt_128l(const unsigned char *plaintextblk, unsigned char *ciphertextblk, __m128i *state) {
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

inline void encrypt_256(const unsigned char *plaintextblk,
                        unsigned char *ciphertextblk, __m128i *state)
{
    __m128i t, ct;
    __m128i msg = _mm_load_si128((__m128i*)plaintextblk);
    __m128i tmp = state[5];

    //encryption
    t  = _mm_and_si128(state[2], state[3]);
    ct = _mm_xor_si128(msg, state[5]);
    ct = _mm_xor_si128(ct, state[4]);
    ct = _mm_xor_si128(ct, state[1]);
    ct = _mm_xor_si128(ct, t);
    _mm_store_si128((__m128i*)ciphertextblk, ct);

    //state update function
    state[5] = _mm_aesenc_si128(state[4],state[5]);
    state[4] = _mm_aesenc_si128(state[3],state[4]);
    state[3] = _mm_aesenc_si128(state[2],state[3]);
    state[2] = _mm_aesenc_si128(state[1],state[2]);
    state[1] = _mm_aesenc_si128(state[0],state[1]);
    state[0] = _mm_aesenc_si128(tmp,state[0]);

    //xor msg with state[0]
    state[0] = _mm_xor_si128(state[0],msg);
}

inline void decrypt_128(unsigned char *plaintextblk,
                        const unsigned char *ciphertextblk, __m128i *state) {
    __m128i msg = _mm_load_si128((__m128i *) ciphertextblk);
    __m128i tmp = state[4];

    //decryption
    msg = _mm_xor_si128(msg, _mm_and_si128(state[2], state[3]));
    msg = _mm_xor_si128(msg, state[4]);
    msg = _mm_xor_si128(msg, state[1]);

    _mm_store_si128((__m128i *) plaintextblk, msg);

    //state update function
    state[4] = _mm_aesenc_si128(state[3], state[4]);
    state[3] = _mm_aesenc_si128(state[2], state[3]);
    state[2] = _mm_aesenc_si128(state[1], state[2]);
    state[1] = _mm_aesenc_si128(state[0], state[1]);
    state[0] = _mm_aesenc_si128(tmp, state[0]);

    //message is used to update the state
    state[0] = _mm_xor_si128(state[0], msg);
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

inline void decrypt_256(unsigned char *plaintextblk,
                        const unsigned char *ciphertextblk, __m128i *state)
{
    __m128i t;
    __m128i msg = _mm_load_si128((__m128i*)ciphertextblk);
    __m128i tmp = state[5];

    //decryption
    t = _mm_and_si128(state[2], state[3]);
    msg = _mm_xor_si128(msg, state[5]);
    msg = _mm_xor_si128(msg, state[4]);
    msg = _mm_xor_si128(msg, state[1]);
    msg = _mm_xor_si128(msg, t);
    _mm_store_si128((__m128i*)plaintextblk, msg);

    //state update function
    state[5] = _mm_aesenc_si128(state[4],state[5]);
    state[4] = _mm_aesenc_si128(state[3],state[4]);
    state[3] = _mm_aesenc_si128(state[2],state[3]);
    state[2] = _mm_aesenc_si128(state[1],state[2]);
    state[1] = _mm_aesenc_si128(state[0],state[1]);
    state[0] = _mm_aesenc_si128(tmp,state[0]);
    state[0] = _mm_xor_si128(state[0], msg);
}

void finalize_128(unsigned long long msglen, unsigned long long adlen, unsigned char *mac, __m128i *state) {
    int i;

    __m128i tmp;
    __m128i msgtmp;
    unsigned char t[16], tt[16];

    for (i = 0; i < 16; i++) tt[i] = 0;

    ((unsigned long long *) tt)[0] = adlen << 3;
    ((unsigned long long *) tt)[1] = msglen << 3;
    msgtmp = _mm_load_si128((__m128i *) tt);

    msgtmp = _mm_xor_si128(msgtmp, state[3]);

    for (i = 0; i < 7; i++) {
        //state update function
        tmp = state[4];
        state[4] = _mm_aesenc_si128(state[3], state[4]);
        state[3] = _mm_aesenc_si128(state[2], state[3]);
        state[2] = _mm_aesenc_si128(state[1], state[2]);
        state[1] = _mm_aesenc_si128(state[0], state[1]);
        state[0] = _mm_aesenc_si128(tmp, state[0]);

        //xor "msg" with state[0]
        state[0] = _mm_xor_si128(state[0], msgtmp);
    }

    state[4] = _mm_xor_si128(state[4], state[3]);
    state[4] = _mm_xor_si128(state[4], state[2]);
    state[4] = _mm_xor_si128(state[4], state[1]);
    state[4] = _mm_xor_si128(state[4], state[0]);

    _mm_store_si128((__m128i *) t, state[4]);
    //in this program, the mac length is assumed to be multiple of bytes
    memcpy(mac, t, 16);
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

void finalize_256(unsigned long long msglen, unsigned long long adlen, unsigned char *mac, __m128i *state)
{
    int i;

    __m128i  tmp;
    __m128i  msgtmp;
    unsigned char t[16], tt[16];

    for (i = 0; i < 16; i++) tt[i] = 0;
    ((unsigned long long*)tt)[0] = adlen  << 3;
    ((unsigned long long*)tt)[1] = msglen << 3;
    msgtmp = _mm_load_si128((__m128i*)tt);

    msgtmp = _mm_xor_si128(msgtmp, state[3]);

    for (i = 0; i < 7; i++) {
        //state update function
        tmp = state[5];
        state[5] = _mm_aesenc_si128(state[4],state[5]);
        state[4] = _mm_aesenc_si128(state[3],state[4]);
        state[3] = _mm_aesenc_si128(state[2],state[3]);
        state[2] = _mm_aesenc_si128(state[1],state[2]);
        state[1] = _mm_aesenc_si128(state[0],state[1]);
        state[0] = _mm_aesenc_si128(tmp,state[0]);

        //xor "msg" with state[0]
        state[0] = _mm_xor_si128(state[0], msgtmp);
    }

    state[5] = _mm_xor_si128(state[5], state[4]);
    state[5] = _mm_xor_si128(state[5], state[3]);
    state[5] = _mm_xor_si128(state[5], state[2]);
    state[5] = _mm_xor_si128(state[5], state[1]);
    state[5] = _mm_xor_si128(state[5], state[0]);

    _mm_store_si128((__m128i*)t, state[5]);
    //in this program, the mac length is assumed to be multiple of bytes
    memcpy(mac,t,16);
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
)
{
    unsigned long long i;
    unsigned char plaintextblock[16], ciphertextblock[16];
    __m128i aegis256_state[6];

    //initialization stage
    init_256(key, iv, aegis256_state);

    //process the associated data
    for (i = 0; (i+16) <= adlen; i += 16) {
        encrypt_256(ad+i, ciphertextblock, aegis256_state);
    }

    //deal with the partial block of associated data
    //in this program, we assume that the message length is multiple of bytes.
    if (  (adlen & 0xf) != 0 )  {
        memset(plaintextblock, 0, 16);
        memcpy(plaintextblock, ad+i, adlen & 0xf);
        encrypt_256(plaintextblock, ciphertextblock, aegis256_state);
    }

    //encrypt the plaintext
    for (i = 0; (i+16) <= msglen; i += 16) {
        encrypt_256(msg+i, cipher+i, aegis256_state);
    }

    // Deal with the partial block
    // In this program, we assume that the message length is multiple of bytes.
    if (  (msglen & 0xf) != 0 )  {
        memset(plaintextblock, 0, 16);
        memcpy(plaintextblock, msg+i, msglen & 0xf);
        encrypt_256(plaintextblock, ciphertextblock, aegis256_state);
        memcpy(cipher+i,ciphertextblock, msglen & 0xf);
    }

    //finalization stage, we assume that the tag length is multiple of bytes
    finalize_256(msglen,adlen, tag, aegis256_state);

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
)
{
    unsigned long long i;
    unsigned char plaintextblock[16], ciphertextblock[16];
    unsigned char check = 0;
    __m128i aegis256_state[6];

    init_256(key, iv, aegis256_state);

    //process the associated data
    for (i = 0; (i+16) <= adlen; i += 16) {
        encrypt_256(ad+i, ciphertextblock, aegis256_state);
    }

    //deal with the partial block of associated data
    //in this program, we assume that the message length is multiple of bytes.
    if (  (adlen & 0xf) != 0 )  {
        memset(plaintextblock, 0, 16);
        memcpy(plaintextblock, ad+i, adlen & 0xf);
        encrypt_256(plaintextblock, ciphertextblock, aegis256_state);
    }

    //decrypt the ciphertext
    for (i = 0; (i+16) <= cipherlen; i += 16) {
        decrypt_256(msg+i, cipher+i, aegis256_state);
    }

    // Deal with the partial block
    // In this program, we assume that the message length is multiple of bytes.
    if (  (cipherlen & 0xf) != 0 )  {
        memset(ciphertextblock, 0, 16);
        memcpy(ciphertextblock, cipher+i, cipherlen & 0xf);
        decrypt_256(plaintextblock, ciphertextblock, aegis256_state);
        memcpy(msg+i, plaintextblock, cipherlen & 0xf);

        //need to modify the state here (because in the last block, keystream is wrongly used to update the state)
        memset(plaintextblock, 0, cipherlen & 0xf);
        aegis256_state[0] = _mm_xor_si128( aegis256_state[0], _mm_load_si128((__m128i*)plaintextblock)  ) ;
    }

    //we assume that the tag length is multiple of bytes
    uint8_t tag_internal[16];
    finalize_256(cipherlen, adlen, tag_internal, aegis256_state);
    //verification
    for (i = 0; i  < 16; i++) check |= (tag[i] ^ tag_internal[i]);
    return !check;
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
    unsigned long long i;
    unsigned char plaintextblock[16], ciphertextblock[16];
    __m128i aegis128_state[5];

    //initialization stage
    init_128(key, iv, aegis128_state);

    //process the associated data
    for (i = 0; (i + 16) <= adlen; i += 16) {
        encrypt_128(ad + i, ciphertextblock, aegis128_state);
    }

    //deal with the partial block of associated data
    //in this program, we assume that the message length is multiple of bytes.
    if ((adlen & 0xf) != 0) {
        memset(plaintextblock, 0, 16);
        memcpy(plaintextblock, ad + i, adlen & 0xf);
        encrypt_128(plaintextblock, ciphertextblock, aegis128_state);
    }

    //encrypt the plaintext
    for (i = 0; (i + 16) <= msglen; i += 16) {
        encrypt_128(msg + i, cipher + i, aegis128_state);
    }

    // Deal with the partial block
    // In this program, we assume that the message length is multiple of bytes.
    if ((msglen & 0xf) != 0) {
        memset(plaintextblock, 0, 16);
        memcpy(plaintextblock, msg + i, msglen & 0xf);
        encrypt_128(plaintextblock, ciphertextblock, aegis128_state);
        memcpy(cipher + i, ciphertextblock, msglen & 0xf);
    }

    //finalization stage, we assume that the tag length is multiple of bytes
    finalize_128(msglen, adlen, tag, aegis128_state);
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
    unsigned long long i;
    unsigned char plaintextblock[16], ciphertextblock[16];
    unsigned char check = 0;
    __m128i aegis128_state[5];

    init_128(key, iv, aegis128_state);

    //process the associated data
    for (i = 0; (i + 16) <= adlen; i += 16) {
        encrypt_128(ad + i, ciphertextblock, aegis128_state);
    }

    //deal with the partial block of associated data
    //in this program, we assume that the message length is multiple of bytes.
    if ((adlen & 0xf) != 0) {
        memset(plaintextblock, 0, 16);
        memcpy(plaintextblock, ad + i, adlen & 0xf);
        encrypt_128(plaintextblock, ciphertextblock, aegis128_state);
    }

    //decrypt the ciphertext
    for (i = 0; (i + 16) <= cipherlen; i += 16) {
        decrypt_128(msg + i, cipher + i, aegis128_state);
    }

    // Deal with the partial block
    // In this program, we assume that the message length is multiple of bytes.
    if ((cipherlen & 0xf) != 0) {
        memset(ciphertextblock, 0, 16);
        memcpy(ciphertextblock, cipher + i, cipherlen & 0xf);
        decrypt_128(plaintextblock, ciphertextblock, aegis128_state);
        memcpy(msg + i, plaintextblock, cipherlen & 0xf);

        //need to modify the state here (because in the last block, keystream is wrongly used to update the state)
        memset(plaintextblock, 0, cipherlen & 0xf);
        aegis128_state[0] = _mm_xor_si128(aegis128_state[0], _mm_load_si128((__m128i *) plaintextblock));
    }

    //we assume that the tag length is multiple of bytes
    uint8_t tag_internal[16];
    finalize_128(cipherlen, adlen, tag_internal, aegis128_state);

    //verification
    for (i = 0; i < 16; i++) check |= (tag[i] ^ tag_internal[i]);
    return !check;
}