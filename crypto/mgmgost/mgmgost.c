//
// Created by msnthrp on 22/04/19.
//

#include <openssl/mgmgost.h>
#include <string.h>
#include <stdint.h>

static unsigned char Pi[8][16] = {
        {1,  7,  14, 13, 0,  5,  8,  3,  4,  15, 10, 6,  9,  12, 11, 2},
        {8,  14, 2,  5,  6,  9,  1,  12, 15, 4,  11, 0,  13, 10, 3,  7},
        {5,  13, 15, 6,  9,  2,  12, 10, 11, 7,  8,  1,  4,  3,  14, 0},
        {7,  15, 5,  10, 8,  1,  6,  13, 0,  9,  3,  14, 11, 4,  2,  12},
        {12, 8,  2,  1,  13, 4,  15, 6,  7,  0,  10, 5,  3,  14, 9,  11},
        {11, 3,  5,  8,  2,  15, 10, 13, 14, 1,  7,  4,  12, 9,  6,  0},
        {6,  8,  2,  3,  9,  10, 5,  12, 1,  14, 4,  7,  11, 13, 0,  15},
        {12, 4,  6,  2,  10, 5,  11, 9,  14, 8,  13, 7,  0,  3,  15, 1}
};

void func_g(const uint8_t *k, const uint8_t *a, uint8_t *out_data) {
    uint8_t internal[4];
    uint32_t out_data_32;
    uint8_t i;

    i = 4;
    unsigned int var = 0;
    while (i--) {
        var = a[i] + k[i] + (var >> 8);
        internal[i] = var & 0xff;
    }

    uint8_t first_part_byte, sec_part_byte;
    i = 4;
    while (i--) {
        first_part_byte = (internal[i] & 0xf0) >> 4;
        sec_part_byte = (internal[i] & 0x0f);
        first_part_byte = Pi[i * 2][first_part_byte];
        sec_part_byte = Pi[i * 2 + 1][sec_part_byte];
        internal[i] = (first_part_byte << 4) | sec_part_byte;
    }

    out_data_32 = internal[0];
    out_data_32 = (out_data_32 << 8) + internal[1];
    out_data_32 = (out_data_32 << 8) + internal[2];
    out_data_32 = (out_data_32 << 8) + internal[3];
    out_data_32 = (out_data_32 << 11) | (out_data_32 >> 21);

    out_data[3] = out_data_32;
    out_data[2] = out_data_32 >> 8;
    out_data[1] = out_data_32 >> 16;
    out_data[0] = out_data_32 >> 24;
}

void magma_G(const uint8_t *k, const uint8_t *a, uint8_t *out_data) {
    uint8_t G[4];
    func_g(k, a + 4, G);

    uint8_t i = 4;
    while (i--) {
        G[i] ^= a[i];
    }

    for (i = 0; i < 4; i++) {
        out_data[i] = a[i + 4];
        out_data[4 + i] = G[i];
    }
}

void magma_G_final(const uint8_t *k, const uint8_t *a, uint8_t *out_data) {
    uint8_t G[4];
    func_g(k, a + 4, G);

    uint8_t i;
    for (i = 0; i < 8; i++) {
        out_data[i] = a[i];
    }

    for (i = 0; i < 4; i++) {
        out_data[i] ^= G[i];
    }
}

void MGMGOST_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out) {
    magma_G(key, in, out);

    uint8_t i;
    uint8_t diff = 4;
    for (i = 1; i < 24; i++) {
        magma_G(key + diff, out, out);
        diff = (diff + 4) & 0x1f; // mod 32
    }
    diff = 28;
    for (i = 24; i < 31; i++) {
        magma_G(key + diff, out, out);
        diff -= 4;
    }
    magma_G_final(key, out, out);
}

void MGMGOST_decrypt(const uint8_t *key, const uint8_t *in, uint8_t *out) {
    magma_G(key, in, out);

    uint8_t i;
    uint8_t diff = 4;
    for (i = 30; i >= 24; i--) {
        magma_G(key + diff, out, out);
        diff += 4;
    }
    diff = 28;
    for (i = 23; i > 0; i--) {
        magma_G(key + diff, out, out);
        diff = (diff - 4) & 0x1f; // mod 32
    }
    magma_G_final(key, out, out);
}
