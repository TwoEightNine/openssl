/*
 * Deoxys=/=-128-128 Reference C Implementation
 *
 * Copyright 2015:
 *     Jeremy Jean <JJean@ntu.edu.sg>
 *     Ivica Nikolic <inikolic@ntu.edu.sg>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/deoxys.h>
#include "tweakableBC.c"

/* Define the three MSB of the tweak (that depend on the stage) */
#define MSB_AD                (0x2<<4)
#define MSB_AD_LAST           (0x6<<4)
#define MSB_M                 (0x0<<4)
#define MSB_M_LAST_NONZERO    (0x4<<4)
#define MSB_CHKSUM_FULL       (0x1<<4)
#define MSB_CHKSUM_NON_FULL   (0x5<<4)

/* Key size: 16 or 32 */
#define KEY_SIZE               16

/**********************************************************************************
*** the tweak is on 128 bits:
***     tweak = <stage> || <nonce> || <blockNumber>
***  where we use:
***      4 bits for stage
***     64 bits for nonce
***     60 bits for blockNumber
***********************************************************************************/

/*
** Modifiy the nonce part in the tweak value
*/
static void set_nonce_in_tweak(uint8_t *tweak, const uint8_t *nonce) {
    tweak[0] = (tweak[0] & 0xf0) ^ (nonce[0] >> 4);
    tweak[1] = (nonce[0] & 0xf) << 4 ^ (nonce[1] >> 4);
    tweak[2] = (nonce[1] & 0xf) << 4 ^ (nonce[2] >> 4);
    tweak[3] = (nonce[2] & 0xf) << 4 ^ (nonce[3] >> 4);
    tweak[4] = (nonce[3] & 0xf) << 4 ^ (nonce[4] >> 4);
    tweak[5] = (nonce[4] & 0xf) << 4 ^ (nonce[5] >> 4);
    tweak[6] = (nonce[5] & 0xf) << 4 ^ (nonce[6] >> 4);
    tweak[7] = (nonce[6] & 0xf) << 4 ^ (nonce[7] >> 4);
    tweak[8] = (nonce[7] & 0xf) << 4;
}

/*
** Modifiy the block number in the tweak value
*/
static void set_block_number_in_tweak(uint8_t *tweak, const uint64_t block_no) {
    tweak[8] = (tweak[8] & 0xf0) ^ ((block_no >> 56ULL) & 0xf);
    tweak[9] = ((block_no >> 48ULL) & 0xff);
    tweak[10] = ((block_no >> 40ULL) & 0xff);
    tweak[11] = ((block_no >> 32ULL) & 0xff);
    tweak[12] = ((block_no >> 24ULL) & 0xff);
    tweak[13] = ((block_no >> 16ULL) & 0xff);
    tweak[14] = ((block_no >> 8ULL) & 0xff);
    tweak[15] = ((block_no >> 0ULL) & 0xff);
}

/*
** Modifiy the stage value in the tweak value
*/
static void set_stage_in_tweak(uint8_t *tweak, const uint8_t value) {
    tweak[0] = (tweak[0] & 0xf) ^ value;
}

/*
** Update the tweak value in the tweakey word.
** In the case of Deoxys-BC-256, the tweakey word is composed of KEY || TWEAK.
** In the case of Deoxys-BC-384, the tweakey word is composed of KEY_2 || KEY_1 || TWEAK.
*/
static void set_tweak_in_tweakey(uint8_t *tweakey, uint8_t *tweak) {
    memcpy(tweakey + KEY_SIZE, tweak, 16);
}

/*
** XOR an input block to another input block
*/
static void xor_values(uint8_t *v1, const uint8_t *v2) {
    uint8_t i = 16;
    while (i--) v1[i] ^= v2[i];
}

void deoxys_encrypt(const uint8_t tweakey_size,
                    const uint8_t *ass_data, size_t ass_data_len,
                    const uint8_t *message, size_t m_len,
                    const uint8_t *key, const uint8_t *nonce,
                    uint8_t *tag, uint8_t *ciphertext) {

    uint64_t i;
    uint64_t j;
    uint8_t tweak[16];
    uint8_t *tweakey = (uint8_t *) malloc(tweakey_size);
    uint8_t auth[16];
    uint8_t last_block[16];
    uint8_t checksum[16];
    uint8_t final[16];
    uint8_t zero_block[16];
    uint8_t Pad[16];
    uint8_t temp[16];


    /* Fill the tweak with zeros (no nonce !!!) */
    memset(tweak, 0, 16);

    /* Fill the key(s) in the tweakey state */
    memcpy(tweakey, key, tweakey_size - 16);

    /* Associated data */
    memset(auth, 0, 16);

    if (ass_data_len) {
        set_stage_in_tweak(tweak, MSB_AD);

        /* For each full input blocks */
        i = 0;
        while (16 * (i + 1) <= ass_data_len) {

            /* Encrypt the current block */
            set_block_number_in_tweak(tweak, i);
            set_tweak_in_tweakey(tweakey, tweak);
            aesTweakEncrypt(tweakey_size, ass_data + 16 * i, tweakey, temp);

            /* Update auth value */
            xor_values(auth, temp);

            /* Go on with the next block */
            i++;
        }

        /* Last block if incomplete */
        if (ass_data_len > 16 * i) {

            /* Prepare the last padded block */
            memset(last_block, 0, 16);
            memcpy(last_block, ass_data + 16 * i, ass_data_len - 16 * i);
            last_block[ass_data_len - 16 * i] = 0x80;

            /* Encrypt the last block */
            set_stage_in_tweak(tweak, MSB_AD_LAST);
            set_block_number_in_tweak(tweak, i);
            set_tweak_in_tweakey(tweakey, tweak);
            aesTweakEncrypt(tweakey_size, last_block, tweakey, temp);

            /* Update the auth value */
            xor_values(auth, temp);
        }

    }/* if ass_data_len>0 */

    /* Message */
    memset(tweak, 0, sizeof(tweak));
    set_nonce_in_tweak(tweak, nonce);

    memset(checksum, 0, 16);
    set_stage_in_tweak(tweak, MSB_M);
    i = 0;
    while (16 * (i + 1) <= m_len) {
        xor_values(checksum, message + 16 * i);
        set_block_number_in_tweak(tweak, i);
        set_tweak_in_tweakey(tweakey, tweak);
        aesTweakEncrypt(tweakey_size, message + 16 * i, tweakey, ciphertext + 16 * i);
        i++;
    }

    /* Process incomplete block */
    if (m_len > 16 * i) {
        memset(last_block, 0, 16);
        memcpy(last_block, message + 16 * i, m_len - 16 * i);
        last_block[m_len - 16 * i] = 0x80;
        xor_values(checksum, last_block);

        /* Create the zero block for encryption */
        memset(zero_block, 0, 16);

        /* Encrypt it */
        set_stage_in_tweak(tweak, MSB_M_LAST_NONZERO);
        set_block_number_in_tweak(tweak, i);
        set_tweak_in_tweakey(tweakey, tweak);
        aesTweakEncrypt(tweakey_size, zero_block, tweakey, Pad);

        for (j = 0; j < m_len - 16 * i; j++) {
            ciphertext[16 * i + j] = last_block[j] ^ Pad[j];
        }
        set_stage_in_tweak(tweak, MSB_CHKSUM_NON_FULL);
        set_tweak_in_tweakey(tweakey, tweak);
        aesTweakEncrypt(tweakey_size, checksum, tweakey, final);
    } else {
        set_block_number_in_tweak(tweak, i);
        set_stage_in_tweak(tweak, MSB_CHKSUM_FULL);
        set_tweak_in_tweakey(tweakey, tweak);
        aesTweakEncrypt(tweakey_size, checksum, tweakey, final);
    }

    /* Append the authentication tag to the ciphertext */
    for (i = 0; i < 16; i++) {
        tag[i] = final[i] ^ auth[i];
    }
    free(tweakey);
}

int deoxys_decrypt(const uint8_t tweakey_size,
                   const uint8_t *ass_data, size_t ass_data_len,
                   const uint8_t *ciphertext, size_t c_len,
                   const uint8_t *key, const uint8_t *nonce,
                   const uint8_t *tag, uint8_t *message) {

    uint64_t i;
    uint64_t j;
    uint8_t tweak[16];
    uint8_t *tweakey = (uint8_t *) malloc(tweakey_size);
    uint8_t auth[16];
    uint8_t last_block[16];
    uint8_t checksum[16];
    uint8_t final[16];
    uint8_t zero_block[16];
    uint8_t Pad[16];
    uint8_t temp[16];

    /* Fill the tweak with zeros (no nonce !!!) */
    memset(tweak, 0, 16);

    /* Fill the key(s) in the tweakey state */
    memcpy(tweakey, key, tweakey_size - 16);

    /* Associated data */
    memset(auth, 0, 16);

    if (ass_data_len) {

        set_stage_in_tweak(tweak, MSB_AD);
        i = 0;
        while (16 * (i + 1) <= ass_data_len) {
            set_block_number_in_tweak(tweak, i);
            set_tweak_in_tweakey(tweakey, tweak);
            aesTweakEncrypt(tweakey_size, ass_data + 16 * i, tweakey, temp);
            xor_values(auth, temp);
            i++;
        }

        /* Last block if incomplete */
        if (ass_data_len > 16 * i) {
            memset(last_block, 0, 16);
            memcpy(last_block, ass_data + 16 * i, ass_data_len - 16 * i);
            last_block[ass_data_len - 16 * i] = 0x80;
            set_stage_in_tweak(tweak, MSB_AD_LAST);
            set_block_number_in_tweak(tweak, i);
            set_tweak_in_tweakey(tweakey, tweak);
            aesTweakEncrypt(tweakey_size, last_block, tweakey, temp);
            xor_values(auth, temp);
        }

    } /* if ass_data_len>0 */

    /* Ciphertext */
    memset(tweak, 0, sizeof(tweak));
    set_nonce_in_tweak(tweak, nonce);


    memset(checksum, 0, 16);
    set_stage_in_tweak(tweak, MSB_M);
    i = 0;
    while (16 * (i + 1) <= c_len) {
        set_tweak_in_tweakey(tweakey, tweak);
        set_block_number_in_tweak(tweak, i);
        set_tweak_in_tweakey(tweakey, tweak);
        aesTweakDecrypt(tweakey_size, ciphertext + 16 * i, tweakey, message + 16 * i);
        xor_values(checksum, message + 16 * i);
        i++;
    }

    /* Last block */
    /* If the block is full, i.e. M_last=epsilon */
    if (c_len == 16 * i) {
        set_block_number_in_tweak(tweak, i);
        set_stage_in_tweak(tweak, MSB_CHKSUM_FULL);
        set_tweak_in_tweakey(tweakey, tweak);
        aesTweakEncrypt(tweakey_size, checksum, tweakey, final);
        xor_values(final, auth);
    } else {

        /* Prepare the full-zero block */
        memset(zero_block, 0, 16);

        /* Prepare the tweak */
        set_stage_in_tweak(tweak, MSB_M_LAST_NONZERO);
        set_block_number_in_tweak(tweak, i);
        set_tweak_in_tweakey(tweakey, tweak);

        /* Encrypt */
        aesTweakEncrypt(tweakey_size, zero_block, tweakey, Pad);

        /* XOR the partial ciphertext */
        memset(last_block, 0, 16);
        memcpy(last_block, ciphertext + 16 * i, c_len - 16 * i);
        memset(Pad + c_len - 16 * i, 0, 16 - (c_len - 16 * i));
        xor_values(last_block, Pad);
        last_block[c_len - 16 * i] = 0x80;

        for (j = 0; j < c_len - 16 * i; j++) {
            message[16 * i + j] = last_block[j];
        }

        /* Update checksum */
        xor_values(checksum, last_block);

        /* Verify the tag */
        set_stage_in_tweak(tweak, MSB_CHKSUM_NON_FULL);
        set_tweak_in_tweakey(tweakey, tweak);
        aesTweakEncrypt(tweakey_size, checksum, tweakey, final);
        xor_values(final, auth);
    }
    free(tweakey);

    return !memcmp(final, tag, 16);
}

/**
 * encrypt and sign message using Deoxys-II-128-128
 * INPUT:
 * @param ass_data, len = @param ass_data_len
 * @param ass_data_len
 * @param message, len = @param m_len
 * @param m_len
 * @param key, len = 16
 * @param nonce, len = 8
 * OUTPUT:
 * @param tag, len = 16
 * @param ciphertext, len = @param m_len
 */
void DEOXYS_encrypt_128(const uint8_t *ass_data, size_t ass_data_len,
                        const uint8_t *message, size_t m_len,
                        const uint8_t *key, const uint8_t *nonce,
                        uint8_t *tag, uint8_t *ciphertext) {
    deoxys_encrypt(32, ass_data, ass_data_len, message, m_len, key, nonce, tag, ciphertext);
}

/**
 * decrypt and verify ciphertext using Deoxys-II-128-128
 * INPUT:
 * @param ass_data, len = @param ass_data_len
 * @param ass_data_len
 * @param ciphertext, len = @param c_len
 * @param c_len
 * @param key, len = 16
 * @param nonce, len = 8
 * @param tag, len = 16
 * OUTPUT:
 * @param message, len = @param c_len
 * @return 1 if tag is valid, 0 otherwise
 */
int DEOXYS_decrypt_128(const uint8_t *ass_data, size_t ass_data_len,
                       const uint8_t *ciphertext, size_t c_len,
                       const uint8_t *key, const uint8_t *nonce,
                       const uint8_t *tag, uint8_t *message) {
    return deoxys_decrypt(32, ass_data, ass_data_len, ciphertext, c_len, key, nonce, tag, message);
}

/**
 * encrypt and sign message using Deoxys-II-256-128
 * INPUT:
 * @param ass_data, len = @param ass_data_len
 * @param ass_data_len
 * @param message, len = @param m_len
 * @param m_len
 * @param key, len = 32
 * @param nonce, len = 8
 * OUTPUT:
 * @param tag, len = 16
 * @param ciphertext, len = @param m_len
 */
void DEOXYS_encrypt_256(const uint8_t *ass_data, size_t ass_data_len,
                        const uint8_t *message, size_t m_len,
                        const uint8_t *key, const uint8_t *nonce,
                        uint8_t *tag, uint8_t *ciphertext) {
    deoxys_encrypt(48, ass_data, ass_data_len, message, m_len, key, nonce, tag, ciphertext);
}

/**
 * decrypt and verify ciphertext using Deoxys-II-256-128
 * INPUT:
 * @param ass_data, len = @param ass_data_len
 * @param ass_data_len
 * @param ciphertext, len = @param c_len
 * @param c_len
 * @param key, len = 32
 * @param nonce, len = 8
 * @param tag, len = 16
 * OUTPUT:
 * @param message, len = @param c_len
 * @return 1 if tag is valid, 0 otherwise
 */
int DEOXYS_decrypt_256(const uint8_t *ass_data, size_t ass_data_len,
                       const uint8_t *ciphertext, size_t c_len,
                       const uint8_t *key, const uint8_t *nonce,
                       const uint8_t *tag, uint8_t *message) {
    return deoxys_decrypt(48, ass_data, ass_data_len, ciphertext, c_len, key, nonce, tag, message);
}