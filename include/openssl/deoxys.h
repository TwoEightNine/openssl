//
// Created by msnthrp on 21/04/19.
//

#ifndef OPENSSL_DEOXYS_H
#define OPENSSL_DEOXYS_H

/**
 * encrypt and sign message
 * INPUT:
 * @param ass_data, len = @param ass_data_len
 * @param ass_data_len
 * @param message, len = @param m_len
 * @param m_len
 * @param key, len = 16
 * @param nonce, len = 16
 * OUTPUT:
 * @param tag, len = 16
 * @param ciphertext, len = @param m_len
 */
void DEOXYS_encrypt(const uint8_t *ass_data, size_t ass_data_len,
                    const uint8_t *message, size_t m_len,
                    const uint8_t *key, const uint8_t *nonce,
                    uint8_t *tag, uint8_t *ciphertext);

/**
 * decrypt and verify ciphertext
 * INPUT:
 * @param ass_data, len = @param ass_data_len
 * @param ass_data_len
 * @param ciphertext, len = @param c_len
 * @param c_len
 * @param key, len = 16
 * @param nonce, len = 16
 * @param tag, len = 16
 * OUTPUT:
 * @param message, len = @param c_len
 * @return 1 if tag is valid, 0 otherwise
 */
int DEOXYS_decrypt(const uint8_t *ass_data, size_t ass_data_len,
                   const uint8_t *ciphertext, size_t c_len,
                   const uint8_t *key, const uint8_t *nonce,
                   const uint8_t *tag, uint8_t *message);

#endif //OPENSSL_DEOXYS_H
