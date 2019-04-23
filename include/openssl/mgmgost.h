//
// Created by msnthrp on 22/04/19.
//

#ifndef OPENSSL_MGMGOST_H
#define OPENSSL_MGMGOST_H

#include <stdint.h>

void MGMGOST_encrypt(const uint8_t *key, const uint8_t *in, uint8_t *out);

void MGMGOST_decrypt(const uint8_t *key, const uint8_t *in, uint8_t *out);

#endif //OPENSSL_MGMGOST_H
