//
// Created by msnthrp on 16/03/19.
//

#include "internal/gost_grasshopper.h"

void GHGOST_encrypt(const unsigned char *in, unsigned char *out,
                    const GHGOST_KEY *key) {
    out = in;
}

void GHGOST_decrypt(const unsigned char *in, unsigned char *out,
                    const GHGOST_KEY *key) {
    out = in;
}

int GHGOST_set_encrypt_key(const unsigned char *userKey, const int bits,
                           GHGOST_KEY *key) {

}

int GHGOST_set_decrypt_key(const unsigned char *userKey, const int bits,
                           GHGOST_KEY *key) {

}