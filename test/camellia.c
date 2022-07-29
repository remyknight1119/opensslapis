/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "api_test.h"
#include "evp.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/camellia.h>

#include "osslapis.h"
#include "debug.h"

int test_camellia_cbc_encrypt_decrypt(void)
{
    unsigned char data[128] = {};
    unsigned char key[16];
    unsigned char cipher1[sizeof(data)*2] = {};
    unsigned char cipher2[sizeof(data)*2] = {};
    unsigned char plaintext[sizeof(data)] = {};
    CAMELLIA_KEY camellia_key;
    unsigned char iv[16];
    unsigned char iv_tmp[sizeof(iv)];
    int len = 0;
    int cipher_len = 0;
    int plaintext_len = 0;

    RAND_bytes(data, sizeof(data));
    RAND_bytes(key, sizeof(key));
    RAND_bytes((void *)&iv, sizeof(iv));

    memcpy(iv_tmp, &iv, sizeof(iv));
    len =  sizeof(data);
    if (osslapis_camellia_cbc_encrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                cipher1, &cipher_len, data, len) < 0) {
        return -1;
    }

    Camellia_set_key(key, sizeof(key)*8, &camellia_key);
    memcpy(iv_tmp, &iv, sizeof(iv));

    Camellia_cbc_encrypt(data, cipher2, len, &camellia_key, iv_tmp, 1);
    if (memcmp(cipher1, cipher2, len) != 0) {
        data_print(cipher1, len);
        data_print(cipher2, len);
        return -1;
    }

    memcpy(iv_tmp, &iv, sizeof(iv));
    if (osslapis_camellia_cbc_decrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                plaintext, &plaintext_len, cipher1, cipher_len) < 0) {
        printf("AES decrypt failed\n");
        return -1;
    }

    if (plaintext_len != len || memcmp(plaintext, data, len) != 0) {
        return -1;
    }

    return 0;
}

