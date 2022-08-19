/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "api_test.h"
#include "evp.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/des.h>

#include "osslapis.h"
#include "debug.h"

int test_3des_encrypt_decrypt(void)
{
    unsigned char key[24];
    unsigned char data[128] = {};
    unsigned char cipher1[sizeof(data)*2] = {};
    unsigned char cipher2[sizeof(data)*2] = {};
    unsigned char plaintext[sizeof(data)] = {};
    DES_cblock *des_key = (DES_cblock *)key;
    DES_key_schedule ksch[3];
    DES_cblock iv;
    unsigned char iv_tmp[sizeof(iv)];
    int len = 0;
    int cipher_len = 0;
    int plaintext_len = 0;

    RAND_bytes(key, sizeof(key));
    RAND_bytes(data, sizeof(data));
    RAND_bytes((void *)&iv, sizeof(iv));

    DES_set_key(&des_key[0], &ksch[0]);
    DES_set_key(&des_key[1], &ksch[1]);
    DES_set_key(&des_key[2], &ksch[2]);

    memcpy(iv_tmp, &iv, sizeof(iv));
    len = sizeof(data);
    if (osslapis_3des_encrypt(key, sizeof(key), (void *)&iv, sizeof(iv),
                cipher1, &cipher_len, data, len) < 0) {
        return -1;
    }

    DES_ede3_cbc_encrypt(data, cipher2, len, &ksch[0], &ksch[1], &ksch[2], &iv,
            DES_ENCRYPT);
    if (memcmp(cipher1, cipher2, len) != 0) {
        data_print(cipher1, len);
        data_print(cipher2, len);
        return -1;
    }

    DES_set_key(&des_key[0], &ksch[0]);
    DES_set_key(&des_key[1], &ksch[1]);
    DES_set_key(&des_key[2], &ksch[2]);

    memcpy(&iv, iv_tmp, sizeof(iv));
    DES_ede3_cbc_encrypt(cipher2, plaintext, len, &ksch[0], &ksch[1], &ksch[2], &iv,
            DES_DECRYPT);

    if (memcmp(plaintext, data, len) != 0) {
        data_print(data, len);
        data_print(plaintext, len);
        return -1;
    }

    memset(plaintext, 0, sizeof(plaintext));
    if (osslapis_3des_decrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                plaintext, &plaintext_len, cipher1, cipher_len) < 0) {
        printf("3DES decrypt failed\n");
        data_print(data, len);
        data_print(plaintext, len);
        return -1;
    }

    if (plaintext_len != len || memcmp(plaintext, data, len) != 0) {
        data_print(data, len);
        data_print(plaintext, len);
        return -1;
    }

    return 0;
}

int test_des_cbc_encrypt_decrypt(void)
{
    unsigned char key[8];
    unsigned char data[128] = {};
    unsigned char cipher1[sizeof(data)*2] = {};
    unsigned char cipher2[sizeof(data)*2] = {};
    unsigned char plaintext[sizeof(data)] = {};
    DES_cblock *des_key = (DES_cblock *)key;
    DES_key_schedule ksch;
    DES_cblock iv;
    unsigned char iv_tmp[sizeof(iv)];
    int len = 0;
    int cipher_len = 0;
    int plaintext_len = 0;

    RAND_bytes(key, sizeof(key));
    RAND_bytes(data, sizeof(data));
    RAND_bytes((void *)&iv, sizeof(iv));

    memcpy(iv_tmp, &iv, sizeof(iv));
    len = sizeof(data);
    if (osslapis_des_cbc_encrypt(key, sizeof(key), (void *)&iv, sizeof(iv),
                cipher1, &cipher_len, data, len) < 0) {
        return -1;
    }

    DES_set_key(des_key, &ksch);
    DES_cbc_encrypt(data, cipher2, len, &ksch, &iv, DES_ENCRYPT);
    if (memcmp(cipher1, cipher2, len) != 0) {
        data_print(cipher1, len);
        data_print(cipher2, len);
        return -1;
    }

    DES_set_key(des_key, &ksch);
    memcpy(&iv, iv_tmp, sizeof(iv));
    DES_cbc_encrypt(cipher2, plaintext, len, &ksch, &iv, DES_DECRYPT);
    if (memcmp(plaintext, data, len) != 0) {
        data_print(data, len);
        data_print(plaintext, len);
        return -1;
    }

    memset(plaintext, 0, sizeof(plaintext));
    if (osslapis_des_cbc_decrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                plaintext, &plaintext_len, cipher1, cipher_len) < 0) {
        printf("DES CBC decrypt failed\n");
        data_print(data, len);
        data_print(plaintext, len);
        return -1;
    }

    if (plaintext_len != len || memcmp(plaintext, data, len) != 0) {
        data_print(data, len);
        data_print(plaintext, len);
        return -1;
    }

    return 0;
}


