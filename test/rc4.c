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
#include <openssl/rc4.h>

#include "osslapis.h"
#include "debug.h"

int test_rc4_encrypt_decrypt(void)
{
    RC4_KEY rc4_key;
    unsigned char key[16] = {};
    unsigned char data[128] = {};
    unsigned char cipher1[sizeof(data)*2] = {};
    unsigned char cipher2[sizeof(data)*2] = {};
    unsigned char plaintext[sizeof(data)] = {};
    int cipher_len = 0;
    int plaintext_len = 0;
    int len = 0;
 
    RAND_bytes(key, sizeof(key));
    RAND_bytes(data, sizeof(data));

    len = sizeof(data);
    if (osslapis_rc4_encrypt(key, sizeof(key), NULL, 0, cipher1, &cipher_len,
                data, len) < 0) {
        return -1;
    }

    RC4_set_key(&rc4_key, sizeof(key), key);
    RC4(&rc4_key, len, data, cipher2);

    if (memcmp(cipher1, cipher2, len) != 0) {
        data_print(cipher1, len);
        data_print(cipher2, len);
        return -1;
    }

    if (osslapis_rc4_decrypt(key, sizeof(key), NULL, 0, plaintext,
                &plaintext_len, cipher1, cipher_len) < 0) {
        printf("RC4 decrypt failed\n");
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
