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
#include <openssl/aes.h>

#include "osslapis.h"
#include "debug.h"

int test_aes_cbc_encrypt_decrypt(void)
{
    unsigned char data[128] = {};
    unsigned char key[16];
    unsigned char cipher1[sizeof(data)*2] = {};
    unsigned char cipher2[sizeof(data)*2] = {};
    unsigned char plaintext[sizeof(data)] = {};
    AES_KEY aes_key;
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
    if (osslapis_aes_cbc_encrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                cipher1, &cipher_len, data, len) < 0) {
        return -1;
    }

    AES_set_encrypt_key(key, sizeof(key)*8, &aes_key);
    memcpy(iv_tmp, &iv, sizeof(iv));

    AES_cbc_encrypt(data, cipher2, len, &aes_key, iv_tmp, AES_ENCRYPT);
    if (memcmp(cipher1, cipher2, len) != 0) {
        data_print(cipher1, len);
        data_print(cipher2, len);
        return -1;
    }

    memcpy(iv_tmp, &iv, sizeof(iv));
    if (osslapis_aes_cbc_decrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                plaintext, &plaintext_len, cipher1, cipher_len) < 0) {
        printf("AES decrypt failed\n");
        return -1;
    }

    if (plaintext_len != len || memcmp(plaintext, data, len) != 0) {
        return -1;
    }

    return 0;
}

int test_aes_ctr_encrypt_decrypt(void)
{
    unsigned char key[16];
    unsigned char data[128] = {};
    unsigned char cipher[sizeof(data)] = {};
    unsigned char plaintext[sizeof(data)] = {};
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
    if (osslapis_aes_ctr_encrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                cipher, &cipher_len, data, len) < 0) {
        return -1;
    }

    if (cipher_len != len) {
        printf("AES CTR cipher len error\n");
        return -1;
    }

    memcpy(iv_tmp, &iv, sizeof(iv));
    if (osslapis_aes_ctr_decrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                plaintext, &plaintext_len, cipher, cipher_len) < 0) {
        printf("AES CTR decrypt failed\n");
        return -1;
    }

    if (plaintext_len != len || memcmp(plaintext, data, len) != 0) {
        return -1;
    }

    plaintext_len = 0;
    memset(plaintext, 0, sizeof(plaintext));
    memcpy(iv_tmp, &iv, sizeof(iv));
    if (osslapis_aes_ctr_encrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                plaintext, &plaintext_len, cipher, cipher_len) < 0) {
        printf("AES CTR encrypt failed\n");
        return -1;
    }

    if (plaintext_len != len || memcmp(plaintext, data, len) != 0) {
        return -1;
    }

    return 0;
}

int test_aes_cfb_encrypt_decrypt(void)
{
    unsigned char data[128] = {};
    unsigned char key[16];
    unsigned char cipher1[sizeof(data)*2] = {};
    unsigned char cipher2[sizeof(data)*2] = {};
    unsigned char plaintext[sizeof(data)] = {};
    AES_KEY aes_key;
    unsigned char iv[16];
    unsigned char iv_tmp[sizeof(iv)];
    int len = 0;
    int iv_len = 0;
    int cipher_len = 0;
    int plaintext_len = 0;

    RAND_bytes(data, sizeof(data));
    RAND_bytes(key, sizeof(key));
    RAND_bytes((void *)&iv, sizeof(iv));

    memcpy(iv_tmp, &iv, sizeof(iv));
    len =  sizeof(data);
    if (osslapis_aes_cfb_encrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                cipher1, &cipher_len, data, len) < 0) {
        return -1;
    }

    AES_set_encrypt_key(key, sizeof(key)*8, &aes_key);
    memcpy(iv_tmp, &iv, sizeof(iv));

    AES_cfb128_encrypt(data, cipher2, len, &aes_key, iv_tmp, &iv_len,
                        AES_ENCRYPT);
    if (memcmp(cipher1, cipher2, len) != 0) {
        data_print(cipher1, len);
        data_print(cipher2, len);
        return -1;
    }

    memcpy(iv_tmp, &iv, sizeof(iv));
    if (osslapis_aes_cfb_decrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                plaintext, &plaintext_len, cipher1, cipher_len) < 0) {
        printf("AES decrypt failed\n");
        return -1;
    }

    if (plaintext_len != len || memcmp(plaintext, data, len) != 0) {
        return -1;
    }

    return 0;
}

int test_aes_ccm_encrypt_decrypt(void)
{
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    unsigned char *nonce = (unsigned char *)"012345678901";
    unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];
    unsigned char tag[EVP_CCM_TLS_TAG_LEN] = {};

    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = osslapis_aes_ccm_encrypt(plaintext, sizeof(plaintext) - 1,
                                     key, nonce, NULL, 0, ciphertext, tag);

    printf("clen = %d\n", ciphertext_len);
    /* Print the encrypted text */
    printf("Ciphertext is:\n");
    for (int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    /* Decrypt the ciphertext */
    decryptedtext_len = osslapis_aes_ccm_decrypt(ciphertext, ciphertext_len,
                                         key, nonce, NULL, 0,
                                         tag, decryptedtext);
    if (decryptedtext_len <= 0) {
        printf("CCM decrypt failed(%d)\n", decryptedtext_len);
        return -1;
    }

    /* Add a null terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Print the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);

    return 0;
}

