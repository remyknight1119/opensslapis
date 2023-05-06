/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "api_test.h"
#include "evp.h"

#include <string.h>

#include "osslapis.h"
#include "debug.h"


int test_chacha20_encrypt_decrypt(void)
{
    unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";
    unsigned char key[] = "01234567890123456789012345678901";
    unsigned char nonce[] = "01234567";
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];
    int plaintext_len = 0;
    int decryptedtext_len = 0;
    int ciphertext_len = 0;

    plaintext_len = sizeof(plaintext);
    /* Encrypt the plaintext */
    ciphertext_len = osslapis_chacha20_encrypt(plaintext, plaintext_len,
                                       key, nonce, ciphertext);

    /* Decrypt the ciphertext */
    decryptedtext_len = osslapis_chacha20_decrypt(ciphertext, ciphertext_len,
                                          key, nonce, decryptedtext);

    /* Add a null terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    if (plaintext_len != decryptedtext_len ||
            memcmp(plaintext, decryptedtext, plaintext_len) != 0) {
        return -1;
    }

    return 0;
}

