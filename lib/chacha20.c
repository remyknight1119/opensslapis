/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "osslapis.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

int osslapis_chacha20_encrypt(unsigned char *plaintext, int plaintext_len,
                      unsigned char *key, unsigned char *nonce,
                      unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;

    /* Create and initialize the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    /* Initialize the encryption operation */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, NULL, NULL))
        return -1;

    /* Set the key and nonce */
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce))
        return -1;

    /* Perform the encryption */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return -1;
    ciphertext_len = len;

    /* Finalize the encryption */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return -1;
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int osslapis_chacha20_decrypt(unsigned char *ciphertext, int ciphertext_len,
                      unsigned char *key, unsigned char *nonce,
                      unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;

    /* Create and initialize the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    /* Initialize the decryption operation */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, NULL, NULL))
        return -1;

    /* Set the key and nonce */
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce))
        return -1;

    /* Perform the decryption */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return -1;
    plaintext_len = len;

    /* Finalize the decryption */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        return -1;
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

