/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "osslapis.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/obj_mac.h>

#include "evp.h"
#include "passwd.h"
#include "log.h"
#include "debug.h"

static EvpPkeyCipher kAesCbcType[] = {
    {
        .key_size = 128,
        .name = SN_aes_128_cbc,
        .get_cipher = EVP_aes_128_cbc,
    },
    {
        .key_size = 192,
        .name = SN_aes_192_cbc,
        .get_cipher = EVP_aes_192_cbc,
    },
    {
        .key_size = 256,
        .name = SN_aes_256_cbc,
        .get_cipher = EVP_aes_256_cbc,
    },
};

#define AES_CBC_TYPE_NUM OAPIS_NELEM(kAesCbcType)

static EvpPkeyCipher kAesCtrType[] = {
    {
        .key_size = 128,
        .name = SN_aes_128_ctr,
        .get_cipher = EVP_aes_128_ctr,
    },
    {
        .key_size = 192,
        .name = SN_aes_192_ctr,
        .get_cipher = EVP_aes_192_ctr,
    },
    {
        .key_size = 256,
        .name = SN_aes_256_ctr,
        .get_cipher = EVP_aes_256_ctr,
    },
};

#define AES_CTR_TYPE_NUM OAPIS_NELEM(kAesCtrType)

static EvpPkeyCipher kAesCfbType[] = {
    {
        .key_size = 128,
        .get_cipher = EVP_aes_128_cfb,
    },
    {
        .key_size = 192,
        .get_cipher = EVP_aes_192_cfb,
    },
    {
        .key_size = 256,
        .get_cipher = EVP_aes_256_cfb,
    },
};

#define AES_CFB_TYPE_NUM OAPIS_NELEM(kAesCfbType)

static const EVP_CIPHER *get_aes_cbc_evp(int key_size)
{
    EvpPkeyCipher *t = NULL;

    t = find_evp_pkey_type(key_size*8, kAesCbcType, AES_CBC_TYPE_NUM);
    if (t == NULL) {
        return NULL;
    }

    if (t->name != NULL) {
        return EVP_CIPHER_fetch(NULL, t->name, NULL);
    }

    return t->get_cipher();
}

static const EVP_CIPHER *get_aes_ctr_evp(int key_size)
{
    EvpPkeyCipher *t = NULL;

    t = find_evp_pkey_type(key_size*8, kAesCtrType, AES_CTR_TYPE_NUM);
    if (t == NULL) {
        return NULL;
    }

    return t->get_cipher();
}

static const EVP_CIPHER *get_aes_cfb_evp(int key_size)
{
    EvpPkeyCipher *t = NULL;

    t = find_evp_pkey_type(key_size*8, kAesCfbType, AES_CFB_TYPE_NUM);
    if (t == NULL) {
        return NULL;
    }

    return t->get_cipher();
}

int osslapis_aes_cbc_encrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl)
{
    const EVP_CIPHER *evp = get_aes_cbc_evp(keylen);

    return osslapis_cipher_encrypt(evp, key, keylen, iv, ivlen, out, outl,
                                    in, inl);
}

int osslapis_aes_cbc_decrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl)
{
    const EVP_CIPHER *evp = get_aes_cbc_evp(keylen);

    return osslapis_cipher_decrypt(evp, key, keylen, iv, ivlen, out, outl,
                                    in, inl);
}

int osslapis_aes_ctr_encrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl)
{
    const EVP_CIPHER *evp = get_aes_ctr_evp(keylen);

    return osslapis_cipher_encrypt(evp, key, keylen, iv, ivlen, out, outl,
                                    in, inl);
}

int osslapis_aes_ctr_decrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl)
{
    const EVP_CIPHER *evp = get_aes_ctr_evp(keylen);

    return osslapis_cipher_decrypt(evp, key, keylen, iv, ivlen, out, outl,
                                    in, inl);
}

int osslapis_aes_cfb_encrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl)
{
    const EVP_CIPHER *evp = get_aes_cfb_evp(keylen);

    return osslapis_cipher_encrypt(evp, key, keylen, iv, ivlen, out, outl,
                                    in, inl);
}

int osslapis_aes_cfb_decrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl)
{
    const EVP_CIPHER *evp = get_aes_cfb_evp(keylen);

    return osslapis_cipher_decrypt(evp, key, keylen, iv, ivlen, out, outl,
                                    in, inl);
}

static EVP_CIPHER_CTX *AesCcmCipherInit(unsigned char *key, int enc)
{
    EVP_CIPHER_CTX *ctx;

    /* Create and initialize the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        return NULL;
    }

    /* Initialize the encryption operation */
    if (1 != EVP_CipherInit(ctx, EVP_aes_128_ccm(), NULL, NULL, enc)) {
        goto err;
    }

    /* Set IV len */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IVLEN, EVP_CCM_TLS_IV_LEN, NULL)) {
        goto err;
    }

    /* Set Tag len */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, EVP_CCM_TLS_TAG_LEN, NULL)) {
        goto err;
    }

    if (1 != EVP_CipherInit(ctx, NULL, key, NULL, enc)) {
        goto err;
    }

    return ctx;
err:
    EVP_CIPHER_CTX_free(ctx);
    return NULL;
}

int osslapis_aes_ccm_encrypt(unsigned char *plaintext, int plaintext_len,
                        unsigned char *key, unsigned char *nonce,
                        unsigned char *aad, int aad_len,
                        unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;

    ctx = AesCcmCipherInit(key, 1);
    if (ctx == NULL) {
        return -1;
    }

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, nonce)) {
        goto err;
    }

    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, NULL, plaintext_len)) {
        printf("Encrypt update NULL failed\n");
        goto err;
    }

    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        printf("Encrypt update AAD failed(%d)\n", aad_len);
        goto err;
    }

    /* Perform the encryption */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        printf("Encrypt update plaintext failed\n");
        goto err;
    }
    ciphertext_len = len;

    /* Finalize the encryption and get the tag */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        goto err;
    }

    ciphertext_len += len;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_GET_TAG, EVP_CCM_TLS_TAG_LEN, tag)) {
        goto err;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int osslapis_aes_ccm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                     unsigned char *key, unsigned char *nonce,
                     unsigned char *aad, int aad_len,
                     unsigned char *tag, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;

    ctx = AesCcmCipherInit(key, 0);
    /* Create and initialize the context */
    if (ctx == NULL) {
        return -1;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_TAG, EVP_CCM_TLS_TAG_LEN, tag)) {
        goto err;
    }

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, NULL, nonce)) {
        goto err;
    }

    if (1 != EVP_DecryptUpdate(ctx, NULL, &len, NULL, ciphertext_len)) {
        printf("Encrypt update NULL failed\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }

    if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        printf("Encrypt update aad failed\n");
        goto err;
    }

    /* Perform the decryption */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        printf("Decrypt update plaintext failed(%d)\n", ciphertext_len);
        ERR_print_errors_fp(stderr);
        goto err;
    }
    plaintext_len = len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int osslapis_aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                        unsigned char *key, unsigned char *nonce,
                        unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        goto err;
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        goto err;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, EVP_GCM_TLS_EXPLICIT_IV_LEN, NULL)) {
        goto err;
    }

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)) {
        goto err;
    }

    /* Perform the encryption */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        printf("Encrypt update plaintext failed\n");
        goto err;
    }
    ciphertext_len = len;

    /* Finalize the encryption and get the tag */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        goto err;
    }

    ciphertext_len += len;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, EVP_GCM_TLS_TAG_LEN, tag)) {
        goto err;
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int osslapis_aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                     unsigned char *key, unsigned char *nonce,
                     unsigned char *plaintext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        goto err;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        printf("Decrypt Init failed\n");
        goto err;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, EVP_GCM_TLS_EXPLICIT_IV_LEN, NULL)) {
        printf("Decrypt Cipher set IV failed\n");
        goto err;
    }

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) {
        printf("Decrypt Init failed\n");
        goto err;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, EVP_GCM_TLS_TAG_LEN, tag)) {
        printf("Decrypt Cipher set TAG failed\n");
        goto err;
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        printf("Decrypt update plaintext failed\n");
        goto err;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        OSSLAPIS_LOG("EVP Cipher final failed: %s\n", OSSLAPIS_ERR_STR());
        goto err;
    }

    plaintext_len += len;
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}


