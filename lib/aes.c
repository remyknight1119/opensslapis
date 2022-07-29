/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "osslapis.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "evp.h"
#include "passwd.h"
#include "log.h"
#include "debug.h"

static EvpPkeyCipher kAesCbcType[] = {
    {
        .key_size = 128,
        .get_cipher = EVP_aes_128_cbc,
    },
    {
        .key_size = 192,
        .get_cipher = EVP_aes_192_cbc,
    },
    {
        .key_size = 256,
        .get_cipher = EVP_aes_256_cbc,
    },
};

#define AES_CBC_TYPE_NUM OAPIS_NELEM(kAesCbcType)

static EvpPkeyCipher kAesCtrType[] = {
    {
        .key_size = 128,
        .get_cipher = EVP_aes_128_ctr,
    },
    {
        .key_size = 192,
        .get_cipher = EVP_aes_192_ctr,
    },
    {
        .key_size = 256,
        .get_cipher = EVP_aes_256_ctr,
    },
};

#define AES_CTR_TYPE_NUM OAPIS_NELEM(kAesCtrType)

static const EVP_CIPHER *get_aes_cbc_evp(int key_size)
{
    EvpPkeyCipher *t = NULL;

    t = find_evp_pkey_type(key_size*8, kAesCbcType, AES_CBC_TYPE_NUM);
    if (t == NULL) {
        return NULL;
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

