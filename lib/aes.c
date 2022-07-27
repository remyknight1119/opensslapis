/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "aes.h"
#include "osslapis.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "evp.h"
#include "passwd.h"
#include "log.h"
#include "debug.h"

static AesType kAesCbcType[] = {
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

static AesType *find_aes_type(int key_size, AesType *t, size_t num)
{
    int i = 0;

    for (i = 0; i < num; i++) {
        if (t[i].key_size == key_size) {
            return &t[i];
        }
    }

    return NULL;
}

static const EVP_CIPHER *get_aes_cbc_evp(int key_size)
{
    AesType *t = NULL;

    t = find_aes_type(key_size*8, kAesCbcType, AES_CBC_TYPE_NUM);
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

