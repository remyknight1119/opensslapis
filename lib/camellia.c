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

static EvpPkeyCipher kCamelliaCbcType[] = {
    {
        .key_size = 128,
        .get_cipher = EVP_camellia_128_cbc,
    },
    {
        .key_size = 192,
        .get_cipher = EVP_camellia_192_cbc,
    },
    {
        .key_size = 256,
        .get_cipher = EVP_camellia_256_cbc,
    },
};

#define CAMELLIA_CBC_TYPE_NUM OAPIS_NELEM(kCamelliaCbcType)

static const EVP_CIPHER *get_camellia_cbc_evp(int key_size)
{
    EvpPkeyCipher *t = NULL;

    t = find_evp_pkey_type(key_size*8, kCamelliaCbcType, CAMELLIA_CBC_TYPE_NUM);
    if (t == NULL) {
        return NULL;
    }

    return t->get_cipher();
}

int osslapis_camellia_cbc_encrypt(unsigned char *k, int klen,
                        unsigned char *iv, int ivlen,
                        unsigned char *out, int *outl,
                        const unsigned char *in, int inl)
{
    const EVP_CIPHER *ci = get_camellia_cbc_evp(klen);

    return osslapis_cipher_encrypt(ci, k, klen, iv, ivlen, out, outl, in, inl);
}

int osslapis_camellia_cbc_decrypt(unsigned char *k, int klen,
                        unsigned char *iv, int ivlen,
                        unsigned char *out, int *outl,
                        const unsigned char *in, int inl)
{
    const EVP_CIPHER *ci = get_camellia_cbc_evp(klen);

    return osslapis_cipher_decrypt(ci, k, klen, iv, ivlen, out, outl, in, inl);
}

