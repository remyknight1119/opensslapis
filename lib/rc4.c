/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "osslapis.h"

#include <string.h>
#include <openssl/evp.h>

#include "evp.h"
#include "log.h"
#include "debug.h"

int osslapis_rc4_encrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl)
{
    return osslapis_cipher_encrypt(EVP_rc4(), key, keylen, iv, ivlen,
                    out, outl, in, inl);
}

int osslapis_rc4_decrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl)
{
    return osslapis_cipher_decrypt(EVP_rc4(), key, keylen, iv, ivlen,
                    out, outl, in, inl);
}

