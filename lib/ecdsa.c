/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "osslapis.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "evp.h"
#include "log.h"

int osslapis_ecdsa_sign(EVP_PKEY *pkey, unsigned char *sig, size_t *siglen,
                    const unsigned char *in, size_t inlen)
{
    return osslapis_pkey_sign(pkey, sig, siglen, in, inlen);
}

int osslapis_ecdsa_verify(EVP_PKEY *pkey, const unsigned char *sig,
                    size_t siglen, const unsigned char *in, size_t inlen)
{
    return osslapis_pkey_verify(pkey, sig, siglen, in, inlen);
}


