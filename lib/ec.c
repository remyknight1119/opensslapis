/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "osslapis.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ec.h>

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

EVP_PKEY *osslapis_gen_ec_key(const char *curve)
{
    return EVP_EC_gen(curve);
}

EVP_PKEY *osslapis_gen_ec_key_by_nid(int nid)
{
    const char *name = NULL;

    name = EC_curve_nid2nist(nid);
    if (name == NULL) {
        OSSLAPIS_LOG("Find name for %d failed\n", nid);
        return NULL;
    }

    return osslapis_gen_ec_key(name);
}

