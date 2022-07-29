/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "osslapis.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "passwd.h"
#include "log.h"

int osslapis_dsa_sign(EVP_PKEY *pkey, unsigned char *sig, size_t *siglen,
                    const unsigned char *in, size_t inlen)
{
    EVP_PKEY_CTX *ctx = NULL;
    int ret = -1;

    if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        return -1;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        goto out;
    }

    if (EVP_PKEY_sign(ctx, NULL, siglen, in, inlen) <= 0) {
        OSSLAPIS_LOG("Get RSA sign len failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    if (EVP_PKEY_sign(ctx, sig, siglen, in, inlen) <= 0) {
        OSSLAPIS_LOG("RSA sign failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    ret = 0;
out:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int osslapis_dsa_verify(EVP_PKEY *pkey, const unsigned char *sig, size_t siglen,
                    const unsigned char *in, size_t inlen)
{
    EVP_PKEY_CTX *ctx = NULL;
    int ret = -1;

    if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        return -1;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        goto out;
    }

    if (EVP_PKEY_verify(ctx, sig, siglen, in, inlen) <= 0) {
        OSSLAPIS_LOG("DSA verify failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    ret = 0;
out:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}


