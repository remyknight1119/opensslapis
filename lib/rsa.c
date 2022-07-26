/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "osslapis.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "passwd.h"
#include "log.h"

int osslapis_rsa_sign(EVP_PKEY *pkey, const EVP_MD *md, unsigned char *sig,
                    size_t *siglen, const unsigned char *in, size_t inlen,
                    int pad)
{
    EVP_PKEY_CTX *ctx = NULL;
    int ret = -1;

    if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        return -1;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        goto out;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, pad) <= 0) {
        OSSLAPIS_LOG("RSA set padding failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
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

int osslapis_rsa_verify(EVP_PKEY *pkey, const EVP_MD *md,
                    const unsigned char *sig, size_t siglen,
                    const unsigned char *in, size_t inlen,
                    int pad)
{
    EVP_PKEY_CTX *ctx = NULL;
    int ret = -1;

    if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        return -1;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        goto out;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, pad) <= 0) {
        goto out;
    }

    if (EVP_PKEY_CTX_set_signature_md(ctx, md) <= 0) {
        goto out;
    }

    if (EVP_PKEY_verify(ctx, sig, siglen, in, inlen) <= 0) {
        OSSLAPIS_LOG("RSA verify failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    ret = 0;
out:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int osslapis_rsa_encrypt(EVP_PKEY *pkey, unsigned char *out, size_t *outlen,
                    const unsigned char *in, size_t inlen, int pad)
{
    EVP_PKEY_CTX *ctx = NULL;
    int ret = -1;

    if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        return -1;
    }

    if (EVP_PKEY_encrypt_init(ctx) <= 0) {
        OSSLAPIS_LOG("RSA init failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, pad) <= 0) {
        OSSLAPIS_LOG("RSA set padding failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    if (EVP_PKEY_encrypt(ctx, NULL, outlen, in, inlen) <= 0) {
        OSSLAPIS_LOG("RSA get buf len failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    if (EVP_PKEY_encrypt(ctx, out, outlen, in, inlen) <= 0) {
        OSSLAPIS_LOG("RSA encrypt failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    ret = 0;
out:
    EVP_PKEY_CTX_free(ctx);
    return ret;

}

int osslapis_rsa_decrypt(EVP_PKEY *pkey, unsigned char *out, size_t *outlen,
                    const unsigned char *in, size_t inlen, int pad)
{
    EVP_PKEY_CTX *ctx = NULL;
    int ret = -1;

    if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        return -1;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        goto out;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, pad) <= 0) {
        goto out;
    }

    if (EVP_PKEY_decrypt(ctx, NULL, outlen, in, inlen) <= 0) {
        OSSLAPIS_LOG("RSA get buf len failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    if (EVP_PKEY_decrypt(ctx, out, outlen, in, inlen) <= 0) {
        OSSLAPIS_LOG("RSA decrypt failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    ret = 0;
out:
    EVP_PKEY_CTX_free(ctx);
    return ret;

}

