/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "osslapis.h"

#include <openssl/evp.h>

#include "log.h"

int osslapis_hmac(const EVP_MD *type, const unsigned char *key, int keylen,
                        unsigned char *in, int len, unsigned char *sign,
                        size_t *sign_len)
{
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = -1;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, keylen);
    if (pkey == NULL) {
        goto err;
    }

    if (EVP_DigestSignInit(ctx, NULL, type, NULL, pkey) <= 0) {
        OSSLAPIS_LOG("Digest Sign Init failed: %s\n", OSSLAPIS_ERR_STR());
        goto err;
    }

    if (EVP_DigestSignUpdate(ctx, in, len) <= 0) {
        OSSLAPIS_LOG("Digest Sign Upgrade failed: %s\n", OSSLAPIS_ERR_STR());
        goto err;
    }

    if (EVP_DigestSignFinal(ctx, sign, sign_len) <= 0) {
        OSSLAPIS_LOG("Digest Sign Final failed: %s\n", OSSLAPIS_ERR_STR());
        goto err;
    }

    ret = 0;
err:
    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(ctx);
    return ret;
}
