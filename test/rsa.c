/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "api_test.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#include "osslapis.h"

static unsigned char rsa_buf[2048];

int test_rsa_verify(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pub = NULL;
    const EVP_MD *md = EVP_sha256();
    unsigned char digest[32];
    size_t siglen = 0;
    int pad = RSA_PKCS1_PADDING;
    int ret = -1;

    pkey = load_private_key(oapis_key, NULL);
    if (pkey == NULL) {
        return -1;
    }

    pub = load_cert_pub_key(oapis_cert, NULL);
    if (pub == NULL) {
        goto out;
    }
    
    RAND_bytes(digest, sizeof(digest));

    if (osslapis_rsa_sign(pkey, md, rsa_buf, &siglen, digest,
                sizeof(digest), pad) < 0) {
        printf("RSA sign failed\n");
        goto out;
    }

    if (osslapis_rsa_verify(pub, md, rsa_buf, siglen, digest,
                sizeof(digest), pad) < 0) {
        printf("RSA verify failed\n");
        goto out;
    }

    if (RSA_verify(EVP_MD_get_type(md), digest, sizeof(digest), rsa_buf,
                siglen, (void *)EVP_PKEY_get0_RSA(pub)) == 0) {
        printf("RSA_verify failed\n");
        goto out;
    }

    ret = 0;
out:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pub);
    return ret;
}

