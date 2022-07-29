/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "api_test.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/dsa.h>
#include <openssl/rand.h>

#include "osslapis.h"
#include "debug.h"

static unsigned char dsa_buf[2048];

int test_dsa_verify(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pub = NULL;
    const EVP_MD *md = EVP_sha256();
    unsigned char digest[32];
    size_t siglen = 0;
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

    if (osslapis_dsa_sign(pkey, md, dsa_buf, &siglen, digest,
                sizeof(digest)) < 0) {
        printf("DSA sign failed\n");
        goto out;
    }

    if (osslapis_dsa_verify(pub, md, dsa_buf, siglen, digest,
                sizeof(digest)) < 0) {
        printf("DSA verify failed\n");
        goto out;
    }

    if (DSA_verify(0, digest, sizeof(digest), dsa_buf, siglen,
                (DSA *)EVP_PKEY_get0_DSA(pub)) <= 0) {
        printf("DSA_verify failed\n");
        goto out;
    }

    ret = 0;
out:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pub);
    return ret;
}
