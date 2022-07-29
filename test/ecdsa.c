/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "api_test.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

#include "osslapis.h"
#include "debug.h"

static unsigned char ecdsa_buf[2048];

int test_ecdsa_verify(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pub = NULL;
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

    if (osslapis_ecdsa_sign(pkey, ecdsa_buf, &siglen, digest,
                        sizeof(digest)) < 0) {
        printf("ECDSA sign failed\n");
        goto out;
    }

    if (osslapis_ecdsa_verify(pub, ecdsa_buf, siglen, digest,
                        sizeof(digest)) < 0) {
        printf("ECDSA verify failed\n");
        goto out;
    }

    if (ECDSA_verify(0, digest, sizeof(digest), ecdsa_buf, siglen,
                (EC_KEY *)EVP_PKEY_get0_EC_KEY(pub)) <= 0) {
        printf("ECDSA_verify failed\n");
        goto out;
    }

    ret = 0;
out:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pub);
    return ret;
}
