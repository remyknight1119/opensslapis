/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "api_test.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

#include "osslapis.h"
#include "debug.h"

static unsigned char rsa_buf[2048];
static int rsa_key_len[] = {2048, 3072, 4096};

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
    
    //printf("s = %d\n", EVP_PKEY_get_size(pub));
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

int test_rsa_encrypt_decrypt(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pub = NULL;
    RSA *rsa = NULL;
    unsigned char *cipher = NULL;
    unsigned char *plaintext = NULL;
    unsigned char digest[32];
    size_t len = sizeof(digest);
    size_t cipher_len = 0;
    size_t p_len = 0;
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

    cipher = rsa_buf;
    if (osslapis_rsa_encrypt(pkey, cipher, &cipher_len, digest, len, pad) < 0) {
        printf("RSA encrypt failed\n");
        goto out;
    }

    plaintext = &rsa_buf[cipher_len];
    if (osslapis_rsa_decrypt(pkey, plaintext, &p_len, cipher,
                cipher_len, pad) < 0) {
        printf("RSA decrypt failed\n");
        goto out;
    }

    if (p_len != len || memcmp(digest, plaintext, len) != 0) {
        data_print(digest, len);
        data_print(plaintext, p_len);
        goto out;
    }

    memset(plaintext, 0, len);
    rsa = (void *)EVP_PKEY_get0_RSA(pkey);
    p_len = RSA_private_decrypt(RSA_size(rsa), cipher, plaintext, rsa, pad);
    if (p_len != len || memcmp(digest, plaintext, len) != 0) {
        data_print(digest, len);
        data_print(plaintext, p_len);
        goto out;
    }


    ret = 0;
out:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pub);
    return ret;
}

int test_rsa_key_gen(void)
{
    EVP_PKEY *pkey = NULL;
    unsigned char *buf = NULL;
    int klen = 0;
    int i = 0;
    int ret = 0;
    int len = 0;

    for (i = 0; i < sizeof(rsa_key_len)/sizeof(rsa_key_len[0]); i++) {
        klen = rsa_key_len[i];
        pkey = osslapis_rsa_key_gen(klen);
        if (pkey == NULL) {
            printf("Gen RSA Key %d bits failed\n", klen);
            return -1;
        }
        
        ret = RSA_check_key(EVP_PKEY_get0_RSA(pkey));
        if (ret == 0) {
            printf("RSA Key %d bits check failed\n", klen);
            EVP_PKEY_free(pkey);
            return -1;
        }
        
        len = i2d_PrivateKey(pkey, &buf);
        EVP_PKEY_free(pkey);
        if (len <= 0 || buf == NULL) {
            printf("i2d Private Key for RSA Key %d bits failed\n", klen);
            return -1;
        }

        pkey = d2i_PrivateKey(EVP_PKEY_RSA, NULL, (void *)&buf, len);
        EVP_PKEY_free(pkey);
        if (pkey == NULL) {
            printf("d2i Private Key for RSA Key %d bits failed\n", klen);
            return -1;
        }
        buf = NULL;
    }

    return 0;
}

