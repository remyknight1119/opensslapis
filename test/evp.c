/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "api_test.h"
#include "evp.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/des.h>

#include "osslapis.h"

static unsigned char kData[] =
    "\x00\xA5\xDA\xFC\x53\x41\xFA\xF2\x89\xC4\xB9\x88\xDB\x30\xC1\xCD"
    "\xF8\x3F\x31\x25\x1E\x06\x68\xB4\x27\x84\x81\x38\x01\x57\x96\x41"
    "\xB2\x94\x10\xB3\xC7\x99\x8D\x6B\xC4\x65\x74\x5E\x5C\x39\x26\x69"
    "\xD6\x87\x0D\xA2\xC0\x82\xA9\x39\xE3\x7F\xDC\xB8\x2E\xC9\x3E\xDA"
    "\xC9\x7F\xF3\xAD\x59\x50\xAC\xCF\xBC\x11\x1C\x76\xF1\xA9\x52\x94"
    "\x44\xE5\x6A\xAF\x68\xC5\x6C\x09\x2C\xD3\x8D\xC3\xBE\xF5\xD2\x0A"
    "\x93\x99\x26\xED\x4F\x74\xA1\x3E\xDD\xFB\xE1\xA1\xCE\xCC\x48\x94"
    "\xAF\x94\x28\xC2\xB7\xB8\x88\x3F\xE4\x46\x3A\x4B\xC8\x5B\x1C\xB3";

static OapisEvpDigest kTestDigest[] = {
    {
        .name = "MD5",
        .osslapis_digest = osslapis_digest_md5,
        .origin_digest = MD5,
        .len = MD5_DIGEST_LENGTH,
    },
    {
        .name = "SHA1",
        .osslapis_digest = osslapis_digest_sha1,
        .origin_digest = SHA1,
        .len = SHA_DIGEST_LENGTH,
    },
    {
        .name = "SHA256",
        .osslapis_digest = osslapis_digest_sha256,
        .origin_digest = SHA256,
        .len = SHA256_DIGEST_LENGTH,
    },
};

#define TEST_DIGEST_NUM OAPIS_NELEM(kTestDigest)

static int test_load_key_file(const char *file, char *passwd)
{
    EVP_PKEY *pkey = NULL;

    pkey = load_private_key(file, passwd);
    if (pkey == NULL) {
        return -1;
    }

    EVP_PKEY_free(pkey);
    return 0;
}


int test_load_key(void)
{
    if (test_load_key_file(oapis_key, NULL) < 0) {
        printf("Load key from pem file failed\n");
        return -1;
    }

    if (test_load_key_file(oapis_key_der, NULL) < 0) {
        printf("Load key from der file failed\n");
        return -1;
    }

    if (test_load_key_file(oapis_key_enc, oapis_key_pwd) < 0) {
        printf("Load encrypted key failed\n");
        return -1;
    }

    return 0;
}


int test_match_csr_key(void)
{
    return 0;
}

int test_match_pkey(void)
{
    if (match_pkey(oapis_key, oapis_key, NULL) < 0) {
        printf("Match key failed");
        return -1;
    }

    if (match_cert_pkey_pair(oapis_key, oapis_cert, NULL, NULL) < 0) {
        printf("Match key and cert failed");
        return -1;
    }

    if (match_cert_pkey_pair(oapis_key_enc, oapis_key_enc,
                oapis_key_pwd, NULL) < 0) {
        printf("Match enc key and cert failed");
        return -1;
    }

    return 0;
}

int test_match_pkey_type(void)
{
    if (get_pkey_type(oapis_key, NULL) != oapis_cert_type) {
        printf("Match key type failed\n");
        return -1;
    }

    if (get_pkey_type(oapis_key_enc, oapis_key_pwd) != oapis_cert_type) {
        printf("Match key type failed\n");
        return -1;
    }

    return 0;
}

void data_print(unsigned char *d, int len)
{
    int i = 0;

    for (i = 0; i < len; i++) {
        fprintf(stdout, "%02X", d[i]);
    }

    fprintf(stdout, "\nlen = %d\n", len);
}

int test_digests(void)
{
    OapisEvpDigest *d = NULL;
    unsigned char *m = NULL;
    unsigned char *r = NULL;
    int i = 0;
    int ret = -1;

    for (i = 0; i < TEST_DIGEST_NUM; i++) {
        d = &kTestDigest[i];
        m = malloc(d->len);
        if (m == NULL) {
            return -1;
        }
        if (d->osslapis_digest(kData, sizeof(kData) - 1, m) < 0) {
            printf("Osslapis digest (%s) failed\n", d->name);
            goto out;
        }

        r = d->origin_digest(kData, sizeof(kData) - 1, NULL);
        if (r == NULL) {
            printf("Origin digest (%s) failed\n", d->name);
            goto out;
        }

        if (memcmp(m, r, d->len) != 0) {
            data_print(m, d->len);
            data_print(r, d->len);
            goto out;
        }

        free(m);
        m = NULL;
    }

    ret = 0;
out:
    if (m != NULL) {
        free(m);
    }

    return ret;
}

int test_3DES_encrypt_decrypt(void)
{
    unsigned char key[24];
    unsigned char cipher1[sizeof(kData)] = {};
    unsigned char cipher2[sizeof(kData)] = {};
    unsigned char plaintext[sizeof(kData)] = {};
    DES_cblock *des_key = (DES_cblock *)key;
    DES_key_schedule ksch[3];
    DES_cblock iv;
    unsigned char iv_tmp[sizeof(iv)];
    int len = 0;

    RAND_bytes(key, sizeof(key));
    RAND_bytes((void *)&iv, sizeof(iv));

    DES_set_key(&des_key[0], &ksch[0]);
    DES_set_key(&des_key[1], &ksch[1]);
    DES_set_key(&des_key[2], &ksch[2]);

    memcpy(iv_tmp, &iv, sizeof(iv));
    len =  sizeof(kData) - 1;
    if (osslapis_3DES_encrypt(key, (void *)&iv, cipher1, kData, len) < 0) {
        return -1;
    }

    DES_ede3_cbc_encrypt(kData, cipher2, len, &ksch[0], &ksch[1], &ksch[2], &iv,
            DES_ENCRYPT);
    if (memcmp(cipher1, cipher2, len) != 0) {
        data_print(cipher1, len);
        data_print(cipher2, len);
        return -1;
    }

    DES_set_key(&des_key[0], &ksch[0]);
    DES_set_key(&des_key[1], &ksch[1]);
    DES_set_key(&des_key[2], &ksch[2]);

    memcpy(&iv, iv_tmp, sizeof(iv));
    DES_ede3_cbc_encrypt(cipher2, plaintext, len, &ksch[0], &ksch[1], &ksch[2], &iv,
            DES_DECRYPT);

    if (memcmp(plaintext, kData, len) != 0) {
        data_print(kData, len);
        data_print(plaintext, len);
        return -1;
    }

    memset(plaintext, 0, sizeof(plaintext));
#if 0
    data_print((void *)iv_tmp, sizeof(iv));
    if (osslapis_3DES_decrypt(key, iv_tmp, plaintext, cipher1, len) < 0) {
        data_print(kData, len);
        data_print(plaintext, len);
        return -1;
    }

    if (memcmp(plaintext, kData, len) != 0) {
        data_print(kData, len);
        data_print(plaintext, len);
        return -1;
    }
#endif

    return 0;
}

int test_load_pub_key(void)
{
    EVP_PKEY *pkey = NULL;
    uint32_t type = 0;

    pkey = load_pub_key(oapis_key_pub, NULL);
    if (pkey == NULL) {
        return -1;
    }

    type = find_pkey_type(pkey);
    EVP_PKEY_free(pkey);
    if (type != oapis_cert_type) {
        printf("type error\n");
        return -1;
    }

    return 0;
}

