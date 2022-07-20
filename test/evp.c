/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "api_test.h"

#include <openssl/evp.h>

#include "opensslapis.h"

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

