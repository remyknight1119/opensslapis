/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "api_test.h"
#include "evp.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#include "osslapis.h"
#include "debug.h"

#define TEST_HMAC_SIGN_BUF_LEN  128

int test_hmac(void)
{
    const EVP_MD *md = EVP_sha256();
    HMAC_CTX *hmac = NULL;
    unsigned char key[32] = {};
    unsigned char data[256] = {};
    static unsigned char sign1[TEST_HMAC_SIGN_BUF_LEN] = {};
    static unsigned char sign2[TEST_HMAC_SIGN_BUF_LEN] = {};
    size_t klen = sizeof(key);
    size_t dlen = sizeof(data);
    size_t md_len = sizeof(sign1);

    RAND_bytes(key, sizeof(key));
    RAND_bytes(data, sizeof(data));

    if (osslapis_hmac(md, key, klen, data, dlen, sign1, &md_len) < 0) {
        return -1;
    }

    hmac = HMAC_CTX_new();
    if (hmac == NULL) {
        return -1;
    }

    HMAC_Init_ex(hmac, key, klen, md, NULL);
    HMAC_Update(hmac, data, dlen);
    HMAC_Final(hmac, sign2, 0);
    HMAC_CTX_free(hmac);

    if (memcmp(sign1, sign2, md_len) != 0) {
        data_print(sign1, md_len);
        data_print(sign2, md_len);
        return -1;
    }

    return 0;
}
