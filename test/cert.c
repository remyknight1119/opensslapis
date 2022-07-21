/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "api_test.h"

#include <openssl/evp.h>

#include "osslapis.h"

int test_match_cert_type(void)
{
    if (get_cert_type(oapis_cert, NULL) != oapis_cert_type) {
        printf("Match cert type failed\n");
        return -1;
    }

    return 0;
}

int test_cert_pubkey_length(void)
{
    int len = 0;

    len = get_cert_pubkey_length(oapis_cert, NULL);
    if (len != oapis_key_bits) {
        return -1;
    }

    return 0;
}
