/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "api_test.h"

#include <openssl/evp.h>
#include <openssl/x509.h>

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

int test_load_pkcs12_cert(void)
{
    X509 *x = NULL;

    x = load_pkcs12_cert(oapis_pkcs, oapis_pkcs_pwd);
    if (x == NULL) {
        return -1;
    }

    X509_free(x);
    return 0;
}
