/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "cert.h"
#include "osslapis.h"

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#include "log.h"
#include "passwd.h"
#include "evp.h"

X509 *load_cert(const char *file, char *passwd)
{
    X509 *cert = NULL;
    FILE *fp = NULL;

    fp = fopen(file, "r");
    if (fp == NULL) {
        goto out;
    }

   cert = PEM_read_X509_AUX(fp, NULL, pem_key_passwd_cb, passwd);
    if (cert == NULL) {
        /* DER */
        rewind(fp);
       cert = d2i_X509_fp(fp, NULL);
        if (cert == NULL) {
            OSSLAPIS_LOG("DER cert load failed\n");
        }
    }

out:
    if (fp != NULL) {
        fclose(fp);
    }

    return cert;
}

EVP_PKEY *load_cert_pub_key(const char *file, char *passwd)
{
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;

    cert = load_cert(file, passwd);
    if (cert == NULL) {
        return NULL;
    }

    pkey = X509_get_pubkey(cert);
    X509_free(cert);
    return pkey;
}

X509 *load_pkcs12_cert(const char *file, char *passwd)
{
    FILE *fp = NULL;
    PKCS12 *p12 = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    STACK_OF(X509) *ca = NULL;

    fp = fopen(file, "r");
    if (fp == NULL) {
        goto out;
    }

    p12 = d2i_PKCS12_fp(fp, NULL);
    if (p12 == NULL) {
        OSSLAPIS_LOG("d2i_PKCS12_fp failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }
    
    if (!PKCS12_parse(p12, passwd, &pkey, &cert, &ca)) {
        OSSLAPIS_LOG("PKCS12_parse failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    EVP_PKEY_free(pkey);
    sk_X509_pop_free(ca, X509_free);
out:
    if (p12 != NULL) {
        PKCS12_free(p12);
    }

    if (fp != NULL) {
        fclose(fp);
    }

    return cert;
}

uint32_t get_cert_type(const char *file, char *passwd)
{
    EVP_PKEY *pub = NULL;
    uint32_t type = OAPIS_KEY_TYPE_UNKNOW;

    pub = load_cert_pub_key(file, passwd);
    type = find_pkey_type(pub);
    EVP_PKEY_free(pub);
    return type;
}

int get_cert_pubkey_length(const char *file, char *passwd)
{
    EVP_PKEY *pub = NULL;
    const EC_KEY *ec_key = NULL;
    const EC_GROUP *group = NULL;
    const DSA *dsa = NULL;
    const BIGNUM *p = NULL;
    uint32_t type = OAPIS_KEY_TYPE_UNKNOW;
    int len = 0;

    pub = load_cert_pub_key(file, passwd);
    if (pub == NULL) {
        return 0;
    }

    type = find_pkey_type(pub);
    switch (type) {
        case OAPIS_KEY_TYPE_RSA:
            len = EVP_PKEY_size(pub) << 3;
            break;
        case OAPIS_KEY_TYPE_ECDSA:
            ec_key = EVP_PKEY_get0_EC_KEY(pub);
            if (ec_key == NULL) {
                goto out;
            }
            group = EC_KEY_get0_group(ec_key);
            if (group == NULL) {
                goto out;
            }
            len = EC_GROUP_order_bits(group);
            break;
        case OAPIS_KEY_TYPE_DSA:
            dsa = EVP_PKEY_get0_DSA(pub);
            if (dsa == NULL) {
                goto out;
            }
            p = DSA_get0_p(dsa);
            if (p == NULL) {
                goto out;
            }
            len = BN_num_bits(p);
            break;
        default:
            break;
    }

out:
    EVP_PKEY_free(pub);
    return len;
}

