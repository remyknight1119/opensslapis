/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "osslapis.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "evp.h"
#include "passwd.h"

static KeyType kPkeyType[] = {
    {
        .id = EVP_PKEY_RSA,
        .type = OAPIS_KEY_TYPE_RSA,
        .get_id = EVP_PKEY_get_id,
    },
    {
        .id = EVP_PKEY_RSA_PSS,
        .type = OAPIS_KEY_TYPE_RSA,
        .get_id = EVP_PKEY_get_id,
    },
    {
        .id = EVP_PKEY_EC,
        .type = OAPIS_KEY_TYPE_ECDSA,
        .get_id = EVP_PKEY_get_base_id,
    },
};

#define EVP_PKEY_TYPE_NUM OAPIS_NELEM(kPkeyType)

EVP_PKEY *load_private_key(const char *file, char *passwd)
{
    EVP_PKEY *pkey = NULL;
    FILE *fp = NULL;

    fp = fopen(file, "r");
    if (fp == NULL) {
        goto out;
    }

    if (passwd == NULL || passwd[0] == 0) {
        passwd = "";
    }
    
    /* PEM */
    pkey = PEM_read_PrivateKey(fp, NULL, pem_key_passwd_cb, passwd);
    if (pkey == NULL) {
        /* DER */
        rewind(fp);
        pkey = d2i_PrivateKey_fp(fp, NULL);
//        printf("DER ");
        if (pkey == NULL) {
            printf("Open %s DER failed\n", file);
        }
    } else {
//        printf("PEM ");
    }

out:
    if (fp != NULL) {
        fclose(fp);
    }

    return pkey;
}

int match_csr_pkey(const char *csr_file, const char *key_file)
{
    return 0;
}

int match_cert_pkey_pair(const char *key, const char *cert,
        char *k_passwd, char *c_passwd)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY *pub = NULL;
    int ret = -1;

    pkey = load_private_key(key, k_passwd);
    if (pkey == NULL) {
        return -1;
    }

    pub = load_cert_pub_key(cert, c_passwd);
    if (pub == NULL) {
        goto out;
    }
    
    if (EVP_PKEY_eq(pkey, pub)) {
        ret = 0;
    }
out:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(pub);
    return ret;
}

int match_pkey(const char *file1, const char *file2, char *passwd)
{
    EVP_PKEY *pkey1 = NULL;
    EVP_PKEY *pkey2 = NULL;
    int ret = -1;

    pkey1 = load_private_key(file1, passwd);
    if (pkey1 == NULL) {
        return -1;
    }

    pkey2 = load_private_key(file2, passwd);
    if (pkey2 == NULL) {
        goto out;
    }
    
    if (EVP_PKEY_eq(pkey1, pkey2)) {
        ret = 0;
    }

out:
    EVP_PKEY_free(pkey2);
    EVP_PKEY_free(pkey1);
    return ret;
}

uint32_t find_pkey_type(EVP_PKEY *pkey)
{
    KeyType *kt = NULL;
    uint32_t type = OAPIS_KEY_TYPE_UNKNOW;
    int i = 0;

    if (pkey == NULL) {
        return type;
    }

    for (i = 0; i < EVP_PKEY_TYPE_NUM; i++) {
        kt = &kPkeyType[i];
        if (kt->get_id(pkey) == kt->id) {
            type = kt->type;
            break;
        }
    }

    return type;
}

uint32_t get_pkey_type(const char *file, char *passwd)
{
    EVP_PKEY *pkey = NULL;
    uint32_t type = OAPIS_KEY_TYPE_UNKNOW;

    pkey = load_private_key(file, passwd);
    type = find_pkey_type(pkey);
    EVP_PKEY_free(pkey);
    return type;
}

int osslapis_digest(const EVP_MD *type, unsigned char *in, int len,
						unsigned char *out)
{
    unsigned int size = 0;

    if (EVP_Digest(in, len, out, &size, type, NULL) == 0) {
        return -1;
    }

	return 0;
}

int osslapis_digest_sha1(unsigned char *in, int len, unsigned char *out)
{
	return osslapis_digest(EVP_sha1(), in, len, out);
}

int osslapis_digest_sha256(unsigned char *in, int len, unsigned char *out)
{
	return osslapis_digest(EVP_sha256(), in, len, out);
}

int osslapis_digest_md5(unsigned char *in, int len, unsigned char *out)
{
	return osslapis_digest(EVP_md5(), in, len, out);
}

