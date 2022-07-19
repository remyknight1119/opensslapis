/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "opensslapis.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

static int key_passwd_cb(char *buf, int size, int rwflag, void *userdata)
{
    char *passwd = userdata;

    if (passwd == NULL) {
        return 0;
    }

    snprintf(buf, size, "%s", passwd);

    return strlen(passwd);
}

EVP_PKEY *read_private_key(const char *file, char *passwd)
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
    pkey = PEM_read_PrivateKey(fp, NULL, key_passwd_cb, passwd);
    if (pkey == NULL) {
        /* DER */
        rewind(fp);
        pkey = d2i_PrivateKey_fp(fp, NULL);
        printf("DER ");
        if (pkey == NULL) {
            printf("Open %s DER failed\n", file);
        }
    } else {
        printf("PEM ");
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

int match_pkey(const char *file1, const char *file2, char *passwd)
{
    EVP_PKEY *pkey1 = NULL;
    EVP_PKEY *pkey2 = NULL;
    int ret = -1;

    pkey1 = read_private_key(file1, passwd);
    if (pkey1 == NULL) {
        return -1;
    }

    pkey2 = read_private_key(file2, passwd);
    if (pkey1 == NULL) {
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

