#ifndef OSSLAPIS_INCLUDE_OPENSSLAPIS_H_
#define OSSLAPIS_INCLUDE_OPENSSLAPIS_H_

#include <openssl/types.h>

#define OAPIS_NELEM(array)    (sizeof(array)/sizeof(array[0]))

enum {
    OAPIS_KEY_TYPE_UNKNOW,
    OAPIS_KEY_TYPE_RSA,
    OAPIS_KEY_TYPE_ECDSA,
    OAPIS_KEY_TYPE_MAX,
};

EVP_PKEY *load_private_key(const char *file, char *passwd);
EVP_PKEY *load_cert_pub_key(const char *file, char *passwd);
int match_csr_key(const char *csr_file, const char *key_file);
int match_cert_pkey_pair(const char *key, const char *cert,
        char *k_passwd, char *c_passwd);
int match_pkey(const char *file1, const char *file2, char *passwd);
uint32_t get_pkey_type(const char *file, char *passwd);
uint32_t get_cert_type(const char *file, char *passwd);
int get_cert_pubkey_length(const char *file, char *passwd);

#endif
