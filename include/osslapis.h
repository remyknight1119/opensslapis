#ifndef OSSLAPIS_INCLUDE_OSSLAPIS_H_
#define OSSLAPIS_INCLUDE_OSSLAPIS_H_

#include <stddef.h>
#include <openssl/types.h>

#define OAPIS_NELEM(array)    (sizeof(array)/sizeof(array[0]))

enum {
    OAPIS_KEY_TYPE_UNKNOW,
    OAPIS_KEY_TYPE_RSA,
    OAPIS_KEY_TYPE_ECDSA,
    OAPIS_KEY_TYPE_ANY,
    OAPIS_KEY_TYPE_MAX,
};

EVP_PKEY *load_private_key(const char *file, char *passwd);
EVP_PKEY *load_cert_pub_key(const char *file, char *passwd);
EVP_PKEY *load_pub_key(const char *file, char *passwd);
EVP_PKEY *load_pub_key_from_mem(const char *key, char *passwd);
uint32_t find_pkey_type(EVP_PKEY *pkey);
int match_csr_key(const char *csr_file, const char *key_file);
int match_cert_pkey_pair(const char *key, const char *cert,
        char *k_passwd, char *c_passwd);
int match_pkey(const char *file1, const char *file2, char *passwd);
uint32_t get_pkey_type(const char *file, char *passwd);
uint32_t get_cert_type(const char *file, char *passwd);
int get_cert_pubkey_length(const char *file, char *passwd);
int osslapis_digest_sha1(unsigned char *in, int len, unsigned char *out);
int osslapis_digest_sha256(unsigned char *in, int len, unsigned char *out);
int osslapis_digest_md5(unsigned char *in, int len, unsigned char *out);
int osslapis_3DES_encrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_3DES_decrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_aes_encrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_aes_decrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_rsa_sign(EVP_PKEY *pkey, const EVP_MD *md, unsigned char *sig,
                    size_t *siglen, const unsigned char *in, size_t inlen,
                    int pad);
int osslapis_rsa_verify(EVP_PKEY *pkey, const EVP_MD *md,
                    const unsigned char *sig, size_t siglen,
                    const unsigned char *in, size_t inlen,
                    int pad);

#endif
