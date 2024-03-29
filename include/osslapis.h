#ifndef OSSLAPIS_INCLUDE_OSSLAPIS_H_
#define OSSLAPIS_INCLUDE_OSSLAPIS_H_

#include <stddef.h>
#include <openssl/types.h>

#define OAPIS_NELEM(array)    (sizeof(array)/sizeof(array[0]))

enum {
    OAPIS_KEY_TYPE_UNKNOW,
    OAPIS_KEY_TYPE_RSA,
    OAPIS_KEY_TYPE_ECDSA,
    OAPIS_KEY_TYPE_DSA,
    OAPIS_KEY_TYPE_ANY,
    OAPIS_KEY_TYPE_MAX,
};

EVP_PKEY *load_private_key(const char *file, char *passwd);
EVP_PKEY *load_cert_pub_key(const char *file, char *passwd);
EVP_PKEY *load_pub_key(const char *file, char *passwd);
EVP_PKEY *load_pub_key_from_mem(const char *key, char *passwd);
EVP_PKEY *osslapis_ec_key_gen(const char *curve);
EVP_PKEY *osslapis_ec_key_gen_by_nid(int nid);
EVP_PKEY *osslapis_rsa_key_gen(int bits);
X509 *load_pkcs12_cert(const char *file, char *passwd);
uint32_t find_pkey_type(EVP_PKEY *pkey);
int match_csr_key(const char *csr_file, const char *key_file);
int match_cert_pkey_pair(const char *key, const char *cert,
        char *k_passwd, char *c_passwd);
int match_pkey(const char *file1, const char *file2, char *passwd);
uint32_t get_pkey_type(const char *file, char *passwd);
uint32_t get_cert_type(const char *file, char *passwd);
int get_cert_pubkey_length(const char *file, char *passwd);
int osslapis_digest_sha1(unsigned char *in, int len, unsigned char *out);
int osslapis_digest_sha224(unsigned char *in, int len, unsigned char *out);
int osslapis_digest_sha256(unsigned char *in, int len, unsigned char *out);
int osslapis_digest_sha384(unsigned char *in, int len, unsigned char *out);
int osslapis_digest_sha512(unsigned char *in, int len, unsigned char *out);
int osslapis_digest_md5(unsigned char *in, int len, unsigned char *out);
int osslapis_digest_md4(unsigned char *in, int len, unsigned char *out);
int osslapis_hmac(const EVP_MD *type, const unsigned char *key, int keylen,
                        unsigned char *in, int len, unsigned char *sign,
                        size_t *sign_len);
int osslapis_3des_encrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_3des_decrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_des_cbc_encrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_des_cbc_decrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_aes_cbc_encrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_aes_cbc_decrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_aes_ctr_encrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_aes_ctr_decrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_aes_cfb_encrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_aes_cfb_decrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_aes_ccm_encrypt(unsigned char *plaintext, int plaintext_len,
                        unsigned char *key, unsigned char *nonce,
                        unsigned char *aad, int aad_len,
                        unsigned char *ciphertext, unsigned char *tag);
int osslapis_aes_ccm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                        unsigned char *key, unsigned char *nonce,
                        unsigned char *aad, int aad_len,
                        unsigned char *tag, unsigned char *plaintext);
int osslapis_aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                        unsigned char *key, unsigned char *nonce,
                        unsigned char *ciphertext, unsigned char *tag);
int osslapis_aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                        unsigned char *key, unsigned char *nonce,
                        unsigned char *plaintext, unsigned char *tag);
int osslapis_rsa_sign(EVP_PKEY *pkey, const EVP_MD *md, unsigned char *sig,
                    size_t *siglen, const unsigned char *in, size_t inlen,
                    int pad);
int osslapis_rsa_verify(EVP_PKEY *pkey, const EVP_MD *md,
                    const unsigned char *sig, size_t siglen,
                    const unsigned char *in, size_t inlen,
                    int pad);
int osslapis_rsa_encrypt(EVP_PKEY *pkey, unsigned char *out, size_t *outlen,
                    const unsigned char *in, size_t inlen, int pad);
int osslapis_rsa_decrypt(EVP_PKEY *pkey, unsigned char *out, size_t *outlen,
                    const unsigned char *in, size_t inlen, int pad);
int osslapis_dsa_sign(EVP_PKEY *pkey, unsigned char *sig, size_t *siglen,
                    const unsigned char *in, size_t inlen);
int osslapis_dsa_verify(EVP_PKEY *pkey, const unsigned char *sig, size_t siglen,
                    const unsigned char *in, size_t inlen);
int osslapis_ecdsa_sign(EVP_PKEY *pkey, unsigned char *sig, size_t *siglen,
                    const unsigned char *in, size_t inlen);
int osslapis_ecdsa_verify(EVP_PKEY *pkey, const unsigned char *sig,
                size_t siglen, const unsigned char *in, size_t inlen);
int osslapis_camellia_cbc_encrypt(unsigned char *k, int klen,
                        unsigned char *iv, int ivlen,
                        unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_camellia_cbc_decrypt(unsigned char *k, int klen,
                        unsigned char *iv, int ivlen,
                        unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_rc4_encrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_rc4_decrypt(unsigned char *key, int keylen, unsigned char *iv,
                        int ivlen, unsigned char *out, int *outl,
                        const unsigned char *in, int inl);
int osslapis_providers_load(const char *legacy_lib);
int osslapis_chacha20_poly1305_encrypt(unsigned char *plaintext,
                        int plaintext_len, unsigned char *key,
                        unsigned char *nonce, unsigned char *ciphertext,
                        unsigned char *tag);
int osslapis_chacha20_poly1305_decrypt(unsigned char *ciphertext,
                        int ciphertext_len, unsigned char *key,
                        unsigned char *nonce, unsigned char *tag,
                        unsigned char *plaintext);
int osslapis_chacha20_encrypt(unsigned char *plaintext, int plaintext_len,
                      unsigned char *key, unsigned char *nonce,
                      unsigned char *ciphertext);
int osslapis_chacha20_decrypt(unsigned char *ciphertext, int ciphertext_len,
                      unsigned char *key, unsigned char *nonce,
                      unsigned char *plaintext);

#endif
