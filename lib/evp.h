#ifndef OSSLAPIS_LIB_EVP_H_
#define OSSLAPIS_LIB_EVP_H_

typedef struct {
    int id;
    uint32_t type;
    int (*get_id)(const EVP_PKEY *pkey);
} KeyType;

typedef struct {
    int key_size;
    const char *name;
    const EVP_CIPHER *(*get_cipher)(void);
} EvpPkeyCipher;

EvpPkeyCipher *find_evp_pkey_type(int key_size, EvpPkeyCipher *t, size_t num);
int osslapis_cipher_encrypt(const EVP_CIPHER *cipher, unsigned char *key,
                        int keylen, unsigned char *iv, int ivlen,
                        unsigned char *out, int *outl, const unsigned char *in,
                        int inl);
int osslapis_cipher_decrypt(const EVP_CIPHER *cipher, unsigned char *key,
                        int keylen, unsigned char *iv, int ivlen,
                        unsigned char *out, int *outl, const unsigned char *in,
                        int inl);
int osslapis_pkey_sign(EVP_PKEY *pkey, unsigned char *sig, size_t *siglen,
                    const unsigned char *in, size_t inlen);
int osslapis_pkey_verify(EVP_PKEY *pkey, const unsigned char *sig,
                    size_t siglen, const unsigned char *in, size_t inlen);

#endif
