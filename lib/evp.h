#ifndef OSSLAPIS_LIB_EVP_H_
#define OSSLAPIS_LIB_EVP_H_

typedef struct {
    int id;
    uint32_t type;
    int (*get_id)(const EVP_PKEY *pkey);
} KeyType;

int osslapis_cipher_encrypt(const EVP_CIPHER *cipher, unsigned char *key,
                        int keylen, unsigned char *iv, int ivlen,
                        unsigned char *out, int *outl, const unsigned char *in,
                        int inl);
int osslapis_cipher_decrypt(const EVP_CIPHER *cipher, unsigned char *key,
                        int keylen, unsigned char *iv, int ivlen,
                        unsigned char *out, int *outl, const unsigned char *in,
                        int inl);

#endif
