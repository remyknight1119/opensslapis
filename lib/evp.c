/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "osslapis.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "evp.h"
#include "passwd.h"
#include "log.h"
#include "debug.h"

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
    {
        .id = EVP_PKEY_DSA,
        .type = OAPIS_KEY_TYPE_DSA,
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

EVP_PKEY *load_pub_key(const char *file, char *passwd)
{
    EVP_PKEY *pkey = NULL;
    FILE *fp = NULL;

    fp = fopen(file, "r");
    if (fp == NULL) {
        printf("open file failed\n");
        return NULL;
    }

    pkey = PEM_read_PUBKEY(fp, NULL, pem_key_passwd_cb, passwd);
    fclose(fp);
    return pkey;
}
 
EVP_PKEY *load_pub_key_from_mem(const char *key, char *passwd)
{
    EVP_PKEY *pub = NULL;
    BIO *b = NULL;

    b = BIO_new(BIO_s_mem());
    if (b == NULL) {
        return NULL;
    }

    BIO_write(b, key, strlen(key));
    pub = PEM_read_bio_PUBKEY_ex(b, NULL, pem_key_passwd_cb, passwd, 
                                    NULL, NULL);
    BIO_free(b);
    return pub;
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
    int ret;
#if 0
    EVP_MD_CTX *ctx = NULL;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    ret = EVP_DigestInit_ex(ctx, type, NULL);
    if (ret == 0) {
        OSSLAPIS_LOG("Digest Init failed\n");
        goto out;
    }

    ret = EVP_DigestUpdate(ctx, in, len);
    if (ret == 0) {
        OSSLAPIS_LOG("Digest Update failed\n");
        goto out;
    }

    ret = EVP_DigestFinal_ex(ctx, out, &size);
out:
    EVP_MD_CTX_free(ctx);

#endif

    ret = EVP_Digest(in, len, out, &size, type, NULL);
    if (ret == 0) {
        OSSLAPIS_LOG("Digest error: %s\n", OSSLAPIS_ERR_STR());
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

static int osslapis_do_cipher(const EVP_CIPHER *cipher, unsigned char *key,
                        int keylen, unsigned char *iv, int ivlen,
                        unsigned char *out, int *outl, const unsigned char *in,
                        int inl, int enc)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int key_len = 0;
    int iv_len = 0;
    int ret = -1;
 
    if (cipher == NULL) {
        return -1;
    }

    key_len = EVP_CIPHER_key_length(cipher);
    if (keylen < key_len) {
        OSSLAPIS_LOG("Key len(%d) error(%d)\n", keylen, key_len);
        return -1;
    }

    iv_len = EVP_CIPHER_iv_length(cipher);
    if (ivlen < iv_len) {
        OSSLAPIS_LOG("IV len(%d) error(%d)\n", ivlen, iv_len);
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    if (EVP_CipherInit(ctx, cipher, key, iv, enc) == 0) {
        OSSLAPIS_LOG("EVP Cipher Init failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    if (EVP_CipherUpdate(ctx, out, outl, in, inl) == 0) {
        OSSLAPIS_LOG("EVP Cipher Update failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    if (EVP_CipherFinal(ctx, &out[*outl], &len) <= 0) {
        OSSLAPIS_LOG("EVP Cipher Final failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    *outl += len;
    ret = 0;
out:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int osslapis_cipher_encrypt(const EVP_CIPHER *cipher, unsigned char *key,
                        int keylen, unsigned char *iv, int ivlen,
                        unsigned char *out, int *outl, const unsigned char *in,
                        int inl)
{
    return osslapis_do_cipher(cipher, key, keylen, iv, ivlen, out, outl,
                                in, inl, 1);
}

int osslapis_cipher_decrypt(const EVP_CIPHER *cipher, unsigned char *key,
                        int keylen, unsigned char *iv, int ivlen,
                        unsigned char *out, int *outl, const unsigned char *in,
                        int inl)
{
    return osslapis_do_cipher(cipher, key, keylen, iv, ivlen, out, outl,
                                in, inl, 0);
}

int osslapis_pkey_sign(EVP_PKEY *pkey, unsigned char *sig, size_t *siglen,
                    const unsigned char *in, size_t inlen)
{
    EVP_PKEY_CTX *ctx = NULL;
    int ret = -1;

    if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        return -1;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        goto out;
    }

    if (EVP_PKEY_sign(ctx, NULL, siglen, in, inlen) <= 0) {
        OSSLAPIS_LOG("Get sign len failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    if (EVP_PKEY_sign(ctx, sig, siglen, in, inlen) <= 0) {
        OSSLAPIS_LOG("sign failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    ret = 0;
out:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

int osslapis_pkey_verify(EVP_PKEY *pkey, const unsigned char *sig,
                    size_t siglen, const unsigned char *in, size_t inlen)
{
    EVP_PKEY_CTX *ctx = NULL;
    int ret = -1;

    if ((ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL) {
        return -1;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        OSSLAPIS_LOG("verify init failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    if (EVP_PKEY_verify(ctx, sig, siglen, in, inlen) <= 0) {
        OSSLAPIS_LOG("verify failed: %s\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    ret = 0;
out:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

EvpPkeyCipher *find_evp_pkey_type(int key_size, EvpPkeyCipher *t, size_t num)
{
    int i = 0;

    for (i = 0; i < num; i++) {
        if (t[i].key_size == key_size) {
            return &t[i];
        }
    }

    return NULL;
}


