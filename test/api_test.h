#ifndef OSSLAPIS_TEST_API_TEST_H
#define OSSLAPIS_TEST_API_TEST_H

#include <stddef.h>
#include <stdint.h>

#define OSSLAPIS_RSA_KEY_LEN    4096

typedef struct {
    int (*api)(void);
    uint32_t cert_type;
    const char *msg;
} OapisApi;

static inline uint8_t char2hex(char c)
{
	if ((c >= '0') && (c <= '9')) {
		return c - 0x30;
	}

	if ((c >= 'A') && (c <= 'F')) {
		return c - 0x37;
	}

	if ((c >= 'a') && (c <= 'f')) {
		return c - 'a' + 10;
	}

	return 0;
}

static inline void str2hex(uint8_t *dest, char *src, size_t len)
{
	char h1 = 0;
	char h2 = 0;
	uint8_t s1 = 0;
	uint8_t s2 = 0;
	size_t i = 0;

	for (i = 0; i < len; i++) {
		h1 = src[2*i];
		h2 = src[2*i + 1];

		s1 = char2hex(h1);
		s2 = char2hex(h2);

		dest[i] = (s1 << 4) + s2;
	}
}

extern int oapis_cert_type;
extern int oapis_key_bits;
extern char *oapis_cert;
extern char *oapis_key;
extern char *oapis_key_enc;
extern char *oapis_key_pwd;
extern char *oapis_key_der;
extern char *oapis_key_pub;
extern char *oapis_csr;
extern char *oapis_ca;
extern char *oapis_pkcs;
extern char *oapis_pkcs_pwd;

int test_match_csr_key(void);
int test_match_pkey(void);
int test_load_key(void);
int test_match_pkey_type(void);
int test_match_cert_type(void);
int test_cert_pubkey_length(void);
int test_digests(void);
int test_3des_encrypt_decrypt(void);
int test_des_cbc_encrypt_decrypt(void);
int test_rsa_verify(void);
int test_load_pub_key_from_file(void);
int test_load_pub_key_from_mem(void);
int test_aes_cbc_encrypt_decrypt(void);
int test_aes_ctr_encrypt_decrypt(void);
int test_aes_cfb_encrypt_decrypt(void);
int test_aes_ccm_encrypt_decrypt(void);
int test_aes_gcm_encrypt_decrypt(void);
int test_rsa_encrypt_decrypt(void);
int test_hmac(void);
int test_dsa_verify(void);
int test_ecdsa_verify(void);
int test_camellia_cbc_encrypt_decrypt(void);
int test_ec_key_gen(void);
int test_rsa_key_gen(void);
int test_rc4_encrypt_decrypt(void);
int test_load_pkcs12_cert(void);
int test_chacha20_poly1305_encrypt_decrypt(void);
int test_chacha20_encrypt_decrypt(void);

#endif
