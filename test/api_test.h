#ifndef OPENSSLAPIS_TEST_API_TEST_H
#define OPENSSLAPIS_TEST_API_TEST_H

#include <stddef.h>
#include <stdint.h>

#define OAPIS_NELEM(array)    (sizeof(array)/sizeof(array[0]))

typedef struct {
    int (*api)(void);
    uint32_t cert_type;
    const char *msg;
} OapisApi;

enum {
    OAPIS_CERT_TYPE_UNKNOW,
    OAPIS_CERT_TYPE_RSA,
    OAPIS_CERT_TYPE_ECDSA,
    OAPIS_CERT_TYPE_MAX,
};

extern char *oapis_cert;
extern char *oapis_key;
extern char *oapis_key_enc;
extern char *oapis_key_pwd;
extern char *oapis_key_der;
extern char *oapis_csr;
extern char *oapis_ca;

int test_match_csr_key(void);
int test_match_pkey(void);
int test_load_key(void);

#endif
