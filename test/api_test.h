#ifndef OPENSSLAPIS_TEST_API_TEST_H
#define OPENSSLAPIS_TEST_API_TEST_H

#define OAPIS_NELEM(array)    (sizeof(array)/sizeof(array[0]))

typedef struct {
    int (*api)(void);
    const char *msg;
} OapisApi;

extern char *oapis_cert;
extern char *oapis_key;
extern char *oapis_csr;
extern char *oapis_ca;

int test_match_csr_key(void);

#endif
