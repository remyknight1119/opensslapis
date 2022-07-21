#ifndef OSSLAPIS_TEST_EVP_H
#define OSSLAPIS_TEST_EVP_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    int (*osslapis_digest)(unsigned char *in, int len, unsigned char *out);
    unsigned char *(*origin_digest)(const unsigned char *d, size_t n,
            unsigned char *md);
    uint32_t len;
} OapisEvpDigest;

#endif
