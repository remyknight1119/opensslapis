#ifndef OPENSSLAPIS_INCLUDE_OPENSSLAPIS_H_
#define OPENSSLAPIS_INCLUDE_OPENSSLAPIS_H_

#include <openssl/types.h>

EVP_PKEY *read_private_key(const char *file, char *passwd);
int match_csr_key(const char *csr_file, const char *key_file);
int match_pkey(const char *file1, const char *file2, char *passwd);

#endif
