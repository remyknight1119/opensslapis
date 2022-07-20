#ifndef OSSLAPIS_LIB_EVP_H_
#define OSSLAPIS_LIB_EVP_H_

typedef struct {
    int id;
    uint32_t type;
    int (*get_id)(const EVP_PKEY *pkey);
} KeyType;

uint32_t find_pkey_type(EVP_PKEY *pkey);

#endif
