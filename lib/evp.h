#ifndef OSSLAPIS_LIB_EVP_H_
#define OSSLAPIS_LIB_EVP_H_

typedef struct {
    int id;
    uint32_t type;
    int (*get_id)(const EVP_PKEY *pkey);
} KeyType;

#endif
