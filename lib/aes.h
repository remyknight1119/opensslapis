#ifndef OSSLAPIS_LIB_AES_H_
#define OSSLAPIS_LIB_AES_H_

#include <openssl/types.h>

typedef struct {
    int key_size;
    const EVP_CIPHER *(*get_cipher)(void);
} AesType;


#endif
