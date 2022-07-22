#ifndef OSSLAPIS_LIB_LOG_H_
#define OSSLAPIS_LIB_LOG_H_

#include <stdio.h>
#include <errno.h>
#include <openssl/err.h>

#define OSSLAPIS_LOG(format, ...) \
    do { \
        fprintf(stdout, "[%s, %d]: "format, __FUNCTION__, \
                __LINE__, ##__VA_ARGS__); \
    } while (0)


#define OSSLAPIS_ERR_STR() ERR_reason_error_string(ERR_get_error())

#endif

