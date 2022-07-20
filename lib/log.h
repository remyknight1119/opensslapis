#ifndef OSSLAPIS_LIB_LOG_H_
#define OSSLAPIS_LIB_LOG_H_

#include <stdio.h>
#include <errno.h>

#define OSSLAPIS_LOG(format, ...) \
    do { \
        fprintf(stdout, "[%s, %d]: "format, __FUNCTION__, \
                __LINE__, ##__VA_ARGS__); \
    } while (0)


#endif
