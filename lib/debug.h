#ifndef OSSLAPIS_LIB_DEBUG_H_
#define OSSLAPIS_LIB_DEBUG_H_

#include <stdio.h>

static inline void data_print(const unsigned char *d, int len)
{
    int i = 0;

    for (i = 0; i < len; i++) {
        fprintf(stdout, "%02X", d[i]);
    }

    fprintf(stdout, "\nlen = %d\n", len);
}

#endif

