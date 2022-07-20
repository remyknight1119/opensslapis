/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "passwd.h"

#include <string.h>
#include <stdio.h>

int pem_key_passwd_cb(char *buf, int size, int rwflag, void *userdata)
{
    char *passwd = userdata;

    if (passwd == NULL) {
        return 0;
    }

    snprintf(buf, size, "%s", passwd);

    return strlen(passwd);
}

