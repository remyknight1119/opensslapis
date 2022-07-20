#ifndef OSSLAPIS_LIB_PASSWD_H_
#define OSSLAPIS_LIB_PASSWD_H_

int pem_key_passwd_cb(char *buf, int size, int rwflag, void *userdata);

#endif
