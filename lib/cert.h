#ifndef OSSLAPIS_LIB_CERT_H_
#define OSSLAPIS_LIB_CERT_H_

#include <openssl/types.h>

X509 *load_cert(const char *file, char *passwd);

#endif
