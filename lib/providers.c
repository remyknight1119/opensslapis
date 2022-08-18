/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "osslapis.h"

#include <string.h>
#include <dlfcn.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include "log.h"

int osslapis_providers_load(const char *legacy_lib)
{
    OSSL_PROVIDER *defprov = NULL;
    OSSL_PROVIDER *lgcyprov = NULL;
    OSSL_LIB_CTX *ctx = NULL;
    void *dlhan = NULL;
    void *provider_init_fn = NULL;
    int ret = -1;

    ctx = OSSL_LIB_CTX_new();
    if (ctx == NULL) {
        return -1;
    }

    EVP_CIPHER *ciph;
    defprov = OSSL_PROVIDER_load(NULL, "default");
    if (defprov == NULL) {
        printf("Load default provider failed\n");
        goto out;
    }

    dlhan = dlopen(legacy_lib, RTLD_LOCAL | RTLD_NOW);
    if (dlhan == NULL) {
        printf("Dlopen %s failed(%s)\n", legacy_lib, dlerror());
        goto out;
    }

    provider_init_fn = dlsym(dlhan, "OSSL_provider_init");
    if (provider_init_fn == NULL) {
        printf("Load func failed(%s)\n", dlerror());
        goto out;
    }

    if (OSSL_PROVIDER_add_builtin(NULL, "legacy", provider_init_fn) == 0) {
        printf("Add provider failed(%s)\n", OSSLAPIS_ERR_STR());
        goto out;
    }

    lgcyprov = OSSL_PROVIDER_load(NULL, "legacy");
    if (lgcyprov == NULL) {
        printf("Load legacy provider failed\n");
        goto out;
    }

    ciph = EVP_CIPHER_fetch(NULL, "DES-CBC", NULL);
    printf("cipher = %p, lp = %p\n", ciph, lgcyprov);

    ret = 0;

out:
    if (dlhan != NULL) {
        dlclose(dlhan);
    }

    OSSL_LIB_CTX_free(ctx);

    return ret;
}

