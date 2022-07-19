/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "api_test.h"

#include <stdio.h>
#include <getopt.h>
#include <arpa/inet.h>

static OapisApi kOsslApis[] = {
    {
        .api = test_match_csr_key,
        .msg = "Match CSR and Key",
    },
};

#define TEST_APIS_NUM OAPIS_NELEM(kOsslApis)

static const char *program_version = "1.0.0";//PACKAGE_STRING;

static const struct option long_opts[] = {
    {"help", 0, 0, 'H'},
    {"certificate", 0, 0, 'c'},
    {"key", 0, 0, 'k'},
    {"ca", 0, 0, 'a'},
    {0, 0, 0, 0}
};

static const char *options[] = {
    "--certificate  		-c	certificate file\n",	
    "--key      		    -k	key file\n",	
    "--csr      		    -s	csr file\n",	
    "--ca      		        -a	ca certificate file\n",	
    "--help         		-H	Print help information\n",	
};

static void help(void)
{
    int     index;

    fprintf(stdout, "Version: %s\n", program_version);

    fprintf(stdout, "\nOptions:\n");
    for (index = 0; index < OAPIS_NELEM(options); index++) {
        fprintf(stdout, "  %s", options[index]);
    }
}

static const char *optstring = "Hda:c:k:s:";

char *oapis_cert;
char *oapis_key;
char *oapis_csr;
char *oapis_ca;

int main(int argc, char **argv)
{
    int i = 0;
    int c = 0;

    while ((c = getopt_long(argc, argv, optstring, long_opts, NULL)) != -1) {
        switch (c) {
            case 'H':
                help();
                return 0;
            case 'c':
                oapis_cert = optarg;
                break;
            case 'k':
                oapis_key = optarg;
                break;
            case 'a':
                oapis_ca = optarg;
                break;
            case 's':
                oapis_csr = optarg;
                break;
            default:
                help();
                return -1;
        }
    }

    if (oapis_cert == NULL) {
        fprintf(stderr, "please input certificate file by -c\n");
        return -1;
    }

    if (oapis_key == NULL) {
        fprintf(stderr, "please input key file by -k\n");
        return -1;
    }

    if (oapis_ca == NULL) {
        fprintf(stderr, "please input ca certificate file by -a\n");
        return -1;
    }

    for (i = 0; i < TEST_APIS_NUM; i++) {
        fprintf(stdout, "Case %s ...", kOsslApis[i].msg);
        if (kOsslApis[i].api() < 0) {
            fprintf(stderr, "failed\n");
            break;
        }
        fprintf(stdout, "OK\n");
    }

    return 0;
}
