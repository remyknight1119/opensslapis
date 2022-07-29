/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "api_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <openssl/pem.h>

#include "osslapis.h"

static OapisApi kOsslApis[] = {
    {
        .api = test_load_key,
        .cert_type = OAPIS_KEY_TYPE_ANY,
        .msg = "Load Key from file",
    },
    {
        .api = test_match_pkey,
        .cert_type = OAPIS_KEY_TYPE_ANY,
        .msg = "Match PKey",
    },
    {
        .api = test_match_pkey_type,
        .cert_type = OAPIS_KEY_TYPE_ANY,
        .msg = "Match PKey Type",
    },
    {
        .api = test_match_cert_type,
        .cert_type = OAPIS_KEY_TYPE_ANY,
        .msg = "Match Cert Type",
    },
    {
        .api = test_cert_pubkey_length,
        .cert_type = OAPIS_KEY_TYPE_ANY,
        .msg = "Cert Key Bit Length",
    },
    {
        .api = test_digests,
        .cert_type = OAPIS_KEY_TYPE_UNKNOW,
        .msg = "Digests",
    },
    {
        .api = test_3des_encrypt_decrypt,
        .cert_type = OAPIS_KEY_TYPE_UNKNOW,
        .msg = "3DES Encrypt/Decrypt",
    },
    {
        .api = test_rsa_verify,
        .cert_type = OAPIS_KEY_TYPE_RSA,
        .msg = "RSA Verify",
    },
    {
        .api = test_load_pub_key_from_file,
        .cert_type = OAPIS_KEY_TYPE_ANY,
        .msg = "Load Public Key from file",
    },
    {
        .api = test_load_pub_key_from_mem,
        .cert_type = OAPIS_KEY_TYPE_ANY,
        .msg = "Load Public Key from memory",
    },
    {
        .api = test_aes_cbc_encrypt_decrypt,
        .cert_type = OAPIS_KEY_TYPE_UNKNOW,
        .msg = "AES CBC Encrypt/Decrypt",
    },
    {
        .api = test_rsa_encrypt_decrypt,
        .cert_type = OAPIS_KEY_TYPE_RSA,
        .msg = "RSA Encrypt/Decrypt",
    },
    {
        .api = test_hmac,
        .cert_type = OAPIS_KEY_TYPE_UNKNOW,
        .msg = "HMAC",
    },
    {
        .api = test_aes_ctr_encrypt_decrypt,
        .cert_type = OAPIS_KEY_TYPE_UNKNOW,
        .msg = "AES CTR Encrypt/Decrypt",
    },
    {
        .api = test_dsa_verify,
        .cert_type = OAPIS_KEY_TYPE_DSA,
        .msg = "DSA Verify",
    },
    {
        .api = test_ecdsa_verify,
        .cert_type = OAPIS_KEY_TYPE_ECDSA,
        .msg = "ECDSA Verify",
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
    "--type  		        -t	type of certificate file(1:RSA, 2:ECDSA)\n",
    "--key      		    -k	key file\n",
    "--pub      		    -b	public key file\n",
    "--pwd      		    -p	key file password\n",
    "--encrypted-file      	-w	key file encrypted with password\n",
    "--der      		    -d	key file encoded by DER\n",
    "--csr      		    -s	csr file\n",
    "--ca      		        -a	ca certificate file\n",
    "--len      		    -l	length of key bits\n",
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

static const char *optstring = "Ht:a:c:k:s:p:d:w:l:b:";

int oapis_cert_type;
int oapis_key_bits;
char *oapis_cert;
char *oapis_key;
char *oapis_key_pwd;
char *oapis_key_enc;
char *oapis_key_der;
char *oapis_key_pub;
char *oapis_csr;
char *oapis_ca;

int main(int argc, char **argv)
{
    OapisApi *cs = NULL;
    int total = 0;
    int passed = 0;
    int i = 0;
    int c = 0;

    while ((c = getopt_long(argc, argv, optstring, long_opts, NULL)) != -1) {
        switch (c) {
            case 'H':
                help();
                return 0;
            case 't':
                oapis_cert_type = atoi(optarg);
                break;
            case 'l':
                oapis_key_bits = atoi(optarg);
                break;
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
            case 'p':
                oapis_key_pwd = optarg;
                break;
            case 'd':
                oapis_key_der = optarg;
                break;
            case 'w':
                oapis_key_enc = optarg;
                break;
            case 'b':
                oapis_key_pub = optarg;
                break;
            default:
                help();
                return -1;
        }
    }

    if (oapis_cert_type < OAPIS_KEY_TYPE_UNKNOW ||
            oapis_cert_type >= OAPIS_KEY_TYPE_MAX) {
        fprintf(stderr, "Unknown cert type(%d)\n", oapis_cert_type);
        return -1;
    }

    if (oapis_cert_type != OAPIS_KEY_TYPE_UNKNOW) {
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
    }

    for (i = 0; i < TEST_APIS_NUM; i++) {
        cs = &kOsslApis[i];
        if (cs->cert_type != OAPIS_KEY_TYPE_ANY &&
                cs->cert_type != oapis_cert_type) {
//            fprintf(stdout, "Case %s skip\n", cs->msg);
            continue;
        }

        if (oapis_cert_type == OAPIS_KEY_TYPE_UNKNOW &&
                cs->cert_type != oapis_cert_type) {
//            fprintf(stdout, "Case %s skip\n", cs->msg);
            continue;
        }

        fprintf(stdout, "Case %s ...", cs->msg);
        total++;
        if (cs->api() < 0) {
            fprintf(stdout, "failed\n");
            continue;
        }
        passed++;
        fprintf(stdout, "OK\n");
    }

    fprintf(stdout, "%d/%d testcase passed\n", passed, total);

    return 0;
}
