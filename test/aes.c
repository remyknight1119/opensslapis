/*
 * Remy Lewis(remyknight1119@gmail.com)
 */

#include "api_test.h"
#include "evp.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

#include "osslapis.h"
#include "debug.h"

int test_aes_cbc_encrypt_decrypt(void)
{
    unsigned char data[128] = {};
    unsigned char key[16];
    unsigned char cipher1[sizeof(data)*2] = {};
    unsigned char cipher2[sizeof(data)*2] = {};
    unsigned char plaintext[sizeof(data)] = {};
    AES_KEY aes_key;
    unsigned char iv[16];
    unsigned char iv_tmp[sizeof(iv)];
    int len = 0;
    int cipher_len = 0;
    int plaintext_len = 0;

    RAND_bytes(data, sizeof(data));
    RAND_bytes(key, sizeof(key));
    RAND_bytes((void *)&iv, sizeof(iv));

    memcpy(iv_tmp, &iv, sizeof(iv));
    len =  sizeof(data);
    if (osslapis_aes_cbc_encrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                cipher1, &cipher_len, data, len) < 0) {
        return -1;
    }

    AES_set_encrypt_key(key, sizeof(key)*8, &aes_key);
    memcpy(iv_tmp, &iv, sizeof(iv));

    AES_cbc_encrypt(data, cipher2, len, &aes_key, iv_tmp, AES_ENCRYPT);
    if (memcmp(cipher1, cipher2, len) != 0) {
        data_print(cipher1, len);
        data_print(cipher2, len);
        return -1;
    }

    memcpy(iv_tmp, &iv, sizeof(iv));
    if (osslapis_aes_cbc_decrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                plaintext, &plaintext_len, cipher1, cipher_len) < 0) {
        printf("AES decrypt failed\n");
        return -1;
    }

    if (plaintext_len != len || memcmp(plaintext, data, len) != 0) {
        return -1;
    }

    return 0;
}

int test_aes_ctr_encrypt_decrypt(void)
{
    unsigned char key[16];
    unsigned char data[128] = {};
    unsigned char cipher[sizeof(data)] = {};
    unsigned char plaintext[sizeof(data)] = {};
    unsigned char iv[16];
    unsigned char iv_tmp[sizeof(iv)];
    int len = 0;
    int cipher_len = 0;
    int plaintext_len = 0;

    RAND_bytes(data, sizeof(data));
    RAND_bytes(key, sizeof(key));
    RAND_bytes((void *)&iv, sizeof(iv));

    memcpy(iv_tmp, &iv, sizeof(iv));
    len =  sizeof(data);
    if (osslapis_aes_ctr_encrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                cipher, &cipher_len, data, len) < 0) {
        return -1;
    }

    if (cipher_len != len) {
        printf("AES CTR cipher len error\n");
        return -1;
    }

    memcpy(iv_tmp, &iv, sizeof(iv));
    if (osslapis_aes_ctr_decrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                plaintext, &plaintext_len, cipher, cipher_len) < 0) {
        printf("AES CTR decrypt failed\n");
        return -1;
    }

    if (plaintext_len != len || memcmp(plaintext, data, len) != 0) {
        return -1;
    }

    plaintext_len = 0;
    memset(plaintext, 0, sizeof(plaintext));
    memcpy(iv_tmp, &iv, sizeof(iv));
    if (osslapis_aes_ctr_encrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                plaintext, &plaintext_len, cipher, cipher_len) < 0) {
        printf("AES CTR encrypt failed\n");
        return -1;
    }

    if (plaintext_len != len || memcmp(plaintext, data, len) != 0) {
        return -1;
    }

    return 0;
}

int test_aes_cfb_encrypt_decrypt(void)
{
    unsigned char data[128] = {};
    unsigned char key[16];
    unsigned char cipher1[sizeof(data)*2] = {};
    unsigned char cipher2[sizeof(data)*2] = {};
    unsigned char plaintext[sizeof(data)] = {};
    AES_KEY aes_key;
    unsigned char iv[16];
    unsigned char iv_tmp[sizeof(iv)];
    int len = 0;
    int iv_len = 0;
    int cipher_len = 0;
    int plaintext_len = 0;

    RAND_bytes(data, sizeof(data));
    RAND_bytes(key, sizeof(key));
    RAND_bytes((void *)&iv, sizeof(iv));

    memcpy(iv_tmp, &iv, sizeof(iv));
    len =  sizeof(data);
    if (osslapis_aes_cfb_encrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                cipher1, &cipher_len, data, len) < 0) {
        return -1;
    }

    AES_set_encrypt_key(key, sizeof(key)*8, &aes_key);
    memcpy(iv_tmp, &iv, sizeof(iv));

    AES_cfb128_encrypt(data, cipher2, len, &aes_key, iv_tmp, &iv_len,
                        AES_ENCRYPT);
    if (memcmp(cipher1, cipher2, len) != 0) {
        data_print(cipher1, len);
        data_print(cipher2, len);
        return -1;
    }

    memcpy(iv_tmp, &iv, sizeof(iv));
    if (osslapis_aes_cfb_decrypt(key, sizeof(key), iv_tmp, sizeof(iv_tmp),
                plaintext, &plaintext_len, cipher1, cipher_len) < 0) {
        printf("AES decrypt failed\n");
        return -1;
    }

    if (plaintext_len != len || memcmp(plaintext, data, len) != 0) {
        return -1;
    }

    return 0;
}

int test_aes_ccm_encrypt_decrypt(void)
{
    unsigned char key[128];
    unsigned char nonce[EVP_CCM_TLS_IV_LEN];
    unsigned char aad[256];
    unsigned char plaintext[2048];
    char *key_str = "25E7FF1DE4D20A59C3CD6968D7D349A5";
    char *iv = "4DA2406FA1AC8E4280E97917";
    char *aad_str = "E0000000010008E65CC99C74E76448444D02";
    char *plaintext_str = "0600443808000073007100000000001000050003026833003900600008E35C7FD31D4F328D0210A04F4B6314DC12AFD7857C01988018340F08E65CC99C74E7644801048000C3500302480004048000FAE005025F5C06025F5C07025F5C0801050901030E010880FF73DB1000000001FF00001D00000001709A50C40B0004E8000004E40004DF308204DB308203C3A0030201020203044E05300D06092A864886F70D01010B05003081AB310B3009060355040613025553311330110603550408130A43616C69666F726E6961311230100603550407130953756E6E7976616C653111300F060355040A1308466F7274696E6574311E301C060355040B1315436572746966696361746520417574686F72697479311B301906035504031312666F7274696E65742D7375626361323030313123302106092A864886F70D0109011614737570706F727440666F7274696E65742E636F6D3020170D3139303232373233353030395A180F32303536303131393033313430375A308196310B3009060355040613025553311330110603550408130A43616C69666F726E6961311230100603550407130953756E6E7976616C653111300F060355040A1308466F7274696E65743111300F060355040B1308466F727469414443311330110603550403130A466F727469414443564D3123302106092A864886F70D0109011614737570706F727440666F7274696E65742E636F6D30820122300D06092A864886F70D01010105000382010F003082010A0282010100CBD25313835D84E4A386ECEC070BA5264222C74F511A6BEDBDE9426E410674B85CAA587490F6E0A3B622157963142973C6E89CD5BC4A0554D7C7D5C8FC95E74B67297278CA2334BD5A2F5E60B7A9AC6CB7CA037BA901BFE5B61821D9F14D19F9617A6E4F456D92EE8C5AAF8D7AFD769EC15343B4DB0AD455C54A5F5733DB925C24B0A20698A123864B8C5821C92F26143E9A1508D5B4A8D90D0E600E4259671D223D7588D4BB4F4D7F7B31B042EA5C7A3FE88416F66A94E4385108DDF4546516321C10DEF5ED4D1CA82667059F559B9027265A9B216694F6FD10AA7FEA37BAD30C508CFD4BCC74B868A027B4FE514FD4BA35C3084AA20BA9E28FD395A69BD5810203010001A382011730820113301D0603551D0E041604142EC1622503BC3883A19314A231141FA5A67284F93081D30603551D230481CB3081C88014982B253C30CA2C2B56E7DBFC5933B3DC3D5B6AD7A181ABA481A83081A5310B3009060355040613025553311330110603550408130A43616C69666F726E6961311230100603550407130953756E6E7976616C653111300F060355040A1308466F7274696E6574311E301C060355040B1315436572746966696361746520417574686F72697479311530130603550403130C666F7274696E65742D6361323123302106092A864886F70D0109011614737570706F727440666F7274696E65742E636F6D82022001300C0603551D130101";
    unsigned char ciphertext[2048];
    unsigned char decryptedtext[2048];
    unsigned char tag[EVP_CCM_TLS_TAG_LEN] = {};
    size_t aad_len = 0;
    size_t plen = 0;

    int decryptedtext_len, ciphertext_len;

    str2hex(key, key_str, strlen(key_str));
    str2hex(nonce, iv, strlen(iv));
    str2hex(aad, aad_str, strlen(aad_str));
    str2hex(plaintext, plaintext_str, strlen(plaintext_str));

    aad_len = strlen(aad_str)/2;
    plen = strlen(plaintext_str)/2;
    /* Encrypt the plaintext */
    ciphertext_len = osslapis_aes_ccm_encrypt(plaintext, plen, key, nonce, aad,
                        aad_len, ciphertext, tag);

    if (ciphertext_len <= 0) {
        printf("CCM encrypt failed\n");
        return -1;
    }

#if 0
    /* Print the encrypted text */
    printf("Ciphertext is:\n");
    for (int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");
    printf("Tag is:\n");
    for (int i = 0; i < EVP_CCM_TLS_TAG_LEN; i++)
        printf("%02x", tag[i]);
    printf("\n");

#endif

    /* Decrypt the ciphertext */
    decryptedtext_len = osslapis_aes_ccm_decrypt(ciphertext, ciphertext_len,
                                         key, nonce, aad, aad_len,
                                         tag, decryptedtext);
    if (decryptedtext_len != plen) {
        printf("CCM decrypt failed(%d)\n", decryptedtext_len);
        return -1;
    }

    if (memcmp(plaintext, decryptedtext, plen)) {
        printf("CCM decrypt invalid\n");
        return -1;
    }

    return 0;
}

