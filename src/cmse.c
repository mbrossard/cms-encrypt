/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "common.h"

#include <openssl/cms.h>
#include <openssl/asn1t.h>

#define PKCS5_ITERATIONS 4096

static char *app_name = "cmse";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "decrypt",            1, 0,           'd' },
    { "encrypt",            1, 0,           'e' },
    { "output",             1, 0,           'o' },
    { "password",           1, 0,           'p' },
    { "verbose",            0, 0,           'v' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Decrypt file",
    "Encrypt file",
    "Output file",
    "Password used to encrypt",
    "Display additional information",
};

unsigned int read_length(BIO *in)
{
    unsigned int l = 0, i, j;
    unsigned char c;

    BIO_read(in, (char *)&c, 1);
    if(c <= 127) {
        l = c;
    } else {
        j = c - 128;
        /* Ugly kludge to 32 bits... */
        for(i = 0; i < j; i++) {
            BIO_read(in, (char *)&c, 1);
            l = l << 8;
            l |= c;
        }
    }

    return l;
}

int main(int argc, char **argv)
{
    char *opt_input = NULL,
        *opt_output = NULL,
        *opt_password = NULL;
    int long_optind = 0, ret = 1;
    int encrypt = 0, decrypt = 0, verbose = 0;

    init_crypto();

    while (1) {
        char c = getopt_long(argc, argv, "d:e:ho:p:v",
                             options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'd':
                decrypt = 1;
                opt_input = optarg;
                break;
            case 'e':
                encrypt = 1;
                opt_input = optarg;
                break;
            case 'o':
                opt_output = optarg;
                break;
            case 'p':
                opt_password = optarg;
                break;
            case 'v':
                verbose += 1;
                break;
            case 'h':
            default:
                print_usage_and_die(app_name, options, option_help);
        }
    }

    int flags = CMS_PARTIAL | CMS_STREAM | CMS_BINARY;
    CMS_ContentInfo *cms;
    BIO *in = NULL, *out = NULL;

    in = BIO_new_file(opt_input, "rb");
    // in = BIO_new_fp(stdin, BIO_NOCLOSE);

    if(opt_output) {
        out = BIO_new_file(opt_output, "wb");
    } else {
        out = BIO_new_fp(stdout, BIO_NOCLOSE);
    }

    if(encrypt) {
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();
        const EVP_CIPHER *wrap = EVP_aes_256_cbc();
        cms = CMS_encrypt(NULL, NULL, cipher, CMS_PARTIAL);

        if (opt_password) {
            unsigned char *tmp = (unsigned char *)BUF_strdup((char *)opt_password);
            if (tmp == NULL || CMS_add0_recipient_password(cms, PKCS5_ITERATIONS, NID_id_alg_PWRI_KEK,
                                                           NID_id_pbkdf2, tmp, -1, wrap) == 0) {
                goto end;
            }
        }

        ret = i2d_CMS_bio_stream(out, cms, in, flags);
    } else if(decrypt) {
        cms = d2i_CMS_bio(in, NULL);
        // CMS_decrypt(cms, NULL, NULL, NULL, NULL, flags);

        if (opt_password) {
            unsigned char *tmp = (unsigned char *)BUF_strdup((char *)opt_password);
            if (!CMS_decrypt_set1_password(cms, tmp, -1)) {
                goto end;
            }
        }
        
        if (!CMS_decrypt(cms, NULL, NULL, NULL, out, flags)) {
            goto end;
        }

        ret = 0;
    }

 end:
    return ret;
}
