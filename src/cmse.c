/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "common.h"
#include "decrypt.h"
#include "encrypt.h"

static char *app_name = "cmse";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "decrypt",            1, 0,           'd' },
    { "encrypt",            1, 0,           'e' },
    { "key",                1, 0,           'k' },
    { "output",             1, 0,           'o' },
    { "password",           1, 0,           'p' },
    { "recipient",          1, 0,           'r' },
    { "verbose",            0, 0,           'v' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Decrypt file",
    "Encrypt file",
    "Key to decrypt file",
    "Output file",
    "Password used to encrypt",
    "Recipient certificate",
    "Display additional information",
};

int main(int argc, char **argv)
{
    char *opt_input = NULL,
        *opt_output = NULL,
        *opt_key = NULL,
        *opt_password = NULL;
    int long_optind = 0, ret = 1;
    int encrypt = 0, decrypt = 0, verbose = 0;
    STACK_OF(X509) *crts = sk_X509_new_null();
    X509 *x509 = NULL;
    EVP_PKEY *key = NULL;

    init_crypto();

    while (1) {
        char c = getopt_long(argc, argv, "d:e:hk:o:p:r:v",
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
            case 'k':
                opt_key = optarg;
                break;
            case 'o':
                opt_output = optarg;
                break;
            case 'p':
                opt_password = optarg;
                break;
            case 'r':
                x509 = load_x509(NULL, optarg);
                if(x509) {
                    sk_X509_push(crts, x509);
                }
                break;
            case 'v':
                verbose += 1;
                break;
            case 'h':
            default:
                print_usage_and_die(app_name, options, option_help);
        }
    }

    if(opt_key) {
        key = load_key(NULL, opt_key, NULL);
    }

    BIO *in = NULL, *out = NULL;

    in = BIO_new_file(opt_input, "rb");
    // in = BIO_new_fp(stdin, BIO_NOCLOSE);

    if(opt_output) {
        out = BIO_new_file(opt_output, "wb");
    } else {
        out = BIO_new_fp(stdout, BIO_NOCLOSE);
    }

    if(encrypt) {
        ret = encrypt_cms(in, out, opt_password, crts);
    } else if(decrypt) {
        ret = decrypt_cms(in, out, opt_password);
    }

    return ret;
}
