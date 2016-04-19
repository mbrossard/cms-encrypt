/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "common.h"
#include "decrypt.h"
#include "encrypt.h"

static char *app_name = "cmse";

static const struct option options[] = {
    { "help",               0, 0,           'h' },
    { "decrypt",            0, 0,           'd' },
    { "encrypt",            0, 0,           'e' },
    { "engine",             1, 0,           'E' },
    { "input",              1, 0,           'i' },
    { "output",             1, 0,           'o' },
    { "password",           1, 0,           'p' },
    { "recipient",          1, 0,           'r' },
    { "key",                1, 0,           'k' },
    { "verbose",            0, 0,           'v' },
    { 0, 0, 0, 0 }
};

static const char *option_help[] = {
    "Print this help and exit",
    "Decrypt file",
    "Encrypt file",
    "Input file (default stdin)",
    "Output file  (default stdout)",
    "Password used to encrypt",
    "Recipient certificate",
    "Key to decrypt file",
    "Display additional information",
};

int main(int argc, char **argv)
{
    char *opt_input = NULL,
        *opt_output = NULL,
        *opt_key = NULL,
        *opt_engine = NULL,
        *opt_password = NULL;
    int long_optind = 0, ret = 1;
    int encrypt = 0, decrypt = 0, verbose = 0;
    STACK_OF(X509) *crts = sk_X509_new_null();
    X509 *x509 = NULL;
    EVP_PKEY *key = NULL;
    BIO *in = NULL, *out = NULL, *err = NULL;
    ENGINE *engine = NULL;

    init_crypto();

    while (1) {
        char c = getopt_long(argc, argv, "deE:hi:k:o:p:r:v",
                             options, &long_optind);
        if (c == -1)
            break;
        switch (c) {
            case 'd':
                decrypt = 1;
                break;
            case 'E':
                opt_engine = optarg;
                break;
            case 'e':
                encrypt = 1;
                break;
            case 'i':
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
                } else {
                    fprintf(stderr, "Error loading certificate '%s'\n", optarg);
                    goto end;
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

    if(encrypt == 0 && decrypt == 0) {
        fprintf(stderr, "You must specify either --encrypt/-e or --decrypt/-d\n");
        goto end;
    }

    err = BIO_new_fp(stderr, BIO_NOCLOSE);
    if(opt_engine) {
        engine = load_engine(err, opt_engine, verbose);
    }

    if(opt_key) {
        if((key = load_key(NULL, opt_key, engine)) == NULL) {
            goto end;
        }
    }

    if(opt_input) {
        in = BIO_new_file(opt_input, "rb");
    } else {
        in = BIO_new_fp(stdin, BIO_NOCLOSE);
    }

    if(opt_output) {
        out = BIO_new_file(opt_output, "wb");
    } else {
        out = BIO_new_fp(stdout, BIO_NOCLOSE);
    }

    if(encrypt) {
        if(opt_password == NULL && sk_X509_num(crts) == 0) {
            fprintf(stderr, "You must specify at least one of --password/-p or --recipient/-r\n");
            goto end;
        }
        ret = encrypt_cms(in, out, err, opt_password, crts);
    } else if(decrypt) {
        if(opt_password == NULL && (opt_key == NULL || sk_X509_num(crts) == 0)) {
            fprintf(stderr, "You must specify either --password/-p or --recipient/-r and --key/-k\n");
            goto end;
        }
        ret = decrypt_cms(in, out, err, opt_password, x509, key);
    }

 end:
    return ret;
}
