/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#ifndef COMMON_H
#define COMMON_H

#include <getopt.h>
#include <string.h>
#include <stdio.h>

#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

void init_crypto();
void print_usage_and_die(const char *name, const struct option *opts, const char **help);

unsigned int read_length(BIO *in);

X509 *load_x509(BIO *err, const char *file);
ENGINE *load_engine(BIO *err, const char *engine, int debug);
EVP_PKEY *load_key(BIO *err, const char *file, ENGINE *e);

#ifdef __cplusplus
};
#endif

#endif /* COMMON_H */
