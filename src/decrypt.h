/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#ifndef DECRYPT_H
#define DECRYPT_H

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

int decrypt_cms(BIO *in, BIO *out, BIO *err, char *password, X509 *x509, EVP_PKEY *key);
int decrypt_cms_legacy(BIO *in, BIO *out, BIO *err, char *password, X509 *x509, EVP_PKEY *key);

#ifdef __cplusplus
};
#endif

#endif /* DECRYPT_H */
