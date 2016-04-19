/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <openssl/bio.h>
#include <openssl/x509.h>

#ifdef __cplusplus
extern "C" {
#endif

int encrypt_cms(BIO *in, BIO *out, BIO *err, char *password, STACK_OF(X509) *crts);

#ifdef __cplusplus
};
#endif

#endif /* ENCRYPT_H */
