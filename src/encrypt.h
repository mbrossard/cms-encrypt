/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <openssl/bio.h>

#ifdef __cplusplus
extern "C" {
#endif

int encrypt(BIO *in, BIO *out, char *password);

#ifdef __cplusplus
};
#endif

#endif /* ENCRYPT_H */
