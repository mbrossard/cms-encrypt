/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#ifndef DECRYPT_H
#define DECRYPT_H

#include <openssl/bio.h>

#ifdef __cplusplus
extern "C" {
#endif

int decrypt_cms(BIO *in, BIO *out, char *password);

#ifdef __cplusplus
};
#endif

#endif /* DECRYPT_H */
