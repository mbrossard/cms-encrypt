/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#ifndef COMMON_H
#define COMMON_H

#include <getopt.h>
#include <string.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

void init_crypto();
void print_usage_and_die(const char *name, const struct option *opts, const char **help);

#ifdef __cplusplus
};
#endif

#endif /* COMMON_H */
