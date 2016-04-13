/*
 * Copyright (C) 2016 Mathias Brossard <mathias@brossard.org>
 */

#include "config.h"
#include "common.h"

#include <openssl/err.h>
#include <openssl/pem.h>

void init_crypto()
{
    OPENSSL_add_all_algorithms_noconf();
}

void print_usage_and_die(const char *name, const struct option *opts, const char **help)
{
    int i = 0;
    fprintf(stdout, "Usage: %s [OPTIONS]\nOptions:\n", name);

    while (opts[i].name) {
        char buf[40], tmp[5];
        const char *arg_str;

        /* Skip "hidden" opts */
        if (help[i] == NULL) {
            i++;
            continue;
        }

        if (opts[i].val > 0 && opts[i].val < 128)
            sprintf(tmp, ", -%c", opts[i].val);
        else
            tmp[0] = 0;
        switch (opts[i].has_arg) {
            case 1:
                arg_str = " <arg>";
                break;
            case 2:
                arg_str = " [arg]";
                break;
            default:
                arg_str = "";
                break;
        }
        sprintf(buf, "--%s%s%s", opts[i].name, tmp, arg_str);
        if (strlen(buf) > 29) {
            fprintf(stdout, "  %s\n", buf);
            buf[0] = '\0';
        }
        fprintf(stdout, "  %-29s %s\n", buf, help[i]);
        i++;
    }
    exit(2);
}

unsigned int read_length(BIO *in)
{
    unsigned int l = 0, i, j;
    unsigned char c;

    BIO_read(in, (char *)&c, 1);
    if(c <= 127) {
        l = c;
    } else {
        j = c - 128;
        /* This probably should be limited to 32 bits... */
        for(i = 0; i < j; i++) {
            BIO_read(in, (char *)&c, 1);
            l = l << 8;
            l |= c;
        }
    }

    return l;
}

X509 *load_x509(BIO *err, const char *file)
{
    X509 *x = NULL;
    BIO *bin;

    if ((bin = BIO_new(BIO_s_file())) == NULL) {
        ERR_print_errors(err);
        goto end;
    }

    if (file == NULL) {
        BIO_set_fp(bin, stdin, BIO_NOCLOSE);
    } else {
        if (BIO_read_filename(bin, file) <= 0) {
            BIO_printf(err, "Error opening %s\n", file);
            ERR_print_errors(err);
            goto end;
        }
    }

    x = PEM_read_bio_X509_AUX(bin, NULL, NULL, NULL);

 end:
    if (x == NULL) {
        BIO_printf(err, "unable to load certificate\n");
        ERR_print_errors(err);
    }
    if (bin != NULL) {
        BIO_free(bin);
    }
    return x;
}

ENGINE *load_engine(BIO *err, const char *engine, int debug)
{
    ENGINE *e = NULL;

    if (engine) {
        ENGINE_load_builtin_engines();

        /* Try internal engines first */
        if ((e = ENGINE_by_id(engine)) == NULL) {
            /* It failed clear errors and try with dynamic */
            ERR_clear_error();
            e = ENGINE_by_id("dynamic");
            if (e) {
                if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0)
                    || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
                    ENGINE_free(e);
                    e = NULL;
                }
            }
        }
        if(e == NULL) {
            BIO_printf(err, "invalid engine \"%s\"\n", engine);
            ERR_print_errors(err);
            return NULL;
        }
        if (debug) {
            ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM, 0, err, 0);
        }
        if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
            if(err) {
                BIO_printf(err, "can't use that engine\n");
                ERR_print_errors(err);
            }
            ENGINE_free(e);
            return NULL;
        }

        if(err && debug) {
            BIO_printf(err, "engine \"%s\" set.\n", ENGINE_get_id(e));
        }

        ENGINE_free(e);
    }
    return e;
}

EVP_PKEY *load_key(BIO *err, const char *file, ENGINE *engine)
{
    BIO *key = NULL;
    EVP_PKEY *pkey = NULL;

    if (file == NULL) {
        BIO_printf(err, "no keyfile specified\n");
        goto end;
    }

    if (engine) {
        pkey = ENGINE_load_private_key(engine, file, NULL, NULL);
        if (!pkey) {
            BIO_printf(err, "cannot load %s from engine\n", file);
            ERR_print_errors(err);
        }
        goto end;
    }

    key = BIO_new(BIO_s_file());
    if (key == NULL) {
        ERR_print_errors(err);
        goto end;
    }
    if (file == NULL) {
        BIO_set_fp(key, stdin, BIO_NOCLOSE);
    } else if (BIO_read_filename(key, file) <= 0) {
        BIO_printf(err, "Error opening %s\n", file);
        ERR_print_errors(err);
        goto end;
    }

    pkey = PEM_read_bio_PrivateKey(key, NULL, NULL, NULL);

 end:
    if (key != NULL) {
        BIO_free(key);
    }
    if (pkey == NULL) {
        BIO_printf(err, "unable to load %s\n", file);
        ERR_print_errors(err);
    }
    return (pkey);
}
