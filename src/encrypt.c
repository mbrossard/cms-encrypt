#include "encrypt.h"

#include <openssl/cms.h>
#include <openssl/err.h>

#define PKCS5_ITERATIONS 16384

int encrypt_cms(BIO *in, BIO *out, BIO *err, char *password, STACK_OF(X509) *crts)
{
    int flags = CMS_PARTIAL | CMS_STREAM | CMS_BINARY, ret = 1;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    const EVP_CIPHER *wrap = EVP_aes_256_cbc();
    CMS_ContentInfo *cms = CMS_encrypt(NULL, NULL, cipher, CMS_PARTIAL);

    if(crts) {
        for (int i = 0; i < sk_X509_num(crts); i++) {
            CMS_RecipientInfo *ri;
            X509 *x = sk_X509_value(crts, i);
            ri = CMS_add1_recipient_cert(cms, x, flags);
            if (!ri) {
                fprintf(stderr, "Error adding certificate recipient\n");
                ERR_print_errors(err);
                goto end;
            }
        }
    }

    if (password) {
        unsigned char *tmp = (unsigned char *)BUF_strdup((char *)password);
        if (tmp == NULL || CMS_add0_recipient_password(cms, PKCS5_ITERATIONS, NID_id_alg_PWRI_KEK,
                                                       NID_id_pbkdf2, tmp, -1, wrap) == 0) {
            ERR_print_errors(err);
            goto end;
        }
    }

    if(i2d_CMS_bio_stream(out, cms, in, flags) <= 0) {
        ERR_print_errors(err);
        goto end;
    }

    ret = 0;
 end:
    return ret;
}
