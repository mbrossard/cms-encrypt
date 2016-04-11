#include "decrypt.h"

#include <openssl/cms.h>

int decrypt_cms(BIO *in, BIO *out, char *password, X509 *x509, EVP_PKEY *key)
{
    int flags = CMS_PARTIAL | CMS_STREAM | CMS_BINARY, ret = 1;
    CMS_ContentInfo *cms;

    cms = d2i_CMS_bio(in, NULL);

    if (password) {
        unsigned char *tmp = (unsigned char *)BUF_strdup((char *)password);
        if (!CMS_decrypt_set1_password(cms, tmp, -1)) {
            goto end;
        }
    } else {
        if(key && x509) {
            if (!CMS_decrypt_set1_pkey(cms, key, x509)) {
                goto end;
            }
        }
    }

    if (!CMS_decrypt(cms, NULL, NULL, NULL, out, flags)) {
        goto end;
    }
    }

    ret = 0;
    
 end:
    return ret;
}
