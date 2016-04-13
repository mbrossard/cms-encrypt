#include "common.h"
#include "decrypt.h"

#include <string.h>
#include <openssl/cms.h>
#include <openssl/asn1t.h>

DECLARE_ASN1_ITEM(CMS_RecipientInfo)

CMS_RecipientInfo *d2i_CMS_RecipientInfo_bio(BIO *bp, CMS_RecipientInfo **cms)
{
    return ASN1_item_d2i_bio(ASN1_ITEM_rptr(CMS_RecipientInfo), bp, cms);
}

typedef struct CMS_EnvelopedData_st CMS_EnvelopedData;
typedef struct CMS_OriginatorInfo_st CMS_OriginatorInfo;
typedef struct CMS_EncryptedContentInfo_st CMS_EncryptedContentInfo;

struct CMS_EncryptedContentInfo_st {
    ASN1_OBJECT *contentType;
    X509_ALGOR *contentEncryptionAlgorithm;
    ASN1_OCTET_STRING *encryptedContent;
    /* Content encryption algorithm and key */
    const EVP_CIPHER *cipher;
    unsigned char *key;
    size_t keylen;
    int debug;
};

struct CMS_EnvelopedData_st {
    long version;
    CMS_OriginatorInfo *originatorInfo;
    STACK_OF(CMS_RecipientInfo) *recipientInfos;
    CMS_EncryptedContentInfo *encryptedContentInfo;
    STACK_OF(X509_ATTRIBUTE) *unprotectedAttrs;
};

struct CMS_ContentInfo_st {
    ASN1_OBJECT *contentType;
    union {
        CMS_EnvelopedData *envelopedData;
    } d;
};

X509_ALGOR *d2i_X509_ALGOR_bio(BIO *bp, X509_ALGOR **x509_a)
{
    return ASN1_item_d2i_bio(ASN1_ITEM_rptr(X509_ALGOR), bp, x509_a);
}

BIO *cms_EncryptedContent_init_bio(CMS_EncryptedContentInfo *ec);

int decrypt_cms(BIO *in, BIO *out, char *password, X509 *x509, EVP_PKEY *key)
{
    int ret = 1;
    CMS_ContentInfo *cms;
    char header[21];
    const unsigned char enveloped_header[19] = {
        0x30, 0x80, /* SEQUENCE (Indefinite Length) */
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03,
        /* OBJECT IDENTIFIER envelopedData (1 2 840 113549 1 7 3) */
        0xA0, 0x80, /* [0] (Indefinite Length) */
        0x30, 0x80, /* SEQUENCE (Indefinite Length) */
        0x02, 0x01, /* INTEGER x (x can be 0 or 3) */
    };
    if(BIO_read(in, header, sizeof(header)) != sizeof(header)) {
        goto end;
    }
    if((memcmp(header, enveloped_header, sizeof(enveloped_header)) != 0)
       || (header[19] != 0x00 && header[19] != 0x02 && header[19] != 0x03)
       || (header[20] != 0x31)  /* SET (Length not read) */) {
        goto end;
    }
    
    unsigned int l = read_length(in);

    cms = CMS_EnvelopedData_create(NULL);
    
    unsigned int i = BIO_number_read(in) + l;
    STACK_OF(CMS_RecipientInfo) *recipientInfos = sk_CMS_RecipientInfo_new_null();
    do {
        CMS_RecipientInfo *ri = d2i_CMS_RecipientInfo_bio(in, NULL);
        if(ri) {
            if(!sk_CMS_RecipientInfo_push(recipientInfos, ri)) {
                goto end;
            }
            if(!sk_CMS_RecipientInfo_push(CMS_get0_RecipientInfos(cms), ri)) {
                goto end;
            }
        } else {
            goto end;
        }
    } while(BIO_number_read(in) < i);
    
    if(key && x509) {
        if (!CMS_decrypt_set1_pkey(cms, key, x509)) {
            goto end;
        }
    }
    
    if (password) {
        unsigned char *tmp = (unsigned char *)BUF_strdup((char *)password);
        if (!CMS_decrypt_set1_password(cms, tmp, -1)) {
            goto end;
        }
    }
    
    CMS_EncryptedContentInfo *ec = cms->d.envelopedData->encryptedContentInfo;
    const unsigned char encrypted_content_info[13] = {
        0x30, 0x80, /* SEQUENCE (Indefinite Length) */
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01
        /* OBJECT IDENTIFIER data (1 2 840 113549 1 7 1) */
    };
    /* Skip encryptedContentInfo NDEF[0] + pkcs7Data OID */
    if(BIO_read(in, header, 13) != 13) {
        goto end;
    }
    if(memcmp(header, encrypted_content_info, 13) != 0) {
        goto end;
    }

    X509_ALGOR *calg = d2i_X509_ALGOR_bio(in, NULL);
    ec->contentEncryptionAlgorithm = calg;
    
    BIO *cmsbio = cms_EncryptedContent_init_bio(ec);
    out = BIO_push(cmsbio, out);
        
    if(BIO_read(in, header, 2) != 2) {
        goto end;
    }

    unsigned char c;
    do {
        BIO_read(in, (char *)&c, 1);
        l = read_length(in);
        if(c) {
            char *buffer[4096];
            do {
                unsigned int i = l > sizeof(buffer) ? sizeof(buffer) : l;
                if(BIO_read(in, buffer, i) != i) {
                    goto end;
                }
                BIO_write(out, buffer, i);
                l -= i;
            } while(l > 0);
        }
    } while(c != 0);
    BIO_flush(out);

    ret = 0;
    
 end:
    return ret;
}

int decrypt_cms_legacy(BIO *in, BIO *out, char *password, X509 *x509, EVP_PKEY *key)
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
    ret = 0;

 end:
    return ret;
}
