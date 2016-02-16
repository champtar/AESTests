#include "AESTests.h"

#include <openssl/evp.h>
#include <stdint.h>
#include <stdlib.h>

#include <stdio.h>

JNIEXPORT jlong JNICALL Java_AESTests_OPENSSL_1CTR_1CTX_1create
  (JNIEnv *env, jclass clazz)
{
    EVP_CIPHER_CTX *ctx = malloc(sizeof(EVP_CIPHER_CTX));

    int ok = -1;
    if (ctx) {
        EVP_CIPHER_CTX_init(ctx);
        ok = EVP_CipherInit_ex(ctx, EVP_aes_128_ctr(), NULL, NULL, NULL, 1);
    }
    return (jlong) (intptr_t) ctx;
}

JNIEXPORT void JNICALL Java_AESTests_OPENSSL_1CTR_1CTX_1destroy
  (JNIEnv *env, jclass clazz, jlong ctx)
{
    if (ctx) {
        EVP_CIPHER_CTX *ctx_ = (EVP_CIPHER_CTX *) (intptr_t) ctx;
        EVP_CIPHER_CTX_cleanup(ctx_);
        free(ctx_);
    }
}

JNIEXPORT jboolean JNICALL Java_AESTests_OPENSSL_1CTR_1CTX_1compute
  (JNIEnv *env, jclass clazz, jlong ctx, jbyteArray iv, jbyteArray key, jbyteArray inOut, jint offset, jint len)
{
    int ok = 0;
    unsigned char iv_[16];
    (*env)->GetByteArrayRegion(env, iv, 0, 16, iv_);
    unsigned char key_[16];
    (*env)->GetByteArrayRegion(env, key, 0, 16, key_);
    jbyte *inOut_;
    inOut_ = (*env)->GetPrimitiveArrayCritical(env, inOut, NULL);
    if (!iv_ || !key_ || !inOut)
        goto exit;

    ok = EVP_CipherInit_ex(
                (EVP_CIPHER_CTX *) (intptr_t) ctx,
                NULL,
                NULL,
                (unsigned char *) key_,
                (unsigned char *) iv_,
                -1);
    if(ok == 0)
        goto exit;

    int len_ = len;
    ok = EVP_CipherUpdate(
                (EVP_CIPHER_CTX *) (intptr_t) ctx,
                (unsigned char *) (inOut_ + offset), &len_,
                (unsigned char *) (inOut_ + offset), len);

exit:
    if (inOut_)
        (*env)->ReleasePrimitiveArrayCritical(env, inOut, inOut_, 0);

    return ok;
}

