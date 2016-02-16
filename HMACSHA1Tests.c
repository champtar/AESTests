#include "HMACSHA1Tests.h"

#include <openssl/hmac.h>
#include <stdint.h>
#include <stdlib.h>

#include <stdio.h>

JNIEXPORT jlong JNICALL Java_HMACSHA1Tests_OPENSSL_1HMACSHA1_1CTX_1create
  (JNIEnv *env, jclass clazz) {
    HMAC_CTX *ctx = malloc(sizeof(HMAC_CTX));
    if (ctx)
        HMAC_CTX_init(ctx);

    return (jlong) (intptr_t) ctx;
}

JNIEXPORT void JNICALL Java_HMACSHA1Tests_OPENSSL_1HMACSHA1_1CTX_1destroy
  (JNIEnv *env, jclass clazz, jlong ctx) {
    if (ctx) {
        HMAC_CTX *ctx_ = (HMAC_CTX *) (intptr_t) ctx;
        HMAC_CTX_cleanup(ctx_);
        free(ctx_);
    }
}

JNIEXPORT jboolean JNICALL Java_HMACSHA1Tests_OPENSSL_1HMACSHA1_1CTX_1init
  (JNIEnv *env, jclass clazz, jlong ctx, jbyteArray key) {
    unsigned char key_[16];
    (*env)->GetByteArrayRegion(env, key, 0, 16, key_);

    return HMAC_Init_ex((HMAC_CTX *) (intptr_t) ctx, key_, 16, EVP_sha1(), NULL);

}

JNIEXPORT jboolean JNICALL Java_HMACSHA1Tests_OPENSSL_1HMACSHA1_1CTX_1process
  (JNIEnv *env, jclass clazz, jlong ctx, jbyteArray inOut, jint inOffset, jint inLen, jint outOffset) {
    int ok = 0;
    jbyte *inOut_;
    inOut_ = (*env)->GetPrimitiveArrayCritical(env, inOut, NULL);
    if (!inOut)
        goto exit1;

    ok = HMAC_Update((HMAC_CTX *) (intptr_t) ctx, (unsigned char *) (inOut_ + inOffset), inLen);
    if(ok == 0)
        goto exit1;
    ok = HMAC_Final((HMAC_CTX *) (intptr_t) ctx, (unsigned char *) (inOut_ + outOffset), NULL);

exit1:
    if (inOut_)
        (*env)->ReleasePrimitiveArrayCritical(env, inOut, inOut_, 0);

    return ok;
}


JNIEXPORT jboolean JNICALL Java_HMACSHA1Tests_OPENSSL_1HMACSHA1_1process
  (JNIEnv *env, jclass clazz, jbyteArray key, jbyteArray inOut, jint inOffset, jint inLen, jint outOffset)
{
    int ok = 0;
    unsigned char key_[16];
    (*env)->GetByteArrayRegion(env, key, 0, 16, key_);
    jbyte *inOut_;
    inOut_ = (*env)->GetPrimitiveArrayCritical(env, inOut, NULL);
    if (!key_ || !inOut)
        goto exit;

    if (HMAC(
        EVP_sha1(),
        key_,
        16,
        (unsigned char *) (inOut_ + inOffset),
        inLen,
        (unsigned char *) (inOut_ + outOffset),
        NULL
    ) != NULL)
        ok = 1;

exit:
    if (inOut_)
        (*env)->ReleasePrimitiveArrayCritical(env, inOut, inOut_, 0);

    return ok;
}

