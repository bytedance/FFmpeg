/*
 * Copyright (c) 2015 Bilibili
 * Copyright (c) 2015 Zhang Rui <bbcallen@gmail.com>
 *
 * This file is part of ijkPlayer.
 *
 * ijkPlayer is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * ijkPlayer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with ijkPlayer; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 * 
 * This file may have been modified by Bytedance Inc. (“Bytedance Modifications”).
 * All Bytedance Modifications are Copyright 2022 Bytedance Inc.
 */

#include <assert.h>
#include "libavformat/avformat.h"
#include "libavformat/url.h"
#include "libavutil/avstring.h"
#include "libavutil/log.h"
#include "libavutil/opt.h"
#include "libavcodec/jni.h"
#include "libavcodec/ffjni.h"

//follow android original design
#define BUFFER_SIZE 64 * 1024

typedef struct Context {
    AVClass        *class;

    /* options */
    int64_t         logical_pos;
    int64_t         logical_size;

    jobject         media_data_source;
    jbyteArray      jbuffer;
    jmethodID       readMethod;
    jmethodID       closeMethod;
} Context;

static int mds_open(URLContext *h, const char *arg, int flags, AVDictionary **options)
{
    Context *c = h->priv_data;
    c->closeMethod = NULL;
    c->jbuffer = NULL;
    c->readMethod = NULL;
    c->media_data_source = NULL;
    jobject media_data_source = NULL;
    char *final = NULL;

    JNIEnv *env = NULL;
    env = ff_jni_get_env(NULL);
    if (!env) {
        av_log(h, AV_LOG_ERROR, "non java vm");
        return AVERROR(EINVAL);
    }
    
    av_strstart(arg, "mediadatasource:", &arg);

    media_data_source = (jobject) (intptr_t) strtoll(arg, &final, 10);
    if (!media_data_source) {
        av_log(h, AV_LOG_ERROR, "non media datasource pointer");
        return AVERROR(EINVAL);
    }

    c->media_data_source = (*env)->NewGlobalRef(env, media_data_source);
    if (ff_jni_exception_check(env, 1, NULL) < 0 || !c->media_data_source) {
        av_log(h, AV_LOG_ERROR, "new mediadatasource failed");
        return AVERROR(ENOMEM);
    }

    jclass cls = (*env)->GetObjectClass(env, c->media_data_source);
    if (cls == NULL) {
        av_log(h, AV_LOG_ERROR, "could not found media datasource class");
        return AVERROR(EINVAL);
    }

    jmethodID method = (*env)->GetMethodID(env, cls, "getSize", "()J");
    if (method == NULL) {
        av_log(h, AV_LOG_ERROR, "could not find getSize method");
        goto fail;
    }

    c->readMethod = (*env)->GetMethodID(env, cls, "readAt", "(J[BII)I");
    if (c->readMethod == NULL) {
        av_log(h, AV_LOG_ERROR, "could not find readAt method");
        goto fail;
    }

    c->closeMethod = (*env)->GetMethodID(env, cls, "close", "()V");
    if (c->closeMethod == NULL) {
        av_log(h, AV_LOG_ERROR, "could not find close method");
        goto fail;
    }

    c->logical_size = (*env)->CallLongMethod(env, media_data_source, method);
    if (ff_jni_exception_check(env, 1, NULL) < 0) {
        av_log(h, AV_LOG_ERROR, "call read method failed");
        goto fail;
    } else if (c->logical_size < 0) {
        h->is_streamed = 1;
        c->logical_size = -1;
    }

    jbyteArray tmp = (*env)->NewByteArray(env, BUFFER_SIZE);
    if (ff_jni_exception_check(env, 1, NULL) < 0 || !tmp) {
        av_log(h, AV_LOG_ERROR, "NewByteArray failed");
        goto fail;
    }

    c->jbuffer = (*env)->NewGlobalRef(env,tmp);
    (*env)->DeleteLocalRef(env, tmp);
    return 0;
fail:
    (*env)->DeleteLocalRef(env,cls);
    return AVERROR(EINVAL);
}

static int mds_close(URLContext *h)
{
    Context *c = h->priv_data;
    JNIEnv *env = NULL;

    env = ff_jni_get_env(NULL);
    if (!env) {
        av_log(h, AV_LOG_ERROR, "non java vm");
        return AVERROR(EINVAL);
    }

    if (c->jbuffer != NULL)
        (*env)->DeleteGlobalRef(env, c->jbuffer);

    if (c->media_data_source != NULL) {
        (*env)->CallVoidMethod(env, c->media_data_source, c->closeMethod);
        ff_jni_exception_check(env, 1, NULL);
        (*env)->DeleteGlobalRef(env, c->media_data_source);
    }

    return 0;
}

static int mds_read(URLContext *h, unsigned char *buf, int size)
{
    Context    *c = h->priv_data;
    JNIEnv     *env = NULL;
    jint        ret = 0;

    env = ff_jni_get_env(NULL);
    if (!env) {
        av_log(h, AV_LOG_ERROR, "non java vm");
        return AVERROR(EINVAL);
    }

    if (!c->media_data_source) 
        return AVERROR(EINVAL);

    if (size > BUFFER_SIZE)
        size = BUFFER_SIZE;

    ret = (*env)->CallIntMethod(env, c->media_data_source, c->readMethod, c->logical_pos, c->jbuffer, 0, size);
    if (ff_jni_exception_check(env, 1, NULL) < 0)
        return AVERROR(EIO);
    else if (ret < 0)
        return AVERROR_EOF;
    else if (ret == 0)
        return AVERROR(EAGAIN);

    (*env)->GetByteArrayRegion(env, c->jbuffer, 0, ret, (jbyte*)buf);
    if (ff_jni_exception_check(env, 1, NULL) < 0)
        return AVERROR(EIO);

    c->logical_pos += ret;
    return ret;
}

static int64_t mds_seek(URLContext *h, int64_t pos, int whence)
{
    Context *c = h->priv_data;
    int64_t  ret;
    int64_t  new_logical_pos;
    JNIEnv     *env = NULL;

    env = ff_jni_get_env(NULL);
    if (!env) {
        av_log(h, AV_LOG_ERROR, "non java vm");
        return AVERROR(EINVAL);
    }

    if (!c->media_data_source) 
        return AVERROR(EINVAL);

    if (whence == AVSEEK_SIZE) {
        av_log(h, AV_LOG_TRACE, "%s: AVSEEK_SIZE: %"PRId64"\n", __func__, (int64_t)c->logical_size);
        return c->logical_size;
    } else if (whence == SEEK_CUR) {
        av_log(h, AV_LOG_TRACE, "%s: %"PRId64"\n", __func__, pos);
        new_logical_pos = pos + c->logical_pos;
    } else if (whence == SEEK_SET){
        av_log(h, AV_LOG_TRACE, "%s: %"PRId64"\n", __func__, pos);
        new_logical_pos = pos;
    } else {
        return AVERROR(EINVAL);
    }
    if (new_logical_pos < 0)
        return AVERROR(EINVAL);

    ret = (*env)->CallIntMethod(env, c->media_data_source, c->readMethod, new_logical_pos, c->jbuffer, 0, 0);
    if (ff_jni_exception_check(env, 1, NULL) < 0)
        return AVERROR(EIO);
    else if (ret < 0)
        return AVERROR_EOF;

    c->logical_pos = new_logical_pos;
    return c->logical_pos;
}

#define OFFSET(x) offsetof(Context, x)
#define D AV_OPT_FLAG_DECODING_PARAM

static const AVOption options[] = {
    { NULL }
};

#undef D
#undef OFFSET

static const AVClass mediadatasource_context_class = {
    .class_name = "mediadatasource",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};

URLProtocol ff_mediadatasource_protocol = {
    .name                = "mediadatasource",
    .url_open2           = mds_open,
    .url_read            = mds_read,
    .url_seek            = mds_seek,
    .url_close           = mds_close,
    .priv_data_size      = sizeof(Context),
    .priv_data_class     = &mediadatasource_context_class,
};
