/*
 * Copyright (c) 2015 Bilibili
 * Copyright (c) 2015 Zhang Rui <bbcallen@gmail.com>
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 * 
 * This file may have been modified by Bytedance Inc. ("Bytedance Modifications").
 * All Bytedance Modifications are Copyright 2022 Bytedance Inc.
 */

#include <assert.h>

#include "libavutil/avstring.h"
#include "libavutil/log.h"
#include "libavutil/opt.h"
#include "libavcodec/jni.h"
#include "libavcodec/ffjni.h"

#include "avformat.h"
#include "url.h"


//follow android original design
#define BUFFER_SIZE 64 * 1024

#define MDS_VERSION_0 0
#define MDS_VERSION_1 1 

typedef struct Context {
    AVClass        *class;

    /* options */
    int             fd;
    int             version;
    char*           file_path;
    int64_t         logical_pos;
    int64_t         logical_size;
    jobject         media_data_source;
    jbyteArray      jbuffer;
    jmethodID       readMethod;
    jmethodID       closeMethod;
    jmethodID       readMethod2;
    jmethodID       closeMethod2;
} Context;

static int mds_open(URLContext *h, const char *arg, int flags, AVDictionary **options)
{
    Context *c = h->priv_data;
    c->closeMethod = NULL;
    c->jbuffer = NULL;
    c->readMethod = NULL;
    c->media_data_source = NULL;
    c->logical_pos = 0;
    c->logical_size = -1;
    c->fd = -1;
    c->version = MDS_VERSION_0;
    c->file_path = NULL;
    c->readMethod2 = NULL;
    c->closeMethod2 = NULL;
    if(h->interrupt_callback.callback != NULL && ff_check_interrupt(&h->interrupt_callback)) {
        return AVERROR_EXIT;
    }
    jobject media_data_source = NULL;
    char *endPtr = NULL;

    JNIEnv *env = NULL;
    env = ff_jni_get_env(NULL);
    if (!env) {
        av_log(h, AV_LOG_ERROR, "non java vm");
        return AVERROR(EINVAL);
    }
    av_log(h, AV_LOG_INFO, "mds arg:%s", arg);
    //Example:"mediadatasource://4337344576/mds_default_file"
    av_strstart(arg, "mediadatasource://", &arg);

    media_data_source = (jobject) (intptr_t) strtoll(arg, &endPtr, 10);
    if (!media_data_source) {
        av_log(h, AV_LOG_ERROR, "non media datasource pointer");
        return AVERROR(EINVAL);
    }
    
    if (endPtr) {
        int length = strlen(endPtr);
        c->file_path =  malloc(length + 1);
        memcpy(c->file_path, endPtr, length + 1);
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

    jmethodID methodVersion = (*env)->GetMethodID(env, cls, "getMDSVersion", "()I");
    if (methodVersion == NULL) {
        av_log(h, AV_LOG_ERROR, "could not find getMDSVersion method");
    } else {
        c->version = (*env)->CallIntMethod(env, media_data_source, methodVersion);
        if (ff_jni_exception_check(env, 1, NULL) < 0) {
            av_log(h, AV_LOG_ERROR, "call getMDSVersion method failed");
            goto fail;
        }
    }
    av_log(h, AV_LOG_INFO, "mds interface verison:%d",c->version);

    if (c->version == MDS_VERSION_0) {
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

        jmethodID method = (*env)->GetMethodID(env, cls, "getSize", "()J");
        if (method == NULL) {
            av_log(h, AV_LOG_ERROR, "could not find getSize method");
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

    } else if (c->version == MDS_VERSION_1) {
        jmethodID open_method = (*env)->GetMethodID(env, cls, "open", "(Ljava/lang/String;)I");
        if (open_method == NULL) {
            av_log(h, AV_LOG_ERROR, "could not find open method");
            goto fail;
        } 

        jstring file_path = (*env)->NewStringUTF(env, c->file_path);
        c->fd = (*env)->CallIntMethod(env, media_data_source, open_method, file_path);
        if (ff_jni_exception_check(env, 1, NULL) < 0) {
            av_log(h, AV_LOG_ERROR, "call open method failed");
            goto fail;
        } else if (c->fd < 0) {
            av_log(h, AV_LOG_ERROR, "open file:%s failed",c->file_path);
            goto fail;
        }

        jmethodID getSize_method = (*env)->GetMethodID(env, cls, "getSize", "(I)J");
        if (getSize_method == NULL) {
            av_log(h, AV_LOG_ERROR, "could not find getSize method");
            goto fail;
        }
        
        c->logical_size = (*env)->CallLongMethod(env, media_data_source, getSize_method, c->fd);
        if (ff_jni_exception_check(env, 1, NULL) < 0) {
            av_log(h, AV_LOG_ERROR, "call getSize method failed");
            goto fail;
        } else if (c->logical_size < 0) {
            h->is_streamed = 1;
            c->logical_size = -1;
        }

        c->readMethod2 = (*env)->GetMethodID(env, cls, "readAt", "(IJLjava/nio/ByteBuffer;II)I");
        if (c->readMethod2 == NULL) {
            av_log(h, AV_LOG_ERROR, "could not find readAt2(ByteBuffer) method");
            goto fail;
        }

        c->closeMethod2  = (*env)->GetMethodID(env, cls, "close", "(I)I");
        if (c->closeMethod2 == NULL) {
            av_log(h, AV_LOG_ERROR, "could not find close2 method");
            goto fail;
        } 
    }
    av_log(h, AV_LOG_INFO, "mds file:%s, size:%lld", arg, c->logical_size);
    return 0;
fail:
    (*env)->DeleteLocalRef(env,cls);
    return AVERROR(EINVAL);
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
    if (c->version == MDS_VERSION_0) {
        ret = (*env)->CallIntMethod(env, c->media_data_source, c->readMethod, c->logical_pos, c->jbuffer, 0, size);
    } else if (c->version == MDS_VERSION_1) {
        jobject directBuffer = (*env)->NewDirectByteBuffer(env, (void *)buf, size);
        // av_log(h, AV_LOG_INFO, "mds NewDirectByteBuffer:%lld,buffer:%lld, size:%d",directBuffer, buf, size);
        ret = (*env)->CallIntMethod(env, c->media_data_source, c->readMethod2, c->fd, c->logical_pos, directBuffer, 0, size);
        (*env)->DeleteLocalRef(env, directBuffer);
    }
    av_log(h, AV_LOG_DEBUG, "mds recv size:%d", ret);
    if (ff_jni_exception_check(env, 1, NULL) < 0)
        return AVERROR(EIO);
    else if (ret < 0)
        return AVERROR_EOF;
    else if (ret == 0)
        return AVERROR(EAGAIN);

    if (c->version == MDS_VERSION_0) {
       (*env)->GetByteArrayRegion(env, c->jbuffer, 0, ret, (jbyte*)buf);
    } else if (c->version == MDS_VERSION_1) {
        
    }
    
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


    if (c->version == MDS_VERSION_0) {
       ret = (*env)->CallIntMethod(env, c->media_data_source, c->readMethod, new_logical_pos, c->jbuffer, 0, 0);
    } else if (c->version == MDS_VERSION_1) {
       ret = (*env)->CallIntMethod(env, c->media_data_source, c->readMethod2, c->fd, new_logical_pos, NULL, 0, 0);
    }
    av_log(h, AV_LOG_INFO, "mds seek:%lld ret:%d",new_logical_pos, ret);
    if (ff_jni_exception_check(env, 1, NULL) < 0)
        return AVERROR(EIO);
    else if (ret < 0)
        return AVERROR_EOF;

    c->logical_pos = new_logical_pos;
    return c->logical_pos;
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
    
    if (c->file_path) {
       av_log(h, AV_LOG_INFO, "mds close file:%s", c->file_path);
       free(c->file_path);
       c->file_path = NULL;
    }
    
    if (c->jbuffer != NULL)
        (*env)->DeleteGlobalRef(env, c->jbuffer);
    
    if (c->media_data_source != NULL) {
        if (c->version == MDS_VERSION_0) {
            (*env)->CallVoidMethod(env, c->media_data_source, c->closeMethod);
        } else if (c->version == MDS_VERSION_1) {
            (*env)->CallIntMethod(env, c->media_data_source, c->closeMethod2, c->fd);
        }
        ff_jni_exception_check(env, 1, NULL);
        (*env)->DeleteGlobalRef(env, c->media_data_source);
    }

    return 0;
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
    .default_whitelist   = "mediadatasource,crypto"
};
