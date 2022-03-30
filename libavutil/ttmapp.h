/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */

#ifndef AVUTIL_TTMAPP_H
#define AVUTIL_TTMAPP_H

#include "common.h"

/**
 * dns resolver delegate methods
 * and network callback methods
 */
typedef void* (*getaddrinfo_a_start)(aptr_t handle,const char* hostname, int user_flag);
typedef int   (*getaddrinfo_a_result)(void* object,char* ipaddress,int size);
typedef void  (*getaddrinfo_a_free)(void* object);
typedef void* (*save_host_addr)(aptr_t handle, const char* ip, int user_flag);
typedef void* (*network_info_callback)(aptr_t handle,int key,int64_t value,const char* strValue);
typedef void  (*network_log_callback)(aptr_t handle, int type, int user_flag);
typedef void  (*tcp_io_read_callback)(aptr_t handle, int type, int size);


/**
 * Drm open decrypt and close methods
 */
typedef int (*fun_drm_open)(void *handle, const char *kid);
typedef int (*fun_drm_open2)(void *handle, const char *kid, const char *line);
typedef int (*fun_drm_decrypt)(void *handle, const uint8_t *src, const int count, const uint8_t *iv, uint8_t *dst);
typedef void (*fun_drm_close)(void *handle);
typedef int (*fun_drm_decrypt_segment)(void *handle, const uint8_t *src, const int src_size, const int segment_num, uint8_t *dst, int *dst_size, int flag);

#define TTM_APP_CALLBACK_CTX_VERSION 20201231

typedef struct TTmAppCallbackCtx {
    intptr_t                magic;
    int                     version;

    getaddrinfo_a_start     addr_start;
    getaddrinfo_a_result    addr_result;
    getaddrinfo_a_free      addr_free;
    save_host_addr          save_ip;
    network_log_callback    log_callback;
    tcp_io_read_callback    io_callback;
    network_info_callback   info_callback;

    fun_drm_open            drm_open;
    fun_drm_decrypt         drm_decrypt;
    fun_drm_close           drm_close;
    fun_drm_open2           drm_open2;
    fun_drm_decrypt_segment drm_decrypt_seg;
} TTmAppCallbackCtx;


intptr_t av_ttm_app_magic(void);

/**
 * cast handle to pointer of TTmAppCallbackCtx 
 * if handle is a valid TTmAppCallbackCtx.
 * This will check magic and version.
 * If check failed, av_ttm_app_cast return NULL;
 */
TTmAppCallbackCtx* av_ttm_app_cast(aptr_t handle);

#endif /* AVUTIL_TTMAPP_H */