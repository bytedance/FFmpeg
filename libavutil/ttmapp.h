/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */

#ifndef AVUTIL_TTMAPP_H
#define AVUTIL_TTMAPP_H

#include "common.h"
#include "ttexport.h"

/**
 * dns resolver delegate methods
 * and network callback methods
 */



/**
 * Drm open decrypt and close methods
 */
typedef int (*fun_drm_open2)(void *handle, const char *kid, const char *line);
typedef int (*fun_drm_decrypt_segment)(void *handle, const uint8_t *src, const int src_size, const int segment_num, uint8_t *dst, int *dst_size, int flag);

#define TTM_APP_CALLBACK_CTX_VERSION 20201231

typedef struct TTmAppCallbackCtx {
    intptr_t                magic;
    int                     version;

    tt_dns_start            addr_start;
    tt_dns_result           addr_result;
    tt_dns_free             addr_free;
    tt_save_ip          save_ip;
    tt_log_callback    log_callback;
    tt_read_callback    io_callback;
    tt_info_callback   info_callback;

    tt_drm_open             drm_open;
    tt_drm_decrypt          drm_decrypt;
    tt_drm_close            drm_close;
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