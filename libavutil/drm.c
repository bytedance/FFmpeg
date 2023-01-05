/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */

#include <stddef.h>
#include <stdint.h>

#include "drm.h"
#include "ttexport.h"

typedef struct DrmCtx {
    tt_drm_open open;
    tt_drm_decrypt decrypt;
    tt_drm_close close;
} DrmCtx;

static DrmCtx g_drm = {
    .open = NULL,
    .decrypt = NULL,
    .close = NULL,
};

void tt_register_drm(tt_drm_open open, tt_drm_decrypt decrypt, tt_drm_close close)
{
    g_drm.open = open;
    g_drm.decrypt = decrypt;
    g_drm.close = close;
}

static int av_drm_support() {
    if (g_drm.open == NULL || g_drm.decrypt == NULL || g_drm.close == NULL) {
        return 0;
    }
    return 1;
}

int av_drm_open(void *handle, const char *kid) {
    if (av_drm_support()) {
        return g_drm.open(handle, kid);
    }
    return -1;
}

int av_drm_decrypt(void *handle, const uint8_t *src, const int count, const uint8_t *iv, uint8_t *dst) {
    if (av_drm_support()) {
        return g_drm.decrypt(handle, src, count, iv, dst);
    }
    return -1;
}

void av_drm_close(void *handle)
{
    if (av_drm_support()) {
        return g_drm.close(handle);
    }
}

int av_idrm_open(aptr_t unused, void *handle, const char *kid) {
    if (av_drm_support()) {
        return g_drm.open(handle, kid);
    }
    return -1;
}

void av_idrm_close(aptr_t unused, void *handle) {
    if (av_drm_support()) {
        return g_drm.close(handle);
    } 
}