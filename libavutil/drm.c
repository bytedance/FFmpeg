/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */

#include "drm.h"
#include "common.h"
#include "ttmapp.h"

static drm g_drm = {
    .open = NULL,
    .decrypt = NULL,
    .close = NULL,
};

int av_drm_support() {
    if (g_drm.open == NULL || g_drm.decrypt == NULL || g_drm.close == NULL) {
        return 0;
    }
    return 1;
}

void av_drm_init(void *open, void *decrypt, void *close, void *open2, void *decrypt_seg) {
    g_drm.open = (fun_drm_open) open;
    g_drm.decrypt = (fun_drm_decrypt) decrypt;
    g_drm.close = (fun_drm_close) close;
}

int av_drm_support2(aptr_t cbptr) {
    TTmAppCallbackCtx *cb = av_ttm_app_cast(cbptr);
    if (cb && cb->drm_open && cb->drm_decrypt && cb->drm_close) {
        return 1;
    }
    return av_drm_support();
}

int av_idrm_open(aptr_t cbptr, void *handle, const char *kid) {
    TTmAppCallbackCtx *cb = av_ttm_app_cast(cbptr);
    if (cb == NULL) {
        if (av_drm_support()) {
            return g_drm.open(handle, kid);
        }
    } else if (cb->drm_open && cb->drm_decrypt && cb->drm_close){
        return cb->drm_open(handle, kid);
    }
    return -1;
}

int av_idrm_decrypt(aptr_t cbptr, void *handle, const uint8_t *src, const int count, const uint8_t *iv, uint8_t *dst) {
    TTmAppCallbackCtx *cb = av_ttm_app_cast(cbptr);
    if (cb == NULL) {
        if (av_drm_support()) {
            return g_drm.decrypt(handle, src, count, iv, dst);
        }
    } else if (cb->drm_decrypt && cb->drm_close) {
        return cb->drm_decrypt(handle, src, count, iv, dst);
    }
    return -1;
}

void av_idrm_close(aptr_t cbptr, void *handle) {
    TTmAppCallbackCtx *cb = av_ttm_app_cast(cbptr);
    if (cb == NULL) {
        if (av_drm_support()) {
            return g_drm.close(handle);
        }
    } else if (cb->drm_close) {
        cb->drm_close(handle);
    }
}
