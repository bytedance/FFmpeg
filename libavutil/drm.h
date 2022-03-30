/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */

#ifndef AVUTIL_DRM_H
#define AVUTIL_DRM_H

#include <stdint.h>
#include "ttmapp.h"

typedef struct drm {
    fun_drm_open open;
    fun_drm_decrypt decrypt;
    fun_drm_close close;
    fun_drm_open2 open2;
    fun_drm_decrypt_segment decrypt_seg;
} drm;

int av_drm_support(void);
int av_drm_support2(aptr_t cbptr);

void av_drm_init(void *open, void *decrypt, void *close, void *open2, void *decrypt_seg);

int av_idrm_open(aptr_t cbptr, void *handle, const char *kid);
int av_idrm_open2(aptr_t cbptr, void *handle, const char *kid, const char *line);
int av_idrm_decrypt(aptr_t cbptr, void *handle, const uint8_t *src, const int count, const uint8_t *iv, uint8_t *dst);
void av_idrm_close(aptr_t cbptr, void *handle);
int av_idrm_decrypt_segment(aptr_t cbptr, void *handle, const uint8_t *src, const int src_size, const int segment_num, uint8_t *dst, int *dst_size, int flag);

#endif /* AVUTIL_DRM_H */
