/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */

#ifndef AVUTIL_DRM_H
#define AVUTIL_DRM_H

#include <stdint.h>
#include "libavutil/ttmapp.h"
#include "libavutil/ttexport.h"
/**
 * Open and init a drm context
 * 
 * @param handle Pointer to user-supplied Context
 * @param kid A key id
 */
int av_drm_open(void *handle, const char *kid);

/**
 * Decrypt the data in src
 * 
 * @param handle Pointer to user-supplied Context
 */
int av_drm_decrypt(void *handle, const uint8_t *src, const int count, const uint8_t *iv, uint8_t *dst);

/**
 * Close and reset the drm context
 * 
 * @param handle Pointer to user-supplied Context
 */
void av_drm_close(void *handle);

/*
* @deprecated Use av_drm_open instead.
*/
int av_idrm_open(aptr_t unused, void *handle, const char *kid);

/*
* @deprecated Use av_drm_close instead.
*/
void av_idrm_close(aptr_t unused, void *handle);

#endif /* AVUTIL_DRM_H */
