/*
 * Media Data Loader Wrapper
 * 
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
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
 */

#ifndef AVUTIL_MDL_INFO_WRAPPER_H
#define AVUTIL_MDL_INFO_WRAPPER_H
 
#include <stdint.h>

/*
 * Note: Don't allow to change MDLInfoXXX from mdl!!!
 */
enum MDLInfoKeys {
    MDLCacheEndOffsetS64I = 0,
    MDLPauseDownloadS64I  = 1,
    MDLResumeDownloadS64I  = 2,
};

typedef struct MDLInfoCallBackContext {
    void (*registerHandle)(void *handle);
    int64_t (*mdlInfoCallBack)(void *strKey, int key, int64_t extraParamter);
} MDLInfoCallBackContext;
typedef struct MDLInfoContext {
    char* mdl_file_key;
    char *mdl_load_traceid;
    int64_t mdl_load_handle;
    int mdl_format_type;
} MDLInfoContext;


void mdl_info_register_handle(void *handle);
int64_t mdl_info_get_int64_value(void *fileKey, int key, int64_t extraParamter);
int64_t mdl_info_set_int64_value(void *traceId, int key, int64_t handle);


void tt_register_mdlctx(MDLInfoCallBackContext *context);

#endif /* AVUTIL_MDL_INFO_WRAPPER_H */