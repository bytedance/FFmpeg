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


#include <string.h>
#include "mdl_info_wrapper.h"

static MDLInfoCallBackContext gMDLInfoCallBackContext = {
    .registerHandle = NULL,
    .mdlInfoCallBack = NULL,
};

void tt_register_mdlctx(MDLInfoCallBackContext *context)
{
    if (context) {
        memcpy(&gMDLInfoCallBackContext, context, sizeof(gMDLInfoCallBackContext));
    }
}

void mdl_info_register_handle(void *handle) {
    if (gMDLInfoCallBackContext.registerHandle) {
        gMDLInfoCallBackContext.registerHandle(handle);
    }
}

int64_t mdl_info_get_int64_value(void *fileKey, int key, int64_t extraParamter) {
    if (gMDLInfoCallBackContext.mdlInfoCallBack) {
        return gMDLInfoCallBackContext.mdlInfoCallBack(fileKey, key, extraParamter);
    }
    return -1;
}

int64_t mdl_info_set_int64_value(void *traceId, int key, int64_t handle) {
    if (gMDLInfoCallBackContext.mdlInfoCallBack) {
        return gMDLInfoCallBackContext.mdlInfoCallBack(traceId, key, handle);
    }
    return -1;
}
