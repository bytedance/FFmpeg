/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */

#include <string.h>
#include "mdl_info_wrapper.h"

static MDLInfoCallBackContext gMDLInfoCallBackContext = {
    .registerHandle = NULL,
    .mdlInfoCallBack = NULL,
};

void register_mdl_info_context(MDLInfoCallBackContext *context) {
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