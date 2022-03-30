/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */

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


void register_mdl_info_context(MDLInfoCallBackContext *context);
void mdl_info_register_handle(void *handle);
int64_t mdl_info_get_int64_value(void *fileKey, int key, int64_t extraParamter);
int64_t mdl_info_set_int64_value(void *traceId, int key, int64_t handle);
