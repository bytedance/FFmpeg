/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */

#include "ttmapp.h"
#include "log.h"

static const void *magic = &magic;

intptr_t av_ttm_app_magic()
{
    return (intptr_t)magic;
}


TTmAppCallbackCtx* av_ttm_app_cast(aptr_t handle)
{
    TTmAppCallbackCtx* callback = (TTmAppCallbackCtx*) handle;
    if (callback == NULL || callback->magic != magic)
        return NULL;
    if (callback->version != TTM_APP_CALLBACK_CTX_VERSION)
        av_log(NULL, AV_LOG_FATAL, "unmatched ttm app callback version: %d != %d", TTM_APP_CALLBACK_CTX_VERSION, callback->version);
    return callback;
}