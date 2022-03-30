/*
 * Copyright (c) 2003 Fabrice Bellard
 * Copyright (c) 2013 Zhang Rui <bbcallen@gmail.com>
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
 * 
 * This file may have been modified by Bytedance Inc. (“Bytedance Modifications”). 
 * All Bytedance Modifications are Copyright 2022 Bytedance Inc.		
 */

#include <stdlib.h>
#include "url.h"

#define TT_FF_PROTOCOL(x)                                                                \
    extern URLProtocol ff_##x##_protocol;                                                \
    int ttav_register_##x##_protocol(URLProtocol *protocol, int protocol_size);          \
    int ttav_register_##x##_protocol(URLProtocol *protocol, int protocol_size) {         \
        if (protocol_size != sizeof(URLProtocol)) {                                      \
            av_log(NULL, AV_LOG_ERROR, "ttav_register_##x##_protocol: ABI mismatch.\n"); \
            return -1;                                                                   \
        }                                                                                \
        memcpy(&ff_##x##_protocol, protocol, protocol_size);                             \
        return 0;                                                                        \
    }

#define TT_DUMMY_PROTOCOL(x)                        \
    TT_FF_PROTOCOL(x);                              \
    static const AVClass tt_##x##_context_class = { \
        .class_name = #x,                           \
        .item_name = av_default_item_name,          \
        .version = LIBAVUTIL_VERSION_INT,           \
    };                                              \
                                                    \
    URLProtocol ff_##x##_protocol = {               \
        .name = #x,                                 \
        .url_open2 = ttdummy_open,                  \
        .priv_data_size = 1,                        \
        .priv_data_class = &tt_##x##_context_class, \
    };

static int ttdummy_open(URLContext *h, const char *arg, int flags, AVDictionary **options) {
    return -1;
}

TT_DUMMY_PROTOCOL(mem);
TT_DUMMY_PROTOCOL(quic);
TT_DUMMY_PROTOCOL(rearquic);
TT_DUMMY_PROTOCOL(mdl);
TT_DUMMY_PROTOCOL(live);
TT_DUMMY_PROTOCOL(httpx);
TT_DUMMY_PROTOCOL(rearhttpx);
TT_DUMMY_PROTOCOL(thirdparty);
