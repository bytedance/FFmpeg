/*
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

#include "ttexport.h"
#include "codec_id.h"
#include <string.h>

AVCodec ff_bytevc1_decoder = {.name = "none", .id = AV_CODEC_ID_NONE};
AVCodec ff_bytevc2_decoder = {.name = "none", .id = AV_CODEC_ID_NONE};

int tt_register_avcodec(AVCodec *codec, int codec_size)
{
    int ret = -1;
    if (codec_size != sizeof(AVCodec))
        return ret;
    if (codec && codec->name) {
        ret = 0;
        if (codec->id == AV_CODEC_ID_BYTE_VC2) {
            memcpy(&ff_bytevc2_decoder, codec, codec_size);
        } else if (strcmp(codec->name, "libbytevc1dec") == 0) {
            memcpy(&ff_bytevc1_decoder, codec, codec_size);
        } else {
            ret = -1;
        }
    }
    return ret;
}