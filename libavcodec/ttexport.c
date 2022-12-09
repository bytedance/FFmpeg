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
#include "avcodec.h"
#include "codec_id.h"
#include <string.h>
#include "libavformat/internal.h"

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

AVCodecParser ff_bvc1_parser = { .codec_ids = {0} };
AVCodecParser ff_bvc2_parser = { .codec_ids = {0} };

int tt_register_codec_parser(AVCodecParser *parser, const char *name, int parser_size)
{
    int ret = -1;
    if (parser_size != sizeof(AVCodecParser))
        return ret;
    if (name) {
        ret = 0;
        if (strcmp(name, "bvc1") == 0) {
            memcpy(&ff_bvc1_parser, parser, parser_size);
        } else if (strcmp(name, "bvc2") == 0) {
            memcpy(&ff_bvc2_parser, parser, parser_size);
        } else {
            ret = -1;
        }
    }
    return ret;
}

AVCodecContext *tt_avstream_get_avctx_from_internal(AVStreamInternal *internal){
    if (internal != NULL) {
        return internal->avctx;
    }
    return NULL;
}