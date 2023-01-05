/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 *
 *
 * Export private or deprecated symbols
 */

#include "ttexport.h"
#include "avcodec.h"
#include "libavformat/internal.h"

int tt_register_avcodec(AVCodec *codec, int codec_size)
{
    avcodec_register(codec);
    return 0;
}

int tt_register_codec_parser(AVCodecParser *parser, const char *name, int parser_size)
{
    av_register_codec_parser(parser);
    return 0;
}

int tt_register_bitstream_filter(AVBitStreamFilter *bsf, int bsf_size)
{
    av_register_bitstream_filter(bsf);
    return 0;
}


AVCodecContext *tt_avstream_get_avctx_from_internal(AVStreamInternal *internal){
    if (internal != NULL) {
        return internal->avctx;
    }
    return NULL;
}