/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 *
 *
 * Export private or deprecated symbols
 */

 #include "avcodec.h"


/**
 * Register the codec codec to libavcodec.
 *
 */
int tt_register_avcodec(AVCodec *codec, int codec_size);


/**
 * A custom AVCodecParser register for private codec implementation
 *
 */
int tt_register_codec_parser(AVCodecParser *parser, const char *name, int parser_size);

typedef struct AVBitStreamFilter AVBitStreamFilter;


/**
 * A custom AVBitStreamFilter register for private codec implementation
 *
 */
int tt_register_bitstream_filter(AVBitStreamFilter *bsf, int bsf_size);



typedef struct AVStreamInternal AVStreamInternal;

AVCodecContext *tt_avstream_get_avctx_from_internal(AVStreamInternal *internal);
