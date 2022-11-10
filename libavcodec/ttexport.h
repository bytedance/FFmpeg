/*
 * Export private or deprecated symbols
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

#ifndef AVCODEC_TTEXPORT_H
#define AVCODEC_TTEXPORT_H

#include "libavcodec/avcodec.h"


/**
 * A custom AVCodec register for private codec implementation
 * 
 * @param codec  pointer to AVCodec, only support a samll set of codecs.
 * @param codec_size additional abi check, must be same as sizeof(AVCodec)
 * @return int Return 0 for success, others failed.
 */
int tt_register_avcodec(AVCodec *codec, int codec_size);

typedef struct AVStreamInternal AVStreamInternal;

AVCodecContext *tt_avstream_get_avctx_from_internal(AVStreamInternal *internal);

#endif /* AVCODEC_TTEXPORT_H */