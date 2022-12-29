/*
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
 *
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */

#ifndef AVCODEC_BYTEVC2_H
#define AVCODEC_BYTEVC2_H

enum BYTEVC2NALUnitType {
    BYTEVC2_NAL_TYPE_0 = 10,
    BYTEVC2_NAL_TYPE_1 = 14,
    BYTEVC2_NAL_TYPE_2 = 15,
    BYTEVC2_NAL_TYPE_3 = 16,
    BYTEVC2_NAL_TYPE_4 = 17,
    BYTEVC2_NAL_TYPE_5 = 18,
    BYTEVC2_NAL_TYPE_6 = 19,
    BYTEVC2_NAL_TYPE_7 = 23,
    BYTEVC2_NAL_TYPE_8 = 24,
    BYTEVC2_NAL_TYPE_9 = 29,
    BYTEVC2_NAL_TYPE_10 = 30,
    BYTEVC2_NAL_TYPE_11 = 31,
};

#define BYTEVC2_MAX_SUB_LAYERS 7
#define BYTEVC2_MAX_SHORT_TERM_RPS_COUNT 64
#define BYTEVC2_MAX_LADF_INTERVALS 5
#define BYTEVC2_SCALING_LIST_REM_NUM 6
#define BYTEVC2_SCALING_LIST_NUM (3*(4-2))

#endif /* AVCODEC_BYTEVC2_H */
