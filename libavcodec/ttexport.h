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

/**
 * A custom AVCodecParser register for private codec implementation
 *
 * @param parser  pointer to AVCodecParser, only support a samll set of codecs.
 * @param name  name of the codec
 * @param parser_size additional abi check, must be same as sizeof(AVCodecParser)
 * @return int Return 0 for success, others failed.
 */
int tt_register_codec_parser(AVCodecParser *parser, const char *name, int parser_size);

typedef struct AVBitStreamFilter AVBitStreamFilter;


/**
 * A custom AVBitStreamFilter register for private codec implementation
 *
 * @param bsf  pointer to AVBitStreamFilter, only support a samll set of codecs.
 * @param bsf_size additional abi check, must be same as sizeof(AVBitStreamFilter)
 * @return int Return 0 for success, others failed.
 */
int tt_register_bitstream_filter(AVBitStreamFilter *bsf, int bsf_size);

typedef struct AVStreamInternal AVStreamInternal;

AVCodecContext *tt_avstream_get_avctx_from_internal(AVStreamInternal *internal);

typedef struct H2645NAL H2645NAL;
typedef struct H264ParamSets H264ParamSets;
typedef struct SPS SPS;
typedef struct PPS PPS;
typedef struct H264POCContext H264POCContext;
typedef struct GetBitContext GetBitContext;

H2645NAL* tt_H2645NAL_malloc(void);
void      tt_H2645NAL_freep(H2645NAL **nal);
uint8_t*  tt_H2645NAL_get_data(const H2645NAL *nal);
int       tt_H2645NAL_get_data_size(const H2645NAL *nal);

H264ParamSets* tt_H264ParamSets_malloc(void);
void           tt_H264ParamSets_free(H264ParamSets **paramSets);
int            tt_H264ParamSets_get_sps_list_count(const H264ParamSets *paramSets);
AVBufferRef*   tt_H264ParamSets_get_sps_list(const H264ParamSets *paramSets, int index);
int            tt_H264ParamSets_get_pps_list_count(const H264ParamSets *paramSets);
AVBufferRef*   tt_H264ParamSets_get_pps_list(const H264ParamSets *paramSets, int index);
const SPS*     tt_H264ParamSets_get_sps(const H264ParamSets *paramSets);
const PPS*     tt_H264ParamSets_get_pps(const H264ParamSets *paramSets);

PPS *tt_PPS_malloc(void);
void tt_PPS_free(PPS **pps);
void         tt_PPS_copy(PPS* dst, const PPS* src);
int          tt_PPS_get_pic_order_present(const PPS* pps);
unsigned int tt_PPS_get_sps_id(const PPS* pps);

enum {
    SPSField_log2_max_frame_num,
    SPSField_frame_mbs_only_flag,
    SPSField_poc_type,
    SPSField_log2_max_poc_lsb,
    SPSField_delta_pic_order_always_zero_flag,
    SPSField_num_reorder_frames,
};

SPS *tt_SPS_malloc(void);
void tt_SPS_free(SPS **sps);
void tt_SPS_copy(SPS *dst, const SPS *src);
void tt_SPS_copy_from_buffer(SPS *sps, const AVBufferRef* buffer);
int  tt_SPS_get_int_field(const SPS *sps, int field);

enum {
    H264POCContextField_prev_frame_num,
    H264POCContextField_prev_frame_num_offset,
    H264POCContextField_prev_poc_msb,
    H264POCContextField_prev_poc_lsb,
    H264POCContextField_frame_num,
    H264POCContextField_frame_num_offset,
    H264POCContextField_poc_msb,
    H264POCContextField_poc_lsb,
    H264POCContextField_delta_poc_bottom,
};

H264POCContext* tt_H264POCContext_malloc(void);
void            tt_H264POCContext_free(H264POCContext **context);
void tt_H264POCContext_set_delta_poc(H264POCContext *context, int index, int delta_poc);
void tt_H264POCContext_set_int_field(H264POCContext *context, int field, int value);
int  tt_H264POCContext_get_int_field(H264POCContext *context, int field);

/**
 * Extract the raw (unescaped) bitstream.
 */
int tt_h264_decode_extradata(const uint8_t *data, int size, H264ParamSets *ps,
                             int *is_avc, int *nal_length_size,
                             int err_recognition, void *logctx);

/**
 * Decode SPS
 */
int tt_h264_decode_seq_parameter_set(GetBitContext *gb, AVCodecContext *avctx,
                                     H264ParamSets *ps, int ignore_truncation);

/**
 * Decode PPS
 */
int tt_h264_decode_picture_parameter_set(GetBitContext *gb, AVCodecContext *avctx,
                                         H264ParamSets *ps, int bit_length);


int tt_h264_init_poc(int pic_field_poc[2], int *pic_poc,
                     const SPS *sps, H264POCContext *poc,
                     int picture_structure, int nal_ref_idc);

int tt_h264_parse_ref_count(int *plist_count, int ref_count[2],
                            GetBitContext *gb, const PPS *pps,
                            int slice_type_nos, int picture_structure, void *logctx);

int tt_scan_mmco_reset(GetBitContext *gb,
                       const SPS *sps,
                       const PPS *pps,
                       int pict_type,
                       int picture_structure,
                       void *logctx);

#endif /* AVCODEC_TTEXPORT_H */
