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
#include "bsf.h"
#include <string.h>

#include "libavformat/internal.h"
#include "h264_ps.h"
#include "h2645_parse.h"
#include "h264_parse.h"
#include "golomb.h"
#include "libavutil/mem.h"
#include "libavutil/buffer.h"

#define MAX_MMCO_COUNT         66

/**
 * Memory management control operation opcode.
 */
typedef enum MMCOOpcode {
    MMCO_END = 0,
    MMCO_SHORT2UNUSED,
    MMCO_LONG2UNUSED,
    MMCO_SHORT2LONG,
    MMCO_SET_MAX_LONG,
    MMCO_RESET,
    MMCO_LONG,
} MMCOOpcode;

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


AVBitStreamFilter ff_bytevc2_mp4toannexb_bsf = {
    .name           = "bytevc2",
    .priv_data_size = 0
};

int tt_register_bitstream_filter(AVBitStreamFilter *bsf, int bsf_size)
{
    int ret = -1;
    if (!bsf || !bsf->codec_ids)
        return ret;
    int i = 0, codec_id = 0;
    AVBitStreamFilter *dst = NULL;
    for (i = 0; bsf->codec_ids[i] != AV_CODEC_ID_NONE; i++) {
        if (bsf->codec_ids[i] == AV_CODEC_ID_BYTE_VC2) {
            dst = &ff_bytevc2_mp4toannexb_bsf;
            codec_id = AV_CODEC_ID_BYTE_VC2;
            ret = 0;
            break;
        }
    }
    if (dst != NULL) {
        memcpy(dst, bsf, sizeof(AVBitStreamFilter));
        av_log(NULL, AV_LOG_INFO, "register bsf:%d %s", codec_id, bsf->name);
    }
    return ret;
}

AVCodecContext *tt_avstream_get_avctx_from_internal(AVStreamInternal *internal){
    if (internal != NULL) {
        return internal->avctx;
    }
    return NULL;
}

H2645NAL* tt_H2645NAL_malloc(void) {
    return av_mallocz(sizeof (H2645NAL));
}

void tt_H2645NAL_freep(H2645NAL **nal) {
    if (!nal || !(*nal)) return;

    av_freep(&(*nal)->rbsp_buffer);
    av_freep(&(*nal)->skipped_bytes_pos);
    av_freep(nal);
}

uint8_t* tt_H2645NAL_get_data(const H2645NAL *nal) {
    return nal->data;
}

int tt_H2645NAL_get_data_size(const H2645NAL *nal) {
    return nal->size;
}

H264ParamSets* tt_H264ParamSets_malloc(void) {
    return av_mallocz(sizeof (H264ParamSets));
}

void tt_H264ParamSets_free(H264ParamSets **paramSets) {
    if (!paramSets || !(*paramSets)) return;
    ff_h264_ps_uninit(*paramSets);
    *paramSets = NULL;
}

int tt_H264ParamSets_get_sps_list_count(const H264ParamSets *paramSets) {
    return MAX_SPS_COUNT;
}

AVBufferRef* tt_H264ParamSets_get_sps_list(const H264ParamSets *paramSets, int index) {
    return paramSets->sps_list[index];
}

int tt_H264ParamSets_get_pps_list_count(const H264ParamSets *paramSets) {
    return MAX_PPS_COUNT;
}

AVBufferRef* tt_H264ParamSets_get_pps_list(const H264ParamSets *paramSets, int index) {
    return paramSets->pps_list[index];
}

const SPS* tt_H264ParamSets_get_sps(const H264ParamSets *paramSets) {
    return paramSets->sps;
}

const PPS* tt_H264ParamSets_get_pps(const H264ParamSets *paramSets) {
    return paramSets->pps;
}

PPS *tt_PPS_malloc(void) {
    return av_mallocz(sizeof(PPS));
}

void tt_PPS_free(PPS **pps) {
    av_freep(pps);
}

void tt_PPS_copy(PPS* dst, const PPS* src) {
    memcpy(dst, src, sizeof(PPS));
}

int tt_PPS_get_pic_order_present(const PPS* pps) {
    return pps->pic_order_present;
}

unsigned int tt_PPS_get_sps_id(const PPS* pps) {
    return pps->sps_id;
}

SPS *tt_SPS_malloc(void) {
    return av_mallocz(sizeof(SPS));
}

void tt_SPS_free(SPS **sps) {
    av_freep(sps);
}

void tt_SPS_copy(SPS *dst, const SPS *src) {
    memcpy(dst, src, sizeof(SPS));
}

void tt_SPS_copy_from_buffer(SPS *sps, const AVBufferRef* buffer) {
    memcpy(sps, buffer->data, sizeof(SPS));
}

int  tt_SPS_get_int_field(const SPS *sps, int field) {
    switch (field)
    {
    case SPSField_log2_max_frame_num:
       return sps->log2_max_frame_num;
    case SPSField_frame_mbs_only_flag:
        return sps->frame_mbs_only_flag;
    case SPSField_poc_type:
        return sps->poc_type;
    case SPSField_log2_max_poc_lsb:
        return sps->log2_max_poc_lsb;
    case SPSField_delta_pic_order_always_zero_flag:
        return sps->delta_pic_order_always_zero_flag;
    case SPSField_num_reorder_frames:
        return sps->num_reorder_frames;
    default:
        return 0;
    }
}

H264POCContext* tt_H264POCContext_malloc(void) {
    return av_mallocz(sizeof(H264POCContext));
}

void tt_H264POCContext_free(H264POCContext **context) {
    av_freep(context);
}

void tt_H264POCContext_set_delta_poc(H264POCContext *context, int index, int delta_poc) {
    context->delta_poc[index] = delta_poc;
}

void tt_H264POCContext_set_int_field(H264POCContext *context, int field, int value) {
    switch (field)
    {
    case H264POCContextField_prev_frame_num:
        context->prev_frame_num = value;
        break;
    case H264POCContextField_prev_frame_num_offset:
        context->prev_frame_num_offset = value;
        break;
    case H264POCContextField_prev_poc_msb:
        context->prev_poc_msb = value;
        break;
    case H264POCContextField_prev_poc_lsb:
        context->prev_poc_lsb = value;
        break;
    case H264POCContextField_frame_num:
        context->frame_num = value;
        break;
    case H264POCContextField_frame_num_offset:
        context->frame_num_offset = value;
        break;
    case H264POCContextField_poc_msb:
        context->poc_msb = value;
        break;
    case H264POCContextField_poc_lsb:
        context->poc_lsb = value;
        break;
    case H264POCContextField_delta_poc_bottom:
        context->delta_poc_bottom = value;
        break;
    default:
        break;
    }
}

int  tt_H264POCContext_get_int_field(H264POCContext *context, int field) {
    switch (field)
    {
    case H264POCContextField_prev_frame_num:
        return context->prev_frame_num;
    case H264POCContextField_prev_frame_num_offset:
        return context->prev_frame_num_offset;
    case H264POCContextField_prev_poc_msb:
        return context->prev_poc_msb;
    case H264POCContextField_prev_poc_lsb:
        return context->prev_poc_lsb;
    case H264POCContextField_frame_num:
        return context->frame_num;
    case H264POCContextField_frame_num_offset:
        return context->frame_num_offset;
    case H264POCContextField_poc_msb:
        return context->poc_msb;
    case H264POCContextField_poc_lsb:
        return context->poc_lsb;
    case H264POCContextField_delta_poc_bottom:
        return context->delta_poc_bottom;
    default:
        return 0;
    }
}

int tt_h2645_extract_rbsp(const uint8_t *src, int length,
                          H2645NAL *nal, int small_padding) {
    return ff_h2645_extract_rbsp(src, length, nal, small_padding);
}

int tt_h264_decode_extradata(const uint8_t *data, int size, H264ParamSets *ps,
                             int *is_avc, int *nal_length_size,
                             int err_recognition, void *logctx) {
    return ff_h264_decode_extradata(data, size, ps, is_avc, nal_length_size, err_recognition, logctx);
}

/**
 * Decode SPS
 */
int tt_h264_decode_seq_parameter_set(GetBitContext *gb, AVCodecContext *avctx,
                                     H264ParamSets *ps, int ignore_truncation) {
    return ff_h264_decode_seq_parameter_set(gb, avctx, ps, ignore_truncation);
}

/**
 * Decode PPS
 */
int tt_h264_decode_picture_parameter_set(GetBitContext *gb, AVCodecContext *avctx,
                                         H264ParamSets *ps, int bit_length) {
    return ff_h264_decode_picture_parameter_set(gb, avctx, ps, bit_length);
}

int tt_h264_init_poc(int pic_field_poc[2], int *pic_poc,
                     const SPS *sps, H264POCContext *poc,
                     int picture_structure, int nal_ref_idc) {
    return ff_h264_init_poc(pic_field_poc, pic_poc, sps, poc, picture_structure, nal_ref_idc);
}

int tt_h264_parse_ref_count(int *plist_count, int ref_count[2],
                            GetBitContext *gb, const PPS *pps,
                            int slice_type_nos, int picture_structure, void *logctx) {
    return ff_h264_parse_ref_count(plist_count, ref_count, gb, pps, slice_type_nos, picture_structure, logctx);
}

int tt_scan_mmco_reset(GetBitContext *gb,
                           const SPS *sps,
                           const PPS *pps,
                           int pict_type,
                           int picture_structure,
                           void *logctx)
{
    H264PredWeightTable pwt;
    int slice_type_nos = pict_type & 3;
    int list_count, ref_count[2];


    if (pps->redundant_pic_cnt_present)
        get_ue_golomb(gb); // redundant_pic_count

    if (slice_type_nos == AV_PICTURE_TYPE_B)
        get_bits1(gb); // direct_spatial_mv_pred

    if (tt_h264_parse_ref_count(&list_count, ref_count, gb, pps,
                                slice_type_nos, picture_structure, logctx) < 0)
        return AVERROR_INVALIDDATA;

    if (slice_type_nos != AV_PICTURE_TYPE_I) {
        int list;
        for (list = 0; list < list_count; list++) {
            if (get_bits1(gb)) {
                int index;
                for (index = 0; ; index++) {
                    unsigned int reordering_of_pic_nums_idc = get_ue_golomb_31(gb);

                    if (reordering_of_pic_nums_idc < 3)
                        get_ue_golomb_long(gb);
                    else if (reordering_of_pic_nums_idc > 3) {
                        av_log(logctx, AV_LOG_ERROR,
                               "illegal reordering_of_pic_nums_idc %d\n",
                               reordering_of_pic_nums_idc);
                        return AVERROR_INVALIDDATA;
                    } else
                        break;

                    if (index >= ref_count[list]) {
                        av_log(logctx, AV_LOG_ERROR,
                               "reference count %d overflow\n", index);
                        return AVERROR_INVALIDDATA;
                    }
                }
            }
        }
    }

    if ((pps->weighted_pred && slice_type_nos == AV_PICTURE_TYPE_P) ||
        (pps->weighted_bipred_idc == 1 && slice_type_nos == AV_PICTURE_TYPE_B))
        ff_h264_pred_weight_table(gb, sps, ref_count, slice_type_nos,
                                  &pwt, picture_structure, logctx);

    if (get_bits1(gb)) { // adaptive_ref_pic_marking_mode_flag
        int i;
        for (i = 0; i < MAX_MMCO_COUNT; i++) {
            MMCOOpcode opcode = (MMCOOpcode) get_ue_golomb_31(gb);
            if (opcode > (unsigned) MMCO_LONG) {
                av_log(logctx, AV_LOG_ERROR,
                       "illegal memory management control operation %d\n",
                       opcode);
                return AVERROR_INVALIDDATA;
            }
            if (opcode == MMCO_END)
                return 0;
            else if (opcode == MMCO_RESET)
                return 1;

            if (opcode == MMCO_SHORT2UNUSED || opcode == MMCO_SHORT2LONG)
                get_ue_golomb_long(gb); // difference_of_pic_nums_minus1
            if (opcode == MMCO_SHORT2LONG || opcode == MMCO_LONG2UNUSED ||
                opcode == MMCO_LONG || opcode == MMCO_SET_MAX_LONG)
                get_ue_golomb_31(gb);
        }
    }

    return 0;
}
