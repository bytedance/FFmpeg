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

#include "libavcodec/avcodec.h"
#include "libavcodec/get_bits.h"
#include "libavcodec/golomb.h"
#include "libavcodec/bytevc2.h"
#include "libavutil/intreadwrite.h"
#include "avc.h"
#include "avio.h"
#include "bytevc2.h"

typedef uint8_t bool;

typedef struct BVC2CNALUnitArray {
    uint8_t  array_completeness;
    uint8_t  NAL_unit_type;
    uint16_t numNalus;
    uint16_t *nalUnitLength;
    uint8_t  **nalUnit;
} BVC2CNALUnitArray;

typedef struct BYTEVC2DecoderConfigurationRecord {
    uint8_t  configurationVersion;
    uint8_t  lengthSizeMinusOne;
    uint8_t  ptl_present_flag;
    uint8_t  max_sub_layers_minus1;

    //ptl start
    uint8_t  chromaFormat; //2bit
    uint8_t  bitDepthLumaMinus8; //3bit
    uint8_t  numTemporalLayers; //3bit
    uint8_t  constantFrameRate; //2bit, reserve 6bit

    //ptl record
    uint8_t  num_bytes_constraint_info;
    uint8_t  general_profile_idc;
    uint8_t  general_tier_flag;
    uint8_t  general_level_idc;
    uint8_t  ptl_frame_only_constraint_flag;
    uint8_t  ptl_multilayer_enabled_flag;
    uint64_t general_constraint_info;
    uint8_t  ptl_sublayer_level_present_flag[8];
    uint8_t  sublayer_level_idc[8];
    uint8_t  num_sub_profiles;
    uint32_t general_sub_profile_idc[64];

    uint8_t  output_layer_set_idx;
    uint16_t picture_width;
    uint16_t picture_height;
    uint16_t avgFrameRate;

    uint8_t  numOfArrays;
    BVC2CNALUnitArray *array;
} BYTEVC2DecoderConfigurationRecord;

typedef struct BVC2CProfileTierLevel {
    uint8_t iGeneralProfileIdc;
    uint8_t iGeneralLevelIdc;
    uint8_t iNumSubProfile;
    uint8_t abSubLayerLevelIdc[BYTEVC2_MAX_SUB_LAYERS];
    bool    bGeneralTierFlag;
    bool    bGeneralFrameOnlyConstraintFlag;
    bool    abSubLayerLevelPresentFlag[BYTEVC2_MAX_SUB_LAYERS];
} BVC2CProfileTierLevel;

static void bvc2c_update_ptl(BYTEVC2DecoderConfigurationRecord *bvc2c,
                            BVC2CProfileTierLevel *ptl)
{
    bvc2c->ptl_present_flag = 1;
    bvc2c->num_bytes_constraint_info = 1;
    bvc2c->general_profile_idc = ptl->iGeneralProfileIdc;
    bvc2c->general_tier_flag = FFMAX(ptl->bGeneralTierFlag, bvc2c->general_tier_flag);
    bvc2c->general_level_idc = ptl->iGeneralLevelIdc;
    bvc2c->ptl_frame_only_constraint_flag = ptl->bGeneralFrameOnlyConstraintFlag;
    for (int i = 0; i < 8; i++) {
        bvc2c->ptl_sublayer_level_present_flag[i] = ptl->abSubLayerLevelPresentFlag[i];
        if (ptl->abSubLayerLevelPresentFlag[i]) {
            bvc2c->sublayer_level_idc[i] = ptl->abSubLayerLevelIdc[i];
        }
    }
}

static void bvc2c_parse_ptl(GetBitContext *gb, uint8_t profile_tier_present,
                           BYTEVC2DecoderConfigurationRecord *bvc2c)
{
    unsigned int max_sub_layers_minus1 = bvc2c->max_sub_layers_minus1;
    BVC2CProfileTierLevel general_ptl;

    if (profile_tier_present) {
        general_ptl.iGeneralProfileIdc = get_bits(gb, 7);
        general_ptl.bGeneralTierFlag = get_bits1(gb);
    }
    general_ptl.iGeneralLevelIdc = get_bits(gb, 8);
    general_ptl.bGeneralFrameOnlyConstraintFlag = get_bits1(gb);
    
    get_bits1(gb);
    if (profile_tier_present) {
        if (get_bits1(gb)) {
            get_bits(gb, 32);
            get_bits(gb, 32);
            get_bits(gb, 9);
            uint8_t reserved_bits = get_bits(gb, 8);
            for (uint32_t i = 0; i < reserved_bits; i++) {
                get_bits1(gb);
            }
        }
        align_get_bits(gb);
    }

    for (int i = max_sub_layers_minus1 - 1; i >= 0; i--) {
        general_ptl.abSubLayerLevelPresentFlag[i] = get_bits1(gb);
    }

    align_get_bits(gb);

    for (int i = max_sub_layers_minus1 - 1; i >= 0; i--) {
        if (general_ptl.abSubLayerLevelPresentFlag[i]) {
            general_ptl.abSubLayerLevelIdc[i] = get_bits(gb, 8);
        }
    }
    general_ptl.abSubLayerLevelIdc[max_sub_layers_minus1] = general_ptl.iGeneralLevelIdc;
    for (int i = max_sub_layers_minus1 - 1; i >= 0; i--) {
        if (!general_ptl.abSubLayerLevelPresentFlag[i]) {
            general_ptl.abSubLayerLevelIdc[i] = general_ptl.abSubLayerLevelIdc[i+1];
        }
    }

    if (profile_tier_present) {
        general_ptl.iNumSubProfile = get_bits(gb, 8);
        for (int i = 0; i < general_ptl.iNumSubProfile; i++) {
            get_bits(gb, 32);
        }
    }
    bvc2c_update_ptl(bvc2c, &general_ptl);
}

static int bvc2c_parse_parameter(GetBitContext *gb,
                           BYTEVC2DecoderConfigurationRecord *bvc2c)
{
    get_bits(gb, 8);
    bvc2c->max_sub_layers_minus1 = get_bits(gb, 3);
    bvc2c->chromaFormat = get_bits(gb, 2);
    get_bits(gb, 2);
    if (get_bits1(gb)) {
        bvc2c_parse_ptl(gb, 1, bvc2c);
    }
    get_bits1(gb);
    if (get_bits1(gb)) {
        get_bits1(gb);
    }
    bvc2c->picture_width = get_ue_golomb_long(gb); 
    bvc2c->picture_height = get_ue_golomb_long(gb);
    if (get_bits1(gb)) {
        get_ue_golomb_long(gb);
        get_ue_golomb_long(gb);
        get_ue_golomb_long(gb);
        get_ue_golomb_long(gb);
    }
    get_bits1(gb);
    bvc2c->bitDepthLumaMinus8 = get_ue_golomb_long(gb);
    bvc2c->numTemporalLayers = FFMAX(bvc2c->numTemporalLayers, bvc2c->max_sub_layers_minus1 + 1);
    return 0;
}

static uint8_t *nal_unit_extract_rbsp(const uint8_t *src, uint32_t src_len,
                                      uint32_t *dst_len)
{
    uint8_t *dst;
    uint32_t i, len;

    dst = av_malloc(src_len + AV_INPUT_BUFFER_PADDING_SIZE);
    if (!dst)
        return NULL;

    /* NAL unit header (2 bytes) */
    i = len = 0;
    while (i < 2 && i < src_len)
        dst[len++] = src[i++];

    while (i + 2 < src_len)
        if (!src[i] && !src[i + 1] && src[i + 2] == 3) {
            dst[len++] = src[i++];
            dst[len++] = src[i++];
            i++; // remove emulation_prevention_three_byte
        } else
            dst[len++] = src[i++];

    while (i < src_len)
        dst[len++] = src[i++];

    memset(dst + len, 0, AV_INPUT_BUFFER_PADDING_SIZE);

    *dst_len = len;
    return dst;
}

static void nal_unit_parse_header(GetBitContext *gb, uint8_t *nal_type)
{
    skip_bits(gb, 8);
    int byte = get_bits(gb, 8);
    *nal_type = byte >> 3;
}

static int bvc2c_array_add_nal_unit(uint8_t *nal_buf, uint32_t nal_size,
                                   uint8_t nal_type, int ps_array_completeness,
                                   BYTEVC2DecoderConfigurationRecord *bvc2c)
{
    int ret;
    uint8_t index;
    uint16_t numNalus;
    BVC2CNALUnitArray *array;

    for (index = 0; index < bvc2c->numOfArrays; index++)
        if (bvc2c->array[index].NAL_unit_type == nal_type)
            break;

    if (index >= bvc2c->numOfArrays) {
        uint8_t i;

        ret = av_reallocp_array(&bvc2c->array, index + 1, sizeof(BVC2CNALUnitArray));
        if (ret < 0)
            return ret;

        for (i = bvc2c->numOfArrays; i <= index; i++)
            memset(&bvc2c->array[i], 0, sizeof(BVC2CNALUnitArray));
        bvc2c->numOfArrays = index + 1;
    }

    array    = &bvc2c->array[index];
    numNalus = array->numNalus;

    ret = av_reallocp_array(&array->nalUnit, numNalus + 1, sizeof(uint8_t*));
    if (ret < 0)
        return ret;

    ret = av_reallocp_array(&array->nalUnitLength, numNalus + 1, sizeof(uint16_t));
    if (ret < 0)
        return ret;

    array->nalUnit      [numNalus] = nal_buf;
    array->nalUnitLength[numNalus] = nal_size;
    array->NAL_unit_type           = nal_type;
    array->numNalus++;

    if (nal_type == BYTEVC2_NAL_TYPE_1 || nal_type == BYTEVC2_NAL_TYPE_2 || nal_type == BYTEVC2_NAL_TYPE_3)
        array->array_completeness = ps_array_completeness;

    return 0;
}

static int bvc2c_add_nal_unit(uint8_t *nal_buf, uint32_t nal_size,
                             int ps_array_completeness,
                             BYTEVC2DecoderConfigurationRecord *bvc2c)
{
    int ret = 0;
    GetBitContext gbc;
    uint8_t nal_type;
    uint8_t *rbsp_buf;
    uint32_t rbsp_size;

    rbsp_buf = nal_unit_extract_rbsp(nal_buf, nal_size, &rbsp_size);
    if (!rbsp_buf) {
        ret = AVERROR(ENOMEM);
        goto end;
    }

    ret = init_get_bits8(&gbc, rbsp_buf, rbsp_size);
    if (ret < 0)
        goto end;

    nal_unit_parse_header(&gbc, &nal_type);

    switch (nal_type) {
    case BYTEVC2_NAL_TYPE_1:
    case BYTEVC2_NAL_TYPE_2:
    case BYTEVC2_NAL_TYPE_3:
    case BYTEVC2_NAL_TYPE_4:
    case BYTEVC2_NAL_TYPE_5:
    case BYTEVC2_NAL_TYPE_7:
    case BYTEVC2_NAL_TYPE_8:
        ret = bvc2c_array_add_nal_unit(nal_buf, nal_size, nal_type,
                                      ps_array_completeness, bvc2c);
        if (ret < 0)
            goto end;
        else if (nal_type == BYTEVC2_NAL_TYPE_2)
            ret = bvc2c_parse_parameter(&gbc, bvc2c);
        if (ret < 0)
            goto end;
        break;
    default:
        ret = AVERROR_INVALIDDATA;
        goto end;
    }

end:
    av_free(rbsp_buf);
    return ret;
}

static void bvc2c_init(BYTEVC2DecoderConfigurationRecord *bvc2c)
{
    memset(bvc2c, 0, sizeof(BYTEVC2DecoderConfigurationRecord));
    bvc2c->configurationVersion = 1;
    bvc2c->lengthSizeMinusOne   = 3; // 4 bytes
}

static void bvc2c_close(BYTEVC2DecoderConfigurationRecord *bvc2c)
{
    uint8_t i;

    for (i = 0; i < bvc2c->numOfArrays; i++) {
        bvc2c->array[i].numNalus = 0;
        av_freep(&bvc2c->array[i].nalUnit);
        av_freep(&bvc2c->array[i].nalUnitLength);
    }

    bvc2c->numOfArrays = 0;
    av_freep(&bvc2c->array);
}

static int bvc2c_write(AVIOContext *pb, BYTEVC2DecoderConfigurationRecord *bvc2c)
{
    uint8_t i;
    uint16_t j;

    bvc2c->configurationVersion = 1;
    bvc2c->avgFrameRate = 0;
    bvc2c->constantFrameRate = 0;

    av_log(NULL, AV_LOG_TRACE,  "configurationVersion:                %"PRIu8"\n",
            bvc2c->configurationVersion);
    av_log(NULL, AV_LOG_TRACE,  "lengthSizeMinusOne:                  %"PRIu8"\n",
            bvc2c->lengthSizeMinusOne);
    av_log(NULL, AV_LOG_TRACE,  "ptl_present_flag:                    %"PRIu8"\n",
            bvc2c->ptl_present_flag);
    if (bvc2c->ptl_present_flag) {
        av_log(NULL, AV_LOG_TRACE,  "\t chromaFormat:                 %"PRIu8"\n",
               bvc2c->chromaFormat);
        av_log(NULL, AV_LOG_TRACE,  "\t bitDepthLumaMinus8:           %"PRIu8"\n",
               bvc2c->bitDepthLumaMinus8);
        av_log(NULL, AV_LOG_TRACE,  "\t numTemporalLayers:            %"PRIu8"\n",
               bvc2c->numTemporalLayers);
        av_log(NULL, AV_LOG_TRACE,  "\t constantFrameRate:            %"PRIu8"\n",
               bvc2c->constantFrameRate);

        av_log(NULL, AV_LOG_TRACE,  "\t num_bytes_constraint_info:      %"PRIu8"\n",
               bvc2c->num_bytes_constraint_info);
        av_log(NULL, AV_LOG_TRACE,  "\t general_profile_idc:            %"PRIu8"\n",
               bvc2c->general_profile_idc);
        av_log(NULL, AV_LOG_TRACE,  "\t general_tier_flag:              %"PRIu8"\n",
               bvc2c->general_tier_flag);
        av_log(NULL, AV_LOG_TRACE,  "\t general_level_idc:              %"PRIu8"\n",
               bvc2c->general_level_idc);
        av_log(NULL, AV_LOG_TRACE,  "\t ptl_frame_only_constraint_flag: %"PRIu8"\n",
               bvc2c->ptl_frame_only_constraint_flag);
        av_log(NULL, AV_LOG_TRACE,  "\t ptl_multilayer_enabled_flag:    %"PRIu8"\n",
               bvc2c->ptl_multilayer_enabled_flag);
        av_log(NULL, AV_LOG_TRACE,  "\t num_sub_profiles:               %"PRIu8"\n",
               bvc2c->num_sub_profiles);
    }

    av_log(NULL, AV_LOG_TRACE,  "output_layer_set_idx:                %"PRIu8"\n",
           bvc2c->output_layer_set_idx);
    av_log(NULL, AV_LOG_TRACE,  "picture_width:                       %"PRIu16"\n",
           bvc2c->picture_width);
    av_log(NULL, AV_LOG_TRACE,  "picture_height:                      %"PRIu16"\n",
           bvc2c->picture_height);
    av_log(NULL, AV_LOG_TRACE,  "avgFrameRate:                        %"PRIu16"\n",
            bvc2c->avgFrameRate);
    av_log(NULL, AV_LOG_TRACE,  "numOfArrays:                         %"PRIu8"\n",
            bvc2c->numOfArrays);
    for (i = 0; i < bvc2c->numOfArrays; i++) {
        av_log(NULL, AV_LOG_TRACE, "array_completeness[%"PRIu8"]:               %"PRIu8"\n",
                i, bvc2c->array[i].array_completeness);
        av_log(NULL, AV_LOG_TRACE, "NAL_unit_type[%"PRIu8"]:                    %"PRIu8"\n",
                i, bvc2c->array[i].NAL_unit_type);
        av_log(NULL, AV_LOG_TRACE, "numNalus[%"PRIu8"]:                         %"PRIu16"\n",
                i, bvc2c->array[i].numNalus);
        for (j = 0; j < bvc2c->array[i].numNalus; j++)
            av_log(NULL, AV_LOG_TRACE,
                    "nalUnitLength[%"PRIu8"][%"PRIu16"]:                 %"PRIu16"\n",
                    i, j, bvc2c->array[i].nalUnitLength[j]);
    }

    /* unsigned int(8) configurationVersion = 1; */
    avio_w8(pb, bvc2c->configurationVersion);

    /*
     bit(5) reserved = '11111'b;
     unsigned int(2) lengthSizeMinusOne;
     unsigned int(1) ptl_present_flag;
     */

    avio_w8(pb, bvc2c->lengthSizeMinusOne     << 1 |
                bvc2c->ptl_present_flag);

    if (bvc2c->ptl_present_flag) {
        avio_w8(pb, (bvc2c->chromaFormat << 6) |
                    (bvc2c->bitDepthLumaMinus8 << 3) |
                    (bvc2c->numTemporalLayers));
        avio_w8(pb, bvc2c->constantFrameRate << 6);

        /*
         bit(2) reserved = 0;
         unsigned int(6) num_bytes_constraint_info;
         */
        avio_w8(pb, bvc2c->num_bytes_constraint_info);

        /*
         unsigned int(7) general_profile_idc;
         unsigned int(1) general_tier_flag;
         */
        avio_w8(pb, (bvc2c->general_profile_idc << 1) | (bvc2c->general_tier_flag));
        /*
         unsigned int(8) general_level_idc;
         */
        avio_w8(pb, bvc2c->general_level_idc);
        /*
         unsigned int(1) ptl_frame_only_constraint_flag;
         unsigned int(1) ptl_multilayer_enabled_flag;
         */
        avio_w8(pb, (bvc2c->ptl_frame_only_constraint_flag << 7) | (bvc2c->ptl_multilayer_enabled_flag << 6));
        for (int i = 0; i < bvc2c->num_bytes_constraint_info - 1; i++) {
            //TODO: no constraint_info defined now
            avio_w8(pb, 0);
        }

        uint8_t ptl_sublayer_level_present_flag_byte = 0;
        for (int i = bvc2c->numTemporalLayers - 2, j = 7; i >= 0; i--, j--) {
            ptl_sublayer_level_present_flag_byte |= bvc2c->ptl_sublayer_level_present_flag[i] << j;
        }
        avio_w8(pb, ptl_sublayer_level_present_flag_byte);
        for (int i = bvc2c->numTemporalLayers - 2; i >= 0; i--) {
            if (bvc2c->ptl_sublayer_level_present_flag[i]) {
                avio_w8(pb, bvc2c->sublayer_level_idc[i]);
            }
        }

        /*
         unsigned int(8) num_sub_profiles;
         */
        avio_w8(pb, bvc2c->num_sub_profiles);

        for (int j = 0; j < bvc2c->num_sub_profiles; j++) {
            avio_wb32(pb, bvc2c->general_sub_profile_idc[j]);
        }

        /*
         unsigned int(16) output_layer_set_idx;
         unsigned_int(16) picture_width;
         unsigned_int(16) picture_height;
         unsigned int(16) avgFrameRate;
         */
        avio_wb16(pb, bvc2c->output_layer_set_idx);
        avio_wb16(pb, bvc2c->picture_width);
        avio_wb16(pb, bvc2c->picture_height);
        avio_wb16(pb, bvc2c->avgFrameRate);
    }

    /* unsigned int(8) numOfArrays; */
    avio_w8(pb, bvc2c->numOfArrays);

    for (i = 0; i < bvc2c->numOfArrays; i++) {
        /*
         * bit(1) array_completeness;
         * unsigned int(1) reserved = 0;
         * unsigned int(6) NAL_unit_type;
         */
        avio_w8(pb, bvc2c->array[i].array_completeness << 7 |
                    bvc2c->array[i].NAL_unit_type & 0x1f);

        /* unsigned int(16) numNalus; */
        avio_wb16(pb, bvc2c->array[i].numNalus);

        for (j = 0; j < bvc2c->array[i].numNalus; j++) {
            /* unsigned int(16) nalUnitLength; */
            avio_wb16(pb, bvc2c->array[i].nalUnitLength[j]);//TODO: nal format

            /* bit(8*nalUnitLength) nalUnit; */
            avio_write(pb, bvc2c->array[i].nalUnit[j],
                       bvc2c->array[i].nalUnitLength[j]);
        }
    }

    return 0;
}

int ff_bytevc2_annexb2mp4(AVIOContext *pb, const uint8_t *buf_in,
                       int size, int filter_ps, int *ps_count)
{
    int num_ps = 0, ret = 0;
    uint8_t *buf, *end, *start = NULL;

    if (!filter_ps) {
        ret = ff_avc_parse_nal_units(pb, buf_in, size);
        goto end;
    }

    ret = ff_avc_parse_nal_units_buf(buf_in, &start, &size);
    if (ret < 0)
        goto end;

    ret = 0;
    buf = start;
    end = start + size;

    while (end - buf > 4) {
        uint32_t len = FFMIN(AV_RB32(buf), end - buf - 4);
        uint8_t type = buf[5] >> 3;

        buf += 4;

        switch (type) {
        case BYTEVC2_NAL_TYPE_1:
        case BYTEVC2_NAL_TYPE_2:
        case BYTEVC2_NAL_TYPE_3:
        case BYTEVC2_NAL_TYPE_4:
        case BYTEVC2_NAL_TYPE_5:
            num_ps++;
            break;
        default:
            ret += 4 + len;
            avio_wb32(pb, len);
            avio_write(pb, buf, len);
            break;
        }

        buf += len;
    }

end:
    av_free(start);
    if (ps_count)
        *ps_count = num_ps;
    return ret;
}

int ff_bytevc2_annexb2mp4_buf(const uint8_t *buf_in, uint8_t **buf_out,
                           int *size, int filter_ps, int *ps_count)
{
    AVIOContext *pb;
    int ret;

    ret = avio_open_dyn_buf(&pb);
    if (ret < 0)
        return ret;

    ret   = ff_bytevc2_annexb2mp4(pb, buf_in, *size, filter_ps, ps_count);
    *size = avio_close_dyn_buf(pb, buf_out);

    return ret;
}

int ff_isom_write_bvc2c(AVIOContext *pb, const uint8_t *data,
                       int size, int ps_array_completeness)
{
    int ret = 0;
    uint8_t *buf, *end, *start = NULL;
    BYTEVC2DecoderConfigurationRecord bvc2c;

    bvc2c_init(&bvc2c);

    if (size < 6) {
        /* We can't write a valid hvcC from the provided data */
        ret = AVERROR_INVALIDDATA;
        goto end;
    } else if (*data == 1) {
        /* Data is already hvcC-formatted */
        avio_write(pb, data, size);
        goto end;
    } else if (!(AV_RB24(data) == 1 || AV_RB32(data) == 1)) {
        /* Not a valid Annex B start code prefix */
        ret = AVERROR_INVALIDDATA;
        goto end;
    }

    ret = ff_avc_parse_nal_units_buf(data, &start, &size);
    if (ret < 0)
        goto end;

    buf = start;
    end = start + size;

    while (end - buf > 4) {
        uint32_t len = FFMIN(AV_RB32(buf), end - buf - 4);
        uint8_t type = (buf[5] >> 3);

        buf += 4;

        switch (type) {
        case BYTEVC2_NAL_TYPE_1:
        case BYTEVC2_NAL_TYPE_2:
        case BYTEVC2_NAL_TYPE_3:
        case BYTEVC2_NAL_TYPE_4:
        case BYTEVC2_NAL_TYPE_5:
        case BYTEVC2_NAL_TYPE_7:
        case BYTEVC2_NAL_TYPE_8:
            ret = bvc2c_add_nal_unit(buf, len, ps_array_completeness, &bvc2c);
            if (ret < 0)
                goto end;
            break;
        default:
            break;
        }

        buf += len;
    }

    ret = bvc2c_write(pb, &bvc2c);

end:
    bvc2c_close(&bvc2c);
    av_free(start);
    return ret;
}
