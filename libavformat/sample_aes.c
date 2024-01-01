/*
 * Apple HTTP Live Streaming Sample Encryption/Decryption
 *
 * Copyright (c) 2021 Nachiket Tarate
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

/**
 * @file
 * Apple HTTP Live Streaming Sample Encryption
 * https://developer.apple.com/library/ios/documentation/AudioVideo/Conceptual/HLS_Sample_Encryption
 */
#include "libavutil/opt.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/aes.h"
#include "libavcodec/hevc.h"
#include "libavcodec/h264.h"
#include "string.h"
#include "sample_aes.h"

typedef struct NALUnit {
    uint8_t     *data;
    int         type;
    int         length;
    int         start_code_length;
} NALUnit;

typedef struct AudioFrame {
    uint8_t     *data;
    int         length;
    int         header_length;
} AudioFrame;

typedef struct CodecParserContext {
    const uint8_t   *buf_ptr;
    const uint8_t   *buf_end;
} CodecParserContext;

/*
 * Remove start code emulation prevention 0x03 bytes
 */
static void remove_scep_3_bytes(NALUnit *nalu)
{
    int i = 0;
    int j = 0;

    uint8_t *data = nalu->data;

    while (i < nalu->length) {
        if (nalu->length - i > 3 && AV_RB24(&data[i]) == 0x000003) {
            data[j++] = data[i++];
            data[j++] = data[i++];
            i++;
        } else {
            data[j++] = data[i++];
        }
    }

    nalu->length = j;
}

static int get_next_nal_unit(enum AVCodecID codec_id, CodecParserContext *ctx, NALUnit *nalu)
{
    const uint8_t *nalu_start = ctx->buf_ptr;

    if (ctx->buf_end - ctx->buf_ptr >= 4 && AV_RB32(ctx->buf_ptr) == 0x00000001)
        nalu->start_code_length = 4;
    else if (ctx->buf_end - ctx->buf_ptr >= 3 && AV_RB24(ctx->buf_ptr) == 0x000001)
        nalu->start_code_length = 3;
    else /* No start code at the beginning of the NAL unit */
        return -1;

    ctx->buf_ptr += nalu->start_code_length;

    while (ctx->buf_ptr < ctx->buf_end) {
        if (ctx->buf_end - ctx->buf_ptr >= 4 && AV_RB32(ctx->buf_ptr) == 0x00000001)
            break;
        else if (ctx->buf_end - ctx->buf_ptr >= 3 && AV_RB24(ctx->buf_ptr) == 0x000001)
            break;
        ctx->buf_ptr++;
    }

    nalu->data   = (uint8_t *)nalu_start + nalu->start_code_length;
    nalu->length = ctx->buf_ptr - nalu->data;
    if (codec_id==AV_CODEC_ID_H264){
        nalu->type = *nalu->data & 0x1F;
    }else if (codec_id==AV_CODEC_ID_H265){
        nalu->type = (*nalu->data&0x7E)>>1;
    }
    return 0;
}

static int decrypt_nal_unit(CryptoContext *crypto_ctx, NALUnit *nalu)
{
    int ret = 0;
    int rem_bytes;
    uint8_t *data;
    uint8_t iv[16];
    ret = av_aes_init(crypto_ctx->aes_ctx, crypto_ctx->key, 16 * 8, 1);
    if (ret < 0)
        return ret;

    /* Remove start code emulation prevention 0x03 bytes */
    remove_scep_3_bytes(nalu);

    data = nalu->data + 32;
    rem_bytes = nalu->length - 32;

    memcpy(iv, crypto_ctx->iv, 16);
    while (rem_bytes > 0) {
        if (rem_bytes > 16) {
            av_aes_crypt(crypto_ctx->aes_ctx, data, data, 1, iv, 1);
            data += 16;
            rem_bytes -= 16;
        }
        data += FFMIN(144, rem_bytes);
        rem_bytes -= FFMIN(144, rem_bytes);
    }

    return 0;
}

static int nalu_encrypted(enum AVCodecID codec_id, NALUnit nalu){
    switch (codec_id) {
        case AV_CODEC_ID_H264:
            if (nalu.length<=48){
                return 0;
            }
            switch (nalu.type) {
                case H264_NAL_SLICE:
                case H264_NAL_IDR_SLICE:
                    return 1;
                default:
                    return 0;
            }
        case AV_CODEC_ID_H265:
            if (nalu.length<=48){
                return 0;
            }
            switch (nalu.type) {
                case HEVC_NAL_TRAIL_N:
                case HEVC_NAL_TRAIL_R:
                case HEVC_NAL_TSA_N:
                case HEVC_NAL_TSA_R:
                case HEVC_NAL_STSA_N:
                case HEVC_NAL_STSA_R:
                case HEVC_NAL_RADL_N:
                case HEVC_NAL_RADL_R:
                case HEVC_NAL_RASL_N:
                case HEVC_NAL_RASL_R:
                case HEVC_NAL_BLA_W_LP:
                case HEVC_NAL_BLA_W_RADL:
                case HEVC_NAL_BLA_N_LP:
                case HEVC_NAL_IDR_W_RADL:
                case HEVC_NAL_IDR_N_LP:
                case HEVC_NAL_CRA_NUT:
                    return 1;
                default:
                    return 0;
            }
    }
    return 0;
}

static int decrypt_video_frame(enum AVCodecID codec_id, CryptoContext *crypto_ctx, AVPacket *pkt)
{
    int ret = 0;
    CodecParserContext  ctx;
    NALUnit nalu;
    uint8_t *data_ptr;
    int move_nalu = 0;

    memset(&ctx, 0, sizeof(ctx));
    ctx.buf_ptr  = pkt->data;
    ctx.buf_end = pkt->data + pkt->size;

    data_ptr = pkt->data;

    while (ctx.buf_ptr < ctx.buf_end) {
        memset(&nalu, 0, sizeof(nalu));
        ret = get_next_nal_unit(codec_id, &ctx, &nalu);
        if (ret < 0)
            return ret;
        if (nalu_encrypted(codec_id, nalu)) {
            int encrypted_nalu_length = nalu.length;
            ret = decrypt_nal_unit(crypto_ctx, &nalu);
            if (ret < 0)
                return ret;
            move_nalu = nalu.length != encrypted_nalu_length;
        }
        if (move_nalu)
            memmove(data_ptr, nalu.data - nalu.start_code_length, nalu.start_code_length + nalu.length);
        data_ptr += nalu.start_code_length + nalu.length;
    }

    av_shrink_packet(pkt, data_ptr - pkt->data);

    return 0;
}

static int decrypt_sync_frame(enum AVCodecID codec_id, CryptoContext *crypto_ctx, AudioFrame *frame)
{
    int ret = 0;
    uint8_t *data;
    int num_of_encrypted_blocks;
    ret = av_aes_init(crypto_ctx->aes_ctx, crypto_ctx->key, 16 * 8, 1);
    if (ret < 0)
        return ret;

    data = frame->data + frame->header_length + 16;

    num_of_encrypted_blocks = (frame->length - frame->header_length - 16)/16;

    av_aes_crypt(crypto_ctx->aes_ctx, data, data, num_of_encrypted_blocks, crypto_ctx->iv, 1);

    return 0;
}

static int decrypt_audio_frame(enum AVCodecID codec_id, CryptoContext *crypto_ctx, AVPacket *pkt)
{
    AudioFrame frame;
    memset(&frame, 0, sizeof(frame));
    frame.length = pkt->size;
    frame.header_length = 7;
    frame.data = pkt->data;
    return decrypt_sync_frame(codec_id, crypto_ctx, &frame);
}

int ff_hls_senc_decrypt_frame(enum AVCodecID codec_id, CryptoContext *crypto_ctx, AVPacket *pkt)
{
    av_log(NULL, AV_LOG_DEBUG,"ff_flv_senc_decrypt_frame key:%s iv:%s\n",crypto_ctx->key,crypto_ctx->iv);
    if (codec_id == AV_CODEC_ID_H264 ||codec_id == AV_CODEC_ID_H265)
        return decrypt_video_frame(codec_id, crypto_ctx, pkt);
    else if (codec_id == AV_CODEC_ID_AAC || codec_id == AV_CODEC_ID_AC3 || codec_id == AV_CODEC_ID_EAC3)
        return decrypt_audio_frame(codec_id, crypto_ctx, pkt);

    return AVERROR_INVALIDDATA;
}


static int get_flv_next_nal_unit(enum AVCodecID codec_id, CodecParserContext *ctx, NALUnit *nalu)
{
    nalu->start_code_length = 4;
    nalu->data = (uint8_t *)ctx->buf_ptr + nalu->start_code_length;
    nalu->length=*(nalu->data-1) | *(nalu->data-2)<<8 | *(nalu->data-3)<<16 | *(nalu->data-4)<<24;
    if (codec_id==AV_CODEC_ID_H264){
        nalu->type = *nalu->data & 0x1F;
    }else if (codec_id==AV_CODEC_ID_H265){
        nalu->type = (*nalu->data&0x7E)>>1;
    }
    ctx->buf_ptr += nalu->start_code_length+nalu->length;
    return 0;
}

static int decrypt_flv_video_frame(enum AVCodecID codec_id, CryptoContext *crypto_ctx, AVPacket *pkt)
{
    int ret = 0;
    CodecParserContext  ctx;
    NALUnit nalu;
    uint8_t *data_ptr;
    int move_nalu = 0;

    memset(&ctx, 0, sizeof(ctx));
    ctx.buf_ptr  = pkt->data;
    ctx.buf_end  = pkt->data + pkt->size;
    data_ptr = pkt->data;
    uint8_t *nalu_start=pkt->data;
    while (nalu_start < ctx.buf_end) {
        memset(&nalu, 0, sizeof(nalu));
        ret = get_flv_next_nal_unit(codec_id, &ctx, &nalu);
        if (ret < 0)
            return ret;
        if (nalu_encrypted(codec_id, nalu)) {
            int encrypted_nalu_length = nalu.length;
            ret = decrypt_nal_unit(crypto_ctx, &nalu);
            if (ret < 0)
                return ret;
            move_nalu =encrypted_nalu_length-nalu.length;
        }

        if (move_nalu){
            for (int i = nalu.start_code_length; i >0; i--)
                *(nalu.data-i) = nalu.length >> (8*(i-1));
            memmove(data_ptr, nalu.data - nalu.start_code_length, nalu.start_code_length + nalu.length);
        }
        data_ptr += nalu.start_code_length + nalu.length;
        nalu_start+=nalu.length+nalu.start_code_length+move_nalu;
    }
    av_shrink_packet(pkt, data_ptr - pkt->data);
    return 0;
}


static int decrypt_flv_audio_frame(enum AVCodecID codec_id, CryptoContext *crypto_ctx, AVPacket *pkt)
{
    AudioFrame frame;
    memset(&frame, 0, sizeof(frame));
    frame.length = pkt->size;
    frame.header_length = 0;
    frame.data = pkt->data;
    return decrypt_sync_frame(codec_id, crypto_ctx, &frame);
}

int ff_flv_senc_decrypt_frame(enum AVCodecID codec_id, CryptoContext *crypto_ctx, AVPacket *pkt)
{
    av_log(NULL, AV_LOG_DEBUG,"ff_flv_senc_decrypt_frame key:%s iv:%s\n",crypto_ctx->key,crypto_ctx->iv);
    if (codec_id == AV_CODEC_ID_H264 ||codec_id == AV_CODEC_ID_H265)
        return decrypt_flv_video_frame(codec_id, crypto_ctx, pkt);
    else if (codec_id == AV_CODEC_ID_AAC || codec_id == AV_CODEC_ID_AC3 || codec_id == AV_CODEC_ID_EAC3)
        return decrypt_flv_audio_frame(codec_id, crypto_ctx, pkt);

    return AVERROR_INVALIDDATA;
}
