/*
 * raw ADTS AAC demuxer
 * Copyright (c) 2008 Michael Niedermayer <michaelni@gmx.at>
 * Copyright (c) 2009 Robert Swain ( rob opendot cl )
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

#include "libavutil/avassert.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/opt.h"
#include "avformat.h"
#include "avio_internal.h"
#include "internal.h"
#include "id3v1.h"
#include "id3v2.h"
#include "apetag.h"

#define ADTS_HEADER_SIZE 7

typedef struct AACContext {
    const AVClass *class;
    int accurate_mode;
} AACContext;

static const AVOption options[] = {
    { "aac_accurate_mode", "use accurate mode", offsetof(AACContext, accurate_mode), AV_OPT_TYPE_BOOL, {.i64 = 0}, 0, 1, AV_OPT_FLAG_AUDIO_PARAM},
    { NULL },
};

static const AVClass ff_aac_demuxer_class = {
    .class_name = "aac_dexmuxer",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
    .category   = AV_CLASS_CATEGORY_DEMUXER,
};

static int adts_aac_resync(AVFormatContext *s)
{
    uint16_t state;

    // skip data until an ADTS frame is found
    state = avio_r8(s->pb);
    while (!avio_feof(s->pb) && avio_tell(s->pb) < s->probesize) {
        state = (state << 8) | avio_r8(s->pb);
        if ((state >> 4) != 0xFFF)
            continue;
        avio_seek(s->pb, -2, SEEK_CUR);
        break;
    }
    if (s->pb->eof_reached)
        return AVERROR_EOF;
    if ((state >> 4) != 0xFFF)
        return AVERROR_INVALIDDATA;

    return 0;
}

static int get_sample_rate(uint8_t index)
{
    static const int sample_rates[] = {
        96000, 88200, 64000, 48000, 44100, 32000,
        24000, 22050, 16000, 12000, 11025, 8000,
        7350
    };

    if (index < sizeof(sample_rates) / sizeof(sample_rates[0])) {
        return sample_rates[index];
    }

    return 0;
}

static int64_t get_adts_aac_frame_size(AVFormatContext *s, int64_t offset)
{
    const uint8_t kAdtsHeaderLengthNoCrc = 7;
    const uint8_t kAdtsHeaderLengthWithCrc = 9;

    uint8_t syncword[2];
    avio_seek(s->pb, offset, SEEK_SET);
    if(avio_read(s->pb, &syncword, 2) != 2) {
        av_log(s, AV_LOG_ERROR, "failed to read adts syncword!\n");
        return AVERROR_INVALIDDATA;
    }
    if ((syncword[0] != 0xff) || ((syncword[1] & 0xf6) != 0xf0)) {
        av_log(s, AV_LOG_ERROR, "failed to read adts syncword, byte error!\n");
        return AVERROR_INVALIDDATA;
    }

    uint8_t protection_absent;
    avio_seek(s->pb, offset + 1, SEEK_SET);
    if (avio_read(s->pb, &protection_absent, 1) < 1) {
        av_log(s, AV_LOG_ERROR, "failed to read adts protection_absent!\n");
        return AVERROR_INVALIDDATA;
    }
    protection_absent &= 0x1;

    uint8_t header[3];
    uint32_t frame_size;
    avio_seek(s->pb, offset + 3, SEEK_SET);
    if (avio_read(s->pb, &header, 3) < 3) {
        av_log(s, AV_LOG_ERROR, "failed to read adts frame_size!\n");
        return AVERROR_INVALIDDATA;
    }
    frame_size = (header[0] & 0x3) << 11 | header[1] << 3 | header[2] >> 5;

    // protectionAbsent is 0 if there is CRC
    uint8_t head_size = protection_absent ? kAdtsHeaderLengthNoCrc : kAdtsHeaderLengthWithCrc;
    if (head_size > frame_size) {
        av_log(s, AV_LOG_ERROR, "adts head_size greater than frame_size!\n");
        return AVERROR_INVALIDDATA;
    }

    return frame_size;
}

static int adts_aac_accurate_read_header(AVFormatContext *s, AVStream *st, AVDictionary **options) {
    int ret = 0;

    int64_t stream_size = avio_size(s->pb);
    if (stream_size <= 0) {
        av_log(s, AV_LOG_ERROR, "avio_size error!\n");
        return AVERROR_INVALIDDATA;
    }

    int64_t first_frame_pos = avio_tell(s->pb);
    do {
        uint8_t header[2];
        avio_seek(s->pb, 2, SEEK_CUR);
        if (avio_read(s->pb, &header, 2) < 2) {
            av_log(s, AV_LOG_ERROR, "failed to read adts profile!\n");
            ret = AVERROR_INVALIDDATA;
            break;
        }
        int profile = (header[0] >> 6) & 0x3;
        st->codecpar->profile = profile;

        uint8_t index = (header[0] >> 2) & 0xf;
        int sample_rate = get_sample_rate(index);
        if (sample_rate == 0) {
            av_log(s, AV_LOG_ERROR, "failed to read adts sample_rate!\n");
            ret = AVERROR_INVALIDDATA;
            break;
        }
        st->codecpar->sample_rate = sample_rate;

        uint8_t channel = (header[0] & 0x1) << 2 | (header[1] >> 6);
        if (channel == 0) {
            av_log(s, AV_LOG_ERROR, "failed to read adts channels!\n");
            ret = AVERROR_INVALIDDATA;
            break;
        }
        st->codecpar->channels = channel;
        st->codecpar->frame_size = 1024;

        avpriv_set_pts_info(st, 64, 1, st->codecpar->sample_rate);

        int64_t offset = 0;
        int64_t frame_size = 0;
        int64_t num_frames = 0;

        while (offset < stream_size) {
            if ((frame_size = get_adts_aac_frame_size(s, first_frame_pos + offset)) <= 0) {
                break;
            }
            offset += frame_size;
            num_frames++;
        }
        // round up and get the duration
        int64_t frame_duration_us = (1024 * 1000000ll + (sample_rate - 1)) / sample_rate;
        int64_t duration_us = num_frames * frame_duration_us;
        st->duration = av_rescale_q(duration_us, AV_TIME_BASE_Q, st->time_base);
    } while (0);

    avio_seek(s->pb, first_frame_pos, SEEK_SET);
    
    return ret;
}

static int adts_aac_probe(const AVProbeData *p)
{
    int max_frames = 0, first_frames = 0;
    int fsize, frames;
    const uint8_t *buf0 = p->buf;
    const uint8_t *buf2;
    const uint8_t *buf;
    const uint8_t *end = buf0 + p->buf_size - 7;

    buf = buf0;

    for (; buf < end; buf = buf2 + 1) {
        buf2 = buf;

        for (frames = 0; buf2 < end; frames++) {
            uint32_t header = AV_RB16(buf2);
            if ((header & 0xFFF6) != 0xFFF0) {
                if (buf != buf0) {
                    // Found something that isn't an ADTS header, starting
                    // from a position other than the start of the buffer.
                    // Discard the count we've accumulated so far since it
                    // probably was a false positive.
                    frames = 0;
                }
                break;
            }
            fsize = (AV_RB32(buf2 + 3) >> 13) & 0x1FFF;
            if (fsize < 7)
                break;
            fsize = FFMIN(fsize, end - buf2);
            buf2 += fsize;
        }
        max_frames = FFMAX(max_frames, frames);
        if (buf == buf0)
            first_frames = frames;
    }

    if (first_frames >= 3)
        return AVPROBE_SCORE_EXTENSION + 1;
    else if (max_frames > 100)
        return AVPROBE_SCORE_EXTENSION;
    else if (max_frames >= 3)
        return AVPROBE_SCORE_EXTENSION / 2;
    else if (first_frames >= 1)
        return 1;
    else
        return 0;
}

static int adts_aac_read_header(AVFormatContext *s)
{
    AVStream *st;
    int ret;

    st = avformat_new_stream(s, NULL);
    if (!st)
        return AVERROR(ENOMEM);

    st->codecpar->codec_type = AVMEDIA_TYPE_AUDIO;
    st->codecpar->codec_id   = s->iformat->raw_codec_id;
    st->need_parsing         = AVSTREAM_PARSE_FULL_RAW;

    ff_id3v1_read(s);
    if ((s->pb->seekable & AVIO_SEEKABLE_NORMAL) &&
        !av_dict_get(s->metadata, "", NULL, AV_DICT_IGNORE_SUFFIX)) {
        int64_t cur = avio_tell(s->pb);
        ff_ape_parse_tag(s);
        avio_seek(s->pb, cur, SEEK_SET);
    }

    ret = adts_aac_resync(s);
    if (ret < 0)
        return ret;

    ret = -1;
    AACContext *ctx = (AACContext *)s->priv_data;
    if (ctx && ctx->accurate_mode == 1) {
        ret = adts_aac_accurate_read_header(s, st, NULL);
    }

    if (ret < 0) {
        // LCM of all possible ADTS sample rates
        avpriv_set_pts_info(st, 64, 1, 28224000);
    }

    return 0;
}

static int handle_id3(AVFormatContext *s, AVPacket *pkt)
{
    AVDictionary *metadata = NULL;
    AVIOContext ioctx;
    ID3v2ExtraMeta *id3v2_extra_meta = NULL;
    int ret;

    ret = av_append_packet(s->pb, pkt, ff_id3v2_tag_len(pkt->data) - pkt->size);
    if (ret < 0) {
        return ret;
    }

    ffio_init_context(&ioctx, pkt->data, pkt->size, 0, NULL, NULL, NULL, NULL);
    ff_id3v2_read_dict(&ioctx, &metadata, ID3v2_DEFAULT_MAGIC, &id3v2_extra_meta);
    if ((ret = ff_id3v2_parse_priv_dict(&metadata, id3v2_extra_meta)) < 0)
        goto error;

    if (metadata) {
        if ((ret = av_dict_copy(&s->metadata, metadata, 0)) < 0)
            goto error;
        s->event_flags |= AVFMT_EVENT_FLAG_METADATA_UPDATED;
    }

error:
    av_packet_unref(pkt);
    ff_id3v2_free_extra_meta(&id3v2_extra_meta);
    av_dict_free(&metadata);

    return ret;
}

static int adts_aac_read_packet(AVFormatContext *s, AVPacket *pkt)
{
    int ret, fsize;

retry:
    ret = av_get_packet(s->pb, pkt, ADTS_HEADER_SIZE);
    if (ret < 0)
        return ret;

    if (ret < ADTS_HEADER_SIZE) {
        return AVERROR(EIO);
    }

    if ((AV_RB16(pkt->data) >> 4) != 0xfff) {
        // Parse all the ID3 headers between frames
        int append = ID3v2_HEADER_SIZE - ADTS_HEADER_SIZE;

        av_assert2(append > 0);
        ret = av_append_packet(s->pb, pkt, append);
        if (ret != append) {
            return AVERROR(EIO);
        }
        if (!ff_id3v2_match(pkt->data, ID3v2_DEFAULT_MAGIC)) {
            av_packet_unref(pkt);
            ret = adts_aac_resync(s);
        } else
            ret = handle_id3(s, pkt);
        if (ret < 0)
            return ret;

        goto retry;
    }

    fsize = (AV_RB32(pkt->data + 3) >> 13) & 0x1FFF;
    if (fsize < ADTS_HEADER_SIZE) {
        return AVERROR_INVALIDDATA;
    }

    ret = av_append_packet(s->pb, pkt, fsize - pkt->size);

    return ret;
}

AVInputFormat ff_aac_demuxer = {
    .name         = "aac",
    .long_name    = NULL_IF_CONFIG_SMALL("raw ADTS AAC (Advanced Audio Coding)"),
    .read_probe   = adts_aac_probe,
    .read_header  = adts_aac_read_header,
    .read_packet  = adts_aac_read_packet,
    .flags        = AVFMT_GENERIC_INDEX,
    .extensions   = "aac",
    .mime_type    = "audio/aac,audio/aacp,audio/x-aac",
    .raw_codec_id = AV_CODEC_ID_AAC,
    .priv_data_size = sizeof(AACContext),
    .priv_class = &ff_aac_demuxer_class,
};
