/*
 * Dynamic Adaptive Streaming over HTTP demux
 * Copyright (c) 2017 samsamsam@o2.pl based on HLS demux
 * Copyright (c) 2017 Steven Liu
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
 * 
 * This file may have been modified by Bytedance Inc. (“Bytedance Modifications”). 
 * All Bytedance Modifications are Copyright 2022 Bytedance Inc.
 */

#ifndef AVFORMAT_DASH_PARSER_H
#define AVFORMAT_DASH_PARSER_H

#include "dash_context.h"

#ifdef WIN32
#define ffmpeg_dash_export __declspec(dllexport)
#else // for GCC
#define ffmpeg_dash_export __attribute__ ((visibility("default")))
#endif

ffmpeg_dash_export int64_t get_segment_start_time_based_on_timeline(struct representation *pls, int64_t cur_seq_no);

ffmpeg_dash_export int64_t calc_next_seg_no_from_timelines(struct representation *pls, int64_t cur_time);

ffmpeg_dash_export void free_fragment(struct fragment **seg);

ffmpeg_dash_export void free_fragment_list(struct representation *pls);

ffmpeg_dash_export void free_timelines_list(struct representation *pls);

ffmpeg_dash_export void free_representation(struct representation *pls);

ffmpeg_dash_export void free_video_list(DASHContext *c);

ffmpeg_dash_export void free_audio_list(DASHContext *c);

ffmpeg_dash_export struct fragment* get_Fragment(char *range);

ffmpeg_dash_export int64_t calc_min_seg_no(DASHContext *c, struct representation *pls);

ffmpeg_dash_export int64_t calc_max_seg_no(struct representation *pls, DASHContext *c);

ffmpeg_dash_export void prepare_init_sec_buf(struct representation *pls);

ffmpeg_dash_export void copy_init_section(struct representation *rep_dest, struct representation *rep_src);

ffmpeg_dash_export int check_url(DASHContext *dash_ctx, AVIOContext **pb, const char *url);

ffmpeg_dash_export int parse_dash_manifest(DASHContext *dash_ctx, const char *buffer, int buffer_size, const char *url);

ffmpeg_dash_export void move_timelines(struct representation *rep_src, struct representation *rep_dest, DASHContext *c);

ffmpeg_dash_export void move_segments(struct representation *rep_src, struct representation *rep_dest, DASHContext *c);

ffmpeg_dash_export int save_avio_options(AVFormatContext *s, DASHContext *c);

ffmpeg_dash_export int nested_io_open(AVFormatContext *s, AVIOContext **pb, const char *url,
                   int flags, AVDictionary **opts);

ffmpeg_dash_export void close_demux_for_component(struct representation *pls);

ffmpeg_dash_export int reopen_demux_for_representation(AVFormatContext *s, DASHContext *dash_ctx,
                                                       struct representation *pls);

enum ReadFromURLMode {
    READ_NORMAL,
    READ_COMPLETE,
};

ffmpeg_dash_export int read_from_url(struct representation *pls, struct fragment *seg,
                  uint8_t *buf, int buf_size, enum ReadFromURLMode mode);

ffmpeg_dash_export int64_t calc_cur_seg_no(DASHContext *dash_ctx, struct representation *pls);

ffmpeg_dash_export int64_t find_nearest_fragment(struct representation *pls, int64_t pos_msec);

ffmpeg_dash_export struct fragment* getFragment(struct representation *pls, struct fragment *seg, const DASHContext *dash_ctx);

ffmpeg_dash_export void ff_cmaf_fill_tmpl_params(char *dst, size_t buffer_size,
                              const char *template, int rep_id,
                              int number, int bit_rate,
                              int64_t time);

ffmpeg_dash_export int is_common_init_section_exist(struct representation **pls, int n_pls);

ffmpeg_dash_export int check_init_section(uint8_t *sec_buf);

ffmpeg_dash_export int64_t seek_data(void *opaque, int64_t offset, int whence);

// for pkt buffer
ffmpeg_dash_export int add_to_pktbuf(AVPacketList **packet_buffer, AVPacket *pkt,
                  AVPacketList **plast_pktl);

ffmpeg_dash_export int read_from_packet_buffer(AVPacketList **pkt_buffer,
                            AVPacketList **pkt_buffer_end,
                            AVPacket      *pkt);

ffmpeg_dash_export void free_packet_buffer(AVPacketList **pkt_buf, AVPacketList **pkt_buf_end);

/**
 * @}
 */

#endif /* AVFORMAT_DASH_CONTEXT_H */

