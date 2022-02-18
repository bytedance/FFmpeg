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

#ifndef AVFORMAT_DASH_CONTEXT_H
#define AVFORMAT_DASH_CONTEXT_H

#include <unistd.h>

//#include "libavformat/avio_internal.h"
//#include "libavformat/internal.h"
#include <libavutil/intreadwrite.h>
#include <libavutil/opt.h>
#include <libavutil/parseutils.h>
//#include "libavutil/thread.h"
#include <libavutil/time.h>
//#include "libavformat/network.h"
#include <libavformat/avformat.h>
#include <libavformat/url.h>
#include <libavutil/avstring.h>
#include <pthread.h>
#if CONFIG_DRM
#include "libavutil/drm.h"
#endif
#include <stdatomic.h>

#define MAX_URL_SIZE 8192

struct fragment {
  int64_t url_offset;
  int64_t size;
  char *url;
};

/*
 * reference to : ISO_IEC_23009-1-DASH-2012
 * Section: 5.3.9.6.2
 * Table: Table 17 — Semantics of SegmentTimeline element
 * */
struct timeline {
  /* starttime: Element or Attribute Name
   * specifies the MPD start time, in @timescale units,
   * the first Segment in the series starts relative to the beginning of the
   * Period. The value of this attribute must be equal to or greater than the
   * sum of the previous S element earliest presentation time and the sum of the
   * contiguous Segment durations. If the value of the attribute is greater than
   * what is expressed by the previous S element, it expresses discontinuities
   * in the timeline. If not present then the value shall be assumed to be zero
   * for the first S element and for the subsequent S elements, the value shall
   * be assumed to be the sum of the previous S element's earliest presentation
   * time and contiguous duration (i.e. previous S@starttime + @duration *
   * (@repeat + 1)).
   * */
  int64_t starttime;
  /* repeat: Element or Attribute Name
   * specifies the repeat count of the number of following contiguous Segments
   * with the same duration expressed by the value of @duration. This value is
   * zero-based (e.g. a value of three means four Segments in the contiguous
   * series).
   * */
  int64_t repeat;
  /* duration: Element or Attribute Name
   * specifies the Segment duration, in units of the value of the @timescale.
   * */
  int64_t duration;
};

struct adaptation_set_property {
    char *scheme_id_uri;
    char *value;
    char *adaptation_type;
};

/*
 * Each playlist has its own demuxer. If it is currently active,
 * it has an opened AVIOContext too, and potentially an AVPacket
 * containing the next packet from this stream.
 */
struct representation {
  char *url_template;
  AVIOContext pb;
  AVIOContext *input;
  AVFormatContext *parent;
  AVFormatContext *ctx;
  AVPacket pkt;
  int rep_idx;
  int rep_count;
  int stream_index;

  enum AVMediaType type;
  char id[20];
  int bandwidth;
  AVRational framerate;
  AVStream
      *assoc_stream; /* demuxer stream associated with this representation */

  int n_fragments;
  struct fragment **fragments; /* VOD list of fragment for profile */

  int n_timelines;
  struct timeline **timelines;

  int64_t first_seq_no;
  int64_t last_seq_no;
  int is_seeking;
  int64_t seek_pos;
  int seek_flags;
  int64_t start_number; /* used in case when we have dynamic list of segment to
                           know which segments are new one*/

  int64_t fragment_duration;
  int64_t fragment_timescale;

  int64_t presentation_timeoffset;

  int seek_retry_error;
  int64_t seek_retry_offset;
  int64_t cur_seq_no;
  int64_t read_seq_no;
  int64_t cur_seg_offset;
  int64_t cur_seg_size;
  struct fragment *cur_seg;

  /* Currently active Media Initialization Section */
  struct fragment *init_section;
  uint8_t *init_sec_buf;
  uint32_t init_sec_buf_size;
  uint32_t init_sec_data_len;
  uint32_t init_sec_buf_read_offset;
  int64_t cur_timestamp;
  int is_restart_needed;
  int is_opened;
  int is_segmentbase;
  int is_need_check_seek;

  /* Content Protection */
  char *cenc_default_kid;

  // opts for io
  AVDictionary *avio_opts;

  /* mutex for update mpd async */
  pthread_mutex_t async_update_lock;

  int is_skip_needed;
  // really download segment count, isn't same to the segment num.
  int down_segment_count;

  struct adaptation_set_property *essential_property;
  struct adaptation_set_property *supplemental_property;
};

typedef struct DASHContext {
  const AVClass *av_class;
  char *base_url;

  int stream_count;
  int need_inject_sidedata;
  int cur_video_bitrate;
  int cur_audio_bitrate;
  int cur_video;
  int cur_audio;
  int next_video;
  int next_audio;
  int n_videos;
  int64_t start_time;
  struct representation **videos;
  int n_audios;
  struct representation **audios;

  /* MediaPresentationDescription Attribute */
  uint64_t media_presentation_duration;
  uint64_t suggested_presentation_delay;
  uint64_t availability_start_time;
  uint64_t publish_time;
  uint64_t minimum_update_period;
  uint64_t time_shift_buffer_depth;
  uint64_t min_buffer_time;

  /* Period Attribute */
  uint64_t period_duration;
  uint64_t period_start;

  int is_live;
  AVIOInterruptCB *interrupt_callback;
  char *allowed_extensions;
  AVDictionary *avio_opts;
  uint64_t avio_opts_ptr;
  int max_url_size;

  /* Flags for init section*/
  int is_init_section_common_video;
  int is_init_section_common_audio;

  // for drm
  char *decryption_key;
  int drm_downgrade;
  int64_t drm_aptr;
  void *drm_ctx;

  uint64_t aptr;
  uint64_t abr;
  int is_live_ended;
  int is_live_started;
  int skip_find_audio_stream_info;

   // set the start segment offset, from the newest segment
  int live_start_segment_offset;

   // set delay time offset from end time (by second)
  int low_delay_time_offset;
} DASHContext;

/**
 * @}
 */

#endif /* AVFORMAT_DASH_CONTEXT_H */
