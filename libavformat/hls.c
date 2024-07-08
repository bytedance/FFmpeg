/*
 * Apple HTTP Live Streaming demuxer
 * Copyright (c) 2010 Martin Storsjo
 * Copyright (c) 2013 Anssi Hannula
 * Copyright (c) 2011 Cedirc Fung (wolfplanet@gmail.com)
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

/**
 * @file
 * Apple HTTP Live Streaming demuxer
 * https://www.rfc-editor.org/rfc/rfc8216.txt
 */

#include "libavformat/http.h"
#include "libavutil/avstring.h"
#include "libavutil/avassert.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/mathematics.h"
#include "libavutil/base64.h"
#include "libavutil/opt.h"
#include "libavutil/dict.h"
#include "libavutil/drm.h"
#include "libavutil/time.h"
#include "avformat.h"
#include "internal.h"
#include "sample_aes.h"
#include "avio_internal.h"
#include "id3v2.h"
#include <stdbool.h>
#define INITIAL_BUFFER_SIZE 32768

#define MAX_FIELD_LEN 64
#define MAX_CHARACTERISTICS_LEN 512
#define CONTENT_ID_LEN 256

#define MPEG_TIME_BASE 90000
#define MPEG_TIME_BASE_Q (AVRational){1, MPEG_TIME_BASE}

/*
 * An apple http stream consists of a playlist with media segment files,
 * played sequentially. There may be several playlists with the same
 * video content, in different bandwidth variants, that are played in
 * parallel (preferably only one bandwidth variant at a time). In this case,
 * the user supplied the url to a main playlist that only lists the variant
 * playlists.
 *
 * If the main playlist doesn't point at any variants, we still create
 * one anonymous toplevel variant for this, to maintain the structure.
 */

enum KeyType {
    KEY_NONE,
    KEY_AES_128,
    KEY_SAMPLE_AES
};

enum ProbeType {
    PRB_KEY_VAR,
    PRB_KEY_REND
};

struct segment {
    int64_t previous_duration;
    int64_t duration;
    int64_t start_time;
    int64_t reconnect_offset;
    int64_t url_offset;
    int64_t size;
    /* `start_dts` and `start_pts` are used to record
     * the starting dts/pts of the current stream in this segment.
     * Their size `timestamp_list_size` is determined by the number of streams.
     * Their size will be initialized to playlist's `n_main_streams` */
    int64_t *start_dts;
    int64_t *start_pts;
    int timestamp_list_size;
    int64_t is_discontinuety;
    char *url;
    char *key;
    enum KeyType key_type;
    uint8_t iv[16];
    int need_set_host;
    int64_t segment_number;
    /* associated Media Initialization Section, treated as a segment */
    struct segment *init_section;
};

struct rendition;

enum PlaylistType {
    PLS_TYPE_UNSPECIFIED,
    PLS_TYPE_EVENT,
    PLS_TYPE_VOD
};

/*
 * Each playlist has its own demuxer. If it currently is active,
 * it has an open AVIOContext too, and potentially an AVPacket
 * containing the next packet from this stream.
 */
struct playlist {
    char url[MAX_URL_SIZE];
    AVIOContext pb;
    uint8_t* read_buffer;
    AVIOContext *input;
    int input_read_done;
    AVIOContext *input_next;
    int input_next_requested;
    AVFormatContext *parent;
    int index;
    AVFormatContext *ctx;
    AVPacket *pkt;
    int has_noheader_flag;

    /* main demuxer streams associated with this playlist
     * indexed by the subdemuxer stream indexes */
    AVStream **main_streams;
    int n_main_streams;

    int reuse;
    int finished;
    enum PlaylistType type;
    int64_t target_duration;
    int64_t start_seq_no;
    int n_segments;
    struct segment **segments;
    int needed;
    int broken;
    int64_t cur_seq_no;
    int64_t last_seq_no;
    int m3u8_hold_counters;
    int64_t cur_refresh_begin_time;
    int64_t cur_seg_offset;
    int64_t last_load_time;

    /* Currently active Media Initialization Section */
    struct segment *cur_init_section;
    uint8_t *init_sec_buf;
    unsigned int init_sec_buf_size;
    unsigned int init_sec_data_len;
    unsigned int init_sec_buf_read_offset;

    char key_url[MAX_URL_SIZE];
    uint8_t key[16];

    /* ID3 timestamp handling (elementary audio streams have ID3 timestamps
     * (and possibly other ID3 tags) in the beginning of each segment) */
    int is_id3_timestamped; /* -1: not yet known */
    int64_t id3_mpegts_timestamp; /* in mpegts tb */
    int64_t id3_offset; /* in stream original tb */
    uint8_t* id3_buf; /* temp buffer for id3 parsing */
    unsigned int id3_buf_size;
    AVDictionary *id3_initial; /* data from first id3 tag */
    int id3_found; /* ID3 tag found at some point */
    int id3_changed; /* ID3 tag data has changed at some point */
    ID3v2ExtraMeta *id3_deferred_extra; /* stored here until subdemuxer is opened */

    int64_t seek_timestamp;
    int seek_flags;
    int seek_stream_index; /* into subdemuxer stream array */

    /* Renditions associated with this playlist, if any.
     * Alternative rendition playlists have a single rendition associated
     * with them, and variant main Media Playlists may have
     * multiple (playlist-less) renditions associated with them. */
    int n_renditions;
    struct rendition **renditions;

    /* Media Initialization Sections (EXT-X-MAP) associated with this
     * playlist, if any. */
    int n_init_sections;
    struct segment **init_sections;
};

/*
 * Renditions are e.g. alternative subtitle or audio streams.
 * The rendition may either be an external playlist or it may be
 * contained in the main Media Playlist of the variant (in which case
 * playlist is NULL).
 */
struct rendition {
    enum AVMediaType type;
    struct playlist *playlist;
    char group_id[MAX_FIELD_LEN];
    char language[MAX_FIELD_LEN];
    char name[MAX_FIELD_LEN];
    int disposition;
};

struct variant {
    int bandwidth;

    /* every variant contains at least the main Media Playlist in index 0 */
    int n_playlists;
    struct playlist **playlists;

    char audio_group[MAX_FIELD_LEN];
    char video_group[MAX_FIELD_LEN];
    char subtitles_group[MAX_FIELD_LEN];
};

typedef struct ABRStrategyCtx {
    int (*probe_bitrate)(int64_t opaque, int current_bitrate);
} ABRStrategyCtx;

typedef struct HLSContext {
    AVClass *class;
    AVFormatContext *ctx;
    int n_variants;
    struct variant **variants;
    int n_playlists;
    struct playlist **playlists;
    int n_renditions;
    struct rendition **renditions;

    int url_index;
    int64_t cur_seq_no;
    int m3u8_hold_counters;
    int live_start_index;
    int first_packet;
    int64_t first_timestamp;
    int64_t cur_timestamp;
    AVIOInterruptCB *interrupt_callback;
    char *headers_without_host;
    AVDictionary *avio_opts;
    char *allowed_extensions;
    int max_reload;
    int http_persistent;
    int http_multiple;
    int http_seekable;
    AVIOContext *playlist_pb;

    intptr_t tt_opaque;
    int tt_hls_drm_enable;
    char* tt_hls_drm_token;
    char *decryption_key;
    int enable_refresh_by_time;
    int cur_video_bitrate;
    int now_video_bitrate;
    int now_var_index;
    int need_inject_sidedata;
    int cur_audio_infoid;
    int now_audio_infoid;
    int now_rend_pls_index;
    int switch_exit;
    AVPacket **packets[AVMEDIA_TYPE_NB];
    int n_packets[AVMEDIA_TYPE_NB];
    int packets_pos[AVMEDIA_TYPE_NB];
    int64_t video_keyframe_time;
    int drm_downgrade;
    int enable_intertrust_drm;
    intptr_t drm_aptr;
    void *drm_ctx;
    // abr              
    intptr_t abr;  /// abr_impl
    CryptoContext crypto_ctx;
    int hls_sub_demuxer_probe_type;
    int enable_master_optimize;
    int seg_max_retry;
    int enable_seg_error;
    int enable_hls_pts_recal_opt;
} HLSContext;

static void free_segment_dynarray(struct segment **segments, int n_segments)
{
    int i;
    for (i = 0; i < n_segments; i++) {
        av_freep(&segments[i]->key);
        av_freep(&segments[i]->url);
        av_freep(&segments[i]->start_dts);
        av_freep(&segments[i]->start_pts);
        av_freep(&segments[i]);
    }
}

static void free_segment_list(struct playlist *pls)
{
    free_segment_dynarray(pls->segments, pls->n_segments);
    av_freep(&pls->segments);
    pls->n_segments = 0;
}

static void free_init_section_list(struct playlist *pls)
{
    int i;
    for (i = 0; i < pls->n_init_sections; i++) {
        av_freep(&pls->init_sections[i]->url);
        av_freep(&pls->init_sections[i]);
    }
    av_freep(&pls->init_sections);
    pls->n_init_sections = 0;
}

static void free_playlist_list(HLSContext *c)
{
    int i;
    for (i = 0; i < c->n_playlists; i++) {
        struct playlist *pls = c->playlists[i];
        free_segment_list(pls);
        free_init_section_list(pls);
        av_freep(&pls->main_streams);
        av_freep(&pls->renditions);
        av_freep(&pls->id3_buf);
        av_dict_free(&pls->id3_initial);
        ff_id3v2_free_extra_meta(&pls->id3_deferred_extra);
        av_freep(&pls->init_sec_buf);
        av_packet_free(&pls->pkt);
        av_freep(&pls->pb.buffer);
        ff_format_io_close(c->ctx, &pls->input);
        pls->input_read_done = 0;
        ff_format_io_close(c->ctx, &pls->input_next);
        pls->input_next_requested = 0;
        if (pls->ctx) {
            pls->ctx->pb = NULL;
            avformat_close_input(&pls->ctx);
        }
        av_free(pls);
    }
    av_freep(&c->playlists);
    av_freep(&c->headers_without_host);
    av_freep(&c->decryption_key);
    c->n_playlists = 0;
}

static void free_variant_list(HLSContext *c)
{
    int i;
    for (i = 0; i < c->n_variants; i++) {
        struct variant *var = c->variants[i];
        av_freep(&var->playlists);
        av_free(var);
    }
    av_freep(&c->variants);
    c->n_variants = 0;
}

static void free_rendition_list(HLSContext *c)
{
    int i;
    for (i = 0; i < c->n_renditions; i++)
        av_freep(&c->renditions[i]);
    av_freep(&c->renditions);
    c->n_renditions = 0;
}

static struct playlist *new_playlist(HLSContext *c, const char *url,
                                     const char *base)
{
    struct playlist *pls = av_mallocz(sizeof(struct playlist));
    if (!pls)
        return NULL;
    pls->pkt = av_packet_alloc();
    if (!pls->pkt) {
        av_free(pls);
        return NULL;
    }
    ff_make_absolute_url(pls->url, sizeof(pls->url), base, url);
    if (!pls->url[0]) {
        av_packet_free(&pls->pkt);
        av_free(pls);
        return NULL;
    }
    pls->seek_timestamp = AV_NOPTS_VALUE;

    pls->is_id3_timestamped = -1;
    pls->id3_mpegts_timestamp = AV_NOPTS_VALUE;

    dynarray_add(&c->playlists, &c->n_playlists, pls);
    return pls;
}

struct variant_info {
    char bandwidth[20];
    /* variant group ids: */
    char audio[MAX_FIELD_LEN];
    char video[MAX_FIELD_LEN];
    char subtitles[MAX_FIELD_LEN];
};

static struct variant *new_variant(HLSContext *c, struct variant_info *info,
                                   const char *url, const char *base)
{
    struct variant *var;
    struct playlist *pls;

    pls = new_playlist(c, url, base);
    if (!pls)
        return NULL;

    var = av_mallocz(sizeof(struct variant));
    if (!var)
        return NULL;

    if (info) {
        var->bandwidth = atoi(info->bandwidth);
        strcpy(var->audio_group, info->audio);
        strcpy(var->video_group, info->video);
        strcpy(var->subtitles_group, info->subtitles);
    }

    dynarray_add(&c->variants, &c->n_variants, var);
    dynarray_add(&var->playlists, &var->n_playlists, pls);
    return var;
}

static void handle_variant_args(struct variant_info *info, const char *key,
                                int key_len, char **dest, int *dest_len)
{
    if (!strncmp(key, "BANDWIDTH=", key_len)) {
        *dest     =        info->bandwidth;
        *dest_len = sizeof(info->bandwidth);
    } else if (!strncmp(key, "AUDIO=", key_len)) {
        *dest     =        info->audio;
        *dest_len = sizeof(info->audio);
    } else if (!strncmp(key, "VIDEO=", key_len)) {
        *dest     =        info->video;
        *dest_len = sizeof(info->video);
    } else if (!strncmp(key, "SUBTITLES=", key_len)) {
        *dest     =        info->subtitles;
        *dest_len = sizeof(info->subtitles);
    }
}

struct key_info {
     char uri[MAX_URL_SIZE];
     char method[11];
     char iv[35];
     char cid[CONTENT_ID_LEN];
     char key_format[MAX_URL_SIZE];
};

static void handle_key_args(struct key_info *info, const char *key,
                            int key_len, char **dest, int *dest_len)
{
    if (!strncmp(key, "METHOD=", key_len)) {
        *dest     =        info->method;
        *dest_len = sizeof(info->method);
    } else if (!strncmp(key, "URI=", key_len)) {
        *dest     =        info->uri;
        *dest_len = sizeof(info->uri);
    } else if (!strncmp(key, "IV=", key_len)) {
        *dest     =        info->iv;
        *dest_len = sizeof(info->iv);
    } else if(!strncmp(key, "CID=", key_len)) {
        *dest     =        info->cid;
        *dest_len = sizeof(info->cid);
    } else if(!strncmp(key, "KEYFORMAT=", key_len)) {
        *dest     =        info->key_format;
        *dest_len = sizeof(info->key_format);
    }
}

struct init_section_info {
    char uri[MAX_URL_SIZE];
    char byterange[32];
};

static struct segment *new_init_section(struct playlist *pls,
                                        struct init_section_info *info,
                                        const char *url_base)
{
    struct segment *sec;
    char tmp_str[MAX_URL_SIZE], *ptr = tmp_str;

    if (!info->uri[0])
        return NULL;

    sec = av_mallocz(sizeof(*sec));
    if (!sec)
        return NULL;

    if (!av_strncasecmp(info->uri, "data:", 5)) {
        ptr = info->uri;
    } else {
        ff_make_absolute_url(tmp_str, sizeof(tmp_str), url_base, info->uri);
        if (!tmp_str[0]) {
            av_free(sec);
            return NULL;
        }
    }
    sec->url = av_strdup(ptr);
    if (!sec->url) {
        av_free(sec);
        return NULL;
    }

    if (info->byterange[0]) {
        sec->size = strtoll(info->byterange, NULL, 10);
        ptr = strchr(info->byterange, '@');
        if (ptr)
            sec->url_offset = strtoll(ptr+1, NULL, 10);
    } else {
        /* the entire file is the init section */
        sec->size = -1;
    }
    sec->reconnect_offset = 0;
    dynarray_add(&pls->init_sections, &pls->n_init_sections, sec);

    return sec;
}

static void handle_init_section_args(struct init_section_info *info, const char *key,
                                           int key_len, char **dest, int *dest_len)
{
    if (!strncmp(key, "URI=", key_len)) {
        *dest     =        info->uri;
        *dest_len = sizeof(info->uri);
    } else if (!strncmp(key, "BYTERANGE=", key_len)) {
        *dest     =        info->byterange;
        *dest_len = sizeof(info->byterange);
    }
}

struct rendition_info {
    char type[16];
    char uri[MAX_URL_SIZE];
    char group_id[MAX_FIELD_LEN];
    char language[MAX_FIELD_LEN];
    char assoc_language[MAX_FIELD_LEN];
    char name[MAX_FIELD_LEN];
    char defaultr[4];
    char forced[4];
    char characteristics[MAX_CHARACTERISTICS_LEN];
};

static struct rendition *new_rendition(HLSContext *c, struct rendition_info *info,
                                      const char *url_base)
{
    struct rendition *rend;
    enum AVMediaType type = AVMEDIA_TYPE_UNKNOWN;
    char *characteristic;
    char *chr_ptr;
    char *saveptr;

    if (!strcmp(info->type, "AUDIO"))
        type = AVMEDIA_TYPE_AUDIO;
    else if (!strcmp(info->type, "VIDEO"))
        type = AVMEDIA_TYPE_VIDEO;
    else if (!strcmp(info->type, "SUBTITLES"))
        type = AVMEDIA_TYPE_SUBTITLE;
    else if (!strcmp(info->type, "CLOSED-CAPTIONS"))
        /* CLOSED-CAPTIONS is ignored since we do not support CEA-608 CC in
         * AVC SEI RBSP anyway */
        return NULL;

    if (type == AVMEDIA_TYPE_UNKNOWN) {
        av_log(c->ctx, AV_LOG_WARNING, "Can't support the type: %s\n", info->type);
        return NULL;
    }

    /* URI is mandatory for subtitles as per spec */
    if (type == AVMEDIA_TYPE_SUBTITLE && !info->uri[0]) {
        av_log(c->ctx, AV_LOG_ERROR, "The URI tag is REQUIRED for subtitle.\n");
        return NULL;
    }

    /* TODO: handle subtitles (each segment has to parsed separately) */
    if (c->ctx->strict_std_compliance > FF_COMPLIANCE_EXPERIMENTAL)
        if (type == AVMEDIA_TYPE_SUBTITLE) {
            av_log(c->ctx, AV_LOG_WARNING, "Can't support the subtitle(uri: %s)\n", info->uri);
            return NULL;
        }

    rend = av_mallocz(sizeof(struct rendition));
    if (!rend)
        return NULL;

    dynarray_add(&c->renditions, &c->n_renditions, rend);

    rend->type = type;
    strcpy(rend->group_id, info->group_id);
    strcpy(rend->language, info->language);
    strcpy(rend->name, info->name);

    /* add the playlist if this is an external rendition */
    if (info->uri[0]) {
        rend->playlist = new_playlist(c, info->uri, url_base);
        if (rend->playlist)
            dynarray_add(&rend->playlist->renditions,
                         &rend->playlist->n_renditions, rend);
    }

    if (info->assoc_language[0]) {
        int langlen = strlen(rend->language);
        if (langlen < sizeof(rend->language) - 3) {
            rend->language[langlen] = ',';
            strncpy(rend->language + langlen + 1, info->assoc_language,
                    sizeof(rend->language) - langlen - 2);
        }
    }

    if (!strcmp(info->defaultr, "YES"))
        rend->disposition |= AV_DISPOSITION_DEFAULT;
    if (!strcmp(info->forced, "YES"))
        rend->disposition |= AV_DISPOSITION_FORCED;

    chr_ptr = info->characteristics;
    while ((characteristic = av_strtok(chr_ptr, ",", &saveptr))) {
        if (!strcmp(characteristic, "public.accessibility.describes-music-and-sound"))
            rend->disposition |= AV_DISPOSITION_HEARING_IMPAIRED;
        else if (!strcmp(characteristic, "public.accessibility.describes-video"))
            rend->disposition |= AV_DISPOSITION_VISUAL_IMPAIRED;

        chr_ptr = NULL;
    }

    return rend;
}

static void handle_rendition_args(struct rendition_info *info, const char *key,
                                  int key_len, char **dest, int *dest_len)
{
    if (!strncmp(key, "TYPE=", key_len)) {
        *dest     =        info->type;
        *dest_len = sizeof(info->type);
    } else if (!strncmp(key, "URI=", key_len)) {
        *dest     =        info->uri;
        *dest_len = sizeof(info->uri);
    } else if (!strncmp(key, "GROUP-ID=", key_len)) {
        *dest     =        info->group_id;
        *dest_len = sizeof(info->group_id);
    } else if (!strncmp(key, "LANGUAGE=", key_len)) {
        *dest     =        info->language;
        *dest_len = sizeof(info->language);
    } else if (!strncmp(key, "ASSOC-LANGUAGE=", key_len)) {
        *dest     =        info->assoc_language;
        *dest_len = sizeof(info->assoc_language);
    } else if (!strncmp(key, "NAME=", key_len)) {
        *dest     =        info->name;
        *dest_len = sizeof(info->name);
    } else if (!strncmp(key, "DEFAULT=", key_len)) {
        *dest     =        info->defaultr;
        *dest_len = sizeof(info->defaultr);
    } else if (!strncmp(key, "FORCED=", key_len)) {
        *dest     =        info->forced;
        *dest_len = sizeof(info->forced);
    } else if (!strncmp(key, "CHARACTERISTICS=", key_len)) {
        *dest     =        info->characteristics;
        *dest_len = sizeof(info->characteristics);
    }
    /*
     * ignored:
     * - AUTOSELECT: client may autoselect based on e.g. system language
     * - INSTREAM-ID: EIA-608 closed caption number ("CC1".."CC4")
     */
}

/* used by parse_playlist to allocate a new variant+playlist when the
 * playlist is detected to be a Media Playlist (not Master Playlist)
 * and we have no parent Master Playlist (parsing of which would have
 * allocated the variant and playlist already)
 * *pls == NULL  => Master Playlist or parentless Media Playlist
 * *pls != NULL => parented Media Playlist, playlist+variant allocated */
static int ensure_playlist(HLSContext *c, struct playlist **pls, const char *url)
{
    if (*pls)
        return 0;
    if (!new_variant(c, NULL, url, NULL))
        return AVERROR(ENOMEM);
    *pls = c->playlists[c->n_playlists - 1];
    return 0;
}

static int open_url_keepalive(AVFormatContext *s, AVIOContext **pb,
                              const char *url, AVDictionary **options)
{
#if !CONFIG_HTTP_PROTOCOL
    return AVERROR_PROTOCOL_NOT_FOUND;
#else
    int ret;
    URLContext *uc = ffio_geturlcontext(*pb);
    av_assert0(uc);
    (*pb)->eof_reached = 0;
    ret = ff_http_do_new_request2(uc, url, options);
    if (ret < 0) {
        ff_format_io_close(s, pb);
    }
    return ret;
#endif
}

static int open_url(AVFormatContext *s, AVIOContext **pb, const char *url,
                    AVDictionary **opts, AVDictionary *opts2, int *is_http_out)
{
    HLSContext *c = s->priv_data;
    AVDictionary *tmp = NULL;
    const char *proto_name = NULL;
    int ret;
    int is_http = 0;
    int is_file = 0;

    if (av_strstart(url, "crypto", NULL)) {
        if (url[6] == '+' || url[6] == ':')
            proto_name = avio_find_protocol_name(url + 7);
    } else if (av_strstart(url, "data", NULL)) {
        if (url[4] == '+' || url[4] == ':')
            proto_name = avio_find_protocol_name(url + 5);
    }

    if (!proto_name)
        proto_name = avio_find_protocol_name(url);

    if (!proto_name)
        return AVERROR_INVALIDDATA;

    // only http(s) & file are allowed
    if (av_strstart(proto_name, "file", NULL)) {
        if (strcmp(c->allowed_extensions, "ALL") && !av_match_ext(url, c->allowed_extensions)) {
            av_log(s, AV_LOG_ERROR,
                "Filename extension of \'%s\' is not a common multimedia extension, blocked for security reasons.\n"
                "If you wish to override this adjust allowed_extensions, you can set it to \'ALL\' to allow all\n",
                url);
            return AVERROR_INVALIDDATA;
        }
        is_file = 1;
    } else if (av_strstart(proto_name, "http", NULL)) {
        is_http = 1;
    } else if (av_strstart(proto_name, "data", NULL)) {
        ;
    } else if (av_strstart(proto_name, "memorydatasource", NULL) || av_strstart(proto_name, "mediadatasource", NULL)) {
        ;
    } else if (av_strstart(proto_name, "mdl", NULL)) {
        ;
    } else
        return AVERROR_INVALIDDATA;

    if (!strncmp(proto_name, url, strlen(proto_name)) && url[strlen(proto_name)] == ':')
        ;
    else if (av_strstart(url, "crypto", NULL) && !strncmp(proto_name, url + 7, strlen(proto_name)) && url[7 + strlen(proto_name)] == ':')
        ;
    else if (av_strstart(url, "data", NULL) && !strncmp(proto_name, url + 5, strlen(proto_name)) && url[5 + strlen(proto_name)] == ':')
        ;
    else if (strcmp(proto_name, "file") || !strncmp(url, "file,", 5))
        return AVERROR_INVALIDDATA;

    if(strcmp(proto_name, "file") == 0 && strncmp(url, "file,", 5) != 0) {
        is_file = 1;
    }

    av_dict_copy(&tmp, *opts, 0);
    av_dict_copy(&tmp, opts2, 0);
    av_dict_set(&tmp, "seekable", is_file ? "-1": "1", 0);

    if (is_http && c->http_persistent && *pb) {
        ret = open_url_keepalive(c->ctx, pb, url, &tmp);
        if (ret == AVERROR_EXIT) {
            av_dict_free(&tmp);
            return ret;
        } else if (ret < 0) {
            if (ret != AVERROR_EOF)
                av_log(s, AV_LOG_WARNING,
                    "keepalive request failed for '%s' with error: '%s' when opening url, retrying with new connection\n",
                    url, av_err2str(ret));
            av_dict_copy(&tmp, *opts, 0);
            av_dict_copy(&tmp, opts2, 0);
            ret = avio_open2(pb, url, AVIO_FLAG_READ, c->interrupt_callback, &tmp);
        }
    } else {
        ret = avio_open2(pb, url, AVIO_FLAG_READ, c->interrupt_callback, &tmp);
    }
    if (ret >= 0) {
        // update cookies on http response with setcookies.
        char *new_cookies = NULL;

        if (!(s->flags & AVFMT_FLAG_CUSTOM_IO))
            av_opt_get(*pb, "cookies", AV_OPT_SEARCH_CHILDREN, (uint8_t**)&new_cookies);

        if (new_cookies)
            av_dict_set(opts, "cookies", new_cookies, AV_DICT_DONT_STRDUP_VAL);
    }

    av_dict_free(&tmp);

    if (is_http_out)
        *is_http_out = is_http;

    return ret;
}

static void check_url_host(HLSContext *c, struct segment *seg, const char *line) {
    if (!strstr(line, "://")) {
        seg->need_set_host = 1;
    } else {
        seg->need_set_host = 0;
        AVDictionaryEntry *t = av_dict_get(c->avio_opts, "headers", NULL, AV_DICT_MATCH_CASE);
        char* headers = NULL;
        if(t) {
            headers = t->value;
        }

        if (headers && !c->headers_without_host) {
            const char* begin = av_strnstr(headers, "Host: ", strlen(headers));
            if (!begin)
                return;

            int host_len = 0;
            int cur_len = 0;
            int new_header_len = 0;
            char *new_header = NULL;
            int host_position = 0;

            host_position = begin - headers;
            const char *end = av_strnstr(begin, "\r\n", strlen(headers) - host_position);
            if (end != NULL) {
                host_len = end + 2 - begin;
            } else {
                host_len = sizeof(headers) - host_position;
            }

            new_header_len = strlen(headers) - host_len;
            new_header_len += 1;
            new_header = av_malloc(new_header_len);
            if (!new_header) {
                return;
            }
            if (host_len != 0 && host_position != 0) {
                memcpy(new_header, headers, host_position);
                cur_len += host_position;
            }
            if (headers)
                memcpy(new_header + cur_len, headers + host_position + host_len,  strlen(headers) - host_position - host_len);
            *(new_header + new_header_len - 1) = 0x0;

            c->headers_without_host = new_header;

            av_log(c, AV_LOG_INFO, "headers: %s", headers);
            av_log(c, AV_LOG_INFO, "headers_without_host: %s", c->headers_without_host);
        }
    }
}

static int parse_playlist(HLSContext *c, const char *url,
                          struct playlist *pls, AVIOContext *in)
{
    int ret = 0, is_segment = 0, is_variant = 0;
    int64_t duration = 0, previous_duration1 = 0, previous_duration = 0, total_duration = 0;
    enum KeyType key_type = KEY_NONE;
    uint8_t iv[16] = "";
    int has_iv = 0;
    int key_format_is_identity = 0;
    char key[MAX_URL_SIZE] = "";
    char line[MAX_URL_SIZE];
    const char *ptr;
    int close_in = 0;
    int64_t seg_offset = 0;
    int64_t seg_size = -1;
    uint8_t *new_url = NULL;
    struct variant_info variant_info;
    char tmp_str[MAX_URL_SIZE];
    struct segment *cur_init_section = NULL;
    int is_discontinuety = 0;
    int is_http = av_strstart(url, "http", NULL);
    struct segment **prev_segments = NULL;
    int prev_n_segments = 0;
    int64_t prev_start_seq_no = -1;

    if (is_http && !in && c->http_persistent && c->playlist_pb) {
        in = c->playlist_pb;
        ret = open_url_keepalive(c->ctx, &c->playlist_pb, url, NULL);
        if (ret == AVERROR_EXIT) {
            return ret;
        } else if (ret < 0) {
            if (ret != AVERROR_EOF)
                av_log(c->ctx, AV_LOG_WARNING,
                    "keepalive request failed for '%s' with error: '%s' when parsing playlist\n",
                    url, av_err2str(ret));
            in = NULL;
        }
    }

    if (!in) {
        AVDictionary *opts = NULL;
        char *new_url = NULL;
        av_dict_copy(&opts, c->avio_opts, 0);

        if (c->http_persistent)
            av_dict_set(&opts, "multiple_requests", "1", 0);

        av_dict_set_int(&opts, "tt_opaque", c->tt_opaque, 0);
        new_url = c->enable_refresh_by_time
            ? av_asprintf("%s%sbegin_time=%lf", url, av_stristr(url, "?") ? "&" : "?",
                pls->cur_refresh_begin_time * av_q2d(AV_TIME_BASE_Q))
            : av_strdup(url);
        ret = avio_open2(&in, new_url, AVIO_FLAG_READ, c->interrupt_callback, &opts);
        av_dict_free(&opts);
        av_freep(&new_url);
        if (ret < 0)
            return ret;

        if (is_http && c->http_persistent)
            c->playlist_pb = in;
        else
            close_in = 1;
    }

    if (av_opt_get(in, "location", AV_OPT_SEARCH_CHILDREN, &new_url) >= 0)
        url = new_url;

    ff_get_chomp_line(in, line, sizeof(line));
    if (strcmp(line, "#EXTM3U")) {
        ret = AVERROR_INVALIDDATA;
        goto fail;
    }

    if (pls) {
        prev_start_seq_no = pls->start_seq_no;
        prev_segments = pls->segments;
        prev_n_segments = pls->n_segments;
        pls->segments = NULL;
        pls->n_segments = 0;

        pls->finished = 0;
        pls->type = PLS_TYPE_UNSPECIFIED;
    }
    while (!avio_feof(in)) {
        ff_get_chomp_line(in, line, sizeof(line));
        if (av_strstart(line, "#EXT-X-STREAM-INF:", &ptr)) {
            is_variant = 1;
            memset(&variant_info, 0, sizeof(variant_info));
            ff_parse_key_value(ptr, (ff_parse_key_val_cb) handle_variant_args,
                               &variant_info);
        } else if (av_strstart(line, "#EXT-X-KEY:", &ptr)) {
            struct key_info info = {{0}};
            ff_parse_key_value(ptr, (ff_parse_key_val_cb) handle_key_args,
                               &info);
            key_type = KEY_NONE;
            has_iv = 0;
            if (!strcmp(info.method, "AES-128"))
                key_type = KEY_AES_128;
            if (!strcmp(info.method, "SAMPLE-AES"))
                key_type = KEY_SAMPLE_AES;
            if (!strncmp(info.iv, "0x", 2) || !strncmp(info.iv, "0X", 2)) {
                ff_hex_to_data(iv, info.iv + 2);
                has_iv = 1;
            }
            if(c->tt_hls_drm_enable && c->tt_hls_drm_token) {
                int size = strlen(info.uri);
                int size2 = strlen(c->tt_hls_drm_token);
                av_strlcat(info.uri, "&token=", size + 9);
                av_strlcat(info.uri, c->tt_hls_drm_token, size + size2 + 9);
            }
            av_strlcpy(key, info.uri, sizeof(key));

            key_format_is_identity = 0;
            if (info.key_format[0] == 0 ||  !strcmp(info.key_format, "identity")) {
                key_format_is_identity = 1;
            }
            if(!strncmp(info.uri, "urn:marlin-drm", 14)) {
                c->drm_ctx = (void *)c->drm_aptr;
                if(c->drm_ctx && (av_drm_open(c->drm_ctx, info.cid /*info.cid*/) != 0)) {
                    av_log(c, AV_LOG_ERROR, "intertrust drm open failed\n");
                    c->drm_ctx = NULL;
                    c->enable_intertrust_drm = 0;
                    goto fail;
                }
                if (c->drm_ctx)
                    c->enable_intertrust_drm = 1;
            }

        } else if (av_strstart(line, "#EXT-X-MEDIA:", &ptr)) {
            struct rendition_info info = {{0}};
            ff_parse_key_value(ptr, (ff_parse_key_val_cb) handle_rendition_args,
                               &info);
            new_rendition(c, &info, url);
        } else if (av_strstart(line, "#EXT-X-TARGETDURATION:", &ptr)) {
            int64_t t;
            ret = ensure_playlist(c, &pls, url);
            if (ret < 0)
                goto fail;
            t = strtoll(ptr, NULL, 10);
            if (t < 0 || t >= INT64_MAX / AV_TIME_BASE) {
                ret = AVERROR_INVALIDDATA;
                goto fail;
            }
            pls->target_duration = t * AV_TIME_BASE;
        } else if (av_strstart(line, "#EXT-X-MEDIA-SEQUENCE:", &ptr)) {
            uint64_t seq_no;
            ret = ensure_playlist(c, &pls, url);
            if (ret < 0)
                goto fail;
            seq_no = strtoull(ptr, NULL, 10);
            if (seq_no > INT64_MAX) {
                av_log(c->ctx, AV_LOG_DEBUG, "MEDIA-SEQUENCE higher than "
                        "INT64_MAX, mask out the highest bit\n");
                seq_no &= INT64_MAX;
            }
            pls->start_seq_no = seq_no;
        } else if (av_strstart(line, "#EXT-X-PLAYLIST-TYPE:", &ptr)) {
            ret = ensure_playlist(c, &pls, url);
            if (ret < 0)
                goto fail;
            if (!strcmp(ptr, "EVENT"))
                pls->type = PLS_TYPE_EVENT;
            else if (!strcmp(ptr, "VOD"))
                pls->type = PLS_TYPE_VOD;
        } else if (av_strstart(line, "#EXT-X-MAP:", &ptr)) {
            struct init_section_info info = {{0}};
            ret = ensure_playlist(c, &pls, url);
            if (ret < 0)
                goto fail;
            ff_parse_key_value(ptr, (ff_parse_key_val_cb) handle_init_section_args,
                               &info);
            cur_init_section = new_init_section(pls, &info, url);
            cur_init_section->key_type = key_type;
            if (has_iv) {
                memcpy(cur_init_section->iv, iv, sizeof(iv));
            } else {
                int64_t seq = pls->start_seq_no + pls->n_segments;
                memset(cur_init_section->iv, 0, sizeof(cur_init_section->iv));
                AV_WB64(cur_init_section->iv + 8, seq);
            }

            if (key_type != KEY_NONE) {
                ff_make_absolute_url(tmp_str, sizeof(tmp_str), url, key);
                if (!tmp_str[0]) {
                    av_free(cur_init_section);
                    ret = AVERROR_INVALIDDATA;
                    goto fail;
                }
                cur_init_section->key = av_strdup(tmp_str);
                if (!cur_init_section->key) {
                    av_free(cur_init_section);
                    ret = AVERROR(ENOMEM);
                    goto fail;
                }
            } else {
                cur_init_section->key = NULL;
            }

        } else if (av_strstart(line, "#EXT-X-ENDLIST", &ptr)) {
            if (pls)
                pls->finished = 1;
        } else if (av_strstart(line, "#EXT-X-DISCONTINUITY", &ptr)) {
            is_discontinuety = 1;
            previous_duration = previous_duration1;
        } else if (av_strstart(line, "#EXTINF:", &ptr)) {
            is_segment = 1;
            duration   = strtod(ptr, NULL) * AV_TIME_BASE;
        } else if (av_strstart(line, "#EXT-X-BYTERANGE:", &ptr)) {
            seg_size = strtoll(ptr, NULL, 10);
            ptr = strchr(ptr, '@');
            if (ptr)
                seg_offset = strtoll(ptr+1, NULL, 10);
        } else if (av_strstart(line, "#", NULL)) {
            av_log(c->ctx, AV_LOG_INFO, "Skip ('%s')\n", line);
            continue;
        } else if (line[0]) {
            if (is_variant) {
                if (!new_variant(c, &variant_info, line, url)) {
                    ret = AVERROR(ENOMEM);
                    goto fail;
                }
                is_variant = 0;
            }
            if (is_segment) {
                struct segment *seg;
                ret = ensure_playlist(c, &pls, url);
                if (ret < 0)
                    goto fail;
                seg = av_malloc(sizeof(struct segment));
                if (!seg) {
                    ret = AVERROR(ENOMEM);
                    goto fail;
                }
                if (duration < 0.001 * AV_TIME_BASE) {
                    av_log(c->ctx, AV_LOG_WARNING, "Cannot get correct #EXTINF value of segment %s,"
                                    " set to default value to 1ms.\n", seg->url);
                    duration = 0.001 * AV_TIME_BASE;
                }
                previous_duration1 += duration;
                seg->previous_duration = is_discontinuety ? previous_duration : 0;
                seg->is_discontinuety = is_discontinuety;
                seg->timestamp_list_size = 0;
                seg->start_dts = NULL;
                seg->start_pts = NULL;
                seg->start_time = total_duration;
                total_duration += duration;
                if (has_iv) {
                    memcpy(seg->iv, iv, sizeof(iv));
                } else {
                    uint64_t seq = pls->start_seq_no + (uint64_t)pls->n_segments;
                    memset(seg->iv, 0, sizeof(seg->iv));
                    AV_WB64(seg->iv + 8, seq);
                    seg->segment_number = seq;
                }
                av_log(NULL, AV_LOG_TRACE, "no: %d, dis: %" PRId64 ", seg: %" PRId64 ", %" PRId64 ", %" PRId64 ",", pls->n_segments,
                    seg->is_discontinuety, seg->previous_duration,
                    seg->start_time, seg->duration);
                is_discontinuety = 0;

                if (key_type != KEY_NONE) {
                    if (key_format_is_identity && av_strstart(key, "data:", NULL)) {
                        seg->key = av_strdup(key);
                    } else {
                        ff_make_absolute_url(tmp_str, sizeof(tmp_str), url, key);
                        if (!tmp_str[0]) {
                            ret = AVERROR_INVALIDDATA;
                            av_free(seg);
                            goto fail;
                        }
                        seg->key = av_strdup(tmp_str);
                    }
                    if (!seg->key) {
                        av_free(seg);
                        ret = AVERROR(ENOMEM);
                        goto fail;
                    }
                } else {
                    seg->key = NULL;
                }

                ff_make_absolute_url(tmp_str, sizeof(tmp_str), url, line);
                if (!tmp_str[0]) {
                    ret = AVERROR_INVALIDDATA;
                    if (seg->key)
                        av_free(seg->key);
                    av_free(seg);
                    goto fail;
                }
                seg->url = av_strdup(tmp_str);
                if (!seg->url) {
                    av_free(seg->key);
                    av_free(seg);
                    ret = AVERROR(ENOMEM);
                    goto fail;
                }

                check_url_host(c, seg, line);

                seg->duration = duration;
                seg->key_type = key_type;
                dynarray_add(&pls->segments, &pls->n_segments, seg);
                is_segment = 0;

                seg->size = seg_size;
                if (seg_size >= 0) {
                    seg->url_offset = seg_offset;
                    seg_offset += seg_size;
                    seg_size = -1;
                } else {
                    seg->url_offset = 0;
                    seg_offset = 0;
                }
                seg->reconnect_offset = 0;
                seg->init_section = cur_init_section;
            }
        }
    }
    if (prev_segments) {
        if (pls->start_seq_no > prev_start_seq_no && c->first_timestamp != AV_NOPTS_VALUE) {
            int64_t prev_timestamp = c->first_timestamp;
            int i;
            int64_t diff = pls->start_seq_no - prev_start_seq_no;
            for (i = 0; i < prev_n_segments && i < diff; i++) {
                c->first_timestamp += prev_segments[i]->duration;
            }
            av_log(c->ctx, AV_LOG_DEBUG, "Media sequence change (%"PRId64" -> %"PRId64")"
                   " reflected in first_timestamp: %"PRId64" -> %"PRId64"\n",
                   prev_start_seq_no, pls->start_seq_no,
                   prev_timestamp, c->first_timestamp);
        } else if (pls->start_seq_no < prev_start_seq_no) {
            av_log(c->ctx, AV_LOG_WARNING, "Media sequence changed unexpectedly: %"PRId64" -> %"PRId64"\n",
                   prev_start_seq_no, pls->start_seq_no);
        }
        free_segment_dynarray(prev_segments, prev_n_segments);
        av_freep(&prev_segments);
    }
    if (pls)
        pls->last_load_time = av_gettime_relative();

fail:
    av_free(new_url);
    if (close_in)
        ff_format_io_close(c->ctx, &in);
    c->ctx->ctx_flags = c->ctx->ctx_flags & ~(unsigned)AVFMTCTX_UNSEEKABLE;
    if (!c->n_variants || !c->variants[0]->n_playlists ||
        !(c->variants[0]->playlists[0]->finished ||
          c->variants[0]->playlists[0]->type == PLS_TYPE_EVENT))
        c->ctx->ctx_flags |= AVFMTCTX_UNSEEKABLE;
    return ret;
}

static struct segment *current_segment(struct playlist *pls)
{
    int64_t n = pls->cur_seq_no - pls->start_seq_no;
    if (n >= pls->n_segments)
        return NULL;
    return pls->segments[n];
}

static struct segment *next_segment(struct playlist *pls)
{
    int64_t n = pls->cur_seq_no - pls->start_seq_no + 1;
    if (n >= pls->n_segments)
        return NULL;
    return pls->segments[n];
}

static int read_from_url(struct playlist *pls, struct segment *seg,
                         uint8_t *buf, int buf_size)
{
    int ret;

     /* limit read if the segment was only a part of a file */
    if (seg->size >= 0)
        buf_size = FFMIN(buf_size, seg->size - pls->cur_seg_offset);

    ret = avio_read(pls->input, buf, buf_size);
    if (ret > 0)
        pls->cur_seg_offset += ret;

    return ret;
}

/* Parse the raw ID3 data and pass contents to caller */
static void parse_id3(AVFormatContext *s, AVIOContext *pb,
                      AVDictionary **metadata, int64_t *dts,
                      ID3v2ExtraMetaAPIC **apic, ID3v2ExtraMeta **extra_meta)
{
    static const char id3_priv_owner_ts[] = "com.apple.streaming.transportStreamTimestamp";
    ID3v2ExtraMeta *meta;

    ff_id3v2_read_dict(pb, metadata, ID3v2_DEFAULT_MAGIC, extra_meta);
    for (meta = *extra_meta; meta; meta = meta->next) {
        if (!strcmp(meta->tag, "PRIV")) {
            ID3v2ExtraMetaPRIV *priv = &meta->data.priv;
            if (priv->datasize == 8 && !strcmp(priv->owner, id3_priv_owner_ts)) {
                /* 33-bit MPEG timestamp */
                int64_t ts = AV_RB64(priv->data);
                av_log(s, AV_LOG_DEBUG, "HLS ID3 audio timestamp %"PRId64"\n", ts);
                if ((ts & ~((1ULL << 33) - 1)) == 0)
                    *dts = ts;
                else
                    av_log(s, AV_LOG_ERROR, "Invalid HLS ID3 audio timestamp %"PRId64"\n", ts);
            }
        } else if (!strcmp(meta->tag, "APIC") && apic)
            *apic = &meta->data.apic;
    }
}

/* Check if the ID3 metadata contents have changed */
static int id3_has_changed_values(struct playlist *pls, AVDictionary *metadata,
                                  ID3v2ExtraMetaAPIC *apic)
{
    AVDictionaryEntry *entry = NULL;
    AVDictionaryEntry *oldentry;
    /* check that no keys have changed values */
    while ((entry = av_dict_get(metadata, "", entry, AV_DICT_IGNORE_SUFFIX))) {
        oldentry = av_dict_get(pls->id3_initial, entry->key, NULL, AV_DICT_MATCH_CASE);
        if (!oldentry || strcmp(oldentry->value, entry->value) != 0)
            return 1;
    }

    /* check if apic appeared */
    if (apic && (pls->ctx->nb_streams != 2 || !pls->ctx->streams[1]->attached_pic.data))
        return 1;

    if (apic) {
        int size = pls->ctx->streams[1]->attached_pic.size;
        if (size != apic->buf->size - AV_INPUT_BUFFER_PADDING_SIZE)
            return 1;

        if (memcmp(apic->buf->data, pls->ctx->streams[1]->attached_pic.data, size) != 0)
            return 1;
    }

    return 0;
}

/* Parse ID3 data and handle the found data */
static void handle_id3(AVIOContext *pb, struct playlist *pls)
{
    AVDictionary *metadata = NULL;
    ID3v2ExtraMetaAPIC *apic = NULL;
    ID3v2ExtraMeta *extra_meta = NULL;
    int64_t timestamp = AV_NOPTS_VALUE;

    parse_id3(pls->ctx, pb, &metadata, &timestamp, &apic, &extra_meta);

    if (timestamp != AV_NOPTS_VALUE) {
        pls->id3_mpegts_timestamp = timestamp;
        pls->id3_offset = 0;
    }

    if (!pls->id3_found) {
        /* initial ID3 tags */
        av_assert0(!pls->id3_deferred_extra);
        pls->id3_found = 1;

        /* get picture attachment and set text metadata */
        if (pls->ctx->nb_streams)
            ff_id3v2_parse_apic(pls->ctx, extra_meta);
        else
            /* demuxer not yet opened, defer picture attachment */
            pls->id3_deferred_extra = extra_meta;

        ff_id3v2_parse_priv_dict(&metadata, extra_meta);
        av_dict_copy(&pls->ctx->metadata, metadata, 0);
        pls->id3_initial = metadata;

    } else {
        if (!pls->id3_changed && id3_has_changed_values(pls, metadata, apic)) {
            avpriv_report_missing_feature(pls->parent, "Changing ID3 metadata in HLS audio elementary stream");
            pls->id3_changed = 1;
        }
        av_dict_free(&metadata);
    }

    if (!pls->id3_deferred_extra)
        ff_id3v2_free_extra_meta(&extra_meta);
}

static void intercept_id3(struct playlist *pls, uint8_t *buf,
                         int buf_size, int *len)
{
    /* intercept id3 tags, we do not want to pass them to the raw
     * demuxer on all segment switches */
    int bytes;
    int id3_buf_pos = 0;
    int fill_buf = 0;
    struct segment *seg = current_segment(pls);

    /* gather all the id3 tags */
    while (1) {
        /* see if we can retrieve enough data for ID3 header */
        if (*len < ID3v2_HEADER_SIZE && buf_size >= ID3v2_HEADER_SIZE) {
            bytes = read_from_url(pls, seg, buf + *len, ID3v2_HEADER_SIZE - *len);
            if (bytes > 0) {

                if (bytes == ID3v2_HEADER_SIZE - *len)
                    /* no EOF yet, so fill the caller buffer again after
                     * we have stripped the ID3 tags */
                    fill_buf = 1;

                *len += bytes;

            } else if (*len <= 0) {
                /* error/EOF */
                *len = bytes;
                fill_buf = 0;
            }
        }

        if (*len < ID3v2_HEADER_SIZE)
            break;

        if (ff_id3v2_match(buf, ID3v2_DEFAULT_MAGIC)) {
            int64_t maxsize = seg->size >= 0 ? seg->size : 1024*1024;
            int taglen = ff_id3v2_tag_len(buf);
            int tag_got_bytes = FFMIN(taglen, *len);
            int remaining = taglen - tag_got_bytes;

            if (taglen > maxsize) {
                av_log(pls->parent, AV_LOG_ERROR, "Too large HLS ID3 tag (%d > %"PRId64" bytes)\n",
                       taglen, maxsize);
                break;
            }

            /*
             * Copy the id3 tag to our temporary id3 buffer.
             * We could read a small id3 tag directly without memcpy, but
             * we would still need to copy the large tags, and handling
             * both of those cases together with the possibility for multiple
             * tags would make the handling a bit complex.
             */
            pls->id3_buf = av_fast_realloc(pls->id3_buf, &pls->id3_buf_size, id3_buf_pos + taglen);
            if (!pls->id3_buf)
                break;
            memcpy(pls->id3_buf + id3_buf_pos, buf, tag_got_bytes);
            id3_buf_pos += tag_got_bytes;

            /* strip the intercepted bytes */
            *len -= tag_got_bytes;
            memmove(buf, buf + tag_got_bytes, *len);
            av_log(pls->parent, AV_LOG_DEBUG, "Stripped %d HLS ID3 bytes\n", tag_got_bytes);

            if (remaining > 0) {
                /* read the rest of the tag in */
                if (read_from_url(pls, seg, pls->id3_buf + id3_buf_pos, remaining) != remaining)
                    break;
                id3_buf_pos += remaining;
                av_log(pls->parent, AV_LOG_DEBUG, "Stripped additional %d HLS ID3 bytes\n", remaining);
            }

        } else {
            /* no more ID3 tags */
            break;
        }
    }

    /* re-fill buffer for the caller unless EOF */
    if (*len >= 0 && (fill_buf || *len == 0)) {
        bytes = read_from_url(pls, seg, buf + *len, buf_size - *len);

        /* ignore error if we already had some data */
        if (bytes >= 0)
            *len += bytes;
        else if (*len == 0)
            *len = bytes;
    }

    if (pls->id3_buf) {
        /* Now parse all the ID3 tags */
        AVIOContext id3ioctx;
        ffio_init_context(&id3ioctx, pls->id3_buf, id3_buf_pos, 0, NULL, NULL, NULL, NULL);
        handle_id3(&id3ioctx, pls);
    }

    if (pls->is_id3_timestamped == -1)
        pls->is_id3_timestamped = (pls->id3_mpegts_timestamp != AV_NOPTS_VALUE);
}

static int open_input(HLSContext *c, struct playlist *pls, struct segment *seg, AVIOContext **in)
{
    AVDictionary *opts = NULL;
    int ret;
    int is_http = 0;

    av_dict_set_int(&opts, "tt_opaque", c->tt_opaque, 0);
    if (seg->need_set_host) {
        AVDictionaryEntry *t = av_dict_get(c->avio_opts, "headers", NULL, AV_DICT_MATCH_CASE);
        char* headers = NULL;
        if(t) {
            headers = t->value;
        }
        av_dict_set(&opts, "headers", headers, 0);
    } else {
        if (c->headers_without_host)
            av_dict_set(&opts, "headers", c->headers_without_host, 0);
        else
            av_dict_set(&opts, "headers", NULL, 0);
    }
    if (c->http_persistent)
        av_dict_set(&opts, "multiple_requests", "1", 0);

    if (seg->reconnect_offset != 0) {
       av_dict_set_int(&opts, "offset", seg->reconnect_offset, 0);
    }

    if (seg->size >= 0) {
        /* try to restrict the HTTP request to the part we want
         * (if this is in fact a HTTP request) */
        av_dict_set_int(&opts, "offset", seg->url_offset + seg->reconnect_offset, 0);
        av_dict_set_int(&opts, "end_offset", seg->url_offset + seg->size, 0);
    }

    av_log(pls->parent, AV_LOG_VERBOSE, "HLS request for url '%s', offset %"PRId64", playlist %d\n",
           seg->url, seg->url_offset, pls->index);

    if (seg->key_type == KEY_AES_128 || seg->key_type == KEY_SAMPLE_AES) {
        if (c->decryption_key) {
            ff_hex_to_data(pls->key,c->decryption_key);
            int decryption_keylen = strlen(c->decryption_key);
            if (decryption_keylen == sizeof(pls->key)) {
                memcpy(pls->key, c->decryption_key, decryption_keylen);
            } else {
                av_log(pls->parent, AV_LOG_ERROR, "decrytion key len:%d error\n", decryption_keylen);
            }
        } else if (strcmp(seg->key, pls->key_url)) {
            AVIOContext *pb = NULL;
            if (!c->enable_intertrust_drm) {
                if (open_url(pls->parent, &pb, seg->key, &c->avio_opts, opts, NULL) == 0) {
                    if(c->tt_hls_drm_enable) {
                        int i = 0;
                        char hls_drm_io[MAX_URL_SIZE];
                        char hls_drm_key[33];
                        const char *cptr = NULL;
                        ret = avio_read(pb, hls_drm_io, sizeof(hls_drm_io));
                        if (ret != sizeof(hls_drm_io)) {
                            av_log(NULL, AV_LOG_ERROR, "Unable to read hls_drm_io file %s\n",
                                seg->key);
                        }
                        if (!(cptr = strstr(hls_drm_io, "\"data\""))) {
                            av_log(pls->parent, AV_LOG_ERROR, "no key found\n");
                            return AVERROR_UNKNOWN;
                        }
                        cptr += strlen("\"data\":\"");
                        while (*cptr && *cptr != '\"' && i < sizeof(hls_drm_key))
                            hls_drm_key[i++] = *cptr++;

                        av_base64_decode(pls->key, hls_drm_key, sizeof(pls->key));
                    } else {
                        ret = avio_read(pb, pls->key, sizeof(pls->key));
                        if (ret != sizeof(pls->key)) {
                            av_log(pls->parent, AV_LOG_ERROR, "Unable to read key file %s\n",
                                seg->key);
                        }
                    }
                    ff_format_io_close(pls->parent, &pb);
                } else {
                    av_log(pls->parent, AV_LOG_ERROR, "Unable to open key file %s\n",
                        seg->key);
                }
            } else {
                memset(pls->key, 0, sizeof(pls->key));
            }
            av_strlcpy(pls->key_url, seg->key, sizeof(pls->key_url));
        }
    }

    if (seg->key_type == KEY_NONE || seg->key_type == KEY_SAMPLE_AES) {
        ret = open_url(pls->parent, in, seg->url, &c->avio_opts, opts, &is_http);
    } else if (seg->key_type == KEY_AES_128) {
        char iv[33], key[33], url[MAX_URL_SIZE];
        ff_data_to_hex(iv, seg->iv, sizeof(seg->iv), 0);
        ff_data_to_hex(key, pls->key, sizeof(pls->key), 0);
        iv[32] = key[32] = '\0';
        if (strstr(seg->url, "://"))
            snprintf(url, sizeof(url), "crypto+%s", seg->url);
        else
            snprintf(url, sizeof(url), "crypto:%s", seg->url);

        av_dict_set(&opts, "key", key, 0);
        av_dict_set(&opts, "iv", iv, 0);
        av_dict_set_int(&opts, "enable_intertrust_drm", c->enable_intertrust_drm, 0);
        if(c->enable_intertrust_drm) {
            av_dict_set_int(&opts, "drm_downgrade", c->drm_downgrade, 0);
            av_dict_set_int(&opts, "drm_aptr", (int64_t)c->drm_ctx, 0);
            av_dict_set_int(&opts, "segment_number", seg->segment_number, 0);
        }

        ret = open_url(pls->parent, in, url, &c->avio_opts, opts, &is_http);
        if (ret < 0) {
            goto cleanup;
        }
        ret = 0;
    }
    else
      ret = AVERROR(ENOSYS);

    if (seg->reconnect_offset != 0) {
        if(pls->input != NULL) {
            pls->input->pos = seg->reconnect_offset;
        }
        seg->reconnect_offset = 0;
    }

    /* Seek to the requested position. If this was a HTTP request, the offset
     * should already be where want it to, but this allows e.g. local testing
     * without a HTTP server.
     *
     * This is not done for HTTP at all as avio_seek() does internal bookkeeping
     * of file offset which is out-of-sync with the actual offset when "offset"
     * AVOption is used with http protocol, causing the seek to not be a no-op
     * as would be expected. Wrong offset received from the server will not be
     * noticed without the call, though.
     */
    if (ret == 0 && !is_http && seg->url_offset) {
        int64_t seekret = avio_seek(*in, seg->url_offset, SEEK_SET);
        if (seekret < 0) {
            av_log(pls->parent, AV_LOG_ERROR, "Unable to seek to offset %"PRId64" of HLS segment '%s'\n", seg->url_offset, seg->url);
            ret = seekret;
            ff_format_io_close(pls->parent, in);
        }
    }

cleanup:
    av_dict_free(&opts);
    pls->cur_seg_offset = 0;
    return ret;
}

static int update_init_section(struct playlist *pls, struct segment *seg)
{
    static const int max_init_section_size = 1024*1024;
    HLSContext *c = pls->parent->priv_data;
    int64_t sec_size;
    int64_t urlsize;
    int ret;

    if (seg->init_section == pls->cur_init_section)
        return 0;

    pls->cur_init_section = NULL;

    if (!seg->init_section)
        return 0;

    ret = open_input(c, pls, seg->init_section, &pls->input);
    if (ret < 0) {
        av_log(pls->parent, AV_LOG_WARNING,
               "Failed to open an initialization section in playlist %d\n",
               pls->index);
        return ret;
    }

    if (seg->init_section->size >= 0)
        sec_size = seg->init_section->size;
    else if ((urlsize = avio_size(pls->input)) >= 0)
        sec_size = urlsize;
    else
        sec_size = max_init_section_size;

    av_log(pls->parent, AV_LOG_DEBUG,
           "Downloading an initialization section of size %"PRId64"\n",
           sec_size);

    sec_size = FFMIN(sec_size, max_init_section_size);

    av_fast_malloc(&pls->init_sec_buf, &pls->init_sec_buf_size, sec_size);

    ret = read_from_url(pls, seg->init_section, pls->init_sec_buf,
                        pls->init_sec_buf_size);
    ff_format_io_close(pls->parent, &pls->input);

    if (ret < 0)
        return ret;

    pls->cur_init_section = seg->init_section;
    pls->init_sec_data_len = ret;
    pls->init_sec_buf_read_offset = 0;

    /* spec says audio elementary streams do not have media initialization
     * sections, so there should be no ID3 timestamps */
    pls->is_id3_timestamped = 0;

    return 0;
}

static int64_t default_reload_interval(struct playlist *pls)
{
    return pls->n_segments > 0 ?
                          pls->segments[pls->n_segments - 1]->duration :
                          pls->target_duration;
}

static int playlist_needed(struct playlist *pls)
{
    AVFormatContext *s = pls->parent;
    int i, j;
    int stream_needed = 0;
    int first_st;

    /* If there is no context or streams yet, the playlist is needed */
    if (!pls->ctx || !pls->n_main_streams)
        return 1;

    /* check if any of the streams in the playlist are needed */
    for (i = 0; i < pls->n_main_streams; i++) {
        if (pls->main_streams[i]->discard < AVDISCARD_ALL) {
            stream_needed = 1;
            break;
        }
    }

    /* If all streams in the playlist were discarded, the playlist is not
     * needed (regardless of whether whole programs are discarded or not). */
    if (!stream_needed)
        return 0;

    /* Otherwise, check if all the programs (variants) this playlist is in are
     * discarded. Since all streams in the playlist are part of the same programs
     * we can just check the programs of the first stream. */

    first_st = pls->main_streams[0]->index;

    for (i = 0; i < s->nb_programs; i++) {
        AVProgram *program = s->programs[i];
        if (program->discard < AVDISCARD_ALL) {
            for (j = 0; j < program->nb_stream_indexes; j++) {
                if (program->stream_index[j] == first_st) {
                    /* playlist is in an undiscarded program */
                    return 1;
                }
            }
        }
    }

    /* some streams were not discarded but all the programs were */
    return 0;
}

static int read_data(void *opaque, uint8_t *buf, int buf_size)
{
    struct playlist *v = opaque;
    HLSContext *c = v->parent->priv_data;
    int ret;
    int just_opened = 0;
    int reload_count = 0;
    struct segment *seg;
    int segment_retries = 0;

restart:
    if (!v->needed)
        return AVERROR_EOF;

    if (!v->input || (c->http_persistent && v->input_read_done)) {
        int64_t reload_interval;

        if (!v->needed) {
            av_log(v->parent, AV_LOG_INFO, "No longer receiving playlist %d ('%s')\n",
                   v->index, v->url);
            return AVERROR_EOF;
        }

        /* If this is a live stream and the reload interval has elapsed since
         * the last playlist reload, reload the playlists now. */
        reload_interval = default_reload_interval(v);

reload:
        reload_count++;
        if (reload_count > c->max_reload)
            return AVERROR_EOF;
        if (!v->finished &&
            av_gettime_relative() - v->last_load_time >= reload_interval) {
            if ((ret = parse_playlist(c, v->url, v, NULL)) < 0) {
                if (ret != AVERROR_EXIT)
                    av_log(v->parent, AV_LOG_WARNING, "Failed to reload playlist %d\n",
                           v->index);
                return ret;
            }
            /* If we need to reload the playlist again below (if
             * there's still no more segments), switch to a reload
             * interval of half the target duration. */
            reload_interval = v->target_duration / 2;
        }
        if (v->cur_seq_no < v->start_seq_no) {
            av_log(v->parent, AV_LOG_WARNING,
                   "skipping %"PRId64" segments ahead, expired from playlists\n",
                   v->start_seq_no - v->cur_seq_no);
            v->cur_seq_no = v->start_seq_no;
        }
        if (v->cur_seq_no > v->last_seq_no) {
            v->last_seq_no = v->cur_seq_no;
            v->m3u8_hold_counters = 0;
        } else if (v->last_seq_no == v->cur_seq_no) {
            v->m3u8_hold_counters++;
            if (v->m3u8_hold_counters >= c->m3u8_hold_counters) {
                return AVERROR_EOF;
            }
        } else {
            av_log(v->parent, AV_LOG_WARNING, "maybe the m3u8 list sequence have been wraped.\n");
        }
        if (v->cur_seq_no >= v->start_seq_no + v->n_segments) {
            if (v->finished)
                return AVERROR_EOF;
            while (av_gettime_relative() - v->last_load_time < reload_interval) {
                if (ff_check_interrupt(c->interrupt_callback))
                    return AVERROR_EXIT;
                av_usleep(100*1000);
            }
            /* Enough time has elapsed since the last reload */
            goto reload;
        }

        v->input_read_done = 0;
        seg = current_segment(v);

        /* load/update Media Initialization Section, if any */
        ret = update_init_section(v, seg);
        if (ret)
            return ret;

        if (c->http_multiple == 1 && v->input_next_requested) {
            FFSWAP(AVIOContext *, v->input, v->input_next);
            v->cur_seg_offset = 0;
            v->input_next_requested = 0;
            ret = 0;
        } else {
            ret = open_input(c, v, seg, &v->input);
        }
        if (ret < 0) {
            if (ff_check_interrupt(c->interrupt_callback))
                return AVERROR_EXIT;
            av_log(v->parent, AV_LOG_WARNING, "Failed to open segment %"PRId64" of playlist %d\n",
                   v->cur_seq_no,
                   v->index);
            if (segment_retries >= c->seg_max_retry) {
                av_log(v->parent, AV_LOG_WARNING, "Segment %"PRId64" of playlist %d failed %d times, ret %d, enable error %d\n",
                       v->cur_seq_no, v->index, segment_retries, ret, c->enable_seg_error);

                if(c->enable_seg_error) {
                    return ret;
                }
                v->cur_seq_no++;
                segment_retries = 0;
            } else {
                segment_retries++;
            }
            goto reload;
        }
        segment_retries = 0;
        just_opened = 1;
    }

    if (c->http_multiple == -1) {
        uint8_t *http_version_opt = NULL;
        int r = av_opt_get(v->input, "http_version", AV_OPT_SEARCH_CHILDREN, &http_version_opt);
        if (r >= 0) {
            c->http_multiple = (!strncmp((const char *)http_version_opt, "1.1", 3) || !strncmp((const char *)http_version_opt, "2.0", 3));
            av_freep(&http_version_opt);
        }
    }

    seg = next_segment(v);
    if (c->http_multiple == 1 && !v->input_next_requested &&
        seg && seg->key_type == KEY_NONE && av_strstart(seg->url, "http", NULL)) {
        ret = open_input(c, v, seg, &v->input_next);
        if (ret < 0) {
            if (ff_check_interrupt(c->interrupt_callback))
                return AVERROR_EXIT;
            av_log(v->parent, AV_LOG_WARNING, "Failed to open segment %"PRId64" of playlist %d\n",
                   v->cur_seq_no + 1,
                   v->index);
        } else {
            v->input_next_requested = 1;
        }
    }

    if (v->init_sec_buf_read_offset < v->init_sec_data_len) {
        /* Push init section out first before first actual segment */
        int copy_size = FFMIN(v->init_sec_data_len - v->init_sec_buf_read_offset, buf_size);
        memcpy(buf, v->init_sec_buf, copy_size);
        v->init_sec_buf_read_offset += copy_size;
        return copy_size;
    }

    seg = current_segment(v);
    ret = read_from_url(v, seg, buf, buf_size);
    if (ret > 0) {
        if (just_opened && v->is_id3_timestamped != 0) {
            /* Intercept ID3 tags here, elementary audio streams are required
             * to convey timestamps using them in the beginning of each segment. */
            intercept_id3(v, buf, buf_size, &ret);
        }

        return ret;
    }
    if (c->http_persistent &&
        seg->key_type == KEY_NONE && av_strstart(seg->url, "http", NULL)) {
        v->input_read_done = 1;
    } else {
        if (ret != AVERROR_EOF) {
            struct segment *cur_seg  = current_segment(v);
            cur_seg->reconnect_offset = v->input->pos;
        }
        ff_format_io_close(v->parent, &v->input);
    }
    if (ret == AVERROR_EOF) {
        v->cur_refresh_begin_time += current_segment(v)->duration;
        v->cur_seq_no++;

        c->cur_seq_no = v->cur_seq_no;

        if (c->abr) {
            ABRStrategyCtx *abr = (ABRStrategyCtx *)c->abr;
            int bitrate = -1;
            if (abr->probe_bitrate)
                bitrate = abr->probe_bitrate(c->tt_opaque, c->now_video_bitrate);

            if (bitrate > 0) {
                c->cur_video_bitrate = bitrate;
                av_log(c, AV_LOG_VERBOSE, "abr probe bitrate:%d\n", bitrate);
            }
        }
        if (c->cur_video_bitrate && c->cur_video_bitrate != c->now_video_bitrate &&
            v->cur_seq_no < v->start_seq_no + v->n_segments) {
            c->switch_exit = 1;
            return ret;
        }
    }
    goto restart;
}

static void add_renditions_to_variant(HLSContext *c, struct variant *var,
                                      enum AVMediaType type, const char *group_id)
{
    int i;

    for (i = 0; i < c->n_renditions; i++) {
        struct rendition *rend = c->renditions[i];

        if (rend->type == type && !strcmp(rend->group_id, group_id)) {

            if (rend->playlist)
                /* rendition is an external playlist
                 * => add the playlist to the variant */
                dynarray_add(&var->playlists, &var->n_playlists, rend->playlist);
            else
                /* rendition is part of the variant main Media Playlist
                 * => add the rendition to the main Media Playlist */
                dynarray_add(&var->playlists[0]->renditions,
                             &var->playlists[0]->n_renditions,
                             rend);
        }
    }
}

static void add_metadata_from_renditions(AVFormatContext *s, struct playlist *pls,
                                         enum AVMediaType type)
{
    HLSContext *c = s->priv_data;
    int rend_idx = 0;
    int i;

    for (i = 0; i < pls->n_main_streams; i++) {
        AVStream *st = pls->main_streams[i];

        if (st->codecpar->codec_type != type)
            continue;

        if(type == AVMEDIA_TYPE_AUDIO && pls->n_renditions > 0 && c->cur_audio_infoid > -1) {
            av_dict_set_int(&st->metadata, "info_id", c->cur_audio_infoid, 0);
        }

        for (; rend_idx < pls->n_renditions; rend_idx++) {
            struct rendition *rend = pls->renditions[rend_idx];

            if (rend->type != type)
                continue;

            if (rend->language[0])
                av_dict_set(&st->metadata, "language", rend->language, 0);
            if (rend->name[0])
                av_dict_set(&st->metadata, "comment", rend->name, 0);

            st->disposition |= rend->disposition;
        }
        if (rend_idx >=pls->n_renditions)
            break;
    }
}

/* if timestamp was in valid range: returns 1 and sets seq_no
 * if not: returns 0 and sets seq_no to closest segment */
static int find_timestamp_in_playlist(HLSContext *c, struct playlist *pls,
                                      int64_t timestamp, int64_t *seq_no)
{
    int i;
    int64_t pos = c->first_timestamp == AV_NOPTS_VALUE ?
                  0 : c->first_timestamp;

    if (timestamp < pos) {
        *seq_no = pls->start_seq_no;
        return 0;
    }

    for (i = 0; i < pls->n_segments; i++) {
        int64_t diff = pos + pls->segments[i]->duration - timestamp;
        if (diff > 0) {
            *seq_no = pls->start_seq_no + i;
            return 1;
        }
        pos += pls->segments[i]->duration;
    }

    *seq_no = pls->start_seq_no + pls->n_segments - 1;

    return 0;
}

static int64_t select_cur_seq_no(HLSContext *c, struct playlist *pls)
{
    int64_t seq_no;

    if (!pls->finished && !c->first_packet &&
        av_gettime_relative() - pls->last_load_time >= default_reload_interval(pls))
        /* reload the playlist since it was suspended */
        parse_playlist(c, pls->url, pls, NULL);

    /* If playback is already in progress (we are just selecting a new
     * playlist) and this is a complete file, find the matching segment
     * by counting durations. */
    if (pls->finished && c->cur_timestamp != AV_NOPTS_VALUE) {
        find_timestamp_in_playlist(c, pls, c->cur_timestamp, &seq_no);
        return seq_no;
    }

    if (!pls->finished) {
        if (!c->first_packet && /* we are doing a segment selection during playback */
            c->cur_seq_no >= pls->start_seq_no &&
            c->cur_seq_no < pls->start_seq_no + pls->n_segments)
            /* While spec 3.4.3 says that we cannot assume anything about the
             * content at the same sequence number on different playlists,
             * in practice this seems to work and doing it otherwise would
             * require us to download a segment to inspect its timestamps. */
            return c->cur_seq_no;

        /* If this is a live stream, start live_start_index segments from the
         * start or end */
        if (c->live_start_index < 0)
            return pls->start_seq_no + FFMAX(pls->n_segments + c->live_start_index, 0);
        else
            return pls->start_seq_no + FFMIN(c->live_start_index, pls->n_segments - 1);
    }

    /* Otherwise just start on the first segment. */
    return pls->start_seq_no;
}

static int save_avio_options(AVFormatContext *s)
{
    HLSContext *c = s->priv_data;
    static const char * const opts[] = {
        "headers", "http_proxy", "user_agent", "cookies", "referer", "rw_timeout", "icy", NULL };
    const char * const * opt = opts;
    uint8_t *buf;
    int ret = 0;

    while (*opt) {
        if (av_opt_get(s->pb, *opt, AV_OPT_SEARCH_CHILDREN | AV_OPT_ALLOW_NULL, &buf) >= 0) {
            ret = av_dict_set(&c->avio_opts, *opt, buf,
                              AV_DICT_DONT_STRDUP_VAL);
            if (ret < 0)
                return ret;
        }
        opt++;
    }

    return ret;
}

static int nested_io_open(AVFormatContext *s, AVIOContext **pb, const char *url,
                          int flags, AVDictionary **opts)
{
    av_log(s, AV_LOG_ERROR,
           "A HLS playlist item '%s' referred to an external file '%s'. "
           "Opening this file was forbidden for security reasons\n",
           s->url, url);
    return AVERROR(EPERM);
}

static void add_stream_to_programs(AVFormatContext *s, struct playlist *pls, AVStream *stream)
{
    HLSContext *c = s->priv_data;
    int i, j;
    int bandwidth = -1;

    for (i = 0; i < c->n_variants; i++) {
        struct variant *v = c->variants[i];

        for (j = 0; j < v->n_playlists; j++) {
            if (v->playlists[j] != pls)
                continue;

            av_program_add_stream_index(s, i, stream->index);

            if (bandwidth < 0)
                bandwidth = v->bandwidth;
            else if (bandwidth != v->bandwidth)
                bandwidth = -1; /* stream in multiple variants with different bandwidths */
        }
    }

    if (bandwidth >= 0)
        av_dict_set_int(&stream->metadata, "variant_bitrate", bandwidth, 0);
}

static int set_stream_info_from_input_stream(AVStream *st, struct playlist *pls, AVStream *ist)
{
    int err;

    err = avcodec_parameters_copy(st->codecpar, ist->codecpar);
    if (err < 0)
        return err;

    if (pls->is_id3_timestamped) /* custom timestamps via id3 */
        avpriv_set_pts_info(st, 33, 1, MPEG_TIME_BASE);
    else
        avpriv_set_pts_info(st, ist->pts_wrap_bits, ist->time_base.num, ist->time_base.den);

    // copy disposition
    st->disposition = ist->disposition;

    // copy side data
    for (int i = 0; i < ist->nb_side_data; i++) {
        const AVPacketSideData *sd_src = &ist->side_data[i];
        uint8_t *dst_data;

        dst_data = av_stream_new_side_data(st, sd_src->type, sd_src->size);
        if (!dst_data)
            return AVERROR(ENOMEM);
        memcpy(dst_data, sd_src->data, sd_src->size);
    }

    st->internal->need_context_update = 1;

    return 0;
}

/* add new subdemuxer streams to our context, if any */
static int update_streams_from_subdemuxer(AVFormatContext *s, struct playlist *pls)
{
    int err;

    while (pls->n_main_streams < pls->ctx->nb_streams) {
        int ist_idx = pls->n_main_streams;
        AVStream *st = avformat_new_stream(s, NULL);
        AVStream *ist = pls->ctx->streams[ist_idx];

        if (!st)
            return AVERROR(ENOMEM);

        st->id = pls->index;
        dynarray_add(&pls->main_streams, &pls->n_main_streams, st);

        add_stream_to_programs(s, pls, st);

        err = set_stream_info_from_input_stream(st, pls, ist);
        if (err < 0)
            return err;
    }

    return 0;
}

static void update_noheader_flag(AVFormatContext *s)
{
    HLSContext *c = s->priv_data;
    int flag_needed = 0;
    int i;

    for (i = 0; i < c->n_playlists; i++) {
        struct playlist *pls = c->playlists[i];

        if (pls->has_noheader_flag) {
            flag_needed = 1;
            break;
        }
    }

    if (flag_needed)
        s->ctx_flags |= AVFMTCTX_NOHEADER;
    else
        s->ctx_flags &= ~AVFMTCTX_NOHEADER;
}

static int close_demuxer_for_playlist(struct playlist *pls)
{
    pls->needed = 0;
    av_freep(&pls->pb.buffer);
    memset(&pls->pb, 0x00, sizeof(AVIOContext));
    if (pls->ctx) {
        pls->ctx->pb = NULL;
        avformat_close_input(&pls->ctx);
    }
    if (pls->input) {
        ff_format_io_close(pls->parent, &pls->input);
    }
    av_packet_unref(pls->pkt);
    return 0;
}

static int open_demuxer_for_playlist(AVFormatContext *s, struct playlist *pls, int highest_cur_seq_no)
{
    int ret = 0;
    AVInputFormat *in_fmt = NULL;
    AVDictionary  *in_fmt_opts = NULL;
    HLSContext *c = s->priv_data;

    pls->needed = 1;
    pls->parent = s;

    if (pls->ctx) {
        close_demuxer_for_playlist(pls);
    }

    if (!(pls->ctx = avformat_alloc_context())) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    if (pls->n_segments == 0)
        goto fail;

    /*
        * If this is a live stream and this playlist looks like it is one segment
        * behind, try to sync it up so that every substream starts at the same
        * time position (so e.g. avformat_find_stream_info() will see packets from
        * all active streams within the first few seconds). This is not very generic,
        * though, as the sequence numbers are technically independent.
        */
    if (!pls->finished) {
        if (pls->cur_seq_no == highest_cur_seq_no - 1 &&
            highest_cur_seq_no < pls->start_seq_no + pls->n_segments) {
            pls->cur_seq_no = highest_cur_seq_no;
        }
        // adapt the live_start_index
        for (int j = pls->start_seq_no; j < pls->cur_seq_no; j++) {
            pls->cur_refresh_begin_time += pls->segments[j - pls->start_seq_no]->duration;
        }
    }

    pls->read_buffer = av_malloc(INITIAL_BUFFER_SIZE);
    if (!pls->read_buffer){
        ret = AVERROR(ENOMEM);
        avformat_free_context(pls->ctx);
        pls->ctx = NULL;
        return ret;
    }
    ffio_init_context(&pls->pb, pls->read_buffer, INITIAL_BUFFER_SIZE, 0, pls,
                        read_data, NULL, NULL);
    pls->pb.seekable = 0;
    ret = av_probe_input_buffer(&pls->pb, &in_fmt, pls->segments[0]->url,
                                NULL, 0, 0);
    if (ret < 0) {
        /* Free the ctx - it isn't initialized properly at this point,
            * so avformat_close_input shouldn't be called. If
            * avformat_open_input fails below, it frees and zeros the
            * context, so it doesn't need any special treatment like this. */
        av_log(s, AV_LOG_ERROR, "Error when loading first segment '%s'\n", pls->segments[0]->url);
        avformat_free_context(pls->ctx);
        pls->ctx = NULL;
        return ret;
    }
    if (c->hls_sub_demuxer_probe_type != 0) {
        if (!strcmp(in_fmt->name, "bmp_pipe")
            || !strcmp(in_fmt->name, "png_pipe")
            || !strcmp(in_fmt->name, "jpeg_pipe")
            || !strcmp(in_fmt->name, "gif_pipe")
            || !strcmp(in_fmt->name, "image2")) {
            av_log(s, AV_LOG_WARNING, "ts file disguised as image\n");
            in_fmt = av_find_input_format("mpegts");
        }
    }
    pls->ctx->pb       = &pls->pb;
    pls->ctx->io_open  = nested_io_open;
    pls->ctx->flags   |= s->flags & ~AVFMT_FLAG_CUSTOM_IO;

    if ((ret = ff_copy_whiteblacklists(pls->ctx, s)) < 0)
        goto fail;

    av_dict_set_int(&in_fmt_opts, "correct_ts_overflow", 0, 0);

    ret = avformat_open_input(&pls->ctx, pls->segments[0]->url, in_fmt, &in_fmt_opts);
    if (ret < 0)
        goto fail;

    if (pls->id3_deferred_extra && pls->ctx->nb_streams == 1) {
        ff_id3v2_parse_apic(pls->ctx, pls->id3_deferred_extra);
        avformat_queue_attached_pictures(pls->ctx);
        ff_id3v2_free_extra_meta(&pls->id3_deferred_extra);
        pls->id3_deferred_extra = NULL;
    }

    if (pls->is_id3_timestamped == -1)
        av_log(s, AV_LOG_WARNING, "No expected HTTP requests have been made\n");

    ret = avformat_find_stream_info(pls->ctx, NULL);
    if (ret < 0)
        goto fail;

    pls->has_noheader_flag = !!(pls->ctx->ctx_flags & AVFMTCTX_NOHEADER);

    /* Create new AVStreams for each stream in this playlist */
    ret = update_streams_from_subdemuxer(s, pls);

    if (ret < 0)
        goto fail;

    add_metadata_from_renditions(s, pls, AVMEDIA_TYPE_AUDIO);
    add_metadata_from_renditions(s, pls, AVMEDIA_TYPE_VIDEO);
    add_metadata_from_renditions(s, pls, AVMEDIA_TYPE_SUBTITLE);

    return ret;
fail:
    close_demuxer_for_playlist(pls);
    return ret;
}

static void reset_packets_cache(HLSContext* c,int index)
{
    if (index < 0 || index > AVMEDIA_TYPE_NB) {
        return;
    }
    int start_index = index;
    int max_index = index + 1;
    if (index == AVMEDIA_TYPE_NB) {
        start_index  = 0;
        max_index = AVMEDIA_TYPE_NB;
    }
    for (int i = start_index; i < max_index; i++) {
        int n_packets = c->n_packets[i];
        if (n_packets <= 0 && c->packets[i] == NULL) {
            continue;
        }
        if (i == AVMEDIA_TYPE_VIDEO) {
            c->video_keyframe_time = AV_NOPTS_VALUE;
        }
        for (int j = 0; j < n_packets; j++) {
            av_packet_free(&c->packets[i][j]);
        }
        av_freep(&c->packets[i]);
        c->n_packets[i] = 0;
        c->packets_pos[i] = 0;  
    }
}

static int hls_close(AVFormatContext *s)
{
    HLSContext *c = s->priv_data;

    reset_packets_cache(c,AVMEDIA_TYPE_NB);
    free_playlist_list(c);
    free_variant_list(c);
    free_rendition_list(c);

    if (c->crypto_ctx.aes_ctx != NULL) {
        av_free(c->crypto_ctx.aes_ctx);
    }

    av_dict_free(&c->avio_opts);
    ff_format_io_close(c->ctx, &c->playlist_pb);

    if (c->drm_aptr) {
        av_drm_close(c->drm_ctx);
        c->drm_ctx = NULL;
    }

    return 0;
}

static char *get_mem_value(char **mem)
{
    if (mem && *mem) {
        return (char *) av_strtok(*mem, " \"\n\t\r,:/", mem);
    }
    return NULL;
}

static char *get_mem_string_value(char **mem)
{
    if (mem && *mem && (*mem = (char *) av_stristr(*mem, "\""))) {
        if (!av_strncasecmp(*mem, "\"\"", 2)) {
            *mem += 2;
        } else {
            return (char *) av_strtok(*mem, "\"", mem);
        }
    }
    return NULL;
}

static char *get_mem_url(char **mem)
{
    char *url = NULL;
    if (mem && *mem) {
        url = get_mem_string_value(mem);
        if (url) {
            char *ptr = url, *ptr_end = url;
            while (*ptr_end != '\0') {
                if (*ptr_end != '\\') {
                    *ptr++ = *ptr_end;
                }
                ptr_end++;
            }
            *ptr = '\0';
        }
    }
    return url;
}

static enum AVMediaType get_mem_media_type(char **mem)
{
    if (mem && *mem) {
        char *type = get_mem_string_value(mem);
        if (type) {
            if (!av_strcasecmp(type, "video")) {
                return AVMEDIA_TYPE_VIDEO;
            } else if (!av_strcasecmp(type, "audio")) {
                return AVMEDIA_TYPE_AUDIO;
            }
        }
    }
    return AVMEDIA_TYPE_UNKNOWN;
}

static int parse_mem_playlist(AVFormatContext *s, int type, char **mem)
{
    HLSContext *c = s->priv_data;
    int ret = 0;
    int bitrate = 0;
    char *value = NULL;
    char *url = NULL;

    while ((value = get_mem_value(mem))) {
        if (c->url_index == 0 && !av_strcasecmp(value, "main_url")) {
            url = get_mem_url(mem);
        } else if (c->url_index != 0 && !av_strcasecmp(value, "backup_url_1")) {
            url = get_mem_url(mem);
        } else if (!av_strcasecmp(value, "bitrate")) {
            value = get_mem_value(mem);
            bitrate = value ? atoi(value) : 0;
        }
        if (av_stristr(value, "}]")) {
            break;
        } else if (av_stristr(value, "}")) {
            break;
        }
    }

    if (url == NULL) {
        av_log(s, AV_LOG_ERROR, "mem:%s,url is null\n",*mem);
        return -1;
    }
    struct variant *var = new_variant(c, NULL, url, NULL);
    if (!var)
        return AVERROR(ENOMEM);
    var->bandwidth = bitrate;
    return ret;
}

static int parse_mem_list(AVFormatContext *s, int type, char **mem)
{
    int ret = 0;
    char *value = NULL;
    while ((value = get_mem_value(mem))) {
        if (!av_strcasecmp(value, "[{") || !av_strcasecmp(value, "{")) {
            ret = parse_mem_playlist(s, type, mem);
            if (ret < 0) {
                return ret;
            }
        } else if (av_stristr(value, "[]")) {
            return AVERROR_EOF;
        }
    }
    return ret;
}

static int parse_mem(AVFormatContext *s, const char *url, AVIOContext *in)
{
    HLSContext *c = s->priv_data;
    int ret = 0;
    int close_in = 0;
    int64_t filesize = 0;
    AVDictionary *opts = NULL;
    char *buffer = NULL;
    char *mem = NULL, *value = NULL;

    if (!in) {
        close_in = 1;
        av_dict_copy(&opts, c->avio_opts, 0);
        ret = avio_open2(&in, url, AVIO_FLAG_READ, c->interrupt_callback, &opts);
        av_dict_free(&opts);
        if (ret < 0) {
            return ret;
        }
    }

    filesize = avio_size(in);
    buffer = av_mallocz(filesize + 1);
    if (!buffer) {
        return AVERROR(ENOMEM);
    }

    filesize = avio_read(in, (unsigned char *) buffer, filesize);
    if (filesize > 0) {
        buffer[filesize] = '\0';
        mem = buffer;
        while ((value = get_mem_value(&mem))) {
            av_log(NULL, AV_LOG_VERBOSE, "value: %s\n", value);
            if (!av_strcasecmp(value, "url_index")) {
                value = get_mem_value(&mem);
                c->url_index = value ? atoi(value) : 0;
            } else if (!av_strcasecmp(value, "dynamic_video_list")) {
                ret = parse_mem_list(s, AVMEDIA_TYPE_VIDEO, &mem);
                if (ret < 0 && ret != AVERROR_EOF) {
                    goto cleanup;
                }
            }
        }
    } else {
        av_log(s, AV_LOG_ERROR, "Unable to read to offset '%s'\n", url);
        ret = AVERROR_INVALIDDATA;
    }

cleanup:
    av_freep(&buffer);
    if (close_in) {
        avio_close(in);
    }
    return ret != AVERROR_EOF ? ret : 0;
}

static void probe_best_stream(HLSContext *c, int probe_type, int *var_index, int *pls_index, int *rend_index)
{
    int i, j, diff = INT_MAX, bitrate = INT_MAX - 1, mediatrack_index = 0;
    
    switch(probe_type) {
        case PRB_KEY_VAR:
            if(var_index == NULL) return;
            *var_index = -1;
            if (c->cur_video_bitrate) {
                bitrate = c->cur_video_bitrate;
            }
            struct variant *var = NULL;
            for (int i = 0; i < c->n_variants; i++) {
                var = c->variants[i];
                if (abs(bitrate - var->bandwidth) < diff) {
                    *var_index = i;
                    diff = abs(bitrate - var->bandwidth);
                }
            }
            if (!c->cur_video_bitrate) {
                c->now_video_bitrate = c->variants[*var_index]->bandwidth;
            } else {
                c->now_video_bitrate = c->cur_video_bitrate;
            }
            break;
        case PRB_KEY_REND:
            if(pls_index == NULL || rend_index == NULL) return;
            *pls_index = -1;
            *rend_index = -1;
            for (i = 0; i < c->variants[c->now_var_index]->n_playlists && (*pls_index < 0); i++) {
                struct playlist *pls = c->variants[c->now_var_index]->playlists[i];
                if(pls->n_renditions > 0) {
                    for(j = 0; j < pls->n_renditions; j++) {
                        if(c->cur_audio_infoid > -1) {
                            if(mediatrack_index == c->cur_audio_infoid) {
                                *pls_index = i;
                                *rend_index = j;
                                break;
                            }
                        } else {
                            *pls_index = i;
                            *rend_index = 0;
                            break;
                        }
                        mediatrack_index++;
                    }
                }
            }
            if (c->cur_audio_infoid < 0) {
                if(*pls_index >= 0 && *rend_index >= 0) {
                    c->now_audio_infoid = 0;
                }
            } else {
                c->now_audio_infoid = c->cur_audio_infoid;
            }
            break;
        default:
            break;
    }
}

static int hls_read_header2(AVFormatContext *s, AVDictionary **options)
{
    HLSContext *c = s->priv_data;
    int ret = 0, i, j, k, rend_index;
    int64_t highest_cur_seq_no = 0;
    char mediatrack_key[MAX_FIELD_LEN];
    char mediatrack_value[MAX_CHARACTERISTICS_LEN];

    c->ctx                = s;
    c->interrupt_callback = &s->interrupt_callback;

    c->first_packet = 1;
    c->first_timestamp = AV_NOPTS_VALUE;
    c->cur_timestamp = AV_NOPTS_VALUE;
    c->switch_exit = 0;

    if (options && *options &&
            (ret = av_dict_copy(&c->avio_opts, *options, 0)) < 0)
        goto fail;
    else if ((ret = save_avio_options(s)) < 0)
        goto fail;

    /* XXX: Some HLS servers don't like being sent the range header,
       in this case, need to  setting http_seekable = 0 to disable
       the range header */
    av_dict_set_int(&c->avio_opts, "seekable", c->http_seekable, 0);

    /* 
    * clear verifyhost option for hls segment 
    * fixbug: segment ssl shake error 
    */
    av_dict_set(&c->avio_opts, "verifyhost", NULL, 0);

    /*
     * Clear decryption_key option. When play AES encrypted HLS,
     * crypto will treat it as hexadecimal string, leading
     * BLOCK_SIZE check fail.
     */
    av_dict_set(&c->avio_opts, "decryption_key", NULL, 0);

    if (av_strstart(s->url, "mem://hls", NULL)) {
        if ((ret = parse_mem(s, s->url, s->pb)) < 0)
            goto fail;
    } else {
        if ((ret = parse_playlist(c, s->url, NULL, s->pb)) < 0)
            goto fail;
    }
    if (c->n_variants == 0) {
        av_log(s, AV_LOG_WARNING, "Empty playlist\n");
        ret = AVERROR_EOF;
        goto fail;
    }
    probe_best_stream(c, PRB_KEY_VAR, &(c->now_var_index), NULL, NULL);
    /* If the playlist only contained playlists (Master Playlist),
     * parse each individual playlist. */
    if (c->n_playlists > 1 || c->playlists[0]->n_segments == 0) {
        for (i = 0; i < c->n_playlists; i++) {
            struct playlist *pls = c->playlists[i];
            pls->m3u8_hold_counters = 0;
            struct variant *now_var = c->variants[c->now_var_index];
            struct playlist *var_pls = now_var->playlists[0];
            if (c->enable_master_optimize == 1 && pls != var_pls) {
                continue;
            }
            if ((ret = parse_playlist(c, pls->url, pls, NULL)) < 0) {
                av_log(s, AV_LOG_WARNING, "parse_playlist error %s [%s]\n", av_err2str(ret), pls->url);
                pls->broken = 1;
                if (c->n_playlists > 1)
                    continue;
                goto fail;
            }
        }
    }

    if (c->enable_master_optimize == 1) {
        if (c->variants[c->now_var_index]->playlists[0]->n_segments == 0) {
            av_log(NULL, AV_LOG_WARNING, "Empty playlist\n");
            ret = AVERROR_EOF;
            goto fail;
        }
    } else {
        for (i = 0; i < c->n_variants; i++) {
            if (c->variants[i]->playlists[0]->n_segments == 0) {
                av_log(s, AV_LOG_WARNING, "Empty segment [%s]\n", c->variants[i]->playlists[0]->url);
                c->variants[i]->playlists[0]->broken = 1;
            }
        }
    }

    /* If this isn't a live stream, calculate the total duration of the
     * stream. */
    if (c->variants[c->now_var_index]->playlists[0]->finished) {
        int64_t duration = 0;
        for (i = 0; i < c->variants[c->now_var_index]->playlists[0]->n_segments; i++)
            duration += c->variants[c->now_var_index]->playlists[0]->segments[i]->duration;
        s->duration = duration;
    }

    /* Associate renditions with variants */
    for (i = 0; i < c->n_variants; i++) {
        struct variant *var = c->variants[i];

        if (var->audio_group[0])
            add_renditions_to_variant(c, var, AVMEDIA_TYPE_AUDIO, var->audio_group);
        if (var->video_group[0])
            add_renditions_to_variant(c, var, AVMEDIA_TYPE_VIDEO, var->video_group);
        if (var->subtitles_group[0])
            add_renditions_to_variant(c, var, AVMEDIA_TYPE_SUBTITLE, var->subtitles_group);
    }

    if (c->enable_master_optimize == 1) {
        struct variant *now_var = c->variants[c->now_var_index];
        int audio_id = c->cur_audio_infoid >=0 ? c->cur_audio_infoid:0;
        if (now_var->n_playlists > audio_id + 1) {
           struct playlist *pls = now_var->playlists[audio_id + 1];
           if ((ret = parse_playlist(c, pls->url, pls, NULL)) < 0)
                goto fail;
        }
    }

    probe_best_stream(c, PRB_KEY_REND, NULL, &(c->now_rend_pls_index), &rend_index);

    /* Create a program for each variant */
    for (i = 0; i < c->n_variants; i++) {
        struct variant *v = c->variants[i];
        AVProgram *program;

        program = av_new_program(s, i);
        if (!program)
            goto fail;
        av_dict_set_int(&program->metadata, "variant_bitrate", v->bandwidth, 0);

        int mediatrack_count = 0;
        for (j = 0; j < v->n_playlists; j++) {
            struct playlist *pls = v->playlists[j];
            
            for (k = 0; k < pls->n_renditions; k++) {
                struct rendition *rend = pls->renditions[k];
                snprintf(mediatrack_key, MAX_FIELD_LEN, "mediatrack_%d", mediatrack_count);
                snprintf(mediatrack_value, MAX_CHARACTERISTICS_LEN, "{\"type\":\"%d\",\"language\":\"%s\",\"name\":\"%s\",\"group_id\":\"%s\",\"disposition\":\"%d\"}", rend->type, rend->language, rend->name, rend->group_id, rend->disposition);
                av_dict_set(&program->metadata, mediatrack_key, mediatrack_value, 0);
                mediatrack_count++;
            }
        }
        av_dict_set_int(&program->metadata, "mediatrack_total", mediatrack_count, 0);
    }

    /* Select the starting segments */
    for (i = 0; i < c->n_playlists; i++) {
        struct playlist *pls = c->playlists[i];
        pls->index = i;

        if (pls->n_segments == 0)
            continue;

        pls->cur_seq_no = select_cur_seq_no(c, pls);
        highest_cur_seq_no = FFMAX(highest_cur_seq_no, pls->cur_seq_no);
    }

    int mediatrack_index = 0;
    /* Open the demuxer for each playlist */
    for (i = 0; i < c->variants[c->now_var_index]->n_playlists; i++) {
        struct playlist *pls = c->variants[c->now_var_index]->playlists[i];
        if(pls->n_renditions > 0) {
            for(j = 0; j < pls->n_renditions; j++) {
                if(pls->renditions[j]->language[0]) {
                    if(c->cur_audio_infoid > -1) {
                        if(mediatrack_index == c->cur_audio_infoid) {
                            if((ret = open_demuxer_for_playlist(s, pls, highest_cur_seq_no)) < 0)
                                goto fail;
                        }
                    } else {
                        c->cur_audio_infoid = 0;
                        if((ret = open_demuxer_for_playlist(s, pls, highest_cur_seq_no)) < 0)
                            goto fail;
                    }
                }
                mediatrack_index++;
            }
        } else {
            if((ret = open_demuxer_for_playlist(s, pls, highest_cur_seq_no)) < 0)
                goto fail;
        }
    }

    update_noheader_flag(s);

    return 0;
fail:
    hls_close(s);
    return ret;
}

static int hls_read_header(AVFormatContext *s)
{
    return hls_read_header2(s, NULL);
}

static void fill_timing_for_id3_timestamped_stream(struct playlist *pls)
{
    if (pls->id3_offset >= 0) {
        pls->pkt->dts = pls->id3_mpegts_timestamp +
                                 av_rescale_q(pls->id3_offset,
                                              pls->ctx->streams[pls->pkt->stream_index]->time_base,
                                              MPEG_TIME_BASE_Q);
        if (pls->pkt->duration)
            pls->id3_offset += pls->pkt->duration;
        else
            pls->id3_offset = -1;
    } else {
        /* there have been packets with unknown duration
         * since the last id3 tag, should not normally happen */
        pls->pkt->dts = AV_NOPTS_VALUE;
    }

    if (pls->pkt->duration)
        pls->pkt->duration = av_rescale_q(pls->pkt->duration,
                                         pls->ctx->streams[pls->pkt->stream_index]->time_base,
                                         MPEG_TIME_BASE_Q);

    pls->pkt->pts = AV_NOPTS_VALUE;
}

static AVRational get_timebase(struct playlist *pls)
{
    if (pls->is_id3_timestamped)
        return MPEG_TIME_BASE_Q;

    return pls->ctx->streams[pls->pkt->stream_index]->time_base;
}

static int compare_ts_with_wrapdetect(int64_t ts_a, struct playlist *pls_a,
                                      int64_t ts_b, struct playlist *pls_b)
{
    int64_t scaled_ts_a = av_rescale_q(ts_a, get_timebase(pls_a), MPEG_TIME_BASE_Q);
    int64_t scaled_ts_b = av_rescale_q(ts_b, get_timebase(pls_b), MPEG_TIME_BASE_Q);

    return av_compare_mod(scaled_ts_a, scaled_ts_b, 1LL << 33);
}

static int switch_stream_internal(HLSContext *c, int64_t timestamp, struct playlist **pls_open, int n_pls_open, struct playlist **pls_close, int n_pls_close)
{
    struct playlist *pls;
    int ret = 0;
    for (int i = 0; i < n_pls_open; i++) {
        pls = pls_open[i];
        pls->reuse = 1;
        pls->cur_refresh_begin_time = pls_close[0]->cur_refresh_begin_time;
        if (!pls->finished && av_gettime_relative() - pls->last_load_time >= default_reload_interval(pls))
            if ((ret = parse_playlist(c, pls->url, pls, NULL)) < 0)
                goto fail;
        pls->seek_timestamp = timestamp;
        if (timestamp == AV_NOPTS_VALUE) {
            pls->cur_seq_no = c->cur_seq_no;
        } else if (!find_timestamp_in_playlist(c, pls, pls->seek_timestamp, &pls->cur_seq_no)) {
            ret = AVERROR(EIO);
            goto fail;
        }
        if (!pls->input && (ret = open_demuxer_for_playlist(pls_close[0]->parent, pls, pls->cur_seq_no)) < 0)
            goto fail;
    }
    for (int i = 0; i < n_pls_close; i++)
        if (!pls_close[i]->reuse)
            close_demuxer_for_playlist(pls_close[i]);
    c->need_inject_sidedata = 0;
    for (int i = 0; i < n_pls_open; i++) {
        pls = pls_open[i];
        pls->reuse = 0;
        for (int j = 0; j < pls->ctx->nb_streams; j++) {
            int stream_type = pls->ctx->streams[j]->codecpar ? pls->ctx->streams[j]->codecpar->codec_type : AVMEDIA_TYPE_UNKNOWN;
            c->need_inject_sidedata |= 1 << stream_type;
        }
    }
    return ret;
fail:
    for (int i = 0; i < n_pls_open; i++) {
        pls_open[i]->reuse = 0;
        close_demuxer_for_playlist(pls_open[i]);
    }
    return ret;
}

static int switch_stream(HLSContext *c, int64_t timestamp)
{
    int bitrate = c->now_video_bitrate, ret = 0, next, pls_next, rend_next;
    if (c->now_video_bitrate != c->cur_video_bitrate && c->cur_video_bitrate) {
        probe_best_stream(c, PRB_KEY_VAR, &next, NULL, NULL);
        if (next >= 0 && next < c->n_variants && c->now_var_index != next) {
            if((ret = switch_stream_internal(c, timestamp, c->variants[next]->playlists, c->variants[next]->n_playlists, c->variants[c->now_var_index]->playlists, c->variants[c->now_var_index]->n_playlists)) < 0) {
                c->now_video_bitrate = bitrate;
                return ret;
            }
            c->now_var_index = next;
        } else {
            return AVERROR_EXIT;
        }
    } else if (c->now_audio_infoid != c->cur_audio_infoid) {
        probe_best_stream(c, PRB_KEY_REND, NULL, &pls_next, &rend_next);
        if (pls_next >= 0 && pls_next < c->variants[c->now_var_index]->n_playlists && c->now_rend_pls_index != pls_next) {
            if((ret = switch_stream_internal(c, timestamp, &(c->variants[c->now_var_index]->playlists[pls_next]), 1, &(c->variants[c->now_var_index]->playlists[c->now_rend_pls_index]), 1)) < 0)
                return ret;
            c->now_rend_pls_index = pls_next;
        } else {
            return AVERROR_EXIT;
        }
    }
    else {
        return AVERROR_EXIT;
    }
    reset_packets_cache(c,AVMEDIA_TYPE_NB);
    return 0;
}

static int read_stream_packets(AVFormatContext *s,int index,AVPacket **pkt,int64_t *pkt_time) {
    if (index < 0 || index >= AVMEDIA_TYPE_NB) {
        return -1;
    }
    HLSContext *c = s->priv_data;
    AVPacket **packets = c->packets[index];
    int n_packets = c->n_packets[index];
    if (packets == NULL || n_packets <= 0) {
        return -1;
    }
    int64_t time = AV_NOPTS_VALUE;
    AVPacket *packet = NULL;
    if (c->packets_pos[index] < n_packets) {
        packet = packets[c->packets_pos[index]];
        int64_t pkt_pts = packet->pts;
        AVStream *stream = s->streams[packet->stream_index];
        if (stream != NULL) {
            time = av_rescale_rnd(pkt_pts, AV_TIME_BASE, stream->time_base.den, AV_ROUND_DOWN);
        }
    }
    if (pkt_time != NULL) {
        *pkt_time = time;
    }
    if (pkt != NULL) {
        *pkt = packet;
    }
    return 0;
}

static int read_cache_packets(AVFormatContext *s,AVPacket *pkt) {
    HLSContext *c = s->priv_data;
    if (c->n_packets[AVMEDIA_TYPE_VIDEO] <= 0) {
        reset_packets_cache(c,AVMEDIA_TYPE_AUDIO);
        return -1;
    }
    AVPacket *aPacket = NULL,*vPacket = NULL;
    int n_videoPackets = c->n_packets[AVMEDIA_TYPE_VIDEO];
    int n_audioPackets = c->n_packets[AVMEDIA_TYPE_AUDIO];
    int64_t audio_pkt_time = AV_NOPTS_VALUE, video_pkt_time = AV_NOPTS_VALUE;
    read_stream_packets(s,AVMEDIA_TYPE_AUDIO,&aPacket,&audio_pkt_time);
    read_stream_packets(s,AVMEDIA_TYPE_VIDEO,&vPacket,&video_pkt_time);
    if (aPacket == NULL && c->packets_pos[AVMEDIA_TYPE_AUDIO] < n_audioPackets) {
        av_log(s, AV_LOG_ERROR, "read hls cache error,audio is null pos:%d,total size:%d.\n",
                   c->packets_pos[AVMEDIA_TYPE_AUDIO],c->n_packets[AVMEDIA_TYPE_AUDIO]);
    }
    if (vPacket == NULL && c->packets_pos[AVMEDIA_TYPE_VIDEO] < n_videoPackets) {
        av_log(s, AV_LOG_ERROR, "read hls cache error,video is null pos:%d,total size:%d.\n",
                   c->packets_pos[AVMEDIA_TYPE_VIDEO],c->n_packets[AVMEDIA_TYPE_VIDEO]);
    }
    if (aPacket == NULL && vPacket == NULL) {
        av_log(s, AV_LOG_ERROR, "read hls cache error,both null, audio pos:%d,total size:%d;\
                                vidoe pos:%d,total size:%d.\n",
                                c->packets_pos[AVMEDIA_TYPE_AUDIO],c->n_packets[AVMEDIA_TYPE_AUDIO],\
                                c->packets_pos[AVMEDIA_TYPE_VIDEO],c->n_packets[AVMEDIA_TYPE_VIDEO]);
    }
    if (audio_pkt_time < c->video_keyframe_time) {
        while (c->packets_pos[AVMEDIA_TYPE_AUDIO] < n_audioPackets && audio_pkt_time < c->video_keyframe_time) {
            c->packets_pos[AVMEDIA_TYPE_AUDIO]++;
            read_stream_packets(s,AVMEDIA_TYPE_AUDIO,&aPacket,&audio_pkt_time);
        }
    }
    if (aPacket != NULL && 
        (vPacket == NULL || audio_pkt_time < video_pkt_time)) {
        av_packet_ref(pkt, aPacket);
        c->packets_pos[AVMEDIA_TYPE_AUDIO]++;
    } else if (vPacket != NULL ) {
        av_packet_ref(pkt, vPacket);
        c->packets_pos[AVMEDIA_TYPE_VIDEO]++;
    }
    if (c->packets_pos[AVMEDIA_TYPE_AUDIO] >= n_audioPackets && c->packets_pos[AVMEDIA_TYPE_VIDEO] >= n_videoPackets) {
        reset_packets_cache(c,AVMEDIA_TYPE_NB);
    }
    if (aPacket == NULL && vPacket == NULL) {
        reset_packets_cache(c,AVMEDIA_TYPE_NB);
        return -1;
    }
    return 0;
}

static int hls_read_packet(AVFormatContext *s, AVPacket *pkt)
{
    HLSContext *c = s->priv_data;
    int ret, i, minplaylist = -1;

    if (c->n_packets[AVMEDIA_TYPE_VIDEO] > 0)
        goto hit_cache;

    c->first_packet = 0;

restart:
    for (i = 0; i < c->n_playlists; i++) {
        struct playlist *pls = c->playlists[i];
        /* Make sure we've got one buffered packet from each open playlist
         * stream */
        AVStream *stream = NULL;
        int stream_type = AVMEDIA_TYPE_UNKNOWN;
        if (pls->needed && !pls->pkt->data) {
            while (1) {
                int64_t pkt_ts;
                int64_t ts_diff;
                AVRational tb;
                ret = av_read_frame(pls->ctx, pls->pkt);
                if (c->switch_exit) {
                    c->switch_exit = 0;
                    if ((ret = switch_stream(c, AV_NOPTS_VALUE)) == 0)
                        goto restart;
                    return ret;
                }
                if (ret < 0) {
                    if ((!avio_feof(&pls->pb) || (c->enable_seg_error && pls->pb.error < 0)) && ret != AVERROR_EOF)
                        return ret;
                    break;
                } else {
                    /* stream_index check prevents matching picture attachments etc. */
                    if (pls->is_id3_timestamped && pls->pkt->stream_index == 0) {
                        /* audio elementary streams are id3 timestamped */
                        fill_timing_for_id3_timestamped_stream(pls);
                    }

                    if (pls->type == PLS_TYPE_VOD && pls->finished) {
                        int seq_no = pls->cur_seq_no - pls->start_seq_no;
                        if (seq_no < pls->n_segments && pls->main_streams[pls->pkt->stream_index]) {
                            struct segment *seg = pls->segments[seq_no];
                            if (pls->pkt->stream_index  >=  seg->timestamp_list_size) {
                                int new_timestamp_list_size = pls->pkt->stream_index + 1 > pls->n_main_streams ? pls->pkt->stream_index + 1 : pls->n_main_streams;
                                seg->start_dts = av_realloc(seg->start_dts, sizeof(int64_t) * new_timestamp_list_size);
                                seg->start_pts = av_realloc(seg->start_pts, sizeof(int64_t) * new_timestamp_list_size);
                                if (!seg->start_dts || !seg->start_pts) {
                                    return AVERROR(ENOMEM);
                                }
                                for (int j = seg->timestamp_list_size; j < new_timestamp_list_size; j++) {
                                    seg->start_dts[j] = AV_NOPTS_VALUE;
                                    seg->start_pts[j] = AV_NOPTS_VALUE;
                                }
                                seg->timestamp_list_size = new_timestamp_list_size;
                            }
                            
                            bool is_need_update_dts = false;
                            
                            if(c->enable_hls_pts_recal_opt) {
                                if((pls->pkt->flags & AV_PKT_FLAG_CORRUPT) == 0) {
                                    is_need_update_dts = (seg->start_dts[pls->pkt->stream_index] == AV_NOPTS_VALUE && (pls->pkt->flags & AV_PKT_FLAG_KEY))
                                                         || (pls->pkt->dts != AV_NOPTS_VALUE && pls->pkt->dts < seg->start_dts[pls->pkt->stream_index]);
                                }
                            } else {
                                is_need_update_dts = (seg->start_dts[pls->pkt->stream_index] == AV_NOPTS_VALUE
                                                      || (pls->pkt->dts != AV_NOPTS_VALUE && pls->pkt->dts < seg->start_dts[pls->pkt->stream_index]));
                            }
                            
                            if (is_need_update_dts) {
                                seg->start_dts[pls->pkt->stream_index] = pls->pkt->dts;
                                seg->start_pts[pls->pkt->stream_index] = pls->pkt->pts;
                            }
                            
                            if(c->enable_hls_pts_recal_opt && seg->start_dts[pls->pkt->stream_index] == AV_NOPTS_VALUE) {
                                continue;
                            }
                                    
                            int64_t pred = av_rescale_q(seg->start_time, AV_TIME_BASE_Q, pls->main_streams[pkt->stream_index]->time_base);
                            // add by teddy: use base time for correct timeStamp
                            
                            if (pls->pkt->dts != AV_NOPTS_VALUE) {
                                pls->pkt->dts = pls->pkt->dts - seg->start_dts[pls->pkt->stream_index] + pred;
                            }
                            if (pls->pkt->pts != AV_NOPTS_VALUE) {
                                pls->pkt->pts = pls->pkt->pts - seg->start_pts[pls->pkt->stream_index] + pred;
                            }
                        }
                    }

                    if (pls->pkt->pts != AV_NOPTS_VALUE)
                        pkt_ts =  pls->pkt->pts;
                    else if (pls->pkt->dts != AV_NOPTS_VALUE)
                        pkt_ts =  pls->pkt->dts;
                    else
                        pkt_ts = AV_NOPTS_VALUE;


                    c->first_timestamp = s->start_time != AV_NOPTS_VALUE ? s->start_time : 0;
                }
                
                stream = pls->ctx->streams[pls->pkt->stream_index];
                stream_type = stream->codecpar ? stream->codecpar->codec_type : AVMEDIA_TYPE_UNKNOWN;
                
                if ((pls->pkt->flags & AV_PKT_FLAG_KEY) &&
                (stream_type == AVMEDIA_TYPE_VIDEO || stream_type == AVMEDIA_TYPE_AUDIO) &&
                ((c->need_inject_sidedata >> stream_type) & 0x1) == 1) {
                    c->need_inject_sidedata &= ~(1 << stream_type);
                    int extradata_size = 0;
                    uint8_t *side, *extradata;
                    extradata_size = stream->codecpar->extradata_size;
                    extradata = stream->codecpar->extradata;
                    if (extradata_size > 0 && extradata) {
                        side = av_packet_new_side_data(pls->pkt, AV_PKT_DATA_NEW_EXTRADATA, extradata_size);
                        if (!side) {
                            return AVERROR(ENOMEM);
                        }
                        memcpy(side, extradata, extradata_size);
                    }
                }
                
                if (pkt_ts != AV_NOPTS_VALUE) {
                    tb = get_timebase(pls);
                    pkt_ts = av_rescale_rnd(pkt_ts, AV_TIME_BASE, tb.den, AV_ROUND_DOWN);
                }
                struct segment *seg = NULL;
                seg = current_segment(pls);

                if (seg && seg->key_type == KEY_SAMPLE_AES && !strstr(pls->ctx->iformat->name, "mov") && c->decryption_key) {
                    if (c->crypto_ctx.aes_ctx==NULL) {
                        c->crypto_ctx.aes_ctx = av_aes_alloc();
                    }
                    enum AVCodecID codec_id = pls->ctx->streams[pls->pkt->stream_index]->codecpar->codec_id;
                    memcpy(c->crypto_ctx.iv, DEFAULT_IV, 16);
                    memcpy(c->crypto_ctx.key, pls->key, sizeof(pls->key));
                    av_log(NULL, AV_LOG_DEBUG,"hls key:%s iv:%s\n",c->crypto_ctx.key,c->crypto_ctx.iv);
                    ff_hls_senc_decrypt_frame(codec_id, &c->crypto_ctx, pls->pkt);
                }

                if (pls->seek_timestamp == AV_NOPTS_VALUE)
                    break;

                if (pkt_ts == AV_NOPTS_VALUE) {
                    pls->seek_timestamp = AV_NOPTS_VALUE;
                    break;
                }

                ts_diff = pkt_ts - pls->seek_timestamp;

                if (stream_type == AVMEDIA_TYPE_VIDEO && pls->pkt->flags & AV_PKT_FLAG_KEY)
                    reset_packets_cache(c,AVMEDIA_TYPE_VIDEO);

                if (ts_diff >= 0) {
                    pls->seek_timestamp = AV_NOPTS_VALUE;
                    break;
                }

                if (stream_type == AVMEDIA_TYPE_VIDEO && (pls->pkt->flags & AV_PKT_FLAG_KEY || c->n_packets[AVMEDIA_TYPE_VIDEO] > 0)) {
                    if (pls->pkt->flags & AV_PKT_FLAG_KEY) {
                        AVStream *vStream = s->streams[pls->pkt->stream_index];
                        if (vStream != NULL) {
                            c->video_keyframe_time = av_rescale_rnd(pls->pkt->pts, AV_TIME_BASE, vStream->time_base.den, AV_ROUND_DOWN);
                        }
                    }
                    if (pls->pkt->stream_index < pls->n_main_streams) {
                        pls->pkt->stream_index = pls->main_streams[pls->pkt->stream_index]->index;
                    }
                    AVPacket *clonePkt = av_packet_clone(pls->pkt);
                    if (clonePkt == NULL) {
                         av_log(s, AV_LOG_ERROR, "clone hls cache error,video failed. pos:%d,total size:%d.\n",
                                 c->packets_pos[AVMEDIA_TYPE_VIDEO],c->n_packets[AVMEDIA_TYPE_VIDEO]);
                    }
                    dynarray_add(&c->packets[AVMEDIA_TYPE_VIDEO], &c->n_packets[AVMEDIA_TYPE_VIDEO], clonePkt);
                }
                if (stream_type == AVMEDIA_TYPE_AUDIO && pls->main_streams[pls->pkt->stream_index]->discard != AVDISCARD_ALL) {
                    if (pls->pkt->stream_index < pls->n_main_streams) {
                        pls->pkt->stream_index = pls->main_streams[pls->pkt->stream_index]->index;
                    }
                    AVPacket *clonePkt = av_packet_clone(pls->pkt);
                    if (clonePkt == NULL) {
                         av_log(s, AV_LOG_ERROR, "clone hls cache error,audio failed. pos:%d,total size:%d\n",
                                 c->packets_pos[AVMEDIA_TYPE_AUDIO],c->n_packets[AVMEDIA_TYPE_AUDIO]);
                    }
                    dynarray_add(&c->packets[AVMEDIA_TYPE_AUDIO], &c->n_packets[AVMEDIA_TYPE_AUDIO], clonePkt);
                }
                av_packet_unref(pls->pkt);
            }
        }
        /* Check if this stream has the packet with the lowest dts */
        if (!c->n_packets[AVMEDIA_TYPE_VIDEO] && pls->needed && pls->pkt->data) {
            struct playlist *minpls = minplaylist < 0 ?
                                     NULL : c->playlists[minplaylist];
            if (minplaylist < 0) {
                minplaylist = i;
            } else {
                int64_t dts     =    pls->pkt->dts;
                int64_t mindts  = minpls->pkt->dts;

                if (dts == AV_NOPTS_VALUE ||
                    (mindts != AV_NOPTS_VALUE && compare_ts_with_wrapdetect(dts, pls, mindts, minpls) < 0))
                    minplaylist = i;
            }
        }
    }
hit_cache:
    if (read_cache_packets(s,pkt) == 0) {
        return 0;
    }
    /* If we got a packet, return it */
    if (minplaylist >= 0) {
        struct playlist *pls = c->playlists[minplaylist];
        AVStream *ist;
        AVStream *st;

        ret = update_streams_from_subdemuxer(s, pls);
        if (ret < 0) {
            av_packet_unref(pls->pkt);
            return ret;
        }

        // If sub-demuxer reports updated metadata, copy it to the first stream
        // and set its AVSTREAM_EVENT_FLAG_METADATA_UPDATED flag.
        if (pls->ctx->event_flags & AVFMT_EVENT_FLAG_METADATA_UPDATED) {
            if (pls->n_main_streams) {
                st = pls->main_streams[0];
                av_dict_copy(&st->metadata, pls->ctx->metadata, 0);
                st->event_flags |= AVSTREAM_EVENT_FLAG_METADATA_UPDATED;
            }
            pls->ctx->event_flags &= ~AVFMT_EVENT_FLAG_METADATA_UPDATED;
        }

        /* check if noheader flag has been cleared by the subdemuxer */
        if (pls->has_noheader_flag && !(pls->ctx->ctx_flags & AVFMTCTX_NOHEADER)) {
            pls->has_noheader_flag = 0;
            update_noheader_flag(s);
        }

        if (pls->pkt->stream_index >= pls->n_main_streams) {
            av_log(s, AV_LOG_ERROR, "stream index inconsistency: index %d, %d main streams, %d subdemuxer streams\n",
                   pls->pkt->stream_index, pls->n_main_streams, pls->ctx->nb_streams);
            av_packet_unref(pls->pkt);
            return AVERROR_BUG;
        }

        ist = pls->ctx->streams[pls->pkt->stream_index];
        st = pls->main_streams[pls->pkt->stream_index];

        av_packet_move_ref(pkt, pls->pkt);
        pkt->stream_index = st->index;

        if (pkt->dts != AV_NOPTS_VALUE)
            c->cur_timestamp = av_rescale_q(pkt->dts,
                                            ist->time_base,
                                            AV_TIME_BASE_Q);

        /* There may be more situations where this would be useful, but this at least
         * handles newly probed codecs properly (i.e. request_probe by mpegts). */
        if (ist->codecpar->codec_id != st->codecpar->codec_id) {
            ret = set_stream_info_from_input_stream(st, pls, ist);
            if (ret < 0) {
                return ret;
            }
        }

        // if (c->playlists[minplaylist]->finished) {
        //     struct playlist *pls = c->playlists[minplaylist];
        //     int seq_no = pls->cur_seq_no - pls->start_seq_no;
        //     if (seq_no < pls->n_segments && s->streams[pkt->stream_index]) {
        //         struct segment *seg = pls->segments[seq_no];
        //         if (seg->start_dts == AV_NOPTS_VALUE || pkt->dts < seg->start_dts) {
        //             seg->start_dts = pkt->dts;
        //             seg->start_pts = pkt->pts;
        //         }
        //         int64_t pred = av_rescale_q(seg->start_time,
        //                                     AV_TIME_BASE_Q,
        //                                     s->streams[pkt->stream_index]->time_base);
        //         int64_t max_ts = av_rescale_q(seg->start_time + seg->duration,
        //                                       AV_TIME_BASE_Q,
        //                                       s->streams[pkt->stream_index]->time_base);
        //         /* EXTINF duration is not precise enough */
        //         max_ts += 2 * AV_TIME_BASE;
        //         if (s->start_time > 0) {
        //             max_ts += av_rescale_q(s->start_time,
        //                                    AV_TIME_BASE_Q,
        //                                    s->streams[pkt->stream_index]->time_base);
        //         }
        //         av_log(s, AV_LOG_ERROR, "debug pkt: （%d, %d） seg:(%lld, %lld, %lld, %lld), pkt(%lld, %lld), %lld\n", 
        //             pls->cur_seq_no, seg->is_discontinuety,
        //             pred, max_ts, seg->start_dts, seg->start_pts,
        //             pkt->dts, pkt->pts, c->cur_timestamp);
        //         //add by teddy: use base time for correct timeStamp
        //         if (pkt->dts != AV_NOPTS_VALUE) {
        //             pkt->dts = pkt->dts - seg->start_dts + pred;
        //         }
        //         if (pkt->pts != AV_NOPTS_VALUE) {
        //             pkt->pts = pkt->pts - seg->start_pts + pred;
        //         }
        //     }
        // }
        return 0;
    }
    return AVERROR_EOF;
}

static int hls_read_seek(AVFormatContext *s, int stream_index,
                               int64_t timestamp, int flags)
{
    HLSContext *c = s->priv_data;
    struct playlist *seek_pls = NULL;
    int i, j;
    int stream_subdemuxer_index;
    int64_t first_timestamp, seek_timestamp, duration;
    int64_t seq_no;

    if (flags & AVSEEK_FLAG_BYTE)
        return AVERROR(ENOSYS);

    if (c->ctx->ctx_flags & AVFMTCTX_UNSEEKABLE) {
        // not support seek, and return 0 to avoid report error
        return 0;
    }

    c->first_timestamp = s->start_time != AV_NOPTS_VALUE ? s->start_time : 0;
    first_timestamp = c->first_timestamp == AV_NOPTS_VALUE ?
                      0 : c->first_timestamp;

    seek_timestamp = av_rescale_rnd(timestamp, AV_TIME_BASE,
                                    s->streams[stream_index]->time_base.den,
                                    flags & AVSEEK_FLAG_BACKWARD ?
                                    AV_ROUND_DOWN : AV_ROUND_UP);

    duration = s->duration == AV_NOPTS_VALUE ?
               0 : s->duration;

    if (0 < duration && duration < seek_timestamp - first_timestamp)
        return AVERROR(EIO);

    /* find the playlist with the specified stream */
    for (i = 0; i < c->n_playlists; i++) {
        struct playlist *pls = c->playlists[i];
        for (j = 0; j < pls->n_main_streams; j++) {
            if (pls->main_streams[j] == s->streams[stream_index]) {
                seek_pls = pls;
                stream_subdemuxer_index = j;
                break;
            }
        }
    }
    int64_t pos = c->first_timestamp == AV_NOPTS_VALUE ? 0 : c->first_timestamp;
    if ((seek_timestamp < pos) && (seek_timestamp >= 0)) {
        seek_timestamp = pos;
    }
    if (switch_stream(c, seek_timestamp) == 0)
        return 0;
    /* check if the timestamp is valid for the playlist with the
     * specified stream index */
    if (!seek_pls || !find_timestamp_in_playlist(c, seek_pls, seek_timestamp, &seq_no))
        return AVERROR(EIO);

    /* set segment now so we do not need to search again below */
    seek_pls->cur_seq_no = seq_no;
    seek_pls->seek_stream_index = stream_subdemuxer_index;
    int64_t pls_seek_time = seek_timestamp;
    if(flags & AVSEEK_FLAG_BACKWARD) {
        int cur_seg_no = seek_pls->cur_seq_no - seek_pls->start_seq_no;
        if (cur_seg_no >= 0 && cur_seg_no < seek_pls->n_segments) {
           pls_seek_time = seek_pls->segments[cur_seg_no]->start_time;
        }
    }
    for (i = 0; i < c->variants[c->now_var_index]->n_playlists; i++) {
        /* Reset reading */
        struct playlist *pls = c->variants[c->now_var_index]->playlists[i];
        ff_format_io_close(pls->parent, &pls->input);
        pls->input_read_done = 0;
        ff_format_io_close(pls->parent, &pls->input_next);
        pls->input_next_requested = 0;
        av_packet_unref(pls->pkt);
        pls->pb.eof_reached = 0;
        /* Clear any buffered data */
        pls->pb.buf_end = pls->pb.buf_ptr = pls->pb.buffer;
        /* Reset the pos, to let the mpegts demuxer know we've seeked. */
        pls->pb.pos = 0;
        /* Flush the packet queue of the subdemuxer. */
        if(pls->needed)
            ff_read_frame_flush(pls->ctx);

        pls->seek_timestamp = seek_timestamp;
        pls->seek_flags = flags;

        if (pls != seek_pls) {
            /* set closest segment seq_no for playlists not handled above */
            find_timestamp_in_playlist(c, pls, pls_seek_time, &pls->cur_seq_no);
            /* seek the playlist to the given position without taking
             * keyframes into account since this playlist does not have the
             * specified stream where we should look for the keyframes */
            pls->seek_stream_index = -1;
            pls->seek_flags |= AVSEEK_FLAG_ANY;
        }
    }

    c->cur_timestamp = seek_timestamp;
    reset_packets_cache(c,AVMEDIA_TYPE_NB);
    return 0;
}

static int hls_probe(const AVProbeData *p)
{
    if (p->filename && av_strstart(p->filename, "mem://hls", NULL)) {
        return AVPROBE_SCORE_MAX;
    }
    /* Require #EXTM3U at the start, and either one of the ones below
     * somewhere for a proper match. */
    if (strncmp(p->buf, "#EXTM3U", 7))
        return 0;

    if (strstr(p->buf, "#EXT-X-STREAM-INF:")     ||
        strstr(p->buf, "#EXT-X-TARGETDURATION:") ||
        strstr(p->buf, "#EXT-X-MEDIA-SEQUENCE:"))
        return AVPROBE_SCORE_MAX;
    return 0;
}

#define OFFSET(x) offsetof(HLSContext, x)
#define FLAGS AV_OPT_FLAG_DECODING_PARAM
static const AVOption hls_options[] = {
    {"live_start_index", "segment index to start live streams at (negative values are from the end)",
        OFFSET(live_start_index), AV_OPT_TYPE_INT, {.i64 = -3}, INT_MIN, INT_MAX, FLAGS},
    {"allowed_extensions", "List of file extensions that hls is allowed to access",
        OFFSET(allowed_extensions), AV_OPT_TYPE_STRING,
        {.str = "3gp,aac,avi,ac3,eac3,flac,mkv,m3u8,m4a,m4s,m4v,mpg,mov,mp2,mp3,mp4,mpeg,mpegts,ogg,ogv,oga,ts,vob,wav"},
        INT_MIN, INT_MAX, FLAGS},
    {"max_reload", "Maximum number of times a insufficient list is attempted to be reloaded",
        OFFSET(max_reload), AV_OPT_TYPE_INT, {.i64 = 1000}, 0, INT_MAX, FLAGS},
    {"m3u8_hold_counters", "The maximum number of times to load m3u8 when it refreshes without new segments",
        OFFSET(m3u8_hold_counters), AV_OPT_TYPE_INT, {.i64 = 1000}, 0, INT_MAX, FLAGS},
    {"http_persistent", "Use persistent HTTP connections",
        OFFSET(http_persistent), AV_OPT_TYPE_BOOL, {.i64 = 1}, 0, 1, FLAGS },
    {"http_multiple", "Use multiple HTTP connections for fetching segments",
        OFFSET(http_multiple), AV_OPT_TYPE_BOOL, {.i64 = -1}, -1, 1, FLAGS},
    {"http_seekable", "Use HTTP partial requests, 0 = disable, 1 = enable, -1 = auto",
        OFFSET(http_seekable), AV_OPT_TYPE_BOOL, { .i64 = -1}, -1, 1, FLAGS},
    {"tt_opaque", "The user data for callback registed by tt_register*", OFFSET(tt_opaque), AV_OPT_TYPE_IPTR, { .i64 = 0 }, INT64_MIN, INT64_MAX, FLAGS},
    { "tt_hls_drm_enable", "tt hls drm enable", OFFSET(tt_hls_drm_enable), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, FLAGS },
    { "tt_hls_drm_token", "tt hls drm token", OFFSET(tt_hls_drm_token), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, FLAGS },
    { "decryption_key", "the media decryption key", OFFSET(decryption_key), AV_OPT_TYPE_STRING, { .str = NULL }, INT_MIN, INT_MAX, FLAGS },
    { "enable_refresh_by_time", "enable refresh by time", OFFSET(enable_refresh_by_time), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, FLAGS },
    { "cur_video_bitrate", "the bitrate of video stream", OFFSET(cur_video_bitrate), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, INT_MAX, FLAGS },
    { "drm_downgrade", "drm downgrade", OFFSET(drm_downgrade), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, INT_MAX, FLAGS },
    { "enable_intertrust_drm", "enable intertrust drm", OFFSET(enable_intertrust_drm), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, FLAGS },
    { "hls_sub_demuxer_probe_type", "subdemuxer probe type", OFFSET(hls_sub_demuxer_probe_type), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, INT_MAX, FLAGS },
    { "drm_aptr", "drm aptr", OFFSET(drm_aptr), AV_OPT_TYPE_IPTR, { .i64 = 0 }, INT64_MIN, INT64_MAX, FLAGS },
    { "cur_audio_infoid", "current audio info id", OFFSET(cur_audio_infoid), AV_OPT_TYPE_INT, { .i64 = -1 }, -1, INT_MAX, FLAGS },
    { "enable_master_optimize", "only open the m3u8 required for play rather than open all m3u8 file",OFFSET(enable_master_optimize), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, FLAGS},
    { "abr", "get abr strategy", OFFSET(abr), AV_OPT_TYPE_IPTR, { .i64 = 0 }, INT64_MIN, INT64_MAX, FLAGS },
    { "seg_max_retry", "Maximum number of times to reload a segment on error.", OFFSET(seg_max_retry), AV_OPT_TYPE_INT, {.i64 = 0}, 0, INT_MAX, FLAGS},
    { "enable_seg_error", "Report error if a segment on error.", OFFSET(enable_seg_error), AV_OPT_TYPE_BOOL, {.i64 = 0}, 0, 1, FLAGS},
    { "hls_pts_recal_opt", "pts and dts recalculate optimize.", OFFSET(enable_hls_pts_recal_opt), AV_OPT_TYPE_INT, {.i64 = 0}, 0, INT_MAX, FLAGS},
    {NULL}
};

static const AVClass hls_class = {
    .class_name = "hls demuxer",
    .item_name  = av_default_item_name,
    .option     = hls_options,
    .version    = LIBAVUTIL_VERSION_INT,
};

AVInputFormat ff_hls_demuxer = {
    .name           = "hls",
    .long_name      = NULL_IF_CONFIG_SMALL("Apple HTTP Live Streaming"),
    .priv_class     = &hls_class,
    .priv_data_size = sizeof(HLSContext),
    .flags          = AVFMT_NOGENSEARCH | AVFMT_TS_DISCONT,
    .read_probe     = hls_probe,
    .read_header    = hls_read_header,
    .read_header2   = hls_read_header2,
    .read_packet    = hls_read_packet,
    .read_close     = hls_close,
    .read_seek      = hls_read_seek,
};
