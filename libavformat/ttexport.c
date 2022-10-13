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
#include "avformat.h"
#include "avio_internal.h"
#include "network.h"
#include "url.h"
#include "internal.h"
#include <string.h>

static int ttdummy_open(URLContext *h, const char *arg, int flags, AVDictionary **options) {
    return -1;
}

#define TT_DUMMY_PROTOCOL(x)                        \
                                                    \
    URLProtocol ff_##x##_protocol = {               \
        .name = #x,                                 \
        .url_open2 = ttdummy_open,                  \
        .priv_data_size = 1,                        \
    };

TT_DUMMY_PROTOCOL(mdl);
TT_DUMMY_PROTOCOL(mem);
TT_DUMMY_PROTOCOL(quic);
TT_DUMMY_PROTOCOL(live);
TT_DUMMY_PROTOCOL(httpx);
TT_DUMMY_PROTOCOL(thirdparty);

int tt_register_protocol(URLProtocol *prot, int protocol_size)
{
    int ret = -1;
    if (protocol_size != sizeof(URLProtocol))
        return ret;
    if (prot && prot->name) {
        ret = 0;
        if (strcmp(prot->name, "mdl") == 0) {
            memcpy(&ff_mdl_protocol, prot, protocol_size);
        } else if (strcmp(prot->name, "mem") == 0) {
            memcpy(&ff_mem_protocol, prot, protocol_size);
        } else if (strcmp(prot->name, "quic") == 0) {
            memcpy(&ff_quic_protocol, prot, protocol_size);
        } else if (strcmp(prot->name, "live") == 0) {
            memcpy(&ff_live_protocol, prot, protocol_size);
        } else if (strcmp(prot->name, "httpx") == 0) {
            memcpy(&ff_httpx_protocol, prot, protocol_size);
        } else {
            ret = -1;
        }
    }
    return ret;
}

int tt_register_3rd_protocol(URLProtocol *prot, int protocol_size)
{
    if (protocol_size != sizeof(URLProtocol) || !prot)
        return -1;
    memcpy(&ff_thirdparty_protocol, prot, protocol_size);
    return 0;
}

static int dummy_probe(const AVProbeData *p)
{
    return 0;
}

#define TT_DUMMY_INPUT_FORMAT(x)                    \
                                                    \
    AVInputFormat ff_##x##_demuxer = {              \
        .name = #x,                                 \
        .read_probe = dummy_probe,                  \
        .priv_data_size = 1,                        \
    };


TT_DUMMY_INPUT_FORMAT(cmaf);
TT_DUMMY_INPUT_FORMAT(llash);
TT_DUMMY_INPUT_FORMAT(live);
TT_DUMMY_INPUT_FORMAT(avph);
TT_DUMMY_INPUT_FORMAT(webrtc);


int tt_register_input_format(AVInputFormat *format, int format_size)
{
    int ret = -1;
    if (format_size != sizeof(AVInputFormat))
        return ret;
    if (format && format->name) {
        ret = 0;
        if (strcmp(format->name, "cmaf") == 0) {
            memcpy(&ff_cmaf_demuxer, format, format_size);
        } else if (strcmp(format->name, "live") == 0) {
            memcpy(&ff_live_demuxer, format, format_size);
        } else if (strcmp(format->name, "webrtc") == 0) {
            memcpy(&ff_webrtc_demuxer, format, format_size);
        } else if (strcmp(format->name, "llash") == 0) {
            memcpy(&ff_llash_demuxer, format, format_size);
        } else if (strcmp(format->name, "avph") == 0) {
            memcpy(&ff_avph_demuxer, format, format_size);
        } else {
            ret = -1;
        }
    }
    return ret;
}

static int (*ff_custom_verify_callback)(void*, void*, const char*, int) = NULL;

void tt_set_verify_callback(int (*callback)(void*, void*, const char*, int))
{
    ff_custom_verify_callback = callback;
}

int ff_do_custom_verify_callback(void* context, void* ssl, const char* host, int port) {
    if (ff_custom_verify_callback != NULL) {
        return ff_custom_verify_callback(context, ssl, host, port);
    }
    return 0;
}

void tt_set_pts_info(AVStream *s, int pts_wrap_bits,
                         unsigned int pts_num, unsigned int pts_den)
{
    avpriv_set_pts_info(s, pts_wrap_bits, pts_num, pts_den);
}


void tt_read_frame_flush(AVFormatContext *s)
{
    ff_read_frame_flush(s);
}

int tt_stream_encode_params_copy(AVStream *dst, const AVStream *src)
{
    return ff_stream_encode_params_copy(dst, src);
}

int tt_copy_whiteblacklists(AVFormatContext *dst, const AVFormatContext *src)
{
    return ff_copy_whiteblacklists(dst, src);
}

int tt_io_init_context(AVIOContext *s,
                  unsigned char *buffer,
                  int buffer_size,
                  int write_flag,
                  void *opaque,
                  int (*read_packet)(void *opaque, uint8_t *buf, int buf_size),
                  int (*write_packet)(void *opaque, uint8_t *buf, int buf_size),
                  int64_t (*seek)(void *opaque, int64_t offset, int whence))
{
    return ffio_init_context(s, buffer, buffer_size, write_flag, opaque, read_packet, write_packet, seek);
}