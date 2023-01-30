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
TT_DUMMY_PROTOCOL(memorydatasource);

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
        } else if (strcmp(prot->name, "memorydatasource") == 0) {
            memcpy(&ff_memorydatasource_protocol, prot, protocol_size);
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

static tt_save_ip       ff_save_ip = NULL;
static tt_log_callback  ff_log_callback = NULL;
static tt_read_callback ff_io_read_callback = NULL;
static tt_info_callback ff_info_callback = NULL;

void tt_register_io_callback(tt_save_ip       save_ip, 
                             tt_log_callback  log_callback, 
                             tt_read_callback read_callback, 
                             tt_info_callback info_callback)
{
    ff_save_ip       = save_ip;
    ff_log_callback  = log_callback;
    ff_io_read_callback = read_callback;
    ff_info_callback = info_callback;
}

void tt_save_host_addr(intptr_t tt_opaque, const char* ip, int user_flag) {
    if (ff_save_ip != NULL) {
        ff_save_ip(tt_opaque, ip, user_flag);
    }
}

void tt_network_log_callback(intptr_t tt_opaque, int type, int user_flag) {
    if (ff_log_callback != NULL) {
        ff_log_callback(tt_opaque, type, user_flag);
    }
}

void tt_network_io_read_callback(intptr_t tt_opaque, int type, int size) {
    if (ff_io_read_callback != NULL && size > 0) {
        ff_io_read_callback(tt_opaque, type, size);
    }
}

void tt_network_info_callback(intptr_t tt_opaque, int key, int64_t value, const char* strValue) {
    if (ff_info_callback != NULL) {
        ff_info_callback(tt_opaque, key, value, strValue);
    }
}

void tt_make_absolute_url(char *buf, int size, const char *base,
                          const char *rel) {
    char *sep = NULL;
    char *path_query = NULL;
    char *tmp = NULL;
    /* Absolute path, relative to the current server */
    if (base && strstr(base, "://") && rel[0] == '/') {
        if (base != buf)
            av_strlcpy(buf, base, size);
        sep = strstr(buf, "://");
        if (sep) {
            /* Take scheme from base url */
            if (rel[1] == '/') {
                sep[1] = '\0';
            } else {
                /* Take scheme and host from base url */
                sep += 3;
                sep = strchr(sep, '/');
                if (sep)
                    *sep = '\0';
            }
        }
        av_strlcat(buf, rel, size);
        return;
    }
    /* If rel actually is an absolute url, just copy it */
    if (!base || strstr(rel, "://") || rel[0] == '/') {
        if (base) {
            tmp = strchr(base, '?');
        }
        av_strlcpy(buf, rel, size);
        if (tmp && !strchr(rel, '?')) {
            av_strlcat(buf, tmp, size);
        }
        return;
    }
    if (base != buf)
        av_strlcpy(buf, base, size);

    /* Strip off any query string from base */
    tmp = strchr(buf, '?');
    if (tmp) {
        path_query = av_mallocz(size);
        av_strlcpy(path_query, tmp, size);
        *tmp = '\0';
    }

    /* Is relative path just a new query part? */
    if (strchr(rel, '?')) {
        av_strlcat(buf, rel, size);
        if (path_query) {
            av_free(path_query);
        }
        return;
    }

    /* Remove the file name from the base url */
    sep = strrchr(buf, '/');
    if (sep)
        sep[1] = '\0';
    else
        buf[0] = '\0';
    while (av_strstart(rel, "../", NULL) && sep) {
        /* Remove the path delimiter at the end */
        sep[0] = '\0';
        sep = strrchr(buf, '/');
        /* If the next directory name to pop off is "..", break here */
        if (!strcmp(sep ? &sep[1] : buf, "..")) {
            /* Readd the slash we just removed */
            av_strlcat(buf, "/", size);
            break;
        }
        /* Cut off the directory name */
        if (sep)
            sep[1] = '\0';
        else
            buf[0] = '\0';
        rel += 3;
    }
    av_strlcat(buf, rel, size);
    if (path_query) {
        av_strlcat(buf, path_query, size);
        av_free(path_query);
    }
}