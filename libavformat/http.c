/*
 * HTTP protocol for ffmpeg client
 * Copyright (c) 2000, 2001 Fabrice Bellard
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

#include "config.h"

#if CONFIG_ZLIB
#include <zlib.h>
#endif /* CONFIG_ZLIB */

#include "libavutil/avassert.h"
#include "libavutil/avstring.h"
#include "libavutil/bprint.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"
#include "libavutil/parseutils.h"
#include "libavutil/thread.h"
#include "libavutil/mdl_info_wrapper.h"
#if HAVE_GETTIMEOFDAY
#include <sys/time.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_WINDOWS_H
#include <windows.h>
#endif
#include <strings.h>

#include "avformat.h"
#include "http.h"
#include "httpauth.h"
#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "url.h"

/* XXX: POST protocol is not completely implemented because ffmpeg uses
 * only a subset of it. */

/* The IO buffer size is unrelated to the max URL size in itself, but needs
 * to be large enough to fit the full request headers (including long
 * path names). */
#define BUFFER_SIZE   MAX_URL_SIZE
#define MAX_REDIRECTS 8
#define HTTP_SINGLE   1
#define HTTP_MUTLI    2
#define MAX_EXPIRY    19
#define WHITESPACES " \n\t\r"
#define HTTP_AUTO_RECONNECT 1
#define DUMP_BITSTREAM 0
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif


#define QUIC_REARGUARD 2

typedef enum {
    LOWER_PROTO,
    READ_HEADERS,
    WRITE_REPLY_HEADERS,
    FINISH
}HandshakeState;

typedef struct HTTPContext {
    const AVClass *class;
    URLContext *hd;
    aptr_t aptr;
    aptr_t gsc;
    aptr_t cbptr;
    char  host_ip[132];
    unsigned char buffer[BUFFER_SIZE], *buf_ptr, *buf_end;
    int line_count;
    int http_code;
    /* Used if "Transfer-Encoding: chunked" otherwise -1. */
    uint64_t chunksize;
    uint64_t off, end_off, filesize;
    char *location;
    HTTPAuthState auth_state;
    HTTPAuthState proxy_auth_state;
    char *http_proxy;
    char *headers;
    char *mime_type;
    char *user_agent;
#if FF_API_HTTP_USER_AGENT
    char *user_agent_deprecated;
#endif
    char *content_type;
    /* Set if the server correctly handles Connection: close and will close
     * the connection after feeding us the content. */
    int willclose;
    int seekable;           /**< Control seekability, 0 = disable, 1 = enable, -1 = probe. */
    int chunked_post;
    /* A flag which indicates if the end of chunked encoding has been sent. */
    int end_chunked_post;
    /* A flag which indicates we have finished to read POST reply. */
    int end_header;
    /* A flag which indicates if we use persistent connections. */
    int multiple_requests;
    uint8_t *post_data;
    int post_datalen;
    int is_akamai;
    int is_mediagateway;
    char *cookies;          ///< holds newline (\n) delimited Set-Cookie header field values (without the "Set-Cookie: " field name)
    /* A dictionary containing cookies keyed by cookie name */
    AVDictionary *cookie_dict;
    int icy;
    /* how much data was read since the last ICY metadata packet */
    uint64_t icy_data_read;
    /* after how many bytes of read data a new metadata packet will be found */
    uint64_t icy_metaint;
    char *icy_metadata_headers;
    char *icy_metadata_packet;
    AVDictionary *metadata;
#if CONFIG_ZLIB
    int compressed;
    z_stream inflate_stream;
    uint8_t *inflate_buffer;
#endif /* CONFIG_ZLIB */
    AVDictionary *chained_options;
    int send_expect_100;
    char *method;
    int reconnect;
    int reconnect_count;
    int reconnect_at_eof;
    int reconnect_streamed;
    int reconnect_delay;
    int reconnect_delay_max;
    int listen;
    char *resource;
    int reply_code;
    int is_multi_client;
    HandshakeState handshake_step;
    int is_connected_server;
    int is_redirect;
    int report_request_headers;
    int report_response_headers;
    char* valid_http_content_type;
    uint64_t recv_size;
    pthread_mutex_t mutex;
    pthread_cond_t   cond;
    int cond_waited;
#if DUMP_BITSTREAM
    FILE *file;
    int dump_bitstream;
#endif
    int user_flag;
    int r_cache_mode;
    int is_r_auto_range;
    int unlimit_header;
    uint64_t auto_range_offset;

    // for mdl info
#if !CONFIG_LITE
    char *mdl_file_key;
    char *mdl_load_traceid;
    int64_t mdl_load_handle;
    int mdl_format_type;
#endif
    int rearguard;
} HTTPContext;

#define OFFSET(x) offsetof(HTTPContext, x)
#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM
#define DEFAULT_USER_AGENT "ttplayer(default)" AV_STRINGIFY(LIBAVFORMAT_VERSION)

static const AVOption options[] = {
    { "seekable", "control seekability of connection", OFFSET(seekable), AV_OPT_TYPE_BOOL, { .i64 = -1 }, -1, 1, D },
    { "aptr", "set log handle for log", OFFSET(aptr), AV_OPT_TYPE_APTR, { .i64 = 0 }, APTR_MIN, APTR_MAX, .flags = D|E },
    { "gsc", "get socket pool", OFFSET(gsc), AV_OPT_TYPE_APTR, { .i64 = 0 }, APTR_MIN, APTR_MAX, .flags = D|E },
    { "cbptr", "app network callback ctx ptr", OFFSET(cbptr), AV_OPT_TYPE_APTR, { .i64 = 0 }, APTR_MIN, APTR_MAX, .flags = D|E },
    { "chunked_post", "use chunked transfer-encoding for posts", OFFSET(chunked_post), AV_OPT_TYPE_BOOL, { .i64 = 1 }, 0, 1, E },
    { "http_proxy", "set HTTP proxy to tunnel through", OFFSET(http_proxy), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "headers", "set custom HTTP headers, can override built in default headers", OFFSET(headers), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "content_type", "set a specific content type for the POST messages", OFFSET(content_type), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "user_agent", "override User-Agent header", OFFSET(user_agent), AV_OPT_TYPE_STRING, { .str = DEFAULT_USER_AGENT }, 0, 0, D },
#if FF_API_HTTP_USER_AGENT
    { "user-agent", "override User-Agent header", OFFSET(user_agent_deprecated), AV_OPT_TYPE_STRING, { .str = DEFAULT_USER_AGENT }, 0, 0, D },
#endif
    { "multiple_requests", "use persistent connections", OFFSET(multiple_requests), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D | E },
    { "post_data", "set custom HTTP post data", OFFSET(post_data), AV_OPT_TYPE_BINARY, .flags = D | E },
    { "mime_type", "export the MIME type", OFFSET(mime_type), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT | AV_OPT_FLAG_READONLY },
    { "cookies", "set cookies to be sent in applicable future requests, use newline delimited Set-Cookie HTTP field value syntax", OFFSET(cookies), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D },
    { "icy", "request ICY metadata", OFFSET(icy), AV_OPT_TYPE_BOOL, { .i64 = 1 }, 0, 1, D },
    { "icy_metadata_headers", "return ICY metadata headers", OFFSET(icy_metadata_headers), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT },
    { "icy_metadata_packet", "return current ICY metadata packet", OFFSET(icy_metadata_packet), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, AV_OPT_FLAG_EXPORT },
    { "metadata", "metadata read from the bitstream", OFFSET(metadata), AV_OPT_TYPE_DICT, {0}, 0, 0, AV_OPT_FLAG_EXPORT },
    { "auth_type", "HTTP authentication type", OFFSET(auth_state.auth_type), AV_OPT_TYPE_INT, { .i64 = HTTP_AUTH_NONE }, HTTP_AUTH_NONE, HTTP_AUTH_BASIC, D | E, "auth_type"},
    { "none", "No auth method set, autodetect", 0, AV_OPT_TYPE_CONST, { .i64 = HTTP_AUTH_NONE }, 0, 0, D | E, "auth_type"},
    { "basic", "HTTP basic authentication", 0, AV_OPT_TYPE_CONST, { .i64 = HTTP_AUTH_BASIC }, 0, 0, D | E, "auth_type"},
    { "send_expect_100", "Force sending an Expect: 100-continue header for POST", OFFSET(send_expect_100), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, E },
    { "location", "The actual location of the data received", OFFSET(location), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "offset", "initial byte offset", OFFSET(off), AV_OPT_TYPE_INT64, { .i64 = 0 }, 0, INT64_MAX, D },
    { "end_offset", "try to limit the request to bytes preceding this offset", OFFSET(end_off), AV_OPT_TYPE_INT64, { .i64 = 0 }, 0, INT64_MAX, D },
    { "method", "Override the HTTP method or set the expected HTTP method from a client", OFFSET(method), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "reconnect", "auto reconnect after disconnect before EOF", OFFSET(reconnect), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_at_eof", "auto reconnect at EOF", OFFSET(reconnect_at_eof), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_streamed", "auto reconnect streamed / non seekable streams", OFFSET(reconnect_streamed), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "reconnect_count", "reconnect count", OFFSET(reconnect_count), AV_OPT_TYPE_INT, { .i64 = 3 }, 0, 3, D },
    { "reconnect_delay_max", "max reconnect delay in seconds after which to give up", OFFSET(reconnect_delay_max), AV_OPT_TYPE_INT, { .i64 = 120 }, 0, UINT_MAX/1000/1000, D },
    { "listen", "listen on HTTP", OFFSET(listen), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, 2, D | E },
    { "resource", "The resource requested by a client", OFFSET(resource), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, E },
    { "reply_code", "The http status code to return to a client", OFFSET(reply_code), AV_OPT_TYPE_INT, { .i64 = 200}, INT_MIN, 599, E},
    { "valid_http_content_type", "valid http content type", OFFSET(valid_http_content_type), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D },
    { "is_redirect", "is auto redirect", OFFSET(is_redirect), AV_OPT_TYPE_BOOL, { .i64 = 1 }, 0, 1, D },
    { "report_request_headers", "report request headers", OFFSET(report_request_headers), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "report_response_headers", "report response headers", OFFSET(report_response_headers), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "user_flag", "user flag", OFFSET(user_flag), AV_OPT_TYPE_INT, { .i64 = 0 }, INT_MIN, INT_MAX, .flags = D|E },
#if DUMP_BITSTREAM
    { "dump_bitstream", "dump bitstream", OFFSET(dump_bitstream), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
#endif
    { "r_cache_mode", "read media loader cache mode", OFFSET(r_cache_mode), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, IsCacheThenNetworkNotCancelPreload, D },
    { "r_auto_range", "http range less than file size. auto new range read", OFFSET(is_r_auto_range), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "unlimit_header", "unlimit http header size", OFFSET(unlimit_header), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "auto_range_offset", "http range size while read auto range mode", OFFSET(auto_range_offset), AV_OPT_TYPE_INT64, { .i64 = 0 }, 0, 5 * 1024 * 1024, D },
#if !CONFIG_LITE
    { "mdl_file_key", "mdl file key", OFFSET(mdl_file_key), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "mdl_load_traceid", "mdl down load traceid", OFFSET(mdl_load_traceid), AV_OPT_TYPE_STRING, { .str = NULL }, 0, 0, D | E },
    { "mdl_load_handle", "initial byte offset", OFFSET(mdl_load_handle), AV_OPT_TYPE_INT64, { .i64 = 0 }, 0, INT64_MAX, D },
    { "mdl_format_type", "format type video or audio", OFFSET(mdl_format_type), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, INT32_MAX, D },
#endif
    { "rearguard", "ios player rearguard version", OFFSET(rearguard), AV_OPT_TYPE_INT, { .i64 = 0 }, 0, INT32_MAX, D},
    { NULL }
};

#if DUMP_BITSTREAM
static char stream_name[64] = {0};
static void get_stream_name(const char* url, char* stream_name) {
    if(url == NULL) {
        return;
    }
    int len = strlen(url);
    int end= -1;
    int start = -1;
    int tar_len = 7;
    for(int i = 0; i < len - tar_len; ++i) {
        if(strncmp(url+i, "stream-", tar_len) == 0) {
            start = i + tar_len;
            break;
        }
    }
    if(start == -1) {
        stream_name[0] = 0;
        return;
    }
    for(int i = start;i < len; ++i) {
        if(url[i] < '0'|| url[i] > '9') {
            end = i;
            break;
        }
    }
    if(end == -1) {
        stream_name[0] = 0;
        return;
    }
    for(int i=0;i<end-start;++i) {
        stream_name[i] = url[start + i];
    }
    stream_name[end-start]='\0';
}
#endif

static int http_connect(URLContext *h, const char *path, const char *local_path,
                        const char *hoststr, const char *auth,
                        const char *proxyauth, int *new_location);
static int http_read_header(URLContext *h, int *new_location);

static int has_header(const char *str, const char *header);

void ff_http_init_auth_state(URLContext *dest, const URLContext *src)
{
    memcpy(&((HTTPContext *)dest->priv_data)->auth_state,
           &((HTTPContext *)src->priv_data)->auth_state,
           sizeof(HTTPAuthState));
    memcpy(&((HTTPContext *)dest->priv_data)->proxy_auth_state,
           &((HTTPContext *)src->priv_data)->proxy_auth_state,
           sizeof(HTTPAuthState));
}
extern const char *tcp_get_ip_addr(URLContext *h);
static void http_save_tcp_hostname_of_ip(HTTPContext *s)
{
     const char *ip_str = NULL;

     if(s->hd == NULL) {
         return;
     }

     ip_str = tcp_get_ip_addr(s->hd);

     if(ip_str != NULL && ip_str[0] != '\0' && strlen(ip_str) <= sizeof(s->host_ip)) {
         memcpy(s->host_ip, ip_str, strlen(ip_str));
     }
     return;
}
static void http_callback_request(URLContext *h, NetworkOpt req, const char* url) {
    HTTPContext *s = h->priv_data;
    httpEvent_ctx ctx;
    if (req == IsRequestStart) {
        av_strlcpy(ctx.url, url, sizeof(ctx.url));
        ctx.off= s->off;
        ctx.end_off = s->end_off;
        av_log(h, AV_LOG_DEBUG,"url is: %s", ctx.url);
    }
    ff_inetwork_info_callback(s->cbptr, s->aptr, IsHTTPReqCallback, req, (char*)(&ctx));

}
static void http_callback_info(URLContext *h) {
#if !CONFIG_LITE
    HTTPContext *s = h->priv_data;
    struct MDLInfoContext info;
    if(s->mdl_file_key == NULL || s->mdl_load_traceid == NULL) {
        av_log(h, AV_LOG_DEBUG, "mdl info fkey or traceid null");
        return;
    }
    info.mdl_file_key = s->mdl_file_key;
    info.mdl_format_type = s->mdl_format_type;
    info.mdl_load_handle = s->mdl_load_handle;
    info.mdl_load_traceid = s->mdl_load_traceid;
    //for callback. notice,it is Shallow copy!
    av_log(h, AV_LOG_DEBUG, "start callback mdl info");
    ff_inetwork_info_callback(s->cbptr, s->aptr, IsMDLInfoCallBack, 0, (char*)(&info));
#endif
}

static int http_change_hostname(HTTPContext*s) {
    int host_len = 0;
    int new_header_len = 0;
    int new_host_len = 0;
    char* new_header = NULL;
    int host_position = 0;
    char hostname[256], hoststr[256+12];
    int port;
    int cur_len = 0;
    const char* begin = av_strnstr(s->headers, "Host: ", strlen(s->headers));
    if (begin == NULL) {
        return 0;
    }
    av_url_split_hostname(hostname, sizeof(hostname), &port, s->location);
    ff_url_join(hoststr, sizeof(hoststr), NULL, NULL, hostname, port, NULL);
    av_log(NULL, AV_LOG_DEBUG, "hostname %s",hostname);
    
    new_host_len = strlen(hoststr);
    host_position = begin - s->headers;
    const char* end = av_strnstr(begin, "\r\n", strlen(s->headers)-host_position);
    if (end != NULL) {
        host_len = end - begin + 2;
    } else {
        host_len = sizeof(s->headers) - host_position;
    }
    new_header_len = strlen(s->headers) - host_len + new_host_len + 8;
    new_header_len += 1;
    
    new_header = av_malloc(new_header_len);
    if(host_len != 0 && host_position != 0) {
        memcpy(new_header,s->headers,host_position);
        cur_len += host_position;
    }
    memcpy(new_header + cur_len, "Host: ", 6);
    cur_len += 6;
    memcpy(new_header + cur_len, hoststr, new_host_len);
    cur_len += new_host_len;
    memcpy(new_header + cur_len, "\r\n", 2);
    cur_len += 2;
    if (s->headers) {
        memcpy(new_header + cur_len, s->headers + host_position + host_len,  strlen(s->headers) - host_position - host_len);
        av_free(s->headers);
    }
    *(new_header + new_header_len - 1) = 0x0;
    av_log(NULL, AV_LOG_DEBUG, "new_header=%s", new_header);
    s->headers = new_header;
    return 0;
}

static int is_ipv4(char* host) {
    int len = strlen(host);

    if (len < 7 || len > 15)
        return 0;

    char tail[16];
    tail[0] = 0;
    unsigned int d[4];

    int c = sscanf(host, "%3u.%3u.%3u.%3u%s", &d[0], &d[1], &d[2], &d[3], tail);

    if (c != 4 || tail[0])
        return 0;
        
    for (int i = 0; i < 4; i++)
        if (d[i] > 255)
            return 0;

    return 1;
}

static int http_open_cnx_internal(URLContext *h, AVDictionary **options)
{
    const char *path, *proxy_path, *lower_proto = "tcp", *local_path;
    char hostname[1024], hoststr[1024], proto[10];
    char auth[1024], proxyauth[1024] = "";
    char path1[MAX_URL_SIZE];
    char buf[1024], urlbuf[MAX_URL_SIZE];
    int port, use_proxy, err, location_changed = 0;
    HTTPContext *s = h->priv_data;
    if(h->interrupt_callback.callback != NULL && ff_check_interrupt(&h->interrupt_callback)) {
        return AVERROR_EXIT;
    }
    av_url_split(proto, sizeof(proto), auth, sizeof(auth),
                 hostname, sizeof(hostname), &port,
                 path1, sizeof(path1), s->location);
    ff_url_join(hoststr, sizeof(hoststr), NULL, NULL, hostname, port, NULL);

    proxy_path = s->http_proxy ? s->http_proxy : getenv("http_proxy");
    use_proxy  = !ff_http_match_no_proxy(getenv("no_proxy"), hostname) &&
                 proxy_path && av_strstart(proxy_path, "http://", NULL);

    if (!strcmp(proto, "https")) {
        av_dict_set_int(options, "fastopen", 0, 0);
        lower_proto = "tls";
        use_proxy   = 0;
        if (port < 0)
            port = 443;
    } else if (!strcmp(proto, "httpq")) {
        lower_proto = (s->rearguard & QUIC_REARGUARD) ? "rearquic" : "quic";
        use_proxy   = 0;
        if (port < 0)
            port = 443;
    }

    if (s->headers) {
        char* pHeader = (char*)av_calloc(strlen(s->headers)+1, sizeof(char));
        if (pHeader) {
            strcpy(pHeader, s->headers);
            char* pFreeHeader = pHeader;
            char* pList[20] = {0};
            av_str_split(pHeader, "\r\n", 20, pList);
            for (int i=0; i<20; i++) {
                if (!pList[i]) {
                    break;
                }
                char* pKey[2] = {0};
                av_str_split(pList[i], ":", 2, pKey);
                if (pKey[1] == NULL) {
                    continue;
                }

                if (!strcasecmp(pKey[0], "suggest_protocol")){
                    const char* pbegin = pKey[1] + av_str_strip(pKey[1], ' ');
                    size_t index = av_str_strip_r(pbegin, ' ');
                    if (!strncasecmp("quic", pbegin, index)) {
                        av_log(h, AV_LOG_DEBUG, "use suggest_protocol: quic");
                        lower_proto = "quic";
                        use_proxy   = 0;
                        if (port < 0)
                            port = 80;
                    }
                }
                if (!strcasecmp(pKey[0], "Host")) {
                    const char* pbegin = pKey[1] + av_str_strip(pKey[1], ' ');
                    av_dict_set(options, "host_domain", pbegin, 0);
                    av_dict_set(options, "verifyhost", pbegin, 0);
                    av_log(h, AV_LOG_DEBUG, "use domain:%s", pbegin);
                }
            }
            av_free(pFreeHeader);
        } else {
            av_log(h, AV_LOG_ERROR, "http header copy fail, calloc is nullptr");
        }
    } else {
        av_log(h, AV_LOG_DEBUG, "http header is nullptr");
    }
    
    if (port < 0)
        port = 80;

    if (path1[0] == '\0')
        path = "/";
    else
        path = path1;
    local_path = path;
    if (use_proxy) {
        /* Reassemble the request URL without auth string - we don't
         * want to leak the auth to the proxy. */
        ff_url_join(urlbuf, sizeof(urlbuf), proto, NULL, hostname, port, "%s",
                    path1);
        path = urlbuf;
        av_url_split(NULL, 0, proxyauth, sizeof(proxyauth),
                     hostname, sizeof(hostname), &port, NULL, 0, proxy_path);
    }

    ff_url_join(buf, sizeof(buf), lower_proto, NULL, hostname, port, NULL);

    if (!s->hd) {
        err = ffurl_open_whitelist(&s->hd, buf, AVIO_FLAG_READ_WRITE,
                                   &h->interrupt_callback, options,
                                   h->protocol_whitelist, h->protocol_blacklist, h);
        if (err < 0)
            return err;
    }

    err = http_connect(h, path, local_path, hoststr,
                       auth, proxyauth, &location_changed);
    if (err < 0)
        return err;

    return location_changed;
}

static int http_split_str(const char** str, char splitChar, int* len) {
    const char* begin = *str;
    if (str != NULL && begin != NULL && *begin != 0x0) {
        while(*begin == splitChar) {
            begin++;
        }
        *str = begin;

        *len = 0;
        while (*begin != 0x0 && *begin != splitChar) {
            begin++;
            *len = (*len) + 1;
        }
        if (len > 0) {
            return 0;
        }
    }
    return -1;
}

static int http_get_context_type(const char* header, char* contentType, int bufferSize) {
    int err = 0;
    if (header == NULL || *header == 0x0) {
        return -1;
    }
    int i = 0;
    const size_t bufLen = strlen(header);
    for (i = 0; i<bufLen; i++) {
        const char* cur = header + i;
        if (*cur == 'C' || *cur == 'c') {
            if (strncasecmp("Content-Type:", cur, 13) == 0) {
                const int offset = 14;
                size_t len = strlen(cur);
                if (len > offset && len - offset < MAX_URL_SIZE) {
                    const char* begin = cur + offset;
                    char* dst = contentType;
                    int size = 0;
                    while (*begin != ' ' && *begin != ';' && size < bufferSize && size < MAX_URL_SIZE) {
                        *dst = *begin;
                        dst++;
                        begin++;
                        size++;
                    }
                    *dst = 0x0;
                }
                break;
            }
        }
    }
    return err;
}
static int http_check_content_type(HTTPContext*s) {
    int ret = 0;
    if (s->valid_http_content_type != NULL) {
        const char* str = s->valid_http_content_type;
        int len = 0;
        int find = 0;
        const int contentTypeMaxSize = 128;
        char contentType[128];
        if (http_get_context_type(s->buffer, contentType, contentTypeMaxSize) == 0) {
            int contentSize = strlen(contentType);
            while( http_split_str(&str, ' ', &len) == 0 ) {
                if (contentSize == len) {
                    if( strncasecmp(str, contentType, len) == 0 ) {
                        find = 1;
                        break;
                    }
                }
                str += len;
            }
            if (find == 0) {
                ret = AVERROR_CONTEXT_TYPE_IS_INVALID;
            }
        }
    }
    return ret;
}
/* return non zero if error */
static int http_open_cnx(URLContext *h, AVDictionary **options)
{
    HTTPAuthType cur_auth_type, cur_proxy_auth_type;
    HTTPContext *s = h->priv_data;
    int location_changed, attempts = 0, redirects = 0, ret = 0;
redo:
    av_dict_copy(options, s->chained_options, 0);

    cur_auth_type       = s->auth_state.auth_type;
    cur_proxy_auth_type = s->auth_state.auth_type;

    location_changed = http_open_cnx_internal(h, options);

    if (location_changed < 0) {
        goto fail;
    }

    attempts++;
    int status_code = s->http_code;
    if (status_code >= 200 && status_code < 300) {
        int ret = http_check_content_type(s);
        if (ret != 0) {
            goto fail;
        }
    }
    if (s->http_code == 401) {
        if ((cur_auth_type == HTTP_AUTH_NONE || s->auth_state.stale) &&
            s->auth_state.auth_type != HTTP_AUTH_NONE && attempts < 4) {
            ffurl_closep(&s->hd);
            goto redo;
        } else {
            goto fail;
        }
    }
    if (s->http_code == 407) {
        if ((cur_proxy_auth_type == HTTP_AUTH_NONE || s->proxy_auth_state.stale) &&
            s->proxy_auth_state.auth_type != HTTP_AUTH_NONE && attempts < 4) {
            ffurl_closep(&s->hd);
            goto redo;
        } else {
            goto fail;
        }
    }
    if ((s->http_code == 301 || s->http_code == 302 ||
         s->http_code == 303 || s->http_code == 307) &&
        location_changed == 1) {
        /* url moved, get next */
        if ( !s->is_redirect) {// redirect
            ret = AVERROR_HTTP_REDIRECT;
            goto fail;
        }

		ffurl_closep(&s->hd);
        if (redirects++ >= MAX_REDIRECTS){
            av_fatal(h, AVERROR_HTTP_REDIRECT_COUNT_OUT,"http error");
            return AVERROR(EIO);
        }
        /* Restart the authentication process with the new target, which
         * might use a different auth mechanism. */
        memset(&s->auth_state, 0, sizeof(s->auth_state));
        attempts         = 0;
        location_changed = 0;
        ff_inetwork_log_callback(s->cbptr, s->aptr, Is3xxHappen, s->user_flag);
        goto redo;
    }
    http_save_tcp_hostname_of_ip(s);
    http_callback_info(h);
    return 0;

fail:
    if (s->hd)
        ffurl_closep(&s->hd);
    if (location_changed < 0) {
        return location_changed;
    }
    if (ret != 0) {
        av_fatal(h, ret, s->buffer);
	    return ret;
    }
    ret = ff_http_averror(s->http_code, AVERROR(EIO));
	if ( ret == AVERROR(EIO) ) {
		av_fatal(h, AVERROR_HTTP_DEFAULT_ERROR, s->buffer);
	} else {
		av_fatal(h, ret, s->buffer);
	}
    return ret;
}

int ff_http_do_new_request(URLContext *h, const char *uri)
{
    HTTPContext *s = h->priv_data;
    AVDictionary *options = NULL;
    int ret;

    s->off           = 0;
    s->icy_data_read = 0;
    av_free(s->location);
    s->location = av_strdup(uri);
    if (!s->location){
        av_trace(h,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
        return AVERROR(ENOMEM);
    }

    ret = http_open_cnx(h, &options);
    av_dict_free(&options);
    return ret;
}

int ff_http_averror(int status_code, int default_averror)
{
    switch (status_code) {
        case 400: return AVERROR_HTTP_BAD_REQUEST;
        case 401: return AVERROR_HTTP_UNAUTHORIZED;
        case 403: return AVERROR_HTTP_FORBIDDEN;
        case 404: return AVERROR_HTTP_NOT_FOUND;
        default: break;
    }
    if (status_code >= 400 && status_code <= 499)
        return AVERROR_HTTP_OTHER_4XX;
    else if (status_code >= 500)
        return AVERROR_HTTP_SERVER_ERROR;
    else
        return default_averror;
}

static int http_write_reply(URLContext* h, int status_code)
{
    int ret, body = 0, reply_code, message_len;
    const char *reply_text, *content_type;
    HTTPContext *s = h->priv_data;
    char message[BUFFER_SIZE];
    content_type = "text/plain";

    if (status_code < 0)
        body = 1;
    switch (status_code) {
    case AVERROR_HTTP_BAD_REQUEST:
    case 400:
        reply_code = 400;
        reply_text = "Bad Request";
        break;
    case AVERROR_HTTP_FORBIDDEN:
    case 403:
        reply_code = 403;
        reply_text = "Forbidden";
        break;
    case AVERROR_HTTP_NOT_FOUND:
    case 404:
        reply_code = 404;
        reply_text = "Not Found";
        break;
    case 200:
        reply_code = 200;
        reply_text = "OK";
        content_type = s->content_type ? s->content_type : "application/octet-stream";
        break;
    case AVERROR_HTTP_SERVER_ERROR:
    case 500:
        reply_code = 500;
        reply_text = "Internal server error";
        break;
    default:
        av_trace(h,AVERROR(EINVAL),"AVERROR(EINVAL)");
        return AVERROR(EINVAL);
    }
    if (body) {
        s->chunked_post = 0;
        message_len = snprintf(message, sizeof(message),
                 "HTTP/1.1 %03d %s\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %"SIZE_SPECIFIER"\r\n"
                 "%s"
                 "\r\n"
                 "%03d %s\r\n",
                 reply_code,
                 reply_text,
                 content_type,
                 strlen(reply_text) + 6, // 3 digit status code + space + \r\n
                 s->headers ? s->headers : "",
                 reply_code,
                 reply_text);
    } else {
        s->chunked_post = 1;
        message_len = snprintf(message, sizeof(message),
                 "HTTP/1.1 %03d %s\r\n"
                 "Content-Type: %s\r\n"
                 "Transfer-Encoding: chunked\r\n"
                 "%s"
                 "\r\n",
                 reply_code,
                 reply_text,
                 content_type,
                 s->headers ? s->headers : "");
    }
    av_log(h, AV_LOG_TRACE, "HTTP reply header: \n%s----\n", message);
    if ((ret = ffurl_write(s->hd, message, message_len)) < 0)
        return ret;
    return 0;
}

static void handle_http_errors(URLContext *h, int error)
{
    av_assert0(error < 0);
    http_write_reply(h, error);
}

static int http_handshake(URLContext *c)
{
    int ret, err, new_location;
    HTTPContext *ch = c->priv_data;
    URLContext *cl = ch->hd;
    switch (ch->handshake_step) {
    case LOWER_PROTO:
        av_log(c, AV_LOG_TRACE, "Lower protocol\n");
        if ((ret = ffurl_handshake(cl)) > 0)
            return 2 + ret;
        if (ret < 0)
            return ret;
        ch->handshake_step = READ_HEADERS;
        ch->is_connected_server = 1;
        return 2;
    case READ_HEADERS:
        av_log(c, AV_LOG_TRACE, "Read headers\n");
        if ((err = http_read_header(c, &new_location)) < 0) {
            handle_http_errors(c, err);
            return err;
        }
        ch->handshake_step = WRITE_REPLY_HEADERS;
        return 1;
    case WRITE_REPLY_HEADERS:
        av_log(c, AV_LOG_TRACE, "Reply code: %d\n", ch->reply_code);
        if ((err = http_write_reply(c, ch->reply_code)) < 0)
            return err;
        ch->handshake_step = FINISH;
        return 1;
    case FINISH:
        return 0;
    }
    // this should never be reached.
    av_trace(ch,AVERROR(EINVAL),"AVERROR(EINVAL)");
    return AVERROR(EINVAL);
}

static int http_listen(URLContext *h, const char *uri, int flags,
                       AVDictionary **options) {
    HTTPContext *s = h->priv_data;
    int ret;
    char hostname[1024], proto[10];
    char lower_url[100];
    const char *lower_proto = "tcp";
    int port;
    av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname), &port,
                 NULL, 0, uri);
    if (!strcmp(proto, "https"))
        lower_proto = "tls";
    else if (!strcmp(proto, "httpq"))
        lower_proto = "quic";
    ff_url_join(lower_url, sizeof(lower_url), lower_proto, NULL, hostname, port,
                NULL);
    if ((ret = av_dict_set_int(options, "listen", s->listen, 0)) < 0){
		av_trace(s,ret,"ret:%d", ret);
        goto fail;
	}
    if ((ret = ffurl_open_whitelist(&s->hd, lower_url, AVIO_FLAG_READ_WRITE,
                                    &h->interrupt_callback, options,
                                    h->protocol_whitelist, h->protocol_blacklist, h
                                   )) < 0)
        goto fail;
    s->handshake_step = LOWER_PROTO;
    if (s->listen == HTTP_SINGLE) { /* single client */
        s->reply_code = 200;
        while ((ret = http_handshake(h)) > 0);
    }
fail:
    av_dict_free(&s->chained_options);
    return ret;
}

static int http_open(URLContext *h, const char *uri, int flags,
                     AVDictionary **options)
{
    HTTPContext *s = h->priv_data;
    ff_inetwork_log_callback(s->cbptr, s->aptr, IsHttpOpenStart, s->user_flag);
    int ret;
#if DUMP_BITSTREAM
    get_stream_name(uri, stream_name);
#endif
#if defined(__ANDROID__) || defined(__APPLE__)	
    pthread_mutex_init(&s->mutex ,NULL);
    pthread_cond_init(&s->cond,NULL);
    s->cond_waited = FALSE;
#endif
    if( s->seekable == 1 )
        h->is_streamed = 0;
    else
        h->is_streamed = 1;

    s->filesize = UINT64_MAX;
    s->location = av_strdup(uri);
    if (!s->location){
        av_trace(s,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
        return AVERROR(ENOMEM);
    }
    if (options)
        av_dict_copy(&s->chained_options, *options, 0);

    if (s->headers) {
        int len = strlen(s->headers);
        if (len < 2 || strcmp("\r\n", s->headers + len - 2)) {
            av_log(h, AV_LOG_WARNING,
                   "No trailing CRLF found in HTTP header.\n");
            ret = av_reallocp(&s->headers, len + 3);
            if (ret < 0){
                av_trace(s,ret,"ret:%d", ret);
                return ret;
            }
            s->headers[len]     = '\r';
            s->headers[len + 1] = '\n';
            s->headers[len + 2] = '\0';
        }
    }

    av_dict_set_int(options, "user_flag", s->user_flag, 0);
    if (s->listen) {
        return http_listen(h, uri, flags, options);
    }
    //add for auto range mode
    //WARNING: this will change offset & end_offset.
    if (s->is_r_auto_range && s->auto_range_offset > 0) {
        if (!s->off && !s->end_off) {
            s->end_off = s->auto_range_offset;
            av_log(h, AV_LOG_DEBUG, "use auto range init, %llx", s->end_off);
        } else {
            s->is_r_auto_range = 0;
            s->auto_range_offset = 0;
            av_log(h, AV_LOG_DEBUG, "disable auto range due to default range req: %llx, %llx", s->off, s->end_off);
        }
    }
    http_callback_request(h, IsRequestStart, uri);
    ret = http_open_cnx(h, options);
    if (ret < 0)
        av_dict_free(&s->chained_options);
    return ret;
}

static int http_accept(URLContext *s, URLContext **c)
{
    int ret;
    HTTPContext *sc = s->priv_data;
    HTTPContext *cc;
    URLContext *sl = sc->hd;
    URLContext *cl = NULL;

    av_assert0(sc->listen);
    if ((ret = ffurl_alloc(c, s->filename, s->flags, &sl->interrupt_callback)) < 0)
        goto fail;
    cc = (*c)->priv_data;
    if ((ret = ffurl_accept(sl, &cl)) < 0)
        goto fail;
    cc->hd = cl;
    cc->is_multi_client = 1;
fail:
    return ret;
}

static int http_getc(HTTPContext *s)
{
    int len;
    if (s->buf_ptr >= s->buf_end) {
        len = ffurl_read(s->hd, s->buffer, BUFFER_SIZE);
        if (len < 0) {
            return len;
        } else if (len == 0) {
            /*although the connection is closed ordely but the header not be read completely,return EIO error*/
            av_trace(s,AVERROR(EIO),"AVERROR(EIO)");
            return AVERROR(EIO);
        } else {
            s->recv_size += len;
            s->buf_ptr = s->buffer;
            s->buf_end = s->buffer + len;
        }
    }
    return *s->buf_ptr++;
}

static int http_get_line(HTTPContext *s, char *line, int line_size)
{
    int ch;
    char *q;

    q = line;
    for (;;) {
        ch = http_getc(s);
        if (ch < 0)
            return ch;
        if (ch == '\n') {
            /* process line */
            if (q > line && q[-1] == '\r')
                q--;
            *q = '\0';

            return 0;
        } else {
            if ((q - line) < line_size - 1)
                *q++ = ch;
        }
    }
}

static int check_http_code(URLContext *h, int http_code, const char *end)
{
    HTTPContext *s = h->priv_data;
    /* error codes are 4xx and 5xx, but regard 401 as a success, so we
     * don't abort until all headers have been parsed. */
    if (http_code >= 400 && http_code < 600 &&
        (http_code != 401 || s->auth_state.auth_type != HTTP_AUTH_NONE) &&
        (http_code != 407 || s->proxy_auth_state.auth_type != HTTP_AUTH_NONE)) {
        end += strspn(end, SPACE_CHARS);
        av_log(h, AV_LOG_WARNING, "HTTP error %d %s\n", http_code, end);
        av_trace(s,AVERROR(EIO),"AVERROR(EIO)");
        return ff_http_averror(http_code, AVERROR(EIO));
    }
    return 0;
}

static int parse_location(HTTPContext *s, const char *p)
{
    char redirected_location[MAX_URL_SIZE], *new_loc;
    ff_make_absolute_url(redirected_location, sizeof(redirected_location),
                         s->location, p);
    new_loc = av_strdup(redirected_location);
    if (!new_loc){
        av_trace(s,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
        return AVERROR(ENOMEM);
    }
    av_free(s->location);
    s->location = new_loc;
    
    if (s->headers != NULL && has_header(s->headers, "\r\nHost:")) {
        http_change_hostname(s);
    }
    return 0;
}

/* "bytes $from-$to/$document_size" */
static void parse_content_range(URLContext *h, const char *p)
{
    HTTPContext *s = h->priv_data;
    const char *slash;

    if (!strncmp(p, "bytes ", 6)) {
        p     += 6;
        s->off = strtoull(p, NULL, 10);
        if ((slash = strchr(p, '/')) && strlen(slash) > 0)
            s->filesize = strtoull(slash + 1, NULL, 10);
    }
    if (s->seekable == -1 && (!s->is_akamai || s->filesize != 2147483647))
        h->is_streamed = 0; /* we _can_ in fact seek */
}

static int parse_content_encoding(URLContext *h, const char *p)
{
    if (!av_strncasecmp(p, "gzip", 4) ||
        !av_strncasecmp(p, "deflate", 7)) {
#if CONFIG_ZLIB
        HTTPContext *s = h->priv_data;

        s->compressed = 1;
        inflateEnd(&s->inflate_stream);
        if (inflateInit2(&s->inflate_stream, 32 + 15) != Z_OK) {
            av_log(h, AV_LOG_WARNING, "Error during zlib initialisation: %s\n",
                   s->inflate_stream.msg);
            av_trace(s,AVERROR(ENOSYS),"AVERROR(ENOSYS)");
            return AVERROR(ENOSYS);
        }
        if (zlibCompileFlags() & (1 << 17)) {
            av_log(h, AV_LOG_WARNING,
                   "Your zlib was compiled without gzip support.\n");
            av_trace(s,AVERROR(ENOSYS),"AVERROR(ENOSYS)");
            return AVERROR(ENOSYS);
        }
#else
        av_log(h, AV_LOG_WARNING,
               "Compressed (%s) content, need zlib with gzip support\n", p);
        av_trace(h,AVERROR(ENOSYS),"AVERROR(ENOSYS)");
        return AVERROR(ENOSYS);
#endif /* CONFIG_ZLIB */
    } else if (!av_strncasecmp(p, "identity", 8)) {
        // The normal, no-encoding case (although servers shouldn't include
        // the header at all if this is the case).
    } else {
        av_log(h, AV_LOG_WARNING, "Unknown content coding: %s\n", p);
    }
    return 0;
}

// Concat all Icy- header lines
static int parse_icy(HTTPContext *s, const char *tag, const char *p)
{
    int len = 4 + strlen(p) + strlen(tag);
    int is_first = !s->icy_metadata_headers;
    int ret;

    av_dict_set(&s->metadata, tag, p, 0);

    if (s->icy_metadata_headers)
        len += strlen(s->icy_metadata_headers);

    if ((ret = av_reallocp(&s->icy_metadata_headers, len)) < 0)
        return ret;

    if (is_first)
        *s->icy_metadata_headers = '\0';

    av_strlcatf(s->icy_metadata_headers, len, "%s: %s\n", tag, p);

    return 0;
}

static int parse_set_cookie_expiry_time(const char *exp_str, struct tm *buf)
{
    char exp_buf[MAX_EXPIRY];
    int i, j, exp_buf_len = MAX_EXPIRY-1;
    char *expiry;

    // strip off any punctuation or whitespace
    for (i = 0, j = 0; exp_str[i] != '\0' && j < exp_buf_len; i++) {
        if ((exp_str[i] >= '0' && exp_str[i] <= '9') ||
            (exp_str[i] >= 'A' && exp_str[i] <= 'Z') ||
            (exp_str[i] >= 'a' && exp_str[i] <= 'z')) {
            exp_buf[j] = exp_str[i];
            j++;
        }
    }
    exp_buf[j] = '\0';
    expiry = exp_buf;

    // move the string beyond the day of week
    while ((*expiry < '0' || *expiry > '9') && *expiry != '\0')
        expiry++;

    return av_small_strptime(expiry, "%d%b%Y%H%M%S", buf) ? 0 : AVERROR(EINVAL);
}

static int parse_set_cookie(const char *set_cookie, AVDictionary **dict)
{
    char *param, *next_param, *cstr, *back;

    if (!(cstr = av_strdup(set_cookie)))
        return AVERROR(EINVAL);

    // strip any trailing whitespace
    back = &cstr[strlen(cstr)-1];
    while (strchr(WHITESPACES, *back)) {
        *back='\0';
        back--;
    }

    next_param = cstr;
    while ((param = av_strtok(next_param, ";", &next_param))) {
        char *name, *value;
        param += strspn(param, WHITESPACES);
        if ((name = av_strtok(param, "=", &value))) {
            if (av_dict_set(dict, name, value, 0) < 0) {
                av_free(cstr);
                return -1;
            }
        }
    }

    av_free(cstr);
    return 0;
}

static int parse_cookie(HTTPContext *s, const char *p, AVDictionary **cookies)
{
    AVDictionary *new_params = NULL;
    AVDictionaryEntry *e, *cookie_entry;
    char *eql, *name;

    // ensure the cookie is parsable
    if (parse_set_cookie(p, &new_params))
        return -1;

    // if there is no cookie value there is nothing to parse
    cookie_entry = av_dict_get(new_params, "", NULL, AV_DICT_IGNORE_SUFFIX);
    if (!cookie_entry || !cookie_entry->value) {
        av_dict_free(&new_params);
        return -1;
    }

    // ensure the cookie is not expired or older than an existing value
    if ((e = av_dict_get(new_params, "expires", NULL, 0)) && e->value) {
        struct tm new_tm = {0};
        if (!parse_set_cookie_expiry_time(e->value, &new_tm)) {
            AVDictionaryEntry *e2;

            // if the cookie has already expired ignore it
            if (av_timegm(&new_tm) < av_gettime() / 1000000) {
                av_dict_free(&new_params);
                return -1;
            }

            // only replace an older cookie with the same name
            e2 = av_dict_get(*cookies, cookie_entry->key, NULL, 0);
            if (e2 && e2->value) {
                AVDictionary *old_params = NULL;
                if (!parse_set_cookie(p, &old_params)) {
                    e2 = av_dict_get(old_params, "expires", NULL, 0);
                    if (e2 && e2->value) {
                        struct tm old_tm = {0};
                        if (!parse_set_cookie_expiry_time(e->value, &old_tm)) {
                            if (av_timegm(&new_tm) < av_timegm(&old_tm)) {
                                av_dict_free(&new_params);
                                av_dict_free(&old_params);
                                return -1;
                            }
                        }
                    }
                }
                av_dict_free(&old_params);
            }
        }
    }
    av_dict_free(&new_params);
    // duplicate the cookie name (dict will dupe the value)
    if (!(eql = strchr(p, '='))) {
	    av_trace(s,AVERROR(EINVAL),"AVERROR(EINVAL)"); 
		return AVERROR(EINVAL);
	}
    if (!(name = av_strndup(p, eql - p))) {
	    av_trace(s,AVERROR(ENOMEM),"AVERROR(ENOMEM)"); 
		return AVERROR(ENOMEM);
	}

    // add the cookie to the dictionary
    av_dict_set(cookies, name, eql, AV_DICT_DONT_STRDUP_KEY);

    return 0;
}

static int cookie_string(AVDictionary *dict, char **cookies)
{
    AVDictionaryEntry *e = NULL;
    int len = 1;

    // determine how much memory is needed for the cookies string
    while (e = av_dict_get(dict, "", e, AV_DICT_IGNORE_SUFFIX))
        len += strlen(e->key) + strlen(e->value) + 1;

    // reallocate the cookies
    e = NULL;
    if (*cookies) av_free(*cookies);
    *cookies = av_malloc(len);
    if (!*cookies) {
        av_trace(NULL,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
        return AVERROR(ENOMEM);
    }
    *cookies[0] = '\0';

    // write out the cookies
    while (e = av_dict_get(dict, "", e, AV_DICT_IGNORE_SUFFIX))
        av_strlcatf(*cookies, len, "%s%s\n", e->key, e->value);

    return 0;
}

static int process_line(URLContext *h, char *line, int line_count,
                        int *new_location)
{
    HTTPContext *s = h->priv_data;
    const char *auto_method =  h->flags & AVIO_FLAG_READ ? "POST" : "GET";
    char *tag, *p, *end, *method, *resource, *version;
    int ret;

    /* end of header */
    if (line[0] == '\0') {
        s->end_header = 1;
        return 0;
    }

    p = line;
    if (line_count == 0) {
        if (s->is_connected_server) {
            // HTTP method
            method = p;
            while (*p && !av_isspace(*p))
                p++;
            *(p++) = '\0';
            av_log(h, AV_LOG_TRACE, "Received method: %s\n", method);
            if (s->method) {
                if (av_strcasecmp(s->method, method)) {
                    av_log(h, AV_LOG_ERROR, "Received and expected HTTP method do not match. (%s expected, %s received)\n",
                           s->method, method);
                    return ff_http_averror(400, AVERROR(EIO));
                }
            } else {
                // use autodetected HTTP method to expect
                av_log(h, AV_LOG_TRACE, "Autodetected %s HTTP method\n", auto_method);
                if (av_strcasecmp(auto_method, method)) {
                    av_log(h, AV_LOG_ERROR, "Received and autodetected HTTP method did not match "
                           "(%s autodetected %s received)\n", auto_method, method);
                    return ff_http_averror(400, AVERROR(EIO));
                }
                if (!(s->method = av_strdup(method))){
                    av_trace(h,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
                    return AVERROR(ENOMEM);
                }
            }

            // HTTP resource
            while (av_isspace(*p))
                p++;
            resource = p;
            while (!av_isspace(*p))
                p++;
            *(p++) = '\0';
            av_log(h, AV_LOG_TRACE, "Requested resource: %s\n", resource);
            if (!(s->resource = av_strdup(resource))){
                av_trace(h,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
                return AVERROR(ENOMEM);
            }

            // HTTP version
            while (av_isspace(*p))
                p++;
            version = p;
            while (*p && !av_isspace(*p))
                p++;
            *p = '\0';
            if (av_strncasecmp(version, "HTTP/", 5)) {
                av_log(h, AV_LOG_ERROR, "Malformed HTTP version string.\n");
                return ff_http_averror(400, AVERROR(EIO));
            }
            av_log(h, AV_LOG_TRACE, "HTTP version string: %s\n", version);
        } else {
            while (!av_isspace(*p) && *p != '\0')
                p++;
            while (av_isspace(*p))
                p++;
            s->http_code = strtol(p, &end, 10);

            av_log(h, AV_LOG_TRACE, "http_code=%d\n", s->http_code);

            if ((ret = check_http_code(h, s->http_code, end)) < 0){
                av_trace(h,ret,"ret:%d",ret);
                return ret;
            }
        }
    } else {
        while (*p != '\0' && *p != ':')
            p++;
        if (*p != ':')
            return 1;

        *p  = '\0';
        tag = line;
        p++;
        while (av_isspace(*p))
            p++;
        if (!av_strcasecmp(tag, "Location")) {
            if ((ret = parse_location(s, p)) < 0){
                av_trace(h,ret,"ret:%d", ret);
                return ret;
            }
            *new_location = 1;
        } else if (!av_strcasecmp(tag, "Content-Length") &&
                   s->filesize == UINT64_MAX) {
            s->filesize = strtoull(p, NULL, 10);
        } else if (!av_strcasecmp(tag, "Content-Range")) {
            parse_content_range(h, p);
        } else if (!av_strcasecmp(tag, "Accept-Ranges") &&
                   !strncmp(p, "bytes", 5) &&
                   s->seekable == -1) {
            h->is_streamed = 0;
        } else if (!av_strcasecmp(tag, "Transfer-Encoding") &&
                   !av_strncasecmp(p, "chunked", 7)) {
            s->filesize  = UINT64_MAX;
            s->chunksize = 0;
#if !CONFIG_LITE
        } else if (!av_strcasecmp(tag, "WWW-Authenticate")) {
            ff_http_auth_handle_header(&s->auth_state, tag, p);
        } else if (!av_strcasecmp(tag, "Authentication-Info")) {
            ff_http_auth_handle_header(&s->auth_state, tag, p);
        } else if (!av_strcasecmp(tag, "Proxy-Authenticate")) {
            ff_http_auth_handle_header(&s->proxy_auth_state, tag, p);
#endif
        } else if (!av_strcasecmp(tag, "Connection")) {
            if (!strcmp(p, "close"))
                s->willclose = 1;
        } else if (!av_strcasecmp(tag, "Server")) {
            if (!av_strcasecmp(p, "AkamaiGHost")) {
                s->is_akamai = 1;
            } else if (!av_strncasecmp(p, "MediaGateway", 12)) {
                s->is_mediagateway = 1;
            }
        } else if (!av_strcasecmp(tag, "Content-Type")) {
            av_free(s->mime_type);
            s->mime_type = av_strdup(p);
        } else if (!av_strcasecmp(tag, "Set-Cookie")) {
            if (parse_cookie(s, p, &s->cookie_dict))
                av_log(h, AV_LOG_WARNING, "Unable to parse '%s'\n", p);
        } else if (!av_strcasecmp(tag, "Icy-MetaInt")) {
            s->icy_metaint = strtoull(p, NULL, 10);
        } else if (!av_strncasecmp(tag, "Icy-", 4)) {
            if ((ret = parse_icy(s, tag, p)) < 0){
                av_trace(h,ret,"ret:%d", ret);
                return ret;
            }
        } else if (!av_strcasecmp(tag, "Content-Encoding")) {
            if ((ret = parse_content_encoding(h, p)) < 0){
                av_trace(h,ret,"ret:%d", ret);
                return ret;
            }
#if !CONFIG_LITE
        } else if (!av_strcasecmp(tag, "X-Loader-Type")) {
            av_log(h, AV_LOG_TRACE, "X-Loader-Type:%s\n", p);
            ff_inetwork_info_callback(s->cbptr, s->aptr, IsLoaderType, 0, p);
        } else if (!av_strcasecmp(tag, "X-Conn-Info")) {
            av_log(h, AV_LOG_TRACE, "X-Conn-Info: %s\n", p);
            ff_inetwork_info_callback(s->cbptr, s->aptr, IsConnectionInfo, (int64_t)s->user_flag, p);
        } else if(!av_strcasecmp(tag, "X-Loader-FKey")) {
            av_freep(&s->mdl_file_key);
            s->mdl_file_key = (char *) av_mallocz(strlen(p) + 1);
            memcpy(s->mdl_file_key, p, strlen(p));
            av_log(h, AV_LOG_DEBUG, "receive mdl file key:%s", s->mdl_file_key);
        } else if(!av_strcasecmp(tag, "X-Loader-MDLInfoTraceId")) {
            av_freep(&s->mdl_load_traceid);
            s->mdl_load_traceid = (char *) av_mallocz(strlen(p) + 1);
            memcpy(s->mdl_load_traceid, p, strlen(p));
            av_log(h, AV_LOG_DEBUG, "receive mdl info tarceid:%s", s->mdl_load_traceid);
        } else if (!av_strcasecmp(tag, "X-Loader-MDLInfoLoadHandle")) {
            s->mdl_load_handle = strtoull(p, NULL, 10);
            av_log(h, AV_LOG_DEBUG, "receive mdl info load handle:%" PRId64"", s->mdl_load_handle);
        }
        else if (!av_strcasecmp(tag, "X-Loader-MDLInfoHandle")) {
            int64_t mdl_info_handle = strtoull(p, NULL, 10);
            if (mdl_info_handle != 0) {
                mdl_info_register_handle((void *) (intptr_t) mdl_info_handle);
                av_log(h, AV_LOG_DEBUG, "register mdl info handle:%"PRId64"", mdl_info_handle);
            }
        }
        else if (!av_strcasecmp(tag, "X-Loader-MDLFormatType")) {
            int mdl_format_type = strtoll(p, NULL, 10);
            av_log(h, AV_LOG_DEBUG, "mdl info format type:%d", mdl_format_type);
#endif
        }
    }
    return 1;
}

/**
 * Create a string containing cookie values for use as a HTTP cookie header
 * field value for a particular path and domain from the cookie values stored in
 * the HTTP protocol context. The cookie string is stored in *cookies.
 *
 * @return a negative value if an error condition occurred, 0 otherwise
 */
static int get_cookies(HTTPContext *s, char **cookies, const char *path,
                       const char *domain)
{
    // cookie strings will look like Set-Cookie header field values.  Multiple
    // Set-Cookie fields will result in multiple values delimited by a newline
    int ret = 0;
    char *cookie, *set_cookies = av_strdup(s->cookies), *next = set_cookies;

    if (!set_cookies) {
        av_trace(s,AVERROR(EINVAL),"AVERROR(EINVAL)");
        return AVERROR(EINVAL);
    }

    // destroy any cookies in the dictionary.
    av_dict_free(&s->cookie_dict);

    *cookies = NULL;
    while ((cookie = av_strtok(next, "\n", &next))) {
        AVDictionary *cookie_params = NULL;
        AVDictionaryEntry *cookie_entry, *e;

        // store the cookie in a dict in case it is updated in the response
        if (parse_cookie(s, cookie, &s->cookie_dict))
            av_log(s, AV_LOG_WARNING, "Unable to parse '%s'\n", cookie);

        // continue on to the next cookie if this one cannot be parsed
        if (parse_set_cookie(cookie, &cookie_params))
            continue;

        // if the cookie has no value, skip it
        cookie_entry = av_dict_get(cookie_params, "", NULL, AV_DICT_IGNORE_SUFFIX);
        if (!cookie_entry || !cookie_entry->value) {
            av_dict_free(&cookie_params);
            continue;
        }

        // if the cookie has expired, don't add it
        if ((e = av_dict_get(cookie_params, "expires", NULL, 0)) && e->value) {
            struct tm tm_buf = {0};
            if (!parse_set_cookie_expiry_time(e->value, &tm_buf)) {
                if (av_timegm(&tm_buf) < av_gettime() / 1000000) {
                    av_dict_free(&cookie_params);
                    continue;
                }
            }
        }

        // if no domain in the cookie assume it appied to this request
        if ((e = av_dict_get(cookie_params, "domain", NULL, 0)) && e->value) {
            // find the offset comparison is on the min domain (b.com, not a.b.com)
            int domain_offset = strlen(domain) - strlen(e->value);
            if (domain_offset < 0) {
                av_dict_free(&cookie_params);
                continue;
            }

            // match the cookie domain
            if (av_strcasecmp(&domain[domain_offset], e->value)) {
                av_dict_free(&cookie_params);
                continue;
            }
        }

        // ensure this cookie matches the path
        e = av_dict_get(cookie_params, "path", NULL, 0);
        if (!e || av_strncasecmp(path, e->value, strlen(e->value))) {
            av_dict_free(&cookie_params);
            continue;
        }

        // cookie parameters match, so copy the value
        if (!*cookies) {
            if (!(*cookies = av_asprintf("%s=%s", cookie_entry->key, cookie_entry->value))) {
                av_trace(s,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
                ret = AVERROR(ENOMEM);
                break;
            }
        } else {
            char *tmp = *cookies;
            size_t str_size = strlen(cookie_entry->key) + strlen(cookie_entry->value) + strlen(*cookies) + 4;
            if (!(*cookies = av_malloc(str_size))) {
                av_trace(s,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
                ret = AVERROR(ENOMEM);
                av_free(tmp);
                break;
            }
            snprintf(*cookies, str_size, "%s; %s=%s", tmp, cookie_entry->key, cookie_entry->value);
            av_free(tmp);
        }
    }

    av_free(set_cookies);

    return ret;
}

static inline int has_header(const char *str, const char *header)
{
    /* header + 2 to skip over CRLF prefix. (make sure you have one!) */
    if (!str)
        return 0;
    return av_stristart(str, header + 2, NULL) || av_stristr(str, header);
}

static int http_read_header(URLContext *h, int *new_location)
{
    HTTPContext *s = h->priv_data;
    char line[MAX_URL_SIZE];
    char headers[HTTP_HEADERS_SIZE] = "";
    int err = 0, len = 0;

    s->chunksize = UINT64_MAX;

    for (;;) {
        if ((err = http_get_line(s, line, sizeof(line))) < 0)
            return err;

        av_log(h, AV_LOG_TRACE, "header='%s'\n", line);
        if (s->report_response_headers) {
            len += av_strlcatf(headers + len, sizeof(headers) - len, "%s\r\n", line);
        }

        err = process_line(h, line, s->line_count, new_location);
        if (err < 0) {
            av_fatal(h, err, line);
            return err;
        }
        if (err == 0)
            break;
        s->line_count++;
    }

#if defined(__ANDROID__) || defined(__APPLE__)	
    ff_inetwork_info_callback(s->cbptr, s->aptr, IsGetResponseHeaders, 0, s->buffer);
#endif

    if (s->report_response_headers && len > 0) {
        av_fatal(h, 0, "response headers: %s\n", headers);
    }

    if (s->seekable == -1 && s->is_mediagateway && s->filesize == 2000000000)
        h->is_streamed = 1; /* we can in fact _not_ seek */

    // add any new cookies into the existing cookie string
    cookie_string(s->cookie_dict, &s->cookies);
    av_dict_free(&s->cookie_dict);

    return err;
}

static int http_connect(URLContext *h, const char *path, const char *local_path,
                        const char *hoststr, const char *auth,
                        const char *proxyauth, int *new_location)
{
    HTTPContext *s = h->priv_data;
    int post, err;
    AVBPrint pheader;
    char headers[HTTP_HEADERS_SIZE] = "";
    char *authstr = NULL, *proxyauthstr = NULL;
    uint64_t off = s->off;
	uint64_t filesize = s->filesize;
    int len = 0;
    const char *method;
    int send_expect_100 = 0;
    int ret;

    /* send http header */
    post = h->flags & AVIO_FLAG_WRITE;

    if (s->post_data) {
        /* force POST method and disable chunked encoding when
         * custom HTTP post data is set */
        post            = 1;
        s->chunked_post = 0;
    }

    if (s->method)
        method = s->method;
    else
        method = post ? "POST" : "GET";

#if !CONFIG_LITE
    authstr      = ff_http_auth_create_response(&s->auth_state, auth,
                                                local_path, method);
    proxyauthstr = ff_http_auth_create_response(&s->proxy_auth_state, proxyauth,
                                                local_path, method);
#endif
    if (post && !s->post_data) {
        send_expect_100 = s->send_expect_100;
        /* The user has supplied authentication but we don't know the auth type,
         * send Expect: 100-continue to get the 401 response including the
         * WWW-Authenticate header, or an 100 continue if no auth actually
         * is needed. */
        if (auth && *auth &&
            s->auth_state.auth_type == HTTP_AUTH_NONE &&
            s->http_code != 401)
            send_expect_100 = 1;
    }
    if (s->unlimit_header) {
        av_bprint_init(&pheader, HTTP_HEADERS_SIZE, AV_BPRINT_SIZE_UNLIMITED);
        av_bprintf(&pheader, "%s ", method);
        av_bprintf(&pheader, "%s ", path);
        av_bprintf(&pheader, "HTTP/1.1\r\n");

        if (post && s->chunked_post) {
            av_bprintf(&pheader, "Transfer-Encoding: chunked\r\n");
        }
    }



#if FF_API_HTTP_USER_AGENT
    if (strcmp(s->user_agent_deprecated, DEFAULT_USER_AGENT)) {
        av_log(s, AV_LOG_WARNING, "the user-agent option is deprecated, please use user_agent option\n");
        s->user_agent = av_strdup(s->user_agent_deprecated);
    }
#endif
    /* set default headers if needed */
    if (!has_header(s->headers, "\r\nUser-Agent: ")) {
        if (s->unlimit_header) {
            av_bprintf(&pheader, "User-Agent: %s\r\n", s->user_agent);
        } else {
            len += av_strlcatf(headers + len, sizeof(headers) - len,
                           "User-Agent: %s\r\n", s->user_agent);
        }
    }
    if (!has_header(s->headers, "\r\nAccept: ")) {
        if (s->unlimit_header) {
            av_bprintf(&pheader, "Accept: */*\r\n");
        } else {
            len += av_strlcpy(headers + len, "Accept: */*\r\n",
                          sizeof(headers) - len);
        }
    }
    // Note: we send this on purpose even when s->off is 0 when we're probing,
    // since it allows us to detect more reliably if a (non-conforming)
    // server supports seeking by analysing the reply headers.
    if (!has_header(s->headers, "\r\nRange: ") && !post && (s->off > 0 || s->end_off || s->seekable == -1)) {
        av_log(h, AV_LOG_DEBUG,"request off: %llx, end_off: %llx, a_r_o : %llx", s->off, s->end_off, s->auto_range_offset);
        if (s->unlimit_header) {
            av_bprintf(&pheader, "Range: bytes=%"PRIu64"-", s->off);
            if (s->end_off) 
                av_bprintf(&pheader, "%"PRId64, s->end_off - 1);
            av_bprintf(&pheader, "\r\n");
        } else {
            len += av_strlcatf(headers + len, sizeof(headers) - len,
                            "Range: bytes=%"PRIu64"-", s->off);
            if (s->end_off)
                len += av_strlcatf(headers + len, sizeof(headers) - len,
                                "%"PRId64, s->end_off - 1);
            len += av_strlcpy(headers + len, "\r\n",
                            sizeof(headers) - len);
        }
    }
    if (send_expect_100 && !has_header(s->headers, "\r\nExpect: ")) {
        if (s->unlimit_header) {
            av_bprintf(&pheader, "Expect: 100-continue\r\n");
        } else {
            len += av_strlcatf(headers + len, sizeof(headers) - len,
                           "Expect: 100-continue\r\n");
        }
    }

    if (!has_header(s->headers, "\r\nConnection: ")) {
        if (s->unlimit_header) {
            if (s->multiple_requests)
                av_bprintf(&pheader, "Connection: keep-alive\r\n");
            else
                av_bprintf(&pheader, "Connection: close\r\n");
        } else {
            if (s->multiple_requests)
                len += av_strlcpy(headers + len, "Connection: keep-alive\r\n",
                                sizeof(headers) - len);
            else
                len += av_strlcpy(headers + len, "Connection: close\r\n",
                                sizeof(headers) - len);
        }
    }

    if (!has_header(s->headers, "\r\nHost: ")) {
        if (s->unlimit_header) {
            av_bprintf(&pheader, "Host: %s\r\n", hoststr);
        } else {
            len += av_strlcatf(headers + len, sizeof(headers) - len,
                           "Host: %s\r\n", hoststr);
        }
    }
    if (!has_header(s->headers, "\r\nContent-Length: ") && s->post_data) {
        if (s->unlimit_header) {
            av_bprintf(&pheader, "Content-Length: %d\r\n", s->post_datalen);
        } else {
            len += av_strlcatf(headers + len, sizeof(headers) - len,
                           "Content-Length: %d\r\n", s->post_datalen);
        }
    }

    if (!has_header(s->headers, "\r\nContent-Type: ") && s->content_type) {
        if (s->unlimit_header) {
            av_bprintf(&pheader, "Content-Type: %s\r\n", s->content_type);
        } else {
            len += av_strlcatf(headers + len, sizeof(headers) - len,
                           "Content-Type: %s\r\n", s->content_type);
        }
    }
    if (!has_header(s->headers, "\r\nCookie: ") && s->cookies) {
        char *cookies = NULL;
        if (!get_cookies(s, &cookies, path, hoststr) && cookies) {
            if (s->unlimit_header) {
                av_bprintf(&pheader, "Cookie: %s\r\n", cookies);
            } else {
                len += av_strlcatf(headers + len, sizeof(headers) - len,
                               "Cookie: %s\r\n", cookies);
            }
            av_free(cookies);
        }
    }
    if (!has_header(s->headers, "\r\nIcy-MetaData: ") && s->icy) {
        if (s->unlimit_header) {
            av_bprintf(&pheader, "Icy-MetaData: %d\r\n", 1);
        } else {
            len += av_strlcatf(headers + len, sizeof(headers) - len,
                           "Icy-MetaData: %d\r\n", 1);
        }
    }

    av_log(h, AV_LOG_DEBUG,"read from cache: %d", s->r_cache_mode);
    //custom opt
    if (!has_header(s->headers, "\r\nX-MDL-ReadSource: ") && s->r_cache_mode >= IsCacheOnlyNotCancelPreload) {
        if (s->unlimit_header) {
            av_bprintf(&pheader, "X-MDL-ReadSource: %s\r\n", s->r_cache_mode == IsCacheOnlyNotCancelPreload ? "cache" : "cache_net");
        } else {
            len += av_strlcatf(headers + len, sizeof(headers) - len,
                           "X-MDL-ReadSource: %s\r\n", s->r_cache_mode == IsCacheOnlyNotCancelPreload ? "cache" : "cache_net");
        }
    }

    /* now add in custom headers */
    if (s->unlimit_header) {
        if (s->headers)
            av_bprint_append_data(&pheader, s->headers, strlen(s->headers));
        if (authstr)
            av_bprintf(&pheader, "%s", authstr);
        if (proxyauthstr)
            av_bprintf(&pheader, "Proxy-%s", proxyauthstr);
        av_bprintf(&pheader, "\r\n");

        if (av_bprint_is_complete(&pheader)) {
            err = ffurl_write(s->hd, pheader.str, pheader.len);
        } else {
            err = AVERROR(EINVAL);
        }
        av_bprint_finalize(&pheader, NULL);
        if (err < 0)
            goto done;
    } else {
        if (s->headers) {
            av_strlcpy(headers + len, s->headers, sizeof(headers) - len);
        }

        ret = snprintf(s->buffer, sizeof(s->buffer),
                "%s %s HTTP/1.1\r\n"
                "%s"
                "%s"
                "%s"
                "%s%s"
                "\r\n",
                method,
                path,
                post && s->chunked_post ? "Transfer-Encoding: chunked\r\n" : "",
                headers,
                authstr ? authstr : "",
                proxyauthstr ? "Proxy-" : "", proxyauthstr ? proxyauthstr : "");

        av_log(h, AV_LOG_DEBUG, "request: %s\n", s->buffer);

        if (strlen(headers) + 1 == sizeof(headers) ||
            ret >= sizeof(s->buffer)) {
            av_log(h, AV_LOG_ERROR, "overlong headers\n");
            err = AVERROR(EINVAL);
            goto done;
        }
        
        if (s->report_request_headers && len > 0) {
            av_fatal(h, 0, "request headers: %s\n", headers);
        }

        if ((err = ffurl_write(s->hd, s->buffer, strlen(s->buffer))) < 0)
            goto done;
    }

    if (s->post_data)
        if ((err = ffurl_write(s->hd, s->post_data, s->post_datalen)) < 0)
            goto done;

    ff_inetwork_log_callback(s->cbptr, s->aptr, IsHttpRepuestFinish, s->user_flag);
    /* init input buffer */
    s->buf_ptr          = s->buffer;
    s->buf_end          = s->buffer;
    s->line_count       = 0;
    s->off              = 0;
    s->icy_data_read    = 0;
    s->filesize         = UINT64_MAX;
    s->willclose        = 0;
    s->end_chunked_post = 0;
    s->end_header       = 0;
    if (post && !s->post_data && !send_expect_100) {
        /* Pretend that it did work. We didn't read any header yet, since
         * we've still to send the POST data, but the code calling this
         * function will check http_code after we return. */
        s->http_code = 200;
        err = 0;
        goto done;
    }

    /* wait for header */
    err = http_read_header(h, new_location);
    if (err < 0)
        goto done;

    ff_inetwork_log_callback(s->cbptr, s->aptr, IsHttpResponseFinish, s->user_flag);

    if (*new_location)
        s->off = off;

    /* Some buggy servers may missing 'Content-Range' header for range request */
    if (off > 0 && s->off <= 0 && (off + s->filesize == filesize)) {
        av_log(NULL, AV_LOG_WARNING,
               "try to fix missing 'Content-Range' at server side (%"PRId64",%"PRId64") => (%"PRId64",%"PRId64")",
               s->off, s->filesize, off, filesize);
        s->off = off;
        s->filesize = filesize;
    }

    err = (off == s->off) ? 0 : -1;
done:
    av_freep(&authstr);
    av_freep(&proxyauthstr);
    return err;
}

static int http_buf_read(URLContext *h, uint8_t *buf, int size)
{
    HTTPContext *s = h->priv_data;
    int len;

    if (s->chunksize != UINT64_MAX) {
        if (!s->chunksize) {
            char line[32];
            int err;

            do {
                if ((err = http_get_line(s, line, sizeof(line))) < 0)
                    return err;
            } while (!*line);    /* skip CR LF from last chunk */

            s->chunksize = strtoull(line, NULL, 16);

            av_log(h, AV_LOG_TRACE,
                   "Chunked encoding data size: %"PRIu64"'\n",
                    s->chunksize);

            if (!s->chunksize)
                return 0;
            else if (s->chunksize == UINT64_MAX) {
                av_log(h, AV_LOG_ERROR, "Invalid chunk size %"PRIu64"\n",
                       s->chunksize);
                return AVERROR(EINVAL);
            }
        }
        size = FFMIN(size, s->chunksize);
    }

    /* read bytes from input buffer first */
    len = s->buf_end - s->buf_ptr;
    if (len > 0) {
        if (len > size)
            len = size;
        memcpy(buf, s->buf_ptr, len);
        s->buf_ptr += len;
    } else {
        uint64_t target_end = (s->end_off > 0 && s->end_off < s->filesize) ? s->end_off : s->filesize;
        if ((!s->willclose || s->chunksize == UINT64_MAX) && s->off >= target_end)
            return AVERROR_EOF;

        len = size;
        if (target_end > 0 && target_end != UINT64_MAX && target_end != 2147483647) {
            int64_t unread = target_end - s->off;
            if (len > unread)
                len = (int)unread;
        }
        if (len > 0)
            len = ffurl_read(s->hd, buf, len);
        if (!len && (!s->willclose || s->chunksize == UINT64_MAX) && s->off < target_end) {
            av_log(h, AV_LOG_ERROR,
                   "Stream ends prematurely at %"PRIu64", should be %"PRIu64"\n",
                   s->off, target_end
                  );
            av_trace(h,AVERROR(EIO),"AVERROR(EIO)");
            return AVERROR(EIO);
        }
    }
    if (len > 0) {
	    s->recv_size += len;
        s->off += len;
        if (s->chunksize > 0 && s->chunksize != UINT64_MAX) {
            av_assert0(s->chunksize >= len);
            s->chunksize -= len;
        }
    }
    return len;
}

#if CONFIG_ZLIB
#define DECOMPRESS_BUF_SIZE (256 * 1024)
static int http_buf_read_compressed(URLContext *h, uint8_t *buf, int size)
{
    HTTPContext *s = h->priv_data;
    int ret;

    if (!s->inflate_buffer) {
        s->inflate_buffer = av_malloc(DECOMPRESS_BUF_SIZE);
        if (!s->inflate_buffer) {
            av_trace(h,AVERROR(ENOMEM),"AVERROR(ENOMEM)");
            return AVERROR(ENOMEM);
        }
    }

    if (s->inflate_stream.avail_in == 0) {
        int read = http_buf_read(h, s->inflate_buffer, DECOMPRESS_BUF_SIZE);
        if (read <= 0)
            return read;
        s->inflate_stream.next_in  = s->inflate_buffer;
        s->inflate_stream.avail_in = read;
    }

    s->inflate_stream.avail_out = size;
    s->inflate_stream.next_out  = buf;

    ret = inflate(&s->inflate_stream, Z_SYNC_FLUSH);
    if (ret != Z_OK && ret != Z_STREAM_END)
        av_log(h, AV_LOG_WARNING, "inflate return value: %d, %s\n",
               ret, s->inflate_stream.msg);

    return size - s->inflate_stream.avail_out;
}
#endif /* CONFIG_ZLIB */

static int64_t http_seek_internal(URLContext *h, int64_t off, int whence, int force_reconnect);

static int http_read_stream(URLContext *h, uint8_t *buf, int size)
{
    HTTPContext *s = h->priv_data;
    int err, new_location, read_ret;
    int64_t seek_ret;
    uint64_t target_end = (s->end_off > 0 && s->end_off < s->filesize) ? s->end_off : s->filesize;

    if (!s->hd){
        return AVERROR_EOF;
    }

    if (s->end_chunked_post && !s->end_header) {
        err = http_read_header(h, &new_location);
        if (err < 0){
            av_trace(h,err,"err:%d", err);
            return err;
        }
    }

#if CONFIG_ZLIB
    if (s->compressed)
        return http_buf_read_compressed(h, buf, size);
#endif /* CONFIG_ZLIB */
    read_ret = http_buf_read(h, buf, size);
    //callback range finish
    if (s->end_off > 0 && s->off == s->end_off
        && s->end_off != s->filesize) {
        http_callback_request(h, IsRequestFinish, NULL);
    }
    //add for auto range req
    if (read_ret == AVERROR_EOF && s->auto_range_offset > 0 && s->off == s->end_off && s->end_off != s->filesize) {
        if (!s->is_r_auto_range) {
            av_log(h, AV_LOG_DEBUG,"auto range read be closed");
            s->auto_range_offset = 0;
        }
        av_log(h, AV_LOG_DEBUG,"auto range read eof, %llx, %llx, %llx", s->off, s->end_off, s->filesize);
        s->off = s->end_off;
        uint64_t nextRange = s->auto_range_offset > 0 ? s->end_off + s->auto_range_offset : s->filesize;
        s->end_off = nextRange >= s->filesize ? 0 : nextRange;
        target_end = nextRange;
        av_log(h, AV_LOG_DEBUG,"auto range read eof change: %llx, %llx, %llx", s->off, s->end_off, s->filesize);
    }
    if (   (read_ret  < 0 && s->reconnect  && read_ret != AVERROR_EXIT && (!h->is_streamed || s->reconnect_streamed) && target_end > 0 && s->off < target_end)
        || (read_ret == 0 && s->reconnect_at_eof && (!h->is_streamed || s->reconnect_streamed))) {
        uint64_t target = h->is_streamed ? 0 : s->off;
#if !defined(HTTP_AUTO_RECONNECT)
        int interrupt = 0;
        if (s->reconnect_delay > s->reconnect_delay_max){
            av_trace(h,AVERROR(EIO),"AVERRR(EIO)");
            return AVERROR(EIO);
        }
#endif
        av_log(h, AV_LOG_INFO, "Will reconnect at %"PRIu64" error=%s., read_ret = %d\n", s->off, av_err2str(read_ret), read_ret);
#if defined(HTTP_AUTO_RECONNECT)
        seek_ret = http_seek_internal(h, target, SEEK_SET, 1);
#else
        if(h->interrupt_callback.callback!= NULL) {
            int64_t timeout = 1000U*1000*s->reconnect_delay;
            while(timeout > 0  && !h->interrupt_callback.callback(h->interrupt_callback.opaque) ) {
                av_usleep(1000);
                timeout -= 1000;
            }
            interrupt = h->interrupt_callback.callback(h->interrupt_callback.opaque);
        } else {
       	    av_usleep(1000U*1000*s->reconnect_delay);
        }
        if(interrupt) {
            return AVERROR_EXIT;
        }
        s->reconnect_delay = 1 + 2*s->reconnect_delay;
        
        seek_ret = http_seek_internal(h, target, SEEK_SET, 1);
#endif
        if (seek_ret != target) {
            av_log(h, AV_LOG_ERROR, "Failed to reconnect at %"PRIu64".\n", target);
            return read_ret;
        }
        read_ret = http_buf_read(h, buf, size);
    } else {
#if !defined(HTTP_AUTO_RECONNECT)
         s->reconnect_delay = 0;
#endif
    }

    return read_ret;
}

// Like http_read_stream(), but no short reads.
// Assumes partial reads are an error.
static int http_read_stream_all(URLContext *h, uint8_t *buf, int size)
{
    int pos = 0;
    while (pos < size) {
        int len = http_read_stream(h, buf + pos, size - pos);
        if (len < 0)
            return len;
        pos += len;
    }
    return pos;
}

static void update_metadata(HTTPContext *s, char *data)
{
    char *key;
    char *val;
    char *end;
    char *next = data;

    while (*next) {
        key = next;
        val = strstr(key, "='");
        if (!val)
            break;
        end = strstr(val, "';");
        if (!end)
            break;

        *val = '\0';
        *end = '\0';
        val += 2;

        av_dict_set(&s->metadata, key, val, 0);

        next = end + 2;
    }
}

static int store_icy(URLContext *h, int size)
{
    HTTPContext *s = h->priv_data;
    /* until next metadata packet */
    uint64_t remaining;

    if (s->icy_metaint < s->icy_data_read) {
	    av_trace(h,AVERROR_INVALIDDATA,"AVERROR_INVALIDDATA");
        return AVERROR_INVALIDDATA;
	}
    remaining = s->icy_metaint - s->icy_data_read;

    if (!remaining) {
        /* The metadata packet is variable sized. It has a 1 byte header
         * which sets the length of the packet (divided by 16). If it's 0,
         * the metadata doesn't change. After the packet, icy_metaint bytes
         * of normal data follows. */
        uint8_t ch;
        int len = http_read_stream_all(h, &ch, 1);
        if (len < 0)
            return len;
        if (ch > 0) {
            char data[255 * 16 + 1];
            int ret;
            len = ch * 16;
            ret = http_read_stream_all(h, data, len);
            if (ret < 0)
                return ret;
            data[len + 1] = 0;
            if ((ret = av_opt_set(s, "icy_metadata_packet", data, 0)) < 0)
                return ret;
            update_metadata(s, data);
        }
        s->icy_data_read = 0;
        remaining        = s->icy_metaint;
    }

    return FFMIN(size, remaining);
}

static int http_read(URLContext *h, uint8_t *buf, int size)
{
    HTTPContext *s = h->priv_data;

    if (s->icy_metaint > 0) {
        size = store_icy(h, size);
        if (size < 0)
            return size;
    }

    size = http_read_stream(h, buf, size);

    if (size > 0) {
        s->icy_data_read += size;
#if DUMP_BITSTREAM
        if (s->dump_bitstream && !s->file) {
            static int read_count = 0;
            char fpath[256] = {"/mnt/sdcard/dump_stream"};
            mkdir(fpath, S_IRWXU|S_IRWXG|S_IRWXO);
            strcat(fpath,"/");
            if(stream_name[0] != 0) {
                strcat(fpath,stream_name);
            } else {
                strcat(fpath,"no_stream_name");
            }
            mkdir(fpath, S_IRWXU|S_IRWXG|S_IRWXO);
            int path_len = strlen(fpath);
            sprintf(fpath+path_len,"/%04d",read_count);
            s->file = fopen(fpath, "wb");
            ++read_count;
            if(s->file!=NULL) {
                av_log(s, AV_LOG_VERBOSE, "open %s offset:%"PRId64"\n",fpath, s->off - size);
            } else {
                av_log(s,AV_LOG_INFO,"open %s filed",fpath);
            }
        }
        if (s->file) {
            // av_log(s, AV_LOG_VERBOSE, "read offset:%"PRId64" size:%d\n", s->off - size, size);
            fwrite(buf, 1, size, s->file);
        }
#endif
    }
    return size;
}

/* used only when posting data */
static int http_write(URLContext *h, const uint8_t *buf, int size)
{
    char temp[11] = "";  /* 32-bit hex + CRLF + nul */
    int ret;
    char crlf[] = "\r\n";
    HTTPContext *s = h->priv_data;

    if (!s->chunked_post) {
        /* non-chunked data is sent without any special encoding */
        return ffurl_write(s->hd, buf, size);
    }

    /* silently ignore zero-size data since chunk encoding that would
     * signal EOF */
    if (size > 0) {
        /* upload data using chunked encoding */
        snprintf(temp, sizeof(temp), "%x\r\n", size);

        if ((ret = ffurl_write(s->hd, temp, strlen(temp))) < 0 ||
            (ret = ffurl_write(s->hd, buf, size)) < 0          ||
            (ret = ffurl_write(s->hd, crlf, sizeof(crlf) - 1)) < 0)
            return ret;
    }
    return size;
}

static int http_shutdown(URLContext *h, int flags)
{
    int ret = 0;
    HTTPContext *s = h->priv_data;
    if(flags & AVIO_FLAG_STOP) {
#if defined(__ANDROID__) || defined(__APPLE__)	
	   if(pthread_mutex_trylock(&s->mutex) == 0) {
		if(s->cond_waited) {
		   pthread_cond_signal(&s->cond);
	   	}
		pthread_mutex_unlock(&s->mutex);
	}
#if defined(__APPLE__)
    if(s->hd != NULL && s->hd->prot->url_shutdown != NULL){
        s->hd->prot->url_shutdown(s->hd,flags);
    }
#endif
#endif
	    return 0;
    }
    /* signal end of chunked encoding if used */
    if (((flags & AVIO_FLAG_WRITE) && s->chunked_post) ||
        ((flags & AVIO_FLAG_READ) && s->chunked_post && s->listen)) {
        char footer[] = "0\r\n\r\n";
        ret = ffurl_write(s->hd, footer, sizeof(footer) - 1);
        ret = ret > 0 ? 0 : ret;
        s->end_chunked_post = 1;
    }

    return ret;
}

static int http_close(URLContext *h)
{
    int ret = 0;
    HTTPContext *s = h->priv_data;

#if !CONFIG_LITE
    av_freep(&s->mdl_file_key);
    av_freep(&s->mdl_load_traceid);
#endif
#if CONFIG_ZLIB
    inflateEnd(&s->inflate_stream);
    av_freep(&s->inflate_buffer);
#endif /* CONFIG_ZLIB */

    if (!s->end_chunked_post)
        /* Close the write direction by sending the end of chunked encoding. */
        ret = http_shutdown(h, h->flags);

    if (s->hd){
        ffurl_closep(&s->hd);
    }
#if defined(__ANDROID__) || defined(__APPLE__)
    pthread_mutex_destroy(&s->mutex);
    pthread_cond_destroy(&s->cond);
    av_dict_free(&s->chained_options);
#endif
#if DUMP_BITSTREAM
    if (s->file) {
        fclose(s->file);
        s->file = NULL;
    }
#endif
    return ret;
}
static void http_sleep(URLContext* h,int millsecond) {
    HTTPContext *s = h->priv_data;
    struct timespec abstime;
#if defined(__ANDROID__)
    clock_gettime(CLOCK_REALTIME, &abstime);
    abstime.tv_nsec += (millsecond % 1000) * 1000000;
    abstime.tv_sec += millsecond / 1000;
#elif defined(__APPLE__)
    struct timeval delta;
    gettimeofday(&delta, NULL); 
    abstime.tv_sec = delta.tv_sec + (millsecond / 1000); 
    abstime.tv_nsec = (delta.tv_usec + (millsecond % 1000) * 1000) * 1000;
#endif 
    if (abstime.tv_nsec > 1000000000) { 
        abstime.tv_sec += 1;
        abstime.tv_nsec -= 1000000000;
    }   
    pthread_mutex_lock(&s->mutex);
    if (h->interrupt_callback.callback != NULL && h->interrupt_callback.callback(h->interrupt_callback.opaque)) {
        pthread_mutex_unlock(&s->mutex);
        return;
    }
    s->cond_waited = TRUE;
    pthread_cond_timedwait(&s->cond,&s->mutex,&abstime);
    s->cond_waited = FALSE;
    pthread_mutex_unlock(&s->mutex);
}
static void close_auto_range(HTTPContext *s, int reset_endoff) {
    s->is_r_auto_range = 0;
    s->r_cache_mode = 0;
    if (reset_endoff)
        s->end_off = 0;
}
static int64_t http_seek_internal(URLContext *h, int64_t off, int whence, int force_reconnect)
{
    HTTPContext *s = h->priv_data;
    URLContext *old_hd = s->hd;
    uint64_t old_off = s->off;
    uint8_t old_buf[BUFFER_SIZE];
    int old_buf_size, ret;
	int reconnect_index = 0,reconnect_delay_time = 5;
	int interrupt = 0;
    AVDictionary *options = NULL;

    if (whence == AVSEEK_SIZE)
        return s->filesize;
    else if(whence == AVSEEK_ADDR){
	    return (int64_t)s->host_ip;
    } else if(whence == AVSEEK_SETDUR) {
	    return -1;
    } else if(whence == AVSEEK_CPSIZE) {
        return s->recv_size;
    } else if(whence == AVSEEK_RESET_AUTO_RANGE) {
        av_log(h, AV_LOG_DEBUG, "external disable auto range");
        close_auto_range(s, 0);
        return s->is_r_auto_range;
    }
    else if (!force_reconnect &&
             ((whence == SEEK_CUR && off == 0) ||
              (whence == SEEK_SET && off == s->off)))
        return s->off;
    else if ((s->filesize == UINT64_MAX && whence == SEEK_END)) {
        // av_trace(h,AVERROR(ENOSYS),"AVERROR(ENOSYS)");
        return AVERROR(ENOSYS);
    }

    if (whence == SEEK_CUR)
        off += s->off;
    else if (whence == SEEK_END)
        off += s->filesize;
    else if (whence != SEEK_SET){
        av_trace(h,AVERROR(EINVAL),"AVERROR(EINVAL)");
        return AVERROR(EINVAL);
    }
    if (off < 0){
        av_trace(h,AVERROR(EINVAL),"AVERROR(EINVAL)");
        return AVERROR(EINVAL);
    }
    if (!force_reconnect) {
        av_log(h, AV_LOG_DEBUG, "http seek reset auto range");
        //reset auto_range modification
        close_auto_range(s, 1);
    }
    s->off = off;

    if (s->off && h->is_streamed){
        av_trace(h,AVERROR(ENOSYS),"AVERROR(ENOSYS)");
        return AVERROR(ENOSYS);
    }

    /* we save the old context in case the seek fails */
    old_buf_size = s->buf_end - s->buf_ptr;
    memcpy(old_buf, s->buf_ptr, old_buf_size);
    s->hd = NULL;

    /* if it fails, continue on old connection */
#if HTTP_AUTO_RECONNECT
    ret = -1;
    if (s->reconnect_count > 0) {
        reconnect_delay_time = s->reconnect_delay_max / s->reconnect_count;
        if (reconnect_delay_time <= 0) {
            reconnect_delay_time = 1;
        }
    }
     do {
        s->off = off;
        http_callback_request(h, IsRequestStart, s->location);
        ret = http_open_cnx(h, &options);
        if(ret >= 0 || 
			ret == AVERROR_HTTP_BAD_REQUEST || 
			ret == AVERROR_HTTP_UNAUTHORIZED ||
			ret == AVERROR_HTTP_FORBIDDEN ||
			ret == AVERROR_HTTP_NOT_FOUND ||
			ret == AVERROR_HTTP_OTHER_4XX ||
			ret == AVERROR_HTTP_SERVER_ERROR)
            break;	
        reconnect_index++;
        av_log(h, AV_LOG_INFO, "reconnect:%d delay_time:%d", reconnect_index, reconnect_delay_time);
        
        if(h->interrupt_callback.callback!= NULL) {
#if defined(__ANDROID__) || defined(__APPLE__)
            http_sleep(h,1000);
#else
            int64_t timeout = 1000U*1000*1;//reconnect_delay_time;
            while(timeout > 0  && !h->interrupt_callback.callback(h->interrupt_callback.opaque) ) {
                av_usleep(1000);
                timeout -= 1000;
			}
#endif
            interrupt = h->interrupt_callback.callback(h->interrupt_callback.opaque);
        } else {
            av_usleep(1000U*1000*reconnect_delay_time);
        }
        if(interrupt) {
            ret = AVERROR_EXIT;
            break;
        }
     } while( ret < 0 && s->reconnect && (s->reconnect_count  == 0 || reconnect_index < s->reconnect_count) );
    if ( ret < 0) {
        av_trace(h,ret,"reconnect:%d delay_time:%d,fail:%d", reconnect_index, reconnect_delay_time);
        av_dict_free(&options);
        memcpy(s->buffer, old_buf, old_buf_size);
        s->buf_ptr = s->buffer;
        s->buf_end = s->buffer + old_buf_size;
        s->hd      = old_hd;
        s->off     = old_off;
        return ret;
    }
    //------
#else
    if ((ret = http_open_cnx(h, &options)) < 0) {
        av_dict_free(&options);
        memcpy(s->buffer, old_buf, old_buf_size);
        s->buf_ptr = s->buffer;
        s->buf_end = s->buffer + old_buf_size;
        s->hd      = old_hd;
        s->off     = old_off;
        return ret;
    }
#endif
    av_dict_free(&options);
    ffurl_close(old_hd);
    return off;
}

static int64_t http_seek(URLContext *h, int64_t off, int whence)
{
#if DUMP_BITSTREAM
    HTTPContext *s = h->priv_data;
    if (s->file) {
        fclose(s->file);
        s->file = NULL;
    }
#endif
    return http_seek_internal(h, off, whence, 0);
}

static int http_get_file_handle(URLContext *h)
{
    HTTPContext *s = h->priv_data;
    return ffurl_get_file_handle(s->hd);
}

static int http_get_short_seek(URLContext *h)
{
    HTTPContext *s = h->priv_data;
    return ffurl_get_short_seek(s->hd);
}
static aptr_t http_get_aptr(void * ptr) {
    HTTPContext* s = ptr;
    return s->aptr;
}
#define HTTP_CLASS(flavor)                          \
static const AVClass flavor ## _context_class = {   \
    .class_name = # flavor,                         \
    .item_name  = av_default_item_name,             \
    .option     = options,                          \
    .version    = LIBAVUTIL_VERSION_INT,            \
    .get_aptr = http_get_aptr,\
}

#if CONFIG_HTTP_PROTOCOL
HTTP_CLASS(http);

const URLProtocol ff_http_protocol = {
    .name                = "http",
    .url_open2           = http_open,
    .url_accept          = http_accept,
    .url_handshake       = http_handshake,
    .url_read            = http_read,
    .url_write           = http_write,
    .url_seek            = http_seek,
    .url_close           = http_close,
    .url_get_file_handle = http_get_file_handle,
    .url_get_short_seek  = http_get_short_seek,
    .url_shutdown        = http_shutdown,
    .priv_data_size      = sizeof(HTTPContext),
    .priv_data_class     = &http_context_class,
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .default_whitelist   = "http,https,httpk,httpq,tls,rtp,tcp,udp,quic,rearquic,crypto,httpproxy"
};
#endif /* CONFIG_HTTP_PROTOCOL */

#if CONFIG_HTTPS_PROTOCOL
HTTP_CLASS(https);

const URLProtocol ff_https_protocol = {
    .name                = "https",
    .url_open2           = http_open,
    .url_read            = http_read,
    .url_write           = http_write,
    .url_seek            = http_seek,
    .url_close           = http_close,
    .url_get_file_handle = http_get_file_handle,
    .url_get_short_seek  = http_get_short_seek,
    .url_shutdown        = http_shutdown,
    .priv_data_size      = sizeof(HTTPContext),
    .priv_data_class     = &https_context_class,
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .default_whitelist   = "http,https,httpk,httpq,tls,rtp,tcp,udp,quic,rearquic,crypto,httpproxy"
};
#endif /* CONFIG_HTTPS_PROTOCOL */

#if CONFIG_HTTPK_PROTOCOL
HTTP_CLASS(httpk);

const URLProtocol ff_httpk_protocol = {
    .name                = "httpk",
    .url_open2           = http_open,
    .url_read            = http_read,
    .url_write           = http_write,
    .url_seek            = http_seek,
    .url_close           = http_close,
    .url_get_file_handle = http_get_file_handle,
    .url_get_short_seek  = http_get_short_seek,
    .url_shutdown        = http_shutdown,
    .priv_data_size      = sizeof(HTTPContext),
    .priv_data_class     = &httpk_context_class,
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .default_whitelist   = "http,https,httpk,httpq,tls,rtp,tcp,udp,quic,rearquic,crypto,httpproxy"
};
#endif /* CONFIG_HTTPK_PROTOCOL */

#if CONFIG_HTTPQ_PROTOCOL
HTTP_CLASS(httpq);

const URLProtocol ff_httpq_protocol = {
    .name                = "httpq",
    .url_open2           = http_open,
    .url_read            = http_read,
    .url_write           = http_write,
    .url_seek            = http_seek,
    .url_close           = http_close,
    .url_get_file_handle = http_get_file_handle,
    .url_get_short_seek  = http_get_short_seek,
    .url_shutdown        = http_shutdown,
    .priv_data_size      = sizeof(HTTPContext),
    .priv_data_class     = &httpq_context_class,
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .default_whitelist   = "http,https,httpq,tls,rtp,tcp,udp,quic,rearquic,crypto,httpproxy"
};
#endif /* CONFIG_HTTPQ_PROTOCOL */

#if CONFIG_HTTPPROXY_PROTOCOL
static int http_proxy_close(URLContext *h)
{
    HTTPContext *s = h->priv_data;
    if (s->hd)
        ffurl_closep(&s->hd);
#if defined(__ANDROID__) || defined(__APPLE__)
    pthread_mutex_destroy(&s->mutex);
    pthread_cond_destroy(&s->cond);
#endif
    return 0;
}

static int http_proxy_open(URLContext *h, const char *uri, int flags)
{
    HTTPContext *s = h->priv_data;
    char hostname[1024], hoststr[1024];
    char auth[1024], pathbuf[1024], *path;
    char lower_url[100];
    int port, ret = 0, attempts = 0;
    HTTPAuthType cur_auth_type;
    char *authstr;
    int new_loc;

    if( s->seekable == 1 )
        h->is_streamed = 0;
    else
        h->is_streamed = 1;

    av_url_split(NULL, 0, auth, sizeof(auth), hostname, sizeof(hostname), &port,
                 pathbuf, sizeof(pathbuf), uri);
    ff_url_join(hoststr, sizeof(hoststr), NULL, NULL, hostname, port, NULL);
    path = pathbuf;
    if (*path == '/')
        path++;

    ff_url_join(lower_url, sizeof(lower_url), "tcp", NULL, hostname, port,
                NULL);
redo:
    ret = ffurl_open_whitelist(&s->hd, lower_url, AVIO_FLAG_READ_WRITE,
                               &h->interrupt_callback, NULL,
                               h->protocol_whitelist, h->protocol_blacklist, h);
    if (ret < 0)
        return ret;

    authstr = ff_http_auth_create_response(&s->proxy_auth_state, auth,
                                           path, "CONNECT");
    snprintf(s->buffer, sizeof(s->buffer),
             "CONNECT %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Connection: close\r\n"
             "%s%s"
             "\r\n",
             path,
             hoststr,
             authstr ? "Proxy-" : "", authstr ? authstr : "");
    av_freep(&authstr);

    if ((ret = ffurl_write(s->hd, s->buffer, strlen(s->buffer))) < 0)
        goto fail;

    s->buf_ptr    = s->buffer;
    s->buf_end    = s->buffer;
    s->line_count = 0;
    s->filesize   = UINT64_MAX;
    cur_auth_type = s->proxy_auth_state.auth_type;

    /* Note: This uses buffering, potentially reading more than the
     * HTTP header. If tunneling a protocol where the server starts
     * the conversation, we might buffer part of that here, too.
     * Reading that requires using the proper ffurl_read() function
     * on this URLContext, not using the fd directly (as the tls
     * protocol does). This shouldn't be an issue for tls though,
     * since the client starts the conversation there, so there
     * is no extra data that we might buffer up here.
     */
    ret = http_read_header(h, &new_loc);
    if (ret < 0)
        goto fail;

    attempts++;
    if (s->http_code == 407 &&
        (cur_auth_type == HTTP_AUTH_NONE || s->proxy_auth_state.stale) &&
        s->proxy_auth_state.auth_type != HTTP_AUTH_NONE && attempts < 2) {
        ffurl_closep(&s->hd);
        goto redo;
    }

    if (s->http_code < 400)
        return 0;
    av_trace(h,AVERROR(EIO),"AVERROR(EIO)");
    ret = ff_http_averror(s->http_code, AVERROR(EIO));

fail:
    http_proxy_close(h);
    return ret;
}

static int http_proxy_write(URLContext *h, const uint8_t *buf, int size)
{
    HTTPContext *s = h->priv_data;
    return ffurl_write(s->hd, buf, size);
}

const URLProtocol ff_httpproxy_protocol = {
    .name                = "httpproxy",
    .url_open            = http_proxy_open,
    .url_read            = http_buf_read,
    .url_write           = http_proxy_write,
    .url_close           = http_proxy_close,
    .url_get_file_handle = http_get_file_handle,
    .priv_data_size      = sizeof(HTTPContext),
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
};
#endif /* CONFIG_HTTPPROXY_PROTOCOL */
