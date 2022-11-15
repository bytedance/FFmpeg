/*
 * TCP protocol
 * Copyright (c) 2002 Fabrice Bellard
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
#include "avformat.h"
#include "libavutil/avassert.h"
#include "libavutil/parseutils.h"
#include "libavutil/opt.h"
#include "libavutil/time.h"

#include "internal.h"
#include "network.h"
#include "os_support.h"
#include "url.h"
#if HAVE_POLL_H
#include <poll.h>
#endif

typedef struct TCPContext {
    const AVClass *class;
    int fd;
    int listen;
    int open_timeout;
    int rw_timeout;
    int listen_timeout;
    int recv_buffer_size;
    int send_buffer_size;
    int tcp_nodelay;
#if !HAVE_WINSOCK2_H
    int tcp_mss;
#endif /* !HAVE_WINSOCK2_H */
    int is_first_packet;
    int user_flag;
    intptr_t tt_opaque;
    char ip_addr[132];
} TCPContext;

#define OFFSET(x) offsetof(TCPContext, x)
#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM
static const AVOption options[] = {
    { "listen",          "Listen for incoming connections",  OFFSET(listen),         AV_OPT_TYPE_INT, { .i64 = 0 },     0,       2,       .flags = D|E },
    { "timeout",     "set timeout (in microseconds) of socket I/O operations", OFFSET(rw_timeout),     AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "listen_timeout",  "Connection awaiting timeout (in milliseconds)",      OFFSET(listen_timeout), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "send_buffer_size", "Socket send buffer size (in bytes)",                OFFSET(send_buffer_size), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "recv_buffer_size", "Socket receive buffer size (in bytes)",             OFFSET(recv_buffer_size), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "tcp_nodelay", "Use TCP_NODELAY to disable nagle's algorithm",           OFFSET(tcp_nodelay), AV_OPT_TYPE_BOOL, { .i64 = 0 },             0, 1, .flags = D|E },
#if !HAVE_WINSOCK2_H
    { "tcp_mss",     "Maximum segment size for outgoing TCP packets",          OFFSET(tcp_mss),     AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
#endif /* !HAVE_WINSOCK2_H */
    { "is_first_packet", "Mark data is first packet or not", OFFSET(is_first_packet), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "user_flag", "user flag", OFFSET(user_flag), AV_OPT_TYPE_INT, { .i64 = 0 }, INT_MIN, INT_MAX, .flags = D|E },
    { "tt_opaque", "set app ptr for ffmpeg", OFFSET(tt_opaque), AV_OPT_TYPE_IPTR, { .i64 = 0 }, INT64_MIN, INT64_MAX, .flags = D|E },
    { NULL }
};

static const AVClass tcp_class = {
    .class_name = "tcp",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};
const char *tcp_get_ip_addr(URLContext *h);

static void customize_fd(void *ctx, int fd)
{
    TCPContext *s = ctx;
    /* Set the socket's send or receive buffer sizes, if specified.
       If unspecified or setting fails, system default is used. */
    if (s->recv_buffer_size > 0) {
        if (setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &s->recv_buffer_size, sizeof (s->recv_buffer_size))) {
            ff_log_net_error(ctx, AV_LOG_WARNING, "setsockopt(SO_RCVBUF)");
        }
    }
    if (s->send_buffer_size > 0) {
        if (setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &s->send_buffer_size, sizeof (s->send_buffer_size))) {
            ff_log_net_error(ctx, AV_LOG_WARNING, "setsockopt(SO_SNDBUF)");
        }
    }
    if (s->tcp_nodelay > 0) {
        if (setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, &s->tcp_nodelay, sizeof (s->tcp_nodelay))) {
            ff_log_net_error(ctx, AV_LOG_WARNING, "setsockopt(TCP_NODELAY)");
        }
    }
#if !HAVE_WINSOCK2_H
    if (s->tcp_mss > 0) {
        if (setsockopt (fd, IPPROTO_TCP, TCP_MAXSEG, &s->tcp_mss, sizeof (s->tcp_mss))) {
            ff_log_net_error(ctx, AV_LOG_WARNING, "setsockopt(TCP_MAXSEG)");
        }
    }
#endif /* !HAVE_WINSOCK2_H */
}

/* return non zero if error */
static int tcp_open(URLContext *h, const char *uri, int flags)
{
    struct addrinfo hints = { 0 }, *ai, *cur_ai;
    int port, fd = -1;
    TCPContext *s = h->priv_data;
    tt_network_log_callback(s->tt_opaque, IsTransOpenStart, s->user_flag);
    const char *p;
    char buf[256];
    int ret;
    char hostname[1024],proto[1024],path[1024];
    char portstr[10];
    s->open_timeout = 5000000;

    av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname),
        &port, path, sizeof(path), uri);
    if (strcmp(proto, "tcp"))
        return AVERROR(EINVAL);
    if (port <= 0 || port >= 65536) {
        av_log(h, AV_LOG_ERROR, "Port missing in uri\n");
        return AVERROR(EINVAL);
    }
    p = strchr(uri, '?');
    if (p) {
        if (av_find_info_tag(buf, sizeof(buf), "listen", p)) {
            char *endptr = NULL;
            s->listen = strtol(buf, &endptr, 10);
            /* assume if no digits were found it is a request to enable it */
            if (buf == endptr)
                s->listen = 1;
        }
        if (av_find_info_tag(buf, sizeof(buf), "timeout", p)) {
            s->rw_timeout = strtol(buf, NULL, 10);
        }
        if (av_find_info_tag(buf, sizeof(buf), "listen_timeout", p)) {
            s->listen_timeout = strtol(buf, NULL, 10);
        }
    }
    if (s->rw_timeout >= 0) {
        s->open_timeout =
        h->rw_timeout   = s->rw_timeout;
    }
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (s->listen)
        hints.ai_flags |= AI_PASSIVE;
    
    if(h->interrupt_callback.callback == NULL || hostname[0] == 0 || ff_support_external_dns() == 0) {
        tt_network_log_callback(s->tt_opaque, IsDNSStart, s->user_flag);
        if (!hostname[0])
                ret = getaddrinfo(NULL, portstr, &hints, &ai);
        else
                ret = getaddrinfo(hostname, portstr, &hints, &ai);

        if (ret) {
            av_log(h, AV_LOG_ERROR, "%d Failed to resolve hostname. %s\n",ff_neterrno(), gai_strerror(ret));
            return AVERROR(EIO);
        }
    } else {
        void* ctx = NULL;
        int timelost = 0;
        int timeout = s->open_timeout;
        if(timeout == -1) {
            timeout = 10*1000000;
        }
        tt_network_log_callback(s->tt_opaque, IsDNSStart, s->user_flag);
        ctx = ff_dns_start(s->tt_opaque, hostname, s->user_flag);
        if(ctx == NULL) {
            av_log(h, AV_LOG_ERROR, "neterrno:%d Failed to resolve hostname.ctx is null.", ff_neterrno());
            return AVERROR(EIO);
        }
	    ret = 0;
        while(!h->interrupt_callback.callback(h->interrupt_callback.opaque)) {
            ret = ff_dns_result(ctx, hostname, 1024);
            if(ret != 0) {
                break;
            }
            av_usleep (30000);
            timelost += 30000;
            if(timelost >= timeout) {
                ret = -2;
                break;
            }
        }
        if(ctx != NULL) {
            ff_dns_free(ctx);
            ctx  = NULL;
        }
        if(ret > 0) {
            ret = getaddrinfo(hostname, portstr, &hints, &ai);
            if (ret) {
                av_error(h, AVERROR_FAILED_TO_RESOLVE_HOSTNAME,"neterrno:%d Failed to resolve hostname,error:%s\n" , ff_neterrno(), gai_strerror(ret));
                return AVERROR(EIO);
            }
            if(strlen(hostname) <= sizeof(s->ip_addr)) {
                memcpy(s->ip_addr, hostname, strlen(hostname));
            }
            tt_save_host_addr(s->tt_opaque, s->ip_addr, s->user_flag);
            ret = 1;
        } else if(ret == -1) {
            av_error(h, AVERROR_FAILED_TO_RESOLVE_HOSTNAME, "%d Failed to resolve hostname %s.", -EFAULT, hostname);
        } else if(ret == -2) {
            av_error(h, AVERROR_FAILED_TO_RESOLVE_HOSTNAME_TIMEOUT, "%d Failed to resolve hostname time out.", -ETIMEDOUT);
        } else {
            av_error(h, AVERROR_FAILED_TO_RESOLVE_HOSTNAME, "ret:%d neterrno:%d Failed to resolve hostname.", ret, ff_neterrno());
        }
        if (ret <= 0) {
            return AVERROR(EIO);
        }
    }

    cur_ai = ai;
    tt_network_log_callback(s->tt_opaque, IsDNSParsed, s->user_flag);

#if HAVE_STRUCT_SOCKADDR_IN6
    // workaround for IOS9 getaddrinfo in IPv6 only network use hardcode IPv4 address can not resolve port number.
    if (cur_ai->ai_family == AF_INET6){
        struct sockaddr_in6 * sockaddr_v6 = (struct sockaddr_in6 *)cur_ai->ai_addr;
        if (!sockaddr_v6->sin6_port){
            sockaddr_v6->sin6_port = htons(port);
        }
    }
#endif

    if (s->listen > 0) {
        while (cur_ai && fd < 0) {
            fd = ff_socket(cur_ai->ai_family,
                           cur_ai->ai_socktype,
                           cur_ai->ai_protocol);
            if (fd < 0) {
                ret = ff_neterrno();
                cur_ai = cur_ai->ai_next;
            }
        }
        if (fd < 0)
            goto fail1;
        tt_network_log_callback(s->tt_opaque, IsSocketCreateSuccess, s->user_flag);
        customize_fd(s, fd);
    }

    if (s->listen == 2) {
        // multi-client
        if ((ret = ff_listen(fd, cur_ai->ai_addr, cur_ai->ai_addrlen)) < 0)
            goto fail1;
    } else if (s->listen == 1) {
        // single client
        if ((ret = ff_listen_bind(fd, cur_ai->ai_addr, cur_ai->ai_addrlen,
                                  s->listen_timeout, h)) < 0)
            goto fail1;
        // Socket descriptor already closed here. Safe to overwrite to client one.
        fd = ret;
    } else {
        ret = ff_connect_parallel(ai, s->open_timeout / 1000, 3, h, &fd, customize_fd, s);
        if (ret < 0)
            goto fail1;
    }

    h->is_streamed = 1;
    s->fd = fd;

    freeaddrinfo(ai);
    tt_network_log_callback(s->tt_opaque, IsSocketConnected, s->user_flag);
    return 0;

 fail1:
    if (ret < 0) {
        tt_network_log_callback(s->tt_opaque, IsSocketOpenErr, ret);
    }

    if (fd >= 0)
        closesocket(fd);
    freeaddrinfo(ai);
    return ret;
}

static int tcp_accept(URLContext *s, URLContext **c)
{
    TCPContext *sc = s->priv_data;
    TCPContext *cc;
    int ret;
    av_assert0(sc->listen);
    if ((ret = ffurl_alloc(c, s->filename, s->flags, &s->interrupt_callback)) < 0)
        return ret;
    cc = (*c)->priv_data;
    ret = ff_accept(sc->fd, sc->listen_timeout, s);
    if (ret < 0) {
        ffurl_closep(c);
        return ret;
    }
    cc->fd = ret;
    return 0;
}

static int tcp_read(URLContext *h, uint8_t *buf, int size)
{
    TCPContext *s = h->priv_data;
    int ret;

    if (!(h->flags & AVIO_FLAG_NONBLOCK)) {
        ret = ff_network_wait_fd_timeout(s->fd, 0, h->rw_timeout, &h->interrupt_callback);
        if (ret) {
            if(ret != AVERROR_EXIT) {
                //you cann't call ff_neterrno here, because errno will be set by other operations.
                tt_network_log_callback(s->tt_opaque, IsSocketReadErr, ret);
                av_error(h, AVERROR_READ_NETWORK_WAIT_TIMEOUT, "ret:%d neterrno:%d network wait timeout", ret, ff_neterrno());
            }

            return ret;
        }
    }
    ret = recv(s->fd, buf, size, 0);
    if (ret == 0)
        return AVERROR_EOF;
    // return ret < 0 ? ff_neterrno() : ret;
    if (ret < 0) {
        int error = ff_neterrno();
        tt_network_log_callback(s->tt_opaque, IsSocketReadErr, error);
        av_error(h, AVERROR_RECEIV_DATA_FAILED, "ret:%d neterrno:%d socket revc data failed", ret, error);
        return error;
    }

    if (ret > 0) {
        tt_network_io_read_callback(s->tt_opaque, IsNetworkIORead, ret);
        if (!s->is_first_packet) {
            tt_network_log_callback(s->tt_opaque, IsPacketRecved, s->user_flag);
            s->is_first_packet = 1;
        }
    }
    return ret;

}

static int tcp_write(URLContext *h, const uint8_t *buf, int size)
{
    TCPContext *s = h->priv_data;
    int ret;

    if (!(h->flags & AVIO_FLAG_NONBLOCK)) {
        ret = ff_network_wait_fd_timeout(s->fd, 1, h->rw_timeout, &h->interrupt_callback);
        if (ret) {
            tt_network_log_callback(s->tt_opaque, IsSocketWriteErr, ret);
            av_error(h, AVERROR_WRITE_NETWORK_WAIT_TIMEOUT, "ret:%d neterrno:%d network wait timeout", ret, ff_neterrno());
            return ret;
        }
    }
    ret = send(s->fd, buf, size, MSG_NOSIGNAL);
    // return ret < 0 ? ff_neterrno() : ret;
    if (ret < 0) {
        int error = ff_neterrno();
        tt_network_log_callback(s->tt_opaque, IsSocketWriteErr, ret);
        av_error(h, AVERROR_SEND_DATA_FAILED, "ret:%d neterrno:%d socket send failed", ret, error);
		return error;
    }
    return ret;

}

static int tcp_shutdown(URLContext *h, int flags)
{
    TCPContext *s = h->priv_data;

    if(flags & AVIO_FLAG_STOP) {
        return 0;
    } else {
        int how;
        if (flags & AVIO_FLAG_WRITE && flags & AVIO_FLAG_READ) {
            how = SHUT_RDWR;
        } else if (flags & AVIO_FLAG_WRITE) {
            how = SHUT_WR;
        } else {
            how = SHUT_RD;
        }
        return shutdown(s->fd, how);
    }
}

static int tcp_close(URLContext *h)
{
    TCPContext *s = h->priv_data;
    closesocket(s->fd);
    return 0;
}

static int tcp_get_file_handle(URLContext *h)
{
    TCPContext *s = h->priv_data;
    return s->fd;
}

const char *tcp_get_ip_addr(URLContext *h)
{
    TCPContext *s = h->priv_data;
    if(s->ip_addr[0] != '\0') {
        return s->ip_addr;
    }
    return NULL;
}

static int tcp_get_window_size(URLContext *h)
{
    TCPContext *s = h->priv_data;
    int avail;
    socklen_t avail_len = sizeof(avail);

#if HAVE_WINSOCK2_H
    /* SO_RCVBUF with winsock only reports the actual TCP window size when
    auto-tuning has been disabled via setting SO_RCVBUF */
    if (s->recv_buffer_size < 0) {
        return AVERROR(ENOSYS);
    }
#endif

    if (getsockopt(s->fd, SOL_SOCKET, SO_RCVBUF, &avail, &avail_len)) {
        return ff_neterrno();
    }
    return avail;
}

const URLProtocol ff_tcp_protocol = {
    .name                = "tcp",
    .url_open            = tcp_open,
    .url_accept          = tcp_accept,
    .url_read            = tcp_read,
    .url_write           = tcp_write,
    .url_close           = tcp_close,
    .url_get_file_handle = tcp_get_file_handle,
    .url_get_short_seek  = tcp_get_window_size,
    .url_shutdown        = tcp_shutdown,
    .priv_data_size      = sizeof(TCPContext),
    .flags               = URL_PROTOCOL_FLAG_NETWORK,
    .priv_data_class     = &tcp_class,
};
