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
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#if defined(__APPLE__)
typedef void* (*getSocketPool)(aptr_t handle);
typedef int (*getSocketHandle)(void *ctx,const char *hostname, int port);
typedef void (*givebackSocketHandle)(void *ctx,const char *hostname, int port, int handle);
typedef struct getSocketPoolCTX{
    getSocketPool getPool;
    getSocketHandle getHandle;
    givebackSocketHandle givebackHandle;
}getSocketPoolCtx;
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
    int is_first_packet;
    int user_flag;
    aptr_t aptr;
    aptr_t gsc;
    aptr_t cbptr;
    char ip_addr[132];
    char hostname[1024];
    int port;
    int fastopen;
    int tcp_connected;
    int fastopen_success;
} TCPContext;

#define FAST_OPEN_FLAG 0x20000000
#define OFFSET(x) offsetof(TCPContext, x)
#define D AV_OPT_FLAG_DECODING_PARAM
#define E AV_OPT_FLAG_ENCODING_PARAM
static const AVOption options[] = {
    { "listen",          "Listen for incoming connections",  OFFSET(listen),         AV_OPT_TYPE_INT, { .i64 = 0 },     0,       2,       .flags = D|E },
    { "timeout",     "set timeout (in microseconds) of socket I/O operations", OFFSET(rw_timeout),     AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "listen_timeout",  "Connection awaiting timeout (in milliseconds)",      OFFSET(listen_timeout), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "send_buffer_size", "Socket send buffer size (in bytes)",                OFFSET(send_buffer_size), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "recv_buffer_size", "Socket receive buffer size (in bytes)",             OFFSET(recv_buffer_size), AV_OPT_TYPE_INT, { .i64 = -1 },         -1, INT_MAX, .flags = D|E },
    { "aptr", "set app ptr for ffmpeg", OFFSET(aptr), AV_OPT_TYPE_APTR, { .i64 = 0 }, APTR_MIN, APTR_MAX, .flags = D|E },
    { "gsc", "get socket pool", OFFSET(gsc),  AV_OPT_TYPE_APTR, { .i64 = 0 }, APTR_MIN, APTR_MAX, .flags = D|E },
    { "cbptr", "app network callback ctx ptr", OFFSET(cbptr), AV_OPT_TYPE_APTR, { .i64 = 0 }, APTR_MIN, APTR_MAX, .flags = D|E },
    { "is_first_packet", "Mark data is first packet or not", OFFSET(is_first_packet), AV_OPT_TYPE_BOOL, { .i64 = 0 }, 0, 1, D },
    { "user_flag", "user flag", OFFSET(user_flag), AV_OPT_TYPE_INT, { .i64 = 0 }, INT_MIN, INT_MAX, .flags = D|E },
    { "fastopen", "enable fastopen",          OFFSET(fastopen), AV_OPT_TYPE_INT, { .i64 = 0},       0, INT_MAX, .flags = D|E },
    { NULL }
};

static const AVClass tcp_class = {
    .class_name = "tcp",
    .item_name  = av_default_item_name,
    .option     = options,
    .version    = LIBAVUTIL_VERSION_INT,
};
const char *tcp_get_ip_addr(URLContext *h);
static int tcp_check_interrupt(AVIOInterruptCB *cb)
{
    int ret;
    if (cb && cb->callback && (ret = cb->callback(cb->opaque)))
        return ret;
    return 0;
}
typedef struct ADDRESS_CTX {
    URLContext* h;
    const char *node;
    const char *service;
    struct addrinfo *hints;
    struct addrinfo **res;
    int   ret;
    int   finish;
}AddressContext;
static void* tcp_getaddrinfo_thread(void* h) {
    AddressContext *s = h;
    s->ret = getaddrinfo(s->node, s->service, s->hints, s->res);
    s->finish = TRUE;
    return 0;
}
static void sigterm_handler(int sig){
    av_log(NULL, AV_LOG_ERROR, "recv dns parser thread kill\n");
    if(sig == SIGUSR1) {
        pthread_exit(0);
    }
}

static int tcp_getaddrinfo_a(URLContext* h,const char *node, const char *service,
                              struct addrinfo *hints,
                              struct addrinfo **res) {
    //struct sigaction act, oldact;
    pthread_t thread;
    int pthread_err;
    TCPContext *s = h->priv_data;
    int timelost = 0,ret = -1;
    int timeout = s->open_timeout;
    if(timeout == -1) {
        timeout = 30*1000000;
    }
    AddressContext context;
    context.h = h;
    context.node = node;
    context.service = service;
    context.hints = hints;
    context.res = res;
    context.ret = 0;
    context.finish = FALSE;

    pthread_attr_t type;
    if ( pthread_attr_init(&type) != 0 ) {
        av_log(s, AV_LOG_ERROR, "open dns parser thread fail\n");
        return FALSE;
    }

    //act.sa_handler = sigterm_handler;
    //sigaddset(&act.sa_mask, SIGQUIT);
    //act.sa_flags = SA_RESETHAND | SA_NODEFER;
    //sigaction(SIGUSR1, &act, &oldact);
    //signal(SIGUSR1 , sigterm_handler); /* Interrupt (ANSI).    */

    pthread_attr_setdetachstate(&type, PTHREAD_CREATE_JOINABLE);
    if ( pthread_create(&thread, &type, tcp_getaddrinfo_thread, &context) != 0 ) {
        av_log(s, AV_LOG_ERROR, "open dns parser thread fail\n");
        return -1;
    }
    while(!tcp_check_interrupt(&h->interrupt_callback)) {
        if(context.finish) {
            ret = context.ret;
            break;
        }
        av_usleep (30000);
        timelost += 30000;
        if(timelost >= timeout) {
            ret = -2;
            pthread_kill(thread,SIGUSR1);
            break;
        }
    }
    pthread_err = pthread_kill(thread,0);
    if(pthread_err == ESRCH) {
        av_log(s, AV_LOG_ERROR, "dns parser thread is kill ok\n");
    }
    else if(pthread_err == EINVAL) {
        av_log(s, AV_LOG_ERROR, "dns thread kill is not inval\n");
    }
    else {
        pthread_join(thread, 0);
    }

    return ret;
}
/* return non zero if error */
static int tcp_open(URLContext *h, const char *uri, int flags)
{
    struct addrinfo hints = { 0 }, *ai = NULL, *cur_ai = NULL;
    int port, fd = -1;
    TCPContext *s = h->priv_data;
    ff_inetwork_log_callback(s->cbptr, s->aptr, IsTransOpenStart, s->user_flag);
    const char *p;
    char buf[256];
    int ret;
    char hostname[1024],proto[1024],path[1024];
    char portstr[10];
#if defined(__APPLE__)
    void *socketpool = NULL;
    getSocketPoolCtx  *gsc = (getSocketPoolCtx*)s->gsc;
#endif
    s->open_timeout = 5000000;

#if defined(__ANDROID__)
    if (s->fastopen) {
        s->fd = fd;
        s->tcp_connected = 0;
        strcpy(s->hostname, uri);
        return 0;
    }
#endif

    av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname),
                 &port, path, sizeof(path), uri);
    if (strcmp(proto, "tcp")){
        av_fatal(h,AVERROR_PROTO_IS_NOT_TCP,"%d proto is not tcp", AVERROR(EINVAL));
        return AVERROR(EINVAL);
    }
    if (port <= 0 || port >= 65536) {
        av_fatal(h,AVERROR_INVALID_PORT,"%d invalid port", AVERROR(EINVAL));
        return AVERROR(EINVAL);
    }
    memcpy(s->hostname, hostname, sizeof(hostname));
    s->port = port;
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
#if defined(__APPLE__)
    if (gsc) {
        socketpool = gsc->getPool(s->aptr);
        if (socketpool) {
            fd = gsc->getHandle(socketpool,hostname,port);
            if (fd > 0) {
                goto label_success;
            }
        }
    }
#endif
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (s->listen)
        hints.ai_flags |= AI_PASSIVE;
#if 0
    if(s->ip_addr[0] != '\0') {
        memcpy(hostname, s->ip_addr, sizeof(s->ip_addr));
        goto lable_get;
    }
#endif
    if(h->interrupt_callback.callback == NULL || hostname[0] == 0 || ff_isupport_getaddrinfo_a(s->cbptr) == 0 || s->aptr == 0) {
        if(ff_isupport_getaddrinfo_a(s->cbptr) == 0 && h->interrupt_callback.callback != NULL && hostname[0] != 0) {
            ret = tcp_getaddrinfo_a(h,hostname,portstr,&hints,&ai);
        } else {
            if (!hostname[0])
                ret = getaddrinfo(NULL, portstr, &hints, &ai);
            else
                ret = getaddrinfo(hostname, portstr, &hints, &ai);
        }
        if (ret) {
            av_fatal(h, AVERROR_GET_ADDR_INFO_FAILED,"%d Failed to resolve hostname. %s\n",ff_neterrno(), gai_strerror(ret));
            return AVERROR(EIO);
        }
        /*
        if(ai != NULL && ai->ai_addr != NULL) {
            if(ai->ai_family == AF_INET) {
                struct sockaddr_in* saddr_in = (struct sockaddr_in*)(ai->ai_addr);
                struct in_addr* sin4_addr = &saddr_in->sin_addr;
                inet_ntop(ai->ai_addr->sa_family,sin4_addr,s->ip_addr,130);
            } else if(ai->ai_family == AF_INET6) {
                struct sockaddr_in6* saddr_in = (struct sockaddr_in6*)(ai->ai_addr);
                struct in6_addr* sin6_addr = &saddr_in->sin6_addr;
                inet_ntop(ai->ai_family,&sin6_addr,s->ip_addr,130);
            }
        }*/
    } else {
        void* ctx = NULL;
        int timelost = 0;
        int timeout = s->open_timeout;
        if(timeout == -1) {
            timeout = 10*1000000;
        }
        ff_inetwork_log_callback(s->cbptr, s->aptr, IsDNSStart, s->user_flag);
        ctx = ff_igetaddrinfo_a_start(s->cbptr, s->aptr,hostname,s->user_flag);
        if(ctx == NULL) {
            av_fatal(h, AVERROR_GET_ADDR_INFO_START_FAILED, "neterrno:%d Failed to resolve hostname.ctx is null.", ff_neterrno());
            return AVERROR(EIO);
        }
	    ret = 0;
        while(!h->interrupt_callback.callback(h->interrupt_callback.opaque)) {
            ret = ff_igetaddrinfo_a_result(s->cbptr, ctx,hostname,1024);
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
            ff_igetaddrinfo_a_free(s->cbptr, ctx);
            ctx  = NULL;
        }
        if(ret > 0) {
            ret = getaddrinfo(hostname, portstr, &hints, &ai);
            if (ret) {
                av_fatal(h, AVERROR_FAILED_TO_RESOLVE_HOSTNAME,"neterrno:%d Failed to resolve hostname,error:%s\n" , ff_neterrno(), gai_strerror(ret));
                return AVERROR(EIO);
            }
            if(strlen(hostname) <= sizeof(s->ip_addr)) {
                memcpy(s->ip_addr, hostname, strlen(hostname));
            }
            ff_isave_host_addr(s->cbptr, s->aptr, s->ip_addr, s->user_flag);
            goto resovle_success;

        } else if(ret == -1) {
            av_fatal(h, AVERROR_FAILED_TO_RESOLVE_HOSTNAME, "%d Failed to resolve hostname %s.", -EFAULT, hostname);
            return AVERROR(EIO);

        } else if(ret == -2) {
            av_fatal(h, AVERROR_FAILED_TO_RESOLVE_HOSTNAME_TIMEOUT, "%d Failed to resolve hostname time out.", -ETIMEDOUT);
        } else {
            av_fatal(h, AVERROR_FAILED_TO_RESOLVE_HOSTNAME, "ret:%d neterrno:%d Failed to resolve hostname.", ret, ff_neterrno());
        }
        return AVERROR(EIO);
    }

resovle_success:
    cur_ai = ai;


 restart:
#if HAVE_STRUCT_SOCKADDR_IN6
    // workaround for IOS9 getaddrinfo in IPv6 only network use hardcode IPv4 address can not resolve port number.
    if (cur_ai->ai_family == AF_INET6){
        struct sockaddr_in6 * sockaddr_v6 = (struct sockaddr_in6 *)cur_ai->ai_addr;
        if (!sockaddr_v6->sin6_port){
            sockaddr_v6->sin6_port = htons(port);
        }
    }
#endif

    fd = ff_socket(cur_ai->ai_family,
                   cur_ai->ai_socktype,
                   cur_ai->ai_protocol);
    if (fd < 0) {
        ret = ff_neterrno();
        av_fatal(h, AVERROR_FF_SOCKET_FAILED, "neterrno:%d ff_socket failed", ret);
        goto fail;
    }
    ff_inetwork_log_callback(s->cbptr, s->aptr, IsSocketCreateSuccess, s->user_flag);

    /* Set the socket's send or receive buffer sizes, if specified.
       If unspecified or setting fails, system default is used. */
    if (s->recv_buffer_size > 0) {
        setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &s->recv_buffer_size, sizeof (s->recv_buffer_size));
    }
    if (s->send_buffer_size > 0) {
        setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &s->send_buffer_size, sizeof (s->send_buffer_size));
    }

    if (s->listen == 2) {
        // multi-client
        if ((ret = ff_listen(fd, cur_ai->ai_addr, cur_ai->ai_addrlen)) < 0) {
            av_fatal(h, AVERROR_FF_LISTEN_FAILED, "ret:%d neterrno:%d ff_listen failed", ret, ff_neterrno());
            goto fail1;
        }
    } else if (s->listen == 1) {
        // single client
        if ((ret = ff_listen_bind(fd, cur_ai->ai_addr, cur_ai->ai_addrlen,
                                  s->listen_timeout, h)) < 0) {
            av_fatal(h, AVERROR_FF_LISTEN_BIND_FAILED, "ret:%d neterrno:%d ff_listen_bind failed", ret, ff_neterrno());
            goto fail1;
        }
        // Socket descriptor already closed here. Safe to overwrite to client one.
        fd = ret;
    } else {
#if defined(__APPLE__)
        if ((ret = ff_listen_connect2(fd, cur_ai->ai_addr, cur_ai->ai_addrlen, s->open_timeout / 1000, h, !!cur_ai->ai_next, s->fastopen)) < 0) {
#else
        if ((ret = ff_listen_connect(fd, cur_ai->ai_addr, cur_ai->ai_addrlen,
                                     s->open_timeout / 1000, h, !!cur_ai->ai_next)) < 0) {
#endif
            if (ret == AVERROR_EXIT){
                goto fail1;
            }
            else{
                av_trace(h, AVERROR_FF_SOCKET_CONNECT_FAILED, "ret:%d neterrno:%d ff_listen_connect failed", ret, ff_neterrno());
                goto fail;
            }
        }
    }
label_success:
    h->is_streamed = 1;
    s->fd = fd;
    if (ai != NULL) {
        freeaddrinfo(ai);
    }
    ff_inetwork_log_callback(s->cbptr, s->aptr, IsSocketConnected, s->user_flag);
    return 0;

fail:
    if (ret < 0) {
        ff_inetwork_log_callback(s->cbptr, s->aptr, IsSocketOpenErr, ret);
    }
    if (cur_ai != NULL && cur_ai->ai_next) {
        /* Retry with the next sockaddr */
        cur_ai = cur_ai->ai_next;
        if (fd >= 0)
            closesocket(fd);
        ret = 0;
        goto restart;
    }
fail1:
    if (fd >= 0)
        closesocket(fd);
	if (ai != NULL) {
        freeaddrinfo(ai);
	}
    return ret;
}

/**
 * ONLY for Android TFO
 * return non zero if error 
 */
static int tcp_fast_open(URLContext *h, const char *http_request, const char *uri, int flags)
{
    struct addrinfo hints = { 0 }, *ai, *cur_ai;
    int port, fd = -1;
    TCPContext *s = h->priv_data;
    const char *p;
    char buf[256];
    int ret;
    char hostname[1024],proto[1024],path[1024];
    char portstr[10];
   
    av_url_split(proto, sizeof(proto), NULL, 0, hostname, sizeof(hostname),
        &port, path, sizeof(path), uri);
    if (strcmp(proto, "tcp")) {
        av_fatal(h,AVERROR_PROTO_IS_NOT_TCP,"%d proto is not tcp", AVERROR(EINVAL));
        return AVERROR(EINVAL);
    }
    if (port <= 0 || port >= 65536) {
        av_fatal(h,AVERROR_INVALID_PORT,"%d invalid port", AVERROR(EINVAL));
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
            if (s->rw_timeout >= 0) {
                s->open_timeout = s->rw_timeout;
            }
        }
        if (av_find_info_tag(buf, sizeof(buf), "listen_timeout", p)) {
            s->listen_timeout = strtol(buf, NULL, 10);
        }
    }
    if (s->rw_timeout >= 0 ) {
        s->open_timeout =
        h->rw_timeout   = s->rw_timeout;
    }

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (s->listen)
        hints.ai_flags |= AI_PASSIVE;
#if 0
    if(s->ip_addr[0] != '\0') {
        memcpy(hostname, s->ip_addr, sizeof(s->ip_addr));
        goto lable_get;
    }
#endif

if(h->interrupt_callback.callback == NULL || hostname[0] == 0 || ff_isupport_getaddrinfo_a(s->cbptr) == 0 || s->aptr == 0) {
        if(ff_isupport_getaddrinfo_a(s->cbptr) == 0 && h->interrupt_callback.callback != NULL && hostname[0] != 0) {
            ret = tcp_getaddrinfo_a(h,hostname,portstr,&hints,&ai);
        } else {
            if (!hostname[0])
                ret = getaddrinfo(NULL, portstr, &hints, &ai);
            else
                ret = getaddrinfo(hostname, portstr, &hints, &ai);
        }
        if (ret) {
            av_fatal(h, AVERROR_GET_ADDR_INFO_FAILED,"%d Failed to resolve hostname. %s\n",ff_neterrno(), gai_strerror(ret));
            return AVERROR(EIO);
        }
        /*
        if(ai != NULL && ai->ai_addr != NULL) {
            if(ai->ai_family == AF_INET) {
                struct sockaddr_in* saddr_in = (struct sockaddr_in*)(ai->ai_addr);
                struct in_addr* sin4_addr = &saddr_in->sin_addr;
                inet_ntop(ai->ai_addr->sa_family,sin4_addr,s->ip_addr,130);
            } else if(ai->ai_family == AF_INET6) {
                struct sockaddr_in6* saddr_in = (struct sockaddr_in6*)(ai->ai_addr);
                struct in6_addr* sin6_addr = &saddr_in->sin6_addr;
                inet_ntop(ai->ai_family,&sin6_addr,s->ip_addr,130);
            }
        }*/
    } else {
        void* ctx = NULL;
        int timelost = 0;
        int timeout = s->open_timeout;
        if(timeout == -1) {
            timeout = 10*1000000;
        }
        ff_inetwork_log_callback(s->cbptr, s->aptr, IsDNSStart, s->user_flag);
        ctx = ff_igetaddrinfo_a_start(s->cbptr, s->aptr,hostname,s->user_flag);
        if(ctx == NULL) {
            av_fatal(h, AVERROR_GET_ADDR_INFO_START_FAILED, "neterrno:%d Failed to resolve hostname.ctx is null.", ff_neterrno());
            return AVERROR(EIO);
        }
	    ret = 0;
        while(!h->interrupt_callback.callback(h->interrupt_callback.opaque)) {
            ret = ff_igetaddrinfo_a_result(s->cbptr, ctx,hostname,1024);
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
            ff_igetaddrinfo_a_free(s->cbptr, ctx);
            ctx  = NULL;
        }
        if(ret > 0) {
            ret = getaddrinfo(hostname, portstr, &hints, &ai);
            if (ret) {
                av_fatal(h, AVERROR_FAILED_TO_RESOLVE_HOSTNAME,"neterrno:%d Failed to resolve hostname,error:%s\n" , ff_neterrno(), gai_strerror(ret));
                return AVERROR(EIO);
            }
            if(strlen(hostname) <= sizeof(s->ip_addr)) {
                memcpy(s->ip_addr, hostname, strlen(hostname));
            }
            ff_isave_host_addr(s->cbptr, s->aptr, s->ip_addr, s->user_flag);
            goto resovle_success;

        } else if(ret == -1) {
            av_fatal(h, AVERROR_FAILED_TO_RESOLVE_HOSTNAME, "%d Failed to resolve hostname %s.", -EFAULT, hostname);
            return AVERROR(EIO);

        } else if(ret == -2) {
            av_fatal(h, AVERROR_FAILED_TO_RESOLVE_HOSTNAME_TIMEOUT, "%d Failed to resolve hostname time out.", -ETIMEDOUT);
        } else {
            av_fatal(h, AVERROR_FAILED_TO_RESOLVE_HOSTNAME, "ret:%d neterrno:%d Failed to resolve hostname.", ret, ff_neterrno());
        }
        return AVERROR(EIO);
    }

resovle_success:
    cur_ai = ai;

 restart:
#if HAVE_STRUCT_SOCKADDR_IN6
    // workaround for IOS9 getaddrinfo in IPv6 only network use hardcode IPv4 address can not resolve port number.
    if (cur_ai->ai_family == AF_INET6){
        struct sockaddr_in6 * sockaddr_v6 = (struct sockaddr_in6 *)cur_ai->ai_addr;
        if (!sockaddr_v6->sin6_port){
            sockaddr_v6->sin6_port = htons(port);
        }
    }
#endif
    fd = ff_socket(cur_ai->ai_family,
                   cur_ai->ai_socktype,
                   cur_ai->ai_protocol);
    if (fd < 0) {
        ret = ff_neterrno();
        av_fatal(h, AVERROR_FF_SOCKET_FAILED, "neterrno:%d ff_socket failed", ret);
        goto fail;
    }
    /* Set the socket's send or receive buffer sizes, if specified.
       If unspecified or setting fails, system default is used. */
    if (s->recv_buffer_size > 0) {
        setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &s->recv_buffer_size, sizeof (s->recv_buffer_size));
    }
    if (s->send_buffer_size > 0) {
        setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &s->send_buffer_size, sizeof (s->send_buffer_size));
    }
    if (s->listen == 2) {
        // multi-client
        if ((ret = ff_listen(fd, cur_ai->ai_addr, cur_ai->ai_addrlen)) < 0) {
            av_fatal(h, AVERROR_FF_LISTEN_FAILED, "ret:%d neterrno:%d ff_listen failed", ret, ff_neterrno());
            goto fail1;
        }
    } else if (s->listen == 1) {
        // single client
        if ((ret = ff_listen_bind(fd, cur_ai->ai_addr, cur_ai->ai_addrlen,
                                  s->listen_timeout, h)) < 0) {
            av_fatal(h, AVERROR_FF_LISTEN_BIND_FAILED, "ret:%d neterrno:%d ff_listen_bind failed", ret, ff_neterrno());
            goto fail1;
        }
        // Socket descriptor already closed here. Safe to overwrite to client one.
        fd = ret;
    } else {
        if ((ret = ff_sendto(fd, http_request, strlen(http_request), FAST_OPEN_FLAG,
                 cur_ai->ai_addr, cur_ai->ai_addrlen, s->open_timeout / 1000, h, !!cur_ai->ai_next)) < 0) {
            s->fastopen_success = 0;
            if (ret == AVERROR_EXIT)
                goto fail1;
            else
                goto fail;
        } else {
            if (ret == 0) {
                s->fastopen_success = 0;
            } else {
                av_log(h, AV_LOG_DEBUG, "tfo sendto success");
                s->fastopen_success = 1;
                ff_inetwork_log_callback(s->cbptr, s->aptr, IsTcpFastOpenSuccess, s->user_flag);
            }
        } 
    }

    h->is_streamed = 1;
    s->fd = fd;

    freeaddrinfo(ai);
    ff_inetwork_log_callback(s->cbptr, s->aptr, IsSocketConnected, s->user_flag);
    return 0;

 fail:
     if (ret < 0) {
        ff_inetwork_log_callback(s->cbptr, s->aptr, IsSocketOpenErr, ret);
    }
    if (cur_ai->ai_next) {
        /* Retry with the next sockaddr */
        cur_ai = cur_ai->ai_next;
        if (fd >= 0)
            closesocket(fd);
        ret = 0;
        goto restart;
    }
 fail1:
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
        int error = ff_neterrno();
        av_fatal(s, AVERROR_FF_ACCPET_FAILED, "ret:%d neterrno:%d ff_accept failed", ret, error);
        return error;
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
                ff_inetwork_log_callback(s->cbptr, s->aptr, IsSocketReadErr, ret);
                av_fatal(h, AVERROR_READ_NETWORK_WAIT_TIMEOUT, "ret:%d neterrno:%d network wait timeout", ret, ff_neterrno());
            }
            return ret;
        }
    }
    ret = recv(s->fd, buf, size, 0);
    if (ret < 0) {
        int error = ff_neterrno();
        ff_inetwork_log_callback(s->cbptr, s->aptr, IsSocketReadErr, error);
        av_fatal(h, AVERROR_RECEIV_DATA_FAILED, "ret:%d neterrno:%d socket revc data failed", ret, error);
        return error;
    }

    if (ret > 0) {
        ff_inetwork_io_read_callback(s->cbptr, s->aptr, IsNetworkIORead, ret);
        if (!s->is_first_packet) {
            ff_inetwork_log_callback(s->cbptr, s->aptr, IsPacketRecved, s->user_flag);
            s->is_first_packet = 1;
        }
    }
    return ret;
}

static int tcp_write(URLContext *h, const uint8_t *buf, int size)
{
    TCPContext *s = h->priv_data;
    int ret;
    if (s->fd > 0 && !(h->flags & AVIO_FLAG_NONBLOCK)) {
        ret = ff_network_wait_fd_timeout(s->fd, 1, h->rw_timeout, &h->interrupt_callback);
        if (ret) {
            ff_inetwork_log_callback(s->cbptr, s->aptr, IsSocketWriteErr, ret);
            av_fatal(h, AVERROR_WRITE_NETWORK_WAIT_TIMEOUT, "ret:%d neterrno:%d network wait timeout", ret, ff_neterrno());
            return ret;
        }
    }
    
#if !defined(__APPLE__)
    if (s->fastopen && !s->tcp_connected && av_stristart(buf, "GET", NULL)) {
        ret = tcp_fast_open(h, buf, s->hostname, 0);
        if (!ret) {
            s->tcp_connected = 1;
            if (!s->fastopen_success) {
                ret = send(s->fd, buf, size, MSG_NOSIGNAL);
                if (ret > 0) {
                    s->fastopen_success = 1;
                    av_log(h, AV_LOG_DEBUG, "tfo send success");
                }
                return ret < 0 ? ff_neterrno() : ret;
            }
            return ret;
        } else {
            av_fatal(h, AVERROR_SEND_DATA_FAILED, "tcp_fast_open is error ret = %d\n", ret);
            return ret;
        }
    }
#endif
    ret = send(s->fd, buf, size, MSG_NOSIGNAL);
    if (ret < 0) {
        int error = ff_neterrno();
        ff_inetwork_log_callback(s->cbptr, s->aptr, IsSocketWriteErr, ret);
        av_fatal(h, AVERROR_SEND_DATA_FAILED, "ret:%d neterrno:%d socket send failed", ret, error);
		return error;
    }
    return ret;
}

static int tcp_shutdown(URLContext *h, int flags)
{
    TCPContext *s = h->priv_data;
#if defined(__APPLE__)
    void *socketpool = NULL;
    getSocketPoolCtx  *gsc = (getSocketPoolCtx*)s->gsc;
    if (gsc && (flags & AVIO_FLAG_REUSE)) {
        socketpool = gsc->getPool(s->aptr);
        if (socketpool) {
            gsc->givebackHandle(socketpool,s->hostname,s->port,s->fd);
            s->fd = -1;
            return 0;
        }
    }
#endif

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
    if (s->fd >= 0)
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
    int avail_len = sizeof(avail);

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
