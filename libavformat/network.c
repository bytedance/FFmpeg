/*
 * Copyright (c) 2007 The FFmpeg Project
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

#include <fcntl.h>
#include "network.h"
#include "tls.h"
#include "url.h"
#include "libavcodec/internal.h"
#include "libavutil/avutil.h"
#include "libavutil/mem.h"
#include "libavutil/time.h"
#include "libavutil/ttmapp.h"

static getaddrinfo_a_ctx gGetAddrinfo_a= {
    .start = NULL,
    .result = NULL,
    .free = NULL,
    .save_ip = NULL,
    .log_callback = NULL,
    .io_callback  = NULL,
    .info_callback = NULL,
};
static resourceLoader_ctx gResourceLoader= {
    .open  = NULL,
    .read  = NULL,
    .seek  = NULL,
    .close = NULL,
};
static int (*ff_custom_verify_callback)(void*, void*, const char*, int) = NULL;
int ff_support_resourceloader() {
    if(gResourceLoader.open == NULL || gResourceLoader.read == NULL ||
       gResourceLoader.seek == NULL || gResourceLoader.close == NULL) {
        return 0;
    }
    return 1;
}
int ff_support_getaddrinfo_a() {
    if(gGetAddrinfo_a.start == NULL || gGetAddrinfo_a.result == NULL || gGetAddrinfo_a.free == NULL) {
        return 0;
    }
    return 1;
}

int ff_isupport_getaddrinfo_a(uint64_t cb_ctx) {
    if (cb_ctx == 0)
        return ff_support_getaddrinfo_a();
    else {
        TTmAppCallbackCtx *app_cb = av_ttm_app_cast(cb_ctx);
        if (app_cb != NULL && app_cb->addr_start != NULL && app_cb->addr_result != NULL && app_cb->addr_free != NULL)
            return 1;
        else if(app_cb != NULL && app_cb->addr_start == NULL && app_cb->addr_result == NULL && app_cb->addr_free == NULL)
            return ff_support_getaddrinfo_a();
    }
    return 0;
}

void ff_resourceloader_init(resource_loader_open open, resource_loader_read read, resource_loader_seek seek, resource_loader_close close) {
    gResourceLoader.open  = open;
    gResourceLoader.read  = read;
    gResourceLoader.seek  = seek;
    gResourceLoader.close = close;
}

void ff_getaddrinfo_a_init(getaddrinfo_a_start getinfo, getaddrinfo_a_result result,getaddrinfo_a_free end,
                           save_host_addr save_ip,  network_log_callback log_callback, tcp_io_read_callback io_callback,
                           network_info_callback info_callback) {
    gGetAddrinfo_a.start = getinfo;
    gGetAddrinfo_a.result = result;
    gGetAddrinfo_a.free = end;
    gGetAddrinfo_a.save_ip = save_ip;
    gGetAddrinfo_a.log_callback = log_callback;
    gGetAddrinfo_a.io_callback = io_callback;
    gGetAddrinfo_a.info_callback = info_callback;
}

void ff_register_dns_parser(getaddrinfo_a_start getinfo, getaddrinfo_a_result result, getaddrinfo_a_free end) {
    if (ff_support_getaddrinfo_a()) {
        return;
    }
    gGetAddrinfo_a.start = getinfo;
    gGetAddrinfo_a.result = result;
    gGetAddrinfo_a.free = end;
}

void* ff_igetaddrinfo_a_start(uint64_t cb_ctx, uint64_t handle,const char* hostname, int user_flag) {
    TTmAppCallbackCtx *app_cb = av_ttm_app_cast(cb_ctx);
    if (app_cb == NULL || app_cb->addr_start == NULL) {
        if (ff_support_getaddrinfo_a()) {
            return gGetAddrinfo_a.start(handle,hostname,user_flag);
        } else {
            return NULL;
        }
    } else {
        if (app_cb && app_cb->addr_start != NULL) {
            return app_cb->addr_start(handle, hostname, user_flag);
        } else {
            return NULL;
        }
    }
}

int ff_igetaddrinfo_a_result(uint64_t cb_ctx, void* ctx,char* ipaddress,int size) {
    TTmAppCallbackCtx *app_cb = av_ttm_app_cast(cb_ctx);
    if (app_cb == NULL || app_cb->addr_result == NULL) {
        if (ff_support_getaddrinfo_a()) {
            return gGetAddrinfo_a.result(ctx,ipaddress,size);
        } else {
            return -1;
        }
    } else {
        if (app_cb && app_cb->addr_result != NULL) {
            return app_cb->addr_result(ctx, ipaddress, size);
        } else {
            return -1;
        }
    }
}

void ff_igetaddrinfo_a_free(uint64_t cb_ctx, void* ctx) {
    TTmAppCallbackCtx *app_cb = av_ttm_app_cast(cb_ctx);
    if (app_cb == NULL || app_cb->addr_free == NULL) {
        if (ff_support_getaddrinfo_a()) {
            gGetAddrinfo_a.free(ctx);
        }
    } else {
        if (app_cb && app_cb->addr_free != NULL) {
            app_cb->addr_free(ctx);
        }
    }
}

void ff_isave_host_addr(uint64_t cb_ctx, aptr_t handle, const char* ip, int user_flag) {
    if (cb_ctx == 0) {
        if (gGetAddrinfo_a.save_ip != NULL) {
            gGetAddrinfo_a.save_ip(handle, ip, user_flag);
        }
    } else {
        TTmAppCallbackCtx *app_cb = av_ttm_app_cast(cb_ctx);
        if (app_cb && app_cb->save_ip != NULL) {
            app_cb->save_ip(handle, ip, user_flag);
        }
    }
}

void ff_inetwork_log_callback(uint64_t cb_ctx, aptr_t handle, int type, int user_flag) {
    if (cb_ctx == 0) {
        if (gGetAddrinfo_a.log_callback != NULL) {
            gGetAddrinfo_a.log_callback(handle, type, user_flag);
        }
    } else {
        TTmAppCallbackCtx *app_cb = av_ttm_app_cast(cb_ctx);
        if (app_cb && app_cb->log_callback != NULL) {
            app_cb->log_callback(handle, type, user_flag);
        }
    }
}

void ff_inetwork_io_read_callback(uint64_t cb_ctx, aptr_t handle, int type, int size) {
    if (cb_ctx == 0) {
        if (gGetAddrinfo_a.io_callback != NULL && size > 0) {
            gGetAddrinfo_a.io_callback(handle, type, size);
        }
    } else {
        TTmAppCallbackCtx *app_cb = av_ttm_app_cast(cb_ctx);
        if (app_cb && app_cb->io_callback != NULL) {
            app_cb->io_callback(handle, type, size);
        }
    }
}

void ff_inetwork_info_callback(uint64_t cb_ctx, aptr_t handle, int key, int64_t value, const char* strValue) {
    if (cb_ctx == 0) {
        if (gGetAddrinfo_a.info_callback != NULL) {
            gGetAddrinfo_a.info_callback(handle, key, value, strValue);
        }
    } else {
        TTmAppCallbackCtx *app_cb = av_ttm_app_cast(cb_ctx);
        if (app_cb && app_cb->info_callback != NULL) {
            app_cb->info_callback(handle, key, value, strValue);
        }
    }
}

void ff_set_custom_verify_callback(int (*callback)(void*, void*, const char*, int)) {
    ff_custom_verify_callback = callback;
}
int ff_do_custom_verify_callback(void* context, void* ssl, const char* host, int port) {
    if (ff_custom_verify_callback != NULL) {
        return ff_custom_verify_callback(context, ssl, host, port);
    }
    return 0;
}

int ff_tls_init(void)
{
#if CONFIG_TLS_OPENSSL_PROTOCOL
    int ret;
    if ((ret = ff_openssl_init()) < 0)
        return ret;
#endif
#if CONFIG_TLS_GNUTLS_PROTOCOL
    ff_gnutls_init();
#endif
    return 0;
}

void ff_tls_deinit(void)
{
#if CONFIG_TLS_OPENSSL_PROTOCOL
    ff_openssl_deinit();
#endif
#if CONFIG_TLS_GNUTLS_PROTOCOL
    ff_gnutls_deinit();
#endif
}

int ff_network_inited_globally;

int ff_network_init(void)
{
#if HAVE_WINSOCK2_H
    WSADATA wsaData;
#endif

    if (!ff_network_inited_globally)
        av_log(NULL, AV_LOG_WARNING, "Using network protocols without global "
                                     "network initialization. Please use "
                                     "avformat_network_init(), this will "
                                     "become mandatory later.\n");
#if HAVE_WINSOCK2_H
    if (WSAStartup(MAKEWORD(1,1), &wsaData))
        return 0;
#endif
    return 1;
}

int ff_network_wait_fd(int fd, int write)
{
    int ev = write ? POLLOUT : POLLIN;
    struct pollfd p = { .fd = fd, .events = ev, .revents = 0 };
    int ret;
    ret = poll(&p, 1, POLLING_TIME);
    return ret < 0 ? ff_neterrno() : p.revents & (ev | POLLERR | POLLHUP) ? 0 : AVERROR(EAGAIN);
}

static int ff_network_wait_fds(int fd0,int fd1,int write)
{
    int ev = write ? POLLOUT : POLLIN;
    struct pollfd p[2] = {
		{ .fd = fd0, .events = ev, .revents = 0 },
		{ .fd = fd1, .events = ev, .revents = 0 }
		};
    int ret;
    ret = poll(&p, 2, POLLING_TIME);
    return ret < 0 ? ff_neterrno() : p[0].revents & (ev | POLLERR | POLLHUP) ? 0 : AVERROR(EAGAIN);
}
int ff_network_wait_fd_timeout(int fd, int write, int64_t timeout, AVIOInterruptCB *int_cb)
{
    int ret;
    int64_t wait_start = 0;

    while (1) {
        if (ff_check_interrupt(int_cb))
            return AVERROR_EXIT;
	
        ret = int_cb>0 && int_cb->fd > 0? ff_network_wait_fds(fd,int_cb->fd,write):ff_network_wait_fd(fd, write);
        if (ret != AVERROR(EAGAIN))
            return ret;
        if (timeout > 0) {
            if (!wait_start)
                wait_start = av_gettime_relative();
            else if (av_gettime_relative() - wait_start > timeout)
                return AVERROR(ETIMEDOUT);
        }
    }
}

void ff_network_close(void)
{
#if HAVE_WINSOCK2_H
    WSACleanup();
#endif
}

#if HAVE_WINSOCK2_H
int ff_neterrno(void)
{
    int err = WSAGetLastError();
    switch (err) {
    case WSAEWOULDBLOCK:
        return AVERROR(EAGAIN);
    case WSAEINTR:
        return AVERROR(EINTR);
    case WSAEPROTONOSUPPORT:
        return AVERROR(EPROTONOSUPPORT);
    case WSAETIMEDOUT:
        return AVERROR(ETIMEDOUT);
    case WSAECONNREFUSED:
        return AVERROR(ECONNREFUSED);
    case WSAEINPROGRESS:
        return AVERROR(EINPROGRESS);
    }
    return -err;
}
#endif

int ff_is_multicast_address(struct sockaddr *addr)
{
    if (addr->sa_family == AF_INET) {
        return IN_MULTICAST(ntohl(((struct sockaddr_in *)addr)->sin_addr.s_addr));
    }
#if HAVE_STRUCT_SOCKADDR_IN6
    if (addr->sa_family == AF_INET6) {
        return IN6_IS_ADDR_MULTICAST(&((struct sockaddr_in6 *)addr)->sin6_addr);
    }
#endif

    return 0;
}

static int ff_poll_interrupt(struct pollfd *p, nfds_t nfds, int timeout,
                             AVIOInterruptCB *cb)
{
    int runs = timeout / POLLING_TIME;
    int ret = 0;

    do {
        if (ff_check_interrupt(cb))
            return AVERROR_EXIT;
        ret = poll(p, nfds, POLLING_TIME);
        if (ret != 0)
            break;
    } while (timeout <= 0 || runs-- > 0);

    if (!ret)
        return AVERROR(ETIMEDOUT);
    if (ret < 0)
        return AVERROR(errno);
    return ret;
}

int ff_socket(int af, int type, int proto)
{
    int fd;

#ifdef SOCK_CLOEXEC
    fd = socket(af, type | SOCK_CLOEXEC, proto);
    if (fd == -1 && errno == EINVAL)
#endif
    {
        fd = socket(af, type, proto);
#if HAVE_FCNTL
        if (fd != -1) {
            if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1)
                av_log(NULL, AV_LOG_DEBUG, "Failed to set close on exec\n");
        }
#endif
    }
#ifdef SO_NOSIGPIPE
    if (fd != -1)
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &(int){1}, sizeof(int));
#endif
    return fd;
}

int ff_listen(int fd, const struct sockaddr *addr,
              socklen_t addrlen)
{
    int ret;
    int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) {
        av_log(NULL, AV_LOG_WARNING, "setsockopt(SO_REUSEADDR) failed\n");
    }
    ret = bind(fd, addr, addrlen);
    if (ret)
        return ff_neterrno();

    ret = listen(fd, 1);
    if (ret)
        return ff_neterrno();
    return ret;
}

int ff_accept(int fd, int timeout, URLContext *h)
{
    int ret;
    struct pollfd lp = { fd, POLLIN, 0 };

    ret = ff_poll_interrupt(&lp, 1, timeout, &h->interrupt_callback);
    if (ret < 0)
        return ret;

    ret = accept(fd, NULL, NULL);
    if (ret < 0)
        return ff_neterrno();
    if (ff_socket_nonblock(ret, 1) < 0)
        av_log(NULL, AV_LOG_DEBUG, "ff_socket_nonblock failed\n");

    return ret;
}

int ff_listen_bind(int fd, const struct sockaddr *addr,
                   socklen_t addrlen, int timeout, URLContext *h)
{
    int ret;
    if ((ret = ff_listen(fd, addr, addrlen)) < 0)
        return ret;
    if ((ret = ff_accept(fd, timeout, h)) < 0)
        return ret;
    closesocket(fd);
    return ret;
}

static int ff_listen_connect_internal(int fd, const struct sockaddr *addr,
                               socklen_t addrlen, int fast_open)
{
#if defined(__APPLE__)
    sa_endpoints_t endpoints;
    if (fast_open) {
        endpoints.sae_srcif = 0;
        endpoints.sae_srcaddr = NULL;
        endpoints.sae_srcaddrlen = 0;
        endpoints.sae_dstaddr = addr;
        endpoints.sae_dstaddrlen = addrlen;
        return connectx(fd, &endpoints, SAE_ASSOCID_ANY, CONNECT_RESUME_ON_READ_WRITE | CONNECT_DATA_IDEMPOTENT, NULL, 0, NULL, NULL);
    }
#endif
    return connect(fd, addr, addrlen);
}

int ff_listen_connect2(int fd, const struct sockaddr *addr,
                      socklen_t addrlen, int timeout, URLContext *h,
                      int will_try_next, int fast_open)
{
    struct pollfd p = {fd, POLLOUT, 0};
    int ret;
    socklen_t optlen;

    if (ff_socket_nonblock(fd, 1) < 0)
        av_log(NULL, AV_LOG_DEBUG, "ff_socket_nonblock failed\n");
    
    while ((ret = ff_listen_connect_internal(fd, addr, addrlen, fast_open))) {
        ret = ff_neterrno();
        switch (ret) {
        case AVERROR(EINTR):
            if (ff_check_interrupt(&h->interrupt_callback))
                return AVERROR_EXIT;
            continue;
        case AVERROR(EINPROGRESS):
        case AVERROR(EAGAIN):
            ret = ff_poll_interrupt(&p, 1, timeout, &h->interrupt_callback);
            if (ret < 0) {
                av_fatal(h, AVERROR_FF_SOCKET_CONNECT_FAILED, "ret:%d neterrno:%d ff_poll_interrupt error", ret, ff_neterrno());
                return ret;
            }
            optlen = sizeof(ret);
            if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &ret, &optlen)) {
                av_fatal(h, AVERROR_FF_SOCKET_CONNECT_FAILED, "ret:%d neterrno:%d getsockop error", ret, ff_neterrno());
                ret = AVUNERROR(ff_neterrno());
            }
            if (ret != 0) {
                char errbuf[100];
                ret = AVERROR(ret);
                av_strerror(ret, errbuf, sizeof(errbuf));
                if (will_try_next)
                    av_log(h, AV_LOG_WARNING,
                           "Connection to %s failed (%s), trying next address\n",
                           h->filename, errbuf);
                else {
                    av_fatal(h, AVERROR_FF_SOCKET_CONNECT_FAILED, "ret:%d neterrno:%d Connection to %s failed: %s\n", ret, ff_neterrno(), h->filename, errbuf);
                }
            }
            return ret;
        default:
            if (ret < 0 ) {
                av_fatal(h, AVERROR_FF_SOCKET_CONNECT_FAILED, "ret:%d neterrno:%d default error", ret, ff_neterrno());
            }
            return ret;
        }
    }
    return ret;
}

int ff_listen_connect(int fd, const struct sockaddr *addr,
                      socklen_t addrlen, int timeout, URLContext *h,
                      int will_try_next)
{
    return ff_listen_connect2(fd, addr, addrlen, timeout, h, will_try_next, 0);
}

int ff_sendto(int fd, const char *msg, int msg_len, int flag,
                      const struct sockaddr *addr,
                      socklen_t addrlen, int timeout, URLContext *h,
                      int will_try_next)
{
    struct pollfd p = {fd, POLLOUT, 0};
    int ret;
    socklen_t optlen;

    if (ff_socket_nonblock(fd, 1) < 0)
        av_log(NULL, AV_LOG_INFO, "ff_socket_nonblock failed\n");

    while ((ret = sendto(fd, msg, msg_len, flag, addr, addrlen)) < 0) {
        ret = ff_neterrno();
        switch (ret) {
        case AVERROR(EINTR):
            if (ff_check_interrupt(&h->interrupt_callback))
                return AVERROR_EXIT;
            continue;
        case AVERROR(EINPROGRESS):
        case AVERROR(EAGAIN):
            ret = ff_poll_interrupt(&p, 1, timeout, &h->interrupt_callback);
            if (ret < 0)
                return ret;
            optlen = sizeof(ret);
            if (getsockopt (fd, SOL_SOCKET, SO_ERROR, &ret, &optlen))
                ret = AVUNERROR(ff_neterrno());
            if (ret != 0) {
                char errbuf[100];
                ret = AVERROR(ret);
                av_strerror(ret, errbuf, sizeof(errbuf));
                if (will_try_next)
                    av_log(h, AV_LOG_WARNING,
                           "Connection to %s failed (%s), trying next address\n",
                           h->filename, errbuf);
                else
                    av_log(h, AV_LOG_ERROR, "Connection to %s failed: %s\n",
                           h->filename, errbuf);
            }
        default:
            return ret;
        }
    }
    return ret;
}

static int match_host_pattern(const char *pattern, const char *hostname)
{
    int len_p, len_h;
    if (!strcmp(pattern, "*"))
        return 1;
    // Skip a possible *. at the start of the pattern
    if (pattern[0] == '*')
        pattern++;
    if (pattern[0] == '.')
        pattern++;
    len_p = strlen(pattern);
    len_h = strlen(hostname);
    if (len_p > len_h)
        return 0;
    // Simply check if the end of hostname is equal to 'pattern'
    if (!strcmp(pattern, &hostname[len_h - len_p])) {
        if (len_h == len_p)
            return 1; // Exact match
        if (hostname[len_h - len_p - 1] == '.')
            return 1; // The matched substring is a domain and not just a substring of a domain
    }
    return 0;
}

int ff_http_match_no_proxy(const char *no_proxy, const char *hostname)
{
    char *buf, *start;
    int ret = 0;
    if (!no_proxy)
        return 0;
    if (!hostname)
        return 0;
    buf = av_strdup(no_proxy);
    if (!buf)
        return 0;
    start = buf;
    while (start) {
        char *sep, *next = NULL;
        start += strspn(start, " ,");
        sep = start + strcspn(start, " ,");
        if (*sep) {
            next = sep + 1;
            *sep = '\0';
        }
        if (match_host_pattern(start, hostname)) {
            ret = 1;
            break;
        }
        start = next;
    }
    av_free(buf);
    return ret;
}
