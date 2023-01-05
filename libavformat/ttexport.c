/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */

#include "ttexport.h"
#include "avformat.h"
#include "avio_internal.h"
#include "network.h"
#include "url.h"
#include "internal.h"



#define TT_FF_PROTOCOL(x)                                                                \
    extern URLProtocol ff_##x##_protocol;                                                \
    int ttav_register_##x##_protocol(URLProtocol *protocol, int protocol_size);          \
    int ttav_register_##x##_protocol(URLProtocol *protocol, int protocol_size) {         \
        if (protocol_size != sizeof(URLProtocol)) {                                      \
            av_log(NULL, AV_LOG_ERROR, "ttav_register_##x##_protocol: ABI mismatch.\n"); \
            return -1;                                                                   \
        }                                                                                \
        memcpy(&ff_##x##_protocol, protocol, protocol_size);                             \
        return 0;                                                                        \
    }

#define TT_DUMMY_PROTOCOL(x)                        \
    TT_FF_PROTOCOL(x);                              \
    static const AVClass tt_##x##_context_class = { \
        .class_name = #x,                           \
        .item_name = av_default_item_name,          \
        .version = LIBAVUTIL_VERSION_INT,           \
    };                                              \
                                                    \
    URLProtocol ff_##x##_protocol = {               \
        .name = #x,                                 \
        .url_open2 = ttdummy_open,                  \
        .priv_data_size = 1,                        \
        .priv_data_class = &tt_##x##_context_class, \
    };

static int ttdummy_open(URLContext *h, const char *arg, int flags, AVDictionary **options) {
    return -1;
}

TT_DUMMY_PROTOCOL(mdl);

#if !CONFIG_LITE
TT_DUMMY_PROTOCOL(mem);
TT_DUMMY_PROTOCOL(quic);
TT_DUMMY_PROTOCOL(rearquic);
TT_DUMMY_PROTOCOL(live);
TT_DUMMY_PROTOCOL(httpx);
TT_DUMMY_PROTOCOL(rearhttpx);
TT_DUMMY_PROTOCOL(thirdparty);
TT_DUMMY_PROTOCOL(hlsproxy);
#endif


int tt_register_protocol(URLProtocol *prot, int protocol_size)
{
    int ret = -1;
    if (protocol_size != sizeof(URLProtocol))
        return ret;
    if (prot && prot->name) {
        if (strcmp(prot->name, "mdl") == 0) {
            memcpy(&ff_mdl_protocol, prot, protocol_size);
            ret = 0;
        } 
        #if !CONFIG_LITE
        ret = 0;
        if (strcmp(prot->name, "mem") == 0) {
            memcpy(&ff_mem_protocol, prot, protocol_size);
        } else if (strcmp(prot->name, "quic") == 0) {
            memcpy(&ff_quic_protocol, prot, protocol_size);
        } else if (strcmp(prot->name, "live") == 0) {
            memcpy(&ff_live_protocol, prot, protocol_size);
        } else if (strcmp(prot->name, "httpx") == 0) {
            memcpy(&ff_httpx_protocol, prot, protocol_size);
        } else if (strcmp(prot->name, "hlsproxy") == 0) {
            memcpy(&ff_hlsproxy_protocol, prot, protocol_size);
        } else {
            ret = -1;
        }
        #endif
    }
    return ret;
}

int tt_register_3rd_protocol(URLProtocol *prot, int protocol_size)
{
    if (protocol_size != sizeof(URLProtocol) || !prot)
        return -1;

    int ret = -1;
#if !CONFIG_LITE
    memcpy(&ff_thirdparty_protocol, prot, protocol_size);
    ret = 0;
#endif

    return ret;
}

void tt_set_pts_info(AVStream *s, int pts_wrap_bits,
                         unsigned int pts_num, unsigned int pts_den)
{
    avpriv_set_pts_info(s, pts_wrap_bits, pts_num, pts_den);
}

void tt_set_verify_callback(int (*callback)(void*, void*, const char*, int))
{
    ff_set_custom_verify_callback(callback);
}

int tt_register_input_format(AVInputFormat *format, int format_size)
{
    av_register_input_format(format);
    return 0;
}

void tt_read_frame_flush(AVFormatContext *s)
{
    ff_read_frame_flush(s);
}

int tt_io_read_partial(AVIOContext *s, unsigned char *buf, int size)
{
    return ffio_read_partial(s, buf, size);
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

void tt_save_host_addr(aptr_t handle, const char* ip, int user_flag) {
    ff_isave_host_addr(0, handle, ip, user_flag);
}

void tt_network_log_callback(aptr_t handle, int type, int user_flag) {
    ff_inetwork_log_callback(0, handle, type, user_flag);
}

void tt_network_io_read_callback(aptr_t handle, int type, int size) {
    ff_inetwork_io_read_callback(0, handle, type, size);
}

void tt_network_info_callback(aptr_t handle, int key, int64_t value, const char* strValue) {
    ff_inetwork_info_callback(0, handle, key, value, strValue);
}

void tt_make_absolute_url(char *buf, int size, const char *base,
                          const char *rel) {
    ff_make_absolute_url2(buf, size, base, rel);
}