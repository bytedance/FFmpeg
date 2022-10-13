/*
 * Export private or deprecated symbols
 * 
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

#ifndef AVFORMAT_TTEXPORT_H
#define AVFORMAT_TTEXPORT_H

#include "libavformat/url.h"
#include "libavformat/avformat.h"

/**
 * A custom URLProtocol for private protocol implementation
 * This method replace the dummy protocol defined in ffmpeg, without append new one
 * 
 * @param prot pointer to URLProtocol, only support a samll set of protocols.
 * @param protocol_size additional abi check, must be same as sizeof(URLProtocol)
 * @return int Return 0 for success, others failed.
 */
int tt_register_protocol(URLProtocol *prot, int protocol_size);

/**
 * A custom AVInputFormat for private protocol implementation 
 * This method replace the dummy format defined in ffmpeg, without append new one
 *
 * @param format 
 * @param format_size additional abi check, must be same as sizeof(AVInputFormat)
 * @return int Return 0 for success, others failed.
 */
int tt_register_input_format(AVInputFormat *format, int format_size);

/**
 * Set a custom borongssl verify callback
 */
void tt_set_verify_callback(int (*callback)(void*, void*, const char*, int));


/**
 * DNS resolver delegate methods
 */
typedef void* (*tt_dns_start) (intptr_t handle, const char* hostname, int user_flag);
typedef int   (*tt_dns_result)(void* object, char* ipaddress, int size);
typedef void  (*tt_dns_free)  (void* object);

/**
 * Register dns delegate methods to ffmpeg
 */
void tt_register_dnsparser(tt_dns_start dns_start, tt_dns_result dns_result, tt_dns_free dns_free);


/**
 * Network callback methods
 */
typedef void (*tt_save_ip)       (intptr_t handle, const char* ip, int user_flag);
typedef void (*tt_info_callback) (intptr_t handle, int key,  int64_t value, const char* strValue);
typedef void (*tt_log_callback)  (intptr_t handle, int type, int user_flag);
typedef void (*tt_read_callback) (intptr_t handle, int type, int size);


/**
 * Register io events delegate methods to ffmpeg
 */
void tt_register_io_callback(tt_save_ip       save_ip, 
                             tt_log_callback  log_callback, 
                             tt_read_callback read_callback, 
                             tt_info_callback info_callback);



/**
 * Set the time base and wrapping info for a given stream. This will be used
 * to interpret the stream's timestamps. If the new time base is invalid
 * (numerator or denominator are non-positive), it leaves the stream
 * unchanged.
 *
 * @param s stream
 * @param pts_wrap_bits number of bits effectively used by the pts
 *        (used for wrap control)
 * @param pts_num time base numerator
 * @param pts_den time base denominator
 */
void tt_set_pts_info(AVStream *s, int pts_wrap_bits,
                         unsigned int pts_num, unsigned int pts_den);

/** Flush the frame reader. */
void tt_read_frame_flush(AVFormatContext *s);

#endif /* AVFORMAT_TTEXPORT_H */
