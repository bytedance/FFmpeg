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

#endif /* AVFORMAT_TTEXPORT_H */
