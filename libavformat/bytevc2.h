/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 */

#ifndef AVFORMAT_BYTEVC2_H
#define AVFORMAT_BYTEVC2_H

#include <stdint.h>
#include "avio.h"

/**
 * Writes Annex B formatted BYTEVC2 NAL units to the provided AVIOContext.
 *
 * The NAL units are converted to an MP4-compatible format (start code prefixes
 * are replaced by 4-byte size fields, as per ISO/IEC 14496-15).
 *
 * If filter_ps is non-zero, any BYTEVC2 parameter sets found in the input will be
 * discarded, and *ps_count will be set to the number of discarded PS NAL units.
 *
 * @param pb address of the AVIOContext where the data shall be written
 * @param buf_in address of the buffer holding the input data
 * @param size size (in bytes) of the input buffer
 * @param filter_ps whether to write parameter set NAL units to the output (0)
 *        or to discard them (non-zero)
 * @param ps_count address of the variable where the number of discarded
 *        parameter set NAL units shall be written, may be NULL
 * @return the amount (in bytes) of data written in case of success, a negative
 *         value corresponding to an AVERROR code in case of failure
 */
int ff_bytevc2_annexb2mp4(AVIOContext *pb, const uint8_t *buf_in,
                       int size, int filter_ps, int *ps_count);

/**
 * Writes Annex B formatted BYTEVC2 NAL units to a data buffer.
 *
 * The NAL units are converted to an MP4-compatible format (start code prefixes
 * are replaced by 4-byte size fields, as per ISO/IEC 14496-15).
 *
 * If filter_ps is non-zero, any BYTEVC2 parameter sets found in the input will be
 * discarded, and *ps_count will be set to the number of discarded PS NAL units.
 *
 * On output, *size holds the size (in bytes) of the output data buffer.
 *
 * @param buf_in address of the buffer holding the input data
 * @param size address of the variable holding the size (in bytes) of the input
 *        buffer (on input) and of the output buffer (on output)
 * @param buf_out address of the variable holding the address of the output
 *        buffer
 * @param filter_ps whether to write parameter set NAL units to the output (0)
 *        or to discard them (non-zero)
 * @param ps_count address of the variable where the number of discarded
 *        parameter set NAL units shall be written, may be NULL
 * @return the amount (in bytes) of data written in case of success, a negative
 *         value corresponding to an AVERROR code in case of failure
 */
int ff_bytevc2_annexb2mp4_buf(const uint8_t *buf_in, uint8_t **buf_out,
                           int *size, int filter_ps, int *ps_count);

/**
 * Writes BYTEVC2 extradata (parameter sets, declarative SEI NAL units) to the
 * provided AVIOContext.
 *
 * If the extradata is Annex B format, it gets converted to hvcC format before
 * writing.
 *
 * @param pb address of the AVIOContext where the hvcC shall be written
 * @param data address of the buffer holding the data needed to write the hvcC
 * @param size size (in bytes) of the data buffer
 * @param ps_array_completeness whether all parameter sets are in the hvcC (1)
 *        or there may be additional parameter sets in the bitstream (0)
 * @return >=0 in case of success, a negative value corresponding to an AVERROR
 *         code in case of failure
 */
int ff_isom_write_bvc2c(AVIOContext *pb, const uint8_t *data,
                       int size, int ps_array_completeness);

#endif /* AVFORMAT_BYTEVC2_H */
