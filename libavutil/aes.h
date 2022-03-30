/*
 * copyright (c) 2007 Michael Niedermayer <michaelni@gmx.at>
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

#ifndef AVUTIL_AES_H
#define AVUTIL_AES_H

#include <stdint.h>

#include "attributes.h"
#include "version.h"

/**
 * @defgroup lavu_aes AES
 * @ingroup lavu_crypto
 * @{
 */

extern const int av_aes_size;

struct AVAES;

/**
 * Allocate an AVAES context.
 */
struct AVAES *av_aes_alloc(void);

/**
 * Initialize an AVAES context.
 * @param key_bits 128, 192 or 256
 * @param decrypt 0 for encryption, 1 for decryption
 */
int av_aes_init(struct AVAES *a, const uint8_t *key, int key_bits, int decrypt);

/**
 * Encrypt or decrypt a buffer using a previously initialized context.
 * @param count number of 16 byte blocks
 * @param dst destination array, can be equal to src
 * @param src source array, can be equal to dst
 * @param iv initialization vector for CBC mode, if NULL then ECB will be used
 * @param decrypt 0 for encryption, 1 for decryption
 */
void av_aes_crypt(struct AVAES *a, uint8_t *dst, const uint8_t *src, int count, uint8_t *iv, int decrypt);

/**
 * @brief Decrypt a cipher to plain text, using gcm 256 mode. 
 * 
 * @param ciphertext encrypted text to be decrypt, bytes array.
 * @param ciphertext_len length of the ciphertext's byte array.
 * @param aad not necessary 
 * @param aad_len not necessary
 * @param tag not necessary.
 * @param key aes gcm decrypt key 
 * @param iv initial vector (aka. nonce)
 * @param iv_len number of bytes of iv.
 * @param plaintext output decrypted text to plaintext
 * @return int length of output plaintext, if >0, decrypt successfully, any other else value should be treated as failure.
 */
int av_aes_gcm_256_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                           const unsigned char *aad, int aad_len,
                           const unsigned char *tag,
                           const unsigned char *key,
                           const unsigned char *iv, int iv_len,
                           unsigned char *plaintext);

/**
 * @}
 */

#endif /* AVUTIL_AES_H */
