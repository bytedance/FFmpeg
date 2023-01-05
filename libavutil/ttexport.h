/*
 * Copyright 2022 Bytedance Inc.
 * SPDX license identifier: LGPL-2.1-or-later
 *
 *
 * Export private or deprecated symbols
 */

#include <stdint.h>

/**
 * Drm open decrypt and close methods
 */
typedef int  (*tt_drm_open)   (void *handle, const char *kid);
typedef int  (*tt_drm_decrypt)(void *handle, const uint8_t *src, const int count, const uint8_t *iv, uint8_t *dst);
typedef void (*tt_drm_close)  (void *handle);

void tt_register_drm(tt_drm_open open, tt_drm_decrypt decrypt, tt_drm_close close);


/**
 * dns resolver delegate methods
 */
typedef void* (*tt_dns_start) (intptr_t handle, const char* hostname, int user_flag);
typedef int   (*tt_dns_result)(void* object, char* ipaddress, int size);
typedef void  (*tt_dns_free)  (void* object);


/**
 * network callback methods
 */
typedef void (*tt_save_ip)       (intptr_t handle, const char* ip, int user_flag);
typedef void (*tt_info_callback) (intptr_t handle, int key,  int64_t value, const char* strValue);
typedef void (*tt_log_callback)  (intptr_t handle, int type, int user_flag);
typedef void (*tt_read_callback) (intptr_t handle, int type, int size);