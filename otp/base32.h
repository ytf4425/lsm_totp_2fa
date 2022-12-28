/*
 *
 *  TOTP: Time-Based One-Time Password Algorithm
 *  Copyright (c) 2017, fmount <fmount9@autistici.org>
 *
 *  This software is distributed under MIT License
 *
 *  Compute the hmac using openssl library.
 *  SHA-1 engine is used by default, but you can pass another one,
 *
 *  e.g EVP_md5(), EVP_sha224, EVP_sha512, etc
 *
 */

#ifndef _BASE32_H
#define _BASE32_H

#include <linux/string.h>
#include <linux/types.h>

// 64 MB should be more than enough
#define MAX_ENCODE_INPUT_LEN 64 * 1024 * 1024

int validate_b32key(char* k, size_t len);
size_t decode_b32key(uint8_t** k, size_t len);
char* base32_encode(const unsigned char* user_data, size_t data_len);

#endif
