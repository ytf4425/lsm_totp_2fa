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

#include <linux/module.h> /* Specifically, a module */
#include "rfc6238.h"

time64_t
get_time(time64_t t0)
{
    return (ktime_get_real_seconds() - t0) / TSTEP;
}

uint32_t
TOTP(uint8_t *key, size_t kl, uint64_t time)
{
    uint32_t totp;

    totp = HOTP(key, kl, time);
    return totp;
}
MODULE_LICENSE("GPL");
