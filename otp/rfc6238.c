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

u32
TOTP(u8 *key, size_t kl, u64 time)
{
    u32 totp;

    totp = HOTP(key, kl, time);
    return totp;
}
MODULE_LICENSE("GPL");
