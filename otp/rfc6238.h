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

#ifndef RFC6238_H
#define RFC6238_H

#include <linux/ktime.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>
#include "rfc4226.h"

#define TSTEP 30   /* time step in seconds, default value */
#define TSTART 0


/******** RFC6238 **********
 *
 * TOTP = HOTP(k,T) where
 * K = the supersecret key
 * T = ( Current Unix time - T0) / X
 * where X is the Time Step
 *
 * *************************/


u32 TOTP(u8 *key, size_t kl, u64 time);
time64_t get_time(time64_t T0);

#endif
