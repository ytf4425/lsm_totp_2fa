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

#ifndef RFC4226_H
#define RFC4226_H

#include <linux/types.h>

//MAIN HOTP function
u32 HOTP(u8 *key, size_t kl, u64 interval);
//First step
u8 *hmac(unsigned char *key, int kl, u64 interval);
//Second step
u32 DT(u8 *digest);

#endif
