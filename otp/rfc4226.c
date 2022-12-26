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

#include <crypto/hash.h>
#include <linux/module.h> /* Specifically, a module */
#include <linux/string.h>
#include <linux/types.h>
#include <linux/vmalloc.h>

u8* hmac(unsigned char* key, int kl, u64 interval)
{
    struct sdesc {
        struct shash_desc shash;
        char ctx[];
    }* sdesc;
    int size;
    struct crypto_shash* hmac_info;
    u8* result;
    result = (u8*)vmalloc(sizeof(u8) * 20); // 20 bytes SHA-1

    hmac_info = crypto_alloc_shash("hmac(sha1)", 0, 0);
    if (IS_ERR(hmac_info)) {
        pr_info("can't alloc hmac(sha1).\n");
        return NULL;
    }

    size = sizeof(struct shash_desc) + crypto_shash_descsize(hmac_info);
    sdesc = vmalloc(size);
    if (!sdesc)
        return NULL;
    sdesc->shash.tfm = hmac_info;

    if (crypto_shash_setkey(hmac_info, key, kl)) {
        pr_info("crypto_hash_setkey() failed.\n");
        return NULL;
    }

    crypto_shash_digest(&sdesc->shash, (u8*)&interval, 8, result);
    
    vfree(sdesc);
    crypto_free_shash(hmac_info);
    return result;
}

u32 DT(u8* digest)
{

    u64 offset;
    u32 bin_code;

#ifdef DEBUG

    char mdString[40];
    for (int i = 0; i < 20; i++)
        sprintf(&mdString[i * 2], "%02x", (unsigned int)digest[i]);
    printf("HMAC digest: %s\n", mdString);

#endif

    // dynamically truncates hash
    offset = digest[19] & 0x0f;

    bin_code = (digest[offset] & 0x7f) << 24
        | (digest[offset + 1] & 0xff) << 16
        | (digest[offset + 2] & 0xff) << 8
        | (digest[offset + 3] & 0xff);

    // truncates code to 6 digits
#ifdef DEBUG
    printf("OFFSET: %d\n", offset);
    printf("\nDBC1: %d\n", bin_code);
#endif

    return bin_code;
}

u32 mod_hotp(u32 bin_code)
{
    u32 otp = bin_code % 1000000;

    return otp;
}

u32 HOTP(u8* key, size_t kl, u64 interval)
{

    u8* digest;
    u32 result;
    u32 endianness;
    u32 dbc;
#ifdef DEBUG
    printf("KEY IS: %s\n", key);
    printf("KEY LEN IS: %d\n", kl);
    printf("COUNTER IS: %d\n", interval);
#endif

    endianness = 0xdeadbeef;
    if ((*(const u8*)&endianness) == 0xef) {
        interval = ((interval & 0x00000000ffffffff) << 32) | ((interval & 0xffffffff00000000) >> 32);
        interval = ((interval & 0x0000ffff0000ffff) << 16) | ((interval & 0xffff0000ffff0000) >> 16);
        interval = ((interval & 0x00ff00ff00ff00ff) << 8) | ((interval & 0xff00ff00ff00ff00) >> 8);
    };

    // First Phase, get the digest of the message using the provided key ...
    digest = (u8*)hmac(key, kl, interval);
    // digest = (u8 *)HMAC(EVP_sha1(), key, kl, (const unsigned char *)&interval, sizeof(interval), NULL, 0);
    // Second Phase, get the dbc from the algorithm
    dbc = DT(digest);
    // Third Phase: calculate the mod_k of the dbc to get the correct number
    result = mod_hotp(dbc);

    return result;
}
MODULE_LICENSE("GPL");
