#include "2fa.h"
#include "otp/base32.h"
#include "otp/rfc6238.h"
#include "utils.h"
#include <linux/vmalloc.h>
#include <linux/ktime.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>

void init_2fa(void)
{
}

char* get_new_2fa_code(void)
{
    time64_t timenow = ktime_get_real_seconds();
    char* ret = (char*)vmalloc(sizeof(char)*11);    // timestamp need 10 chars
    itoa(timenow, ret, 10);
    return ret;
}

int totp(char* key)
{
    size_t len;
    size_t keylen;
    uint8_t* k;
    uint32_t result;
    time64_t t;

    len = strlen(key);
    if (validate_b32key(key, len) == 1) {
        printk(KERN_INFO "%s: invalid base32 secret\n", key);
        return -1;
    }
    k = (uint8_t*)key;
    keylen = decode_b32key(&k, len);
    t = get_time(TSTART);
    result = TOTP(k, keylen, t);
    return result;
}

int lock(struct file_node* file_info)
{
    // TODO: lock
    printk(KERN_INFO "[proc_2fa]: %s locked.\n", file_info->path);
    return 0;
}

int unlock(struct file_node* file_info, char* key)
{
    // TODO: check
    if (1) {
        // TODO: unlock
        printk(KERN_INFO "[proc_2fa]: %s unlocked.\n", file_info->path);
    } else {
        printk(KERN_INFO "[proc_2fa]: %s failed to be unlocked.\n", file_info->path);
        return -EFAULT;
    }
    return 0;
}
