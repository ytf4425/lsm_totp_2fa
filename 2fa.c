#include "2fa.h"
#include "otp/base32.h"
#include "otp/rfc6238.h"
#include "utils.h"
#include <linux/ktime.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>
#include <linux/vmalloc.h>

struct hlist_head htable[16];

void init_hashtable(void)
{
    hash_init(htable);
}

struct file_node* get_file_info(char* path, int uid)
{
    int hash_value = hash_calc(path);
    struct file_node* file_entry;
    hash_for_each_possible(htable, file_entry, node, hash_value) {
        if (file_entry->hash_value == hash_value) {
            if (strcmp(file_entry->path, path) == 0 && file_entry->uid == uid) {
                return file_entry;
            }
        }
    }
    return NULL;
}

int hash_calc(char* str)
{
    int i, ret;
    for (i = 0, ret = 0; str[i] != 0; i++) {
        ret += str[i];
    }
    return ret;
}

char* get_new_2fa_code(void)
{
    time64_t timenow = ktime_get_real_seconds();
    char* ret = (char*)vmalloc(sizeof(char) * 11); // timestamp need 10 chars
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
