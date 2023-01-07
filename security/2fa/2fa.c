#include "2fa.h"
#include "otp/base32.h"
#include "otp/rfc6238.h"
#include "utils.h"
#include <linux/ktime.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>
#include <linux/vmalloc.h>
#include <linux/string.h>

struct hlist_head htable[16];

const char* conf_path="/etc/security/2fa.conf";
const char* primary_conf_path="/etc/security/2fa_primary_code.conf";

static struct file_node* generate_new_entry(const char* path, const char* code, int uid);
static void insert_entry_to_file(struct file_node* new_file_entry);

void init_hashtable(void)
{
    hash_init(htable);
}

void load_config(void)
{
    char line[256] = { 0 }; // 256 bytes a line
    struct file* conf_file;
    int close_result;
    loff_t fpos;
    ssize_t read_count;
    char *read_path, *read_code;
    int read_uid;
    struct file_node* new_file_entry;
    int bkt; // for debug: print all entries.

    read_path = (char*)vmalloc(sizeof(char) * 256);
    read_code = (char*)vmalloc(sizeof(char) * 256);

    /** add all 2fa entries except primary code */
    conf_file = filp_open(conf_path, O_RDONLY | O_CREAT, 0600);
    if (IS_ERR(conf_file)) {
        pr_info("[proc_2fa] init: cannot open conf: %ld.\n", PTR_ERR(conf_file));
        return;
    }

    fpos = 0;
    while ((read_count = kernel_read(conf_file, line, sizeof(line), &fpos) > 0)) {
        sscanf(line, "%s %s %d", read_path, read_code, &read_uid);
        new_file_entry = generate_new_entry(read_path, read_code, read_uid);
        hash_add(htable, &(new_file_entry->node), new_file_entry->hash_value);
    }
    close_result = filp_close(conf_file, NULL);
    pr_info("[proc_2fa] init: conf_file closed: %d\n", close_result);
    /** add all 2fa entries end */

    /** add primary code for conf_file */
    conf_file = filp_open(primary_conf_path, O_RDONLY | O_CREAT, 0600);
    if (IS_ERR(conf_file)) {
        pr_info("[proc_2fa] init: cannot open primary code conf: %ld.\n", PTR_ERR(conf_file));
        return;
    }
    fpos = 0;
    if ((read_count = kernel_read(conf_file, line, sizeof(line), &fpos) > 0)) {
        sscanf(line, "%s", read_code);
    } else {
        pr_info("[proc_2fa] init: primary code load failed, read_count is %ld.\n", read_count);
        // clean
        close_result = filp_close(conf_file, NULL);
        vfree(read_path);
        vfree(read_code);
        return;
    }
    close_result = filp_close(conf_file, NULL);
    pr_info("[proc_2fa] init: primary_conf_file closed: %d\n", close_result);

    new_file_entry = generate_new_entry(conf_path, read_code, -1);
    hash_add(htable, &(new_file_entry->node), new_file_entry->hash_value);
    new_file_entry = generate_new_entry(primary_conf_path, read_code, -1);
    hash_add(htable, &(new_file_entry->node), new_file_entry->hash_value);
    /** add primary code end */

    // do some cleaning
    vfree(read_path);
    vfree(read_code);

    // for debug: print all entries.
    hash_for_each(htable, bkt, new_file_entry, node)
    {
        pr_info("%d: path: %s, code: %s, uid: %d\n", bkt, new_file_entry->path, new_file_entry->code, new_file_entry->uid);
    }
}

struct file_node* get_file_info(char* path, int uid)
{
    int hash_value = hash_calc(path);
    struct file_node* file_entry;
    hash_for_each_possible(htable, file_entry, node, hash_value) {
        if (file_entry->hash_value != hash_value)
            continue;
        if (strcmp(file_entry->path, path) == 0 && file_entry->uid == uid) {
            return file_entry;
        }
    }
    return NULL;
}

int check_permission(char* path, int uid)
{
    int hash_value = hash_calc(path);
    struct file_node* file_entry;
    int state = UNLOCKED;

    hash_for_each_possible(htable, file_entry, node, hash_value)
    {
        if (file_entry->hash_value != hash_value)
            continue;
        if (strcmp(file_entry->path, path) != 0)
            continue;

        if (file_entry->uid == uid) {
            pr_info("[2fa_lsm] pemission denied: access %s with uid %d.\n", path, uid);
            return file_entry->state; // exact match first
        } else if (file_entry->uid == -1){
            state = file_entry->state;
            if (state == LOCKED)
                pr_info("[2fa_lsm] access pemission denied %s for all unspecified users, but it may be accessible for user %d\n", path, uid);
        }
    }
    return state;
}

static struct file_node* generate_new_entry(const char* path, const char* code, int uid){
    struct file_node* new_file_entry=(struct file_node*)vmalloc(sizeof(struct file_node));
    new_file_entry->path = (char*)vmalloc(sizeof(char) * 256);
    new_file_entry->code = (char*)vmalloc(sizeof(char) * 256);

    strcpy(new_file_entry->code, code);
    strcpy(new_file_entry->path, path);
    new_file_entry->hash_value = hash_calc(path);
    new_file_entry->state = LOCKED;
    new_file_entry->uid=uid;

    return new_file_entry;
}

void insert_new_entry(char* path, char* code, int uid)
{
    struct file_node* new_file_entry = generate_new_entry(path, code, uid);
    hash_add(htable, &(new_file_entry->node), new_file_entry->hash_value);
    insert_entry_to_file(new_file_entry);
}

void delete_entry(struct file_node* now_file){
    // TODO: delete in file

    hash_del(&(now_file->node));
    vfree(now_file->path);
    vfree(now_file->code);
    vfree(now_file);
}

static void insert_entry_to_file(struct file_node* new_file_entry){
    char line[256] = { 0 }; // 256 bytes a line
    struct file *conf_file;
    loff_t fpos;

    sprintf(line, "%s\t%s\t%d\n", new_file_entry->path, new_file_entry->code, new_file_entry->uid);

    conf_file = filp_open(conf_path, O_RDWR | O_APPEND | O_CREAT, 0600);
    if (IS_ERR(conf_file)) {
        pr_info("[proc_2fa] cannot open conf while writing conf: %ld\n", PTR_ERR(conf_file));
        return;
    }
    fpos = 0;
    kernel_write(conf_file, line, sizeof(line), &fpos);
    filp_close(conf_file, NULL);
}

int hash_calc(const char* str)
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
    char* str = (char*)vmalloc(sizeof(char) * 17); // timestamp need 10 chars, 16 bytes base32 code
    itoa(timenow, str, 10);
    return base32_encode(str, 10);
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

EXPORT_SYMBOL(lock);
EXPORT_SYMBOL(unlock);
EXPORT_SYMBOL(get_file_info);
EXPORT_SYMBOL(get_new_2fa_code);
EXPORT_SYMBOL(load_config);
EXPORT_SYMBOL(hash_calc);
EXPORT_SYMBOL(totp);
EXPORT_SYMBOL(insert_new_entry);
EXPORT_SYMBOL(delete_entry);
