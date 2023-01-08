#include "2fa.h"
#include "otp/base32.h"
#include "otp/rfc6238.h"
#include <linux/ktime.h>
#include <linux/time64.h>
#include <linux/timekeeping.h>
#include <linux/vmalloc.h>
#include <linux/string.h>

extern struct hlist_head htable[16];
const char* conf_path="/etc/security/2fa.conf";
const char* primary_conf_path="/etc/security/2fa_primary_code.conf";

static struct file_node* generate_new_entry(const char* path, const char* code, int uid);
static int insert_entry_to_file(struct file_node* new_file_entry);
static int add(struct file_node* file_info, const char* path, const char* key, int uid);
static int update_config_file(struct file* conf_file);
static int unlock(struct file_node* file_info, const char* key);
static int lock(struct file_node* file_info);
static int totp(char* key);
static int insert_new_entry(const char* path, const char* code, int uid);
static int delete_entry(struct file_node* now_file, const char* key);
extern int hash_calc(const char* str);

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

struct file_node* get_file_info(const char* path, int uid)
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

static int insert_new_entry(const char* path, const char* code, int uid)
{
    int err;
    struct file_node* new_file_entry = generate_new_entry(path, code, uid);
    err = insert_entry_to_file(new_file_entry);
    hash_add(htable, &(new_file_entry->node), new_file_entry->hash_value);
    return err;
}

static int delete_entry(struct file_node* now_file, const char* key)
{
    int err;
    struct file* conf_file;

    // Unlock first. Deleting while locked is not allowed.
    if (now_file->state != UNLOCKED) {
        err = unlock(now_file, key);
        if (err != 0)
            return err;
    }

    // test file permission
    conf_file = filp_open(conf_path, O_WRONLY | O_CREAT, 0600);
    if (IS_ERR(conf_file)) {
        pr_info("[proc_2fa] delete: cannot open conf: %ld.\n", PTR_ERR(conf_file));
        return PTR_ERR(conf_file);
    }

    hash_del(&(now_file->node));
    err = update_config_file(conf_file);
    if (err) {
        filp_close(conf_file, NULL);
        return err;
    }

    vfree(now_file->path);
    vfree(now_file->code);
    vfree(now_file);
    err = filp_close(conf_file, NULL);
    pr_info("[proc_2fa] update_config_file: conf_file closed: %d\n", err);
    return err;
}

static int update_config_file(struct file* conf_file) {
    loff_t fpos;
    struct file_node* new_file_entry;
    int bkt;
    int err;

    /** write all 2fa entries except primary code */
    fpos = 0;
    hash_for_each(htable, bkt, new_file_entry, node)
    {
        if ((strcmp(new_file_entry->path, conf_path) == 0 || strcmp(new_file_entry->path, primary_conf_path) == 0)
            && (new_file_entry->uid == -1 || new_file_entry->uid == 0))
            continue;

        err = insert_entry_to_file(new_file_entry);
    }
    /** write all 2fa entries end */

    return err;
}

static int insert_entry_to_file(struct file_node* new_file_entry){
    char line[256] = { 0 }; // 256 bytes a line
    struct file *conf_file;
    loff_t fpos;

    sprintf(line, "%s\t%s\t%d\n", new_file_entry->path, new_file_entry->code, new_file_entry->uid);

    conf_file = filp_open(conf_path, O_RDWR | O_APPEND | O_CREAT, 0600);
    if (IS_ERR(conf_file)) {
        pr_info("[proc_2fa] cannot open conf while writing conf: %ld\n", PTR_ERR(conf_file));
        return PTR_ERR(conf_file);
    }
    fpos = 0;
    kernel_write(conf_file, line, sizeof(line), &fpos);
    return filp_close(conf_file, NULL);
}


// char* get_new_2fa_code(void)
// {
//     time64_t timenow = ktime_get_real_seconds();
//     char* str = (char*)vmalloc(sizeof(char) * 17); // timestamp need 10 chars, 16 bytes base32 code
//     itoa(timenow, str, 10);
//     return base32_encode(str, 10);
// }

static int totp(char* key)
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

static int lock(struct file_node* file_info)
{
    file_info->state = LOCKED;
    printk(KERN_INFO "[proc_2fa]: %s locked.\n", file_info->path);
    return 0;
}

static int unlock(struct file_node* file_info, const char* key)
{
    int key_in;
    char* key_true = (char*)vmalloc(sizeof(char) * 256);
    sscanf(key, "%d", &key_in);
    strcpy(key_true,file_info->code);
    int key_real=totp(key_true);

    if (key_real == key_in) {
        file_info->state = UNLOCKED;
        printk(KERN_INFO "[proc_2fa]: %s unlocked.\n", file_info->path);
        vfree(key_true);
        return 0;
    } else {
        printk(KERN_INFO "[proc_2fa]: %s failed to be unlocked, key_in is %d, totp is %d.\n", file_info->path, key_in, key_real);
        vfree(key_true);
        return -EFAULT;
    }
}

static int add(struct file_node* file_info, const char* path, const char* key, int uid)
{
    if (file_info != NULL) {
        pr_info("[proc_2fa]: 2fa entry has already existed: path: %s, uid: %d.\n", path, uid);
        return -EFAULT;
    }

    return insert_new_entry(path, key, uid);
}

int execute_command(struct file_node* file_info, int new_state, const char* path, const char* key, int uid)
{
    switch (new_state) {
    case LOCK:
        return lock(file_info);
    case UNLOCK:
        return unlock(file_info, key);
    case ADD:
        // char* new_code = get_new_2fa_code();
        // vfree(new_code);
        return add(file_info, path, key, uid);
    case DELETE:
        return delete_entry(file_info, key);
    default:
        printk(KERN_INFO "[proc_2fa]: /proc/2fa/state got unavaliable input.\n");
        return -EFAULT;
    }
}

EXPORT_SYMBOL(get_file_info);
EXPORT_SYMBOL(load_config);
EXPORT_SYMBOL(execute_command);
