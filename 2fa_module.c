#include <asm/uaccess.h> /* for copy_from_user */
#include <linux/kernel.h> /* We're doing kernel work */
#include <linux/module.h> /* Specifically, a module */
#include <linux/proc_fs.h> /* Necessary because we use the proc fs */
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/time.h> 
#include "otp/rfc4226.h"
#include "otp/rfc6238.h"
#include "otp/base32.h"
#include "utils.h"
#include "2fa.h"

// #include <linux/seq_file.h> /* using seq_printf */
// #include <linux/slab.h>     /* Using kzalloc */

#define PROCFS_NAME "2fa"
#define MAX_BUFF_SIZE 2048

MODULE_AUTHOR("Tommy Yu");
static char* sbuff = NULL;
static struct proc_dir_entry *dir, *fpath, *fkey, *fstate;
static char *path = NULL, *key = NULL;

static ssize_t proc_read_state(struct file* file, char __user* buffer, size_t count, loff_t* f_pos);
static ssize_t proc_write_state(struct file* file, const char __user* buffer, size_t count, loff_t* f_pos);
static ssize_t proc_read_path(struct file* file, char __user* buffer, size_t count, loff_t* f_pos);
static ssize_t proc_write_path(struct file* file, const char __user* buffer, size_t count, loff_t* f_pos);
static ssize_t proc_write_key(struct file* file, const char __user* buffer, size_t count, loff_t* f_pos);

static const struct proc_ops path_fops = {
    .proc_read = proc_read_path,
    .proc_write = proc_write_path,
};
static const struct proc_ops key_fops = {
    .proc_write = proc_write_key,
};

static const struct proc_ops state_fops = {
    .proc_read = proc_read_state,
    .proc_write = proc_write_state,
};

static int __init proc_2fa_init(void)
{
    /* prepare procfs */
    dir = proc_mkdir(PROCFS_NAME, NULL);
    if (dir == NULL)
        return -ENOMEM;
    else {
        fpath = proc_create("path", 0777, dir, &path_fops);
        fkey = proc_create("key", 0777, dir, &key_fops);
        fstate = proc_create("state", 0777, dir, &state_fops);
        if (fpath == NULL || fkey == NULL || fstate == NULL)
            return -ENOMEM;
        else
            printk(KERN_INFO "[proc_2fa] module loaded.\n");
    }

    /* init buff */
    sbuff = (char*)vmalloc(MAX_BUFF_SIZE);
    path = (char*)vmalloc(MAX_BUFF_SIZE);
    key = (char*)vmalloc(MAX_BUFF_SIZE);
    if (!sbuff || !path || !key)
        return -ENOMEM;
    else {
        memset(sbuff, 0, MAX_BUFF_SIZE);
        memset(path, 0, MAX_BUFF_SIZE);
        memset(key, 0, MAX_BUFF_SIZE);
    }

    init_hashtable();
    return 0;
}

static void __exit proc_2fa_exit(void)
{
    proc_remove(dir);
    vfree(sbuff);
    vfree(path);
    vfree(key);
    if (!IS_ERR(conf_file)) {
        filp_close(conf_file, NULL);
    }
    printk(KERN_INFO "[proc_2fa] module exit.\n");
}

static ssize_t proc_write_key(struct file* file, const char __user* buffer, size_t count, loff_t* f_pos)
{
    count = count < MAX_BUFF_SIZE ? count : MAX_BUFF_SIZE;

    if (copy_from_user(sbuff, buffer, count)) { // error
        printk(KERN_INFO "[proc_2fa]: copy_from_user() error!\n");
        return -EFAULT;
    }

    sscanf(sbuff, "%s", key);

    if (strlen(key)!=6) {
        printk(KERN_INFO "[proc_2fa]: /proc/2fa/key got unavaliable input.\n");
        return -EFAULT;
    }
    return count;
}

static ssize_t proc_read_path(struct file* file, char __user* buffer, size_t count, loff_t* f_pos)
{
    count = strlen(path);
    if (*f_pos >= count) {
        return 0;
    }
    count -= *f_pos;
    if (copy_to_user(buffer, path + *f_pos, count)) {
        return -EFAULT;
    }
    *f_pos += count;
    return count;
}

static ssize_t proc_write_path(struct file* file, const char __user* buffer, size_t count, loff_t* f_pos)
{
    count = count < MAX_BUFF_SIZE ? count : MAX_BUFF_SIZE;

    if (copy_from_user(sbuff, buffer, count)) { // error
        printk(KERN_INFO "[proc_2fa]: copy_from_user() error!\n");
        return -EFAULT;
    }

    sscanf(sbuff, "%s", path);

    // TODO: check path
    if (0) {
        printk(KERN_INFO "[proc_2fa]: /proc/2fa/path got unavaliable input.\n");
        return -EFAULT;
    }
    return count;
}


static ssize_t proc_read_state(struct file* file, char __user* buffer, size_t count, loff_t* f_pos)
{
    // TODO: read state to sbuff

    strcpy(key,"M52WQZ3IM5UGU5Q=");
    int a=totp(key);
    pr_info("%d\n",a);
    char * stra = (char*)vmalloc(100);
    get_new_2fa_code();
    itoa(a,stra,10);
    count = strlen(stra);
    if (*f_pos >= count) {
        return 0;
    }
    count -= *f_pos;
    if (copy_to_user(buffer, stra + *f_pos, count)) {
        return -EFAULT;
    }
    *f_pos += count;
    return count;
}

static ssize_t proc_write_state(struct file* file, const char __user* buffer, size_t count, loff_t* f_pos)
{
    int new_state;
    struct file_node file_info;

    count = count < MAX_BUFF_SIZE ? count : MAX_BUFF_SIZE;

    if (copy_from_user(sbuff, buffer, count)) { // error
        printk(KERN_INFO "[proc_2fa]: copy_from_user() error!\n");
        return -EFAULT;
    }

    sscanf(sbuff, "%d", &new_state);
    if (new_state == 1)
        lock(&file_info);
    else if (new_state == 0) {
        if (unlock(&file_info,key))
            return -EFAULT;
    } else {
        printk(KERN_INFO "[proc_2fa]: /proc/2fa/state got unavaliable input.\n");
        return -EFAULT;
    }
    return count;
}

module_init(proc_2fa_init);
module_exit(proc_2fa_exit);
MODULE_LICENSE("GPL");
