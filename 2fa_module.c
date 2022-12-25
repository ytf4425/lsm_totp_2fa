#include <asm/uaccess.h> /* for copy_from_user */
#include <linux/kernel.h> /* We're doing kernel work */
#include <linux/module.h> /* Specifically, a module */
#include <linux/proc_fs.h> /* Necessary because we use the proc fs */
#include <linux/string.h>
#include <linux/slab.h>

// #include <linux/seq_file.h> /* using seq_printf */
// #include <linux/slab.h>     /* Using kzalloc */

#define PROCFS_NAME "2fa"
#define MAX_BUFF_SIZE 2048

MODULE_AUTHOR("Tommy Yu");
static char* sbuff= NULL;
struct proc_dir_entry *dir, *fpath, *fkey, *fstate;
char *path = "", *key = "", *state = "locked";

static int unlock(void);
static int lock(void);
static ssize_t proc_read_state(struct file* file, char __user* buffer, size_t count, loff_t* f_pos);
static ssize_t proc_write_state(struct file* file, const char __user* buffer, size_t count, loff_t* f_pos);

static const struct proc_ops path_fops = {
    .proc_read = proc_read_state,
    .proc_write = proc_write_state,
};
static const struct proc_ops key_fops = {
    .proc_read = proc_read_state,
    .proc_write = proc_write_state,
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
    // sbuff = (char*)vmalloc(MAX_BUFF_SIZE);
    // if (!sbuff)
    //     return -ENOMEM;
    // else
    //     memset(sbuff, 0, MAX_BUFF_SIZE);
    // strcpy(sbuff, "aaa");

    return 0;
}

static void __exit proc_2fa_exit(void)
{
    proc_remove(dir);
    // vfree(sbuff);
    printk(KERN_INFO "[proc_2fa] module exit.\n");
}

static ssize_t proc_read_state(struct file* file, char __user* buffer, size_t count, loff_t* f_pos)
{
    count = strlen(state);
    if (*f_pos >= count) {
        return 0;
    }
    count -= *f_pos;
    if (copy_to_user(buffer, sbuff + *f_pos, count)) {
        return -EFAULT;
    }
    *f_pos += count;
    return count;
}

static ssize_t proc_write_state(struct file* file, const char __user* buffer, size_t count, loff_t* f_pos)
{
    int new_state;

    count = count < MAX_BUFF_SIZE ? count : MAX_BUFF_SIZE;

    char* tmp = kzalloc((count + 1), GFP_KERNEL);
    if (!tmp)
        return -ENOMEM;
    if (copy_from_user(tmp, buffer, count)) {
        printk(KERN_INFO "[proc_2fa]: copy_from_user() error!\n");
        kfree(tmp);
        return -EFAULT;
    }
    kfree(sbuff);
    sbuff = tmp;

    sscanf(sbuff, "%d", &new_state);
    if (new_state == 1)
        lock();
    else if (new_state == 0) {
        if (unlock())
            return -EFAULT;
    } else {
        printk(KERN_INFO "[proc_2fa]: /proc/2fa/state got unavaliable input.\n");
        return -EFAULT;
    }
    return count;
}

static int lock(void)
{
    sbuff = "lock";
    printk(KERN_INFO "[proc_2fa]: %s locked.\n", path);
    return 0;
}

static int unlock(void)
{
    if (1) {
        printk(KERN_INFO "[proc_2fa]: %s unlocked.\n", path);
    } else {
        printk(KERN_INFO "[proc_2fa]: %s failed to be unlocked.\n", path);
        return -EFAULT;
    }
    return 0;
}

module_init(proc_2fa_init);
module_exit(proc_2fa_exit);
MODULE_LICENSE("GPL");
