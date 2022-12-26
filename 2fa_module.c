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

// #include <linux/seq_file.h> /* using seq_printf */
// #include <linux/slab.h>     /* Using kzalloc */

#define PROCFS_NAME "2fa"
#define MAX_BUFF_SIZE 2048

MODULE_AUTHOR("Tommy Yu");
static char* sbuff = NULL;
static struct proc_dir_entry *dir, *fpath, *fkey, *fstate;
static char *path = NULL, *key = NULL;

static int unlock(void);
static int lock(void);
static int totp(char* key);
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
    return 0;
}

static void __exit proc_2fa_exit(void)
{
    proc_remove(dir);
    vfree(sbuff);
    vfree(path);
    vfree(key);
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

char* itoa(int num,char* str,int radix)
{
    char index[]="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";//索引表
    unsigned unum;//存放要转换的整数的绝对值,转换的整数可能是负数
    int i=0,j,k;//i用来指示设置字符串相应位，转换之后i其实就是字符串的长度；转换后顺序是逆序的，有正负的情况，k用来指示调整顺序的开始位置;j用来指示调整顺序时的交换。
 
    //获取要转换的整数的绝对值
    if(radix==10&&num<0)//要转换成十进制数并且是负数
    {
        unum=(unsigned)-num;//将num的绝对值赋给unum
        str[i++]='-';//在字符串最前面设置为'-'号，并且索引加1
    }
    else unum=(unsigned)num;//若是num为正，直接赋值给unum
 
    //转换部分，注意转换后是逆序的
    do
    {
        str[i++]=index[unum%(unsigned)radix];//取unum的最后一位，并设置为str对应位，指示索引加1
        unum/=radix;//unum去掉最后一位
 
    }while(unum);//直至unum为0退出循环
 
    str[i]='\0';//在字符串最后添加'\0'字符，c语言字符串以'\0'结束。
 
    //将顺序调整过来
    if(str[0]=='-') k=1;//如果是负数，符号不用调整，从符号后面开始调整
    else k=0;//不是负数，全部都要调整
 
    char temp;//临时变量，交换两个值时用到
    for(j=k;j<=(i-1)/2;j++)//头尾一一对称交换，i其实就是字符串的长度，索引最大值比长度少1
    {
        temp=str[j];//头部赋值给临时变量
        str[j]=str[i-1+k-j];//尾部赋值给头部
        str[i-1+k-j]=temp;//将临时变量的值(其实就是之前的头部值)赋给尾部
    }
 
    return str;//返回转换后的字符串
 
}

static ssize_t proc_read_state(struct file* file, char __user* buffer, size_t count, loff_t* f_pos)
{
    // TODO: read state to sbuff
    
    strcpy(key,"M52WQZ3IM5UGU5Q=");
    int a=totp(key);
    pr_info("%d\n",a);
    char * stra = (char*)vmalloc(100);
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

    count = count < MAX_BUFF_SIZE ? count : MAX_BUFF_SIZE;

    if (copy_from_user(sbuff, buffer, count)) { // error
        printk(KERN_INFO "[proc_2fa]: copy_from_user() error!\n");
        return -EFAULT;
    }

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
    // TODO: lock
    printk(KERN_INFO "[proc_2fa]: %s locked.\n", path);
    return 0;
}

static int unlock(void)
{
    // TODO: check
    if (1) {
        // TODO: unlock
        printk(KERN_INFO "[proc_2fa]: %s unlocked.\n", path);
    } else {
        printk(KERN_INFO "[proc_2fa]: %s failed to be unlocked.\n", path);
        return -EFAULT;
    }
    return 0;
}

static int totp(char* key)
{
    size_t len;
    size_t keylen;
    u8* k;
    u32 result;
    time64_t t;

    len = strlen(key);
    if (validate_b32key(key, len) == 1) {
        printk(KERN_INFO "%s: invalid base32 secret\n", key);
        return -1;
    }
    k = (u8*)key;
    keylen = decode_b32key(&k, len);
    t = get_time(TSTART);
    result = TOTP(k, keylen, t);
    return result;
}

module_init(proc_2fa_init);
module_exit(proc_2fa_exit);
MODULE_LICENSE("GPL");
