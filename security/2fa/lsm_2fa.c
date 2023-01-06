#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
#include <linux/string.h>
#include <linux/cred.h>
#include "2fa.h"

/*
*lsm_2fa_file_permission 函数的就是hook处理函数
*在这里需要注意的是 lsm_2fa_file_permission 的函数头需要和 include/linux/lsm_hooks.h 文件
*中对应hook的函数头保持一致（在这里就是和 ’file_permission‘ hook的函数头对应） 
*/
static int lsm_2fa_file_permission(struct file* file, int mask)
{
    char* full_path;
    char buf[256];
    // printk(KERN_INFO "[+ 2fa_lsm] 'file_name' of the access file is:%s\n", file->f_path.dentry->d_iname);
    full_path = d_path(&(file->f_path), buf, sizeof(buf));
    // printk(KERN_INFO "[+ 2fa_lsm] 'full_path' of the access file is:%s\n", full_path);
    uid_t uid = current_uid().val;

    struct file_node* file_info;
    if (file_info = get_file_info(full_path, -1)) {
        pr_info("%d\n", uid);
    }
    return 0;
}
/*
 *LSM_HOOK_INIT 就是将file_permission hook 和 处理函数 lsm_2fa_file_permission 关联起来，并
 *添加到 security_hook_list 结构体中
 */
static struct security_hook_list lsm_2fa_hooks[] __lsm_ro_after_init = {
		LSM_HOOK_INIT(file_permission,lsm_2fa_file_permission),
};

static struct lsm_id lsm_2fa_lsmid __lsm_ro_after_init = {
	.lsm  = "lsm_2fa",
	.slot = LSMBLOB_NOT_NEEDED
};

/*
* 注册添加了hook处理函数的 security_hook_list 结构体
*/

static int __init lsm_2fa_init(void)
{
	security_add_hooks(lsm_2fa_hooks,ARRAY_SIZE(lsm_2fa_hooks), &lsm_2fa_lsmid);
    init_hashtable();
    pr_info("[2fa_lsm] module loaded.\n");
    return 0;
}

/*
*将指定的安全模块添加到LSM框架中
*这里需要注意 DEFINE_LSM(lsm_2fa)  中的 lsm_2fa 就是指定在LSM安全框架启动过程中要启用的安全模
*块的标识。（LSM安全框架要启动的模块后续在.config 文件需要进行手动修改或者通过 make menuconfig 过程中的配置来进行修改。）
*/
DEFINE_LSM(lsm_2fa) = {
		.name = "lsm_2fa",
		.init = lsm_2fa_init,
};
