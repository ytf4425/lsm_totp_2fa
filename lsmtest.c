#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
#include <linux/string.h>
/*
*lsmtest_file_permission 函数的就是hook处理函数
*在这里需要注意的是 lsmtest_file_permission 的函数头需要和 include/linux/lsm_hooks.h 文件
*中对应hook的函数头保持一致（在这里就是和 ’file_permission‘ hook的函数头对应） 
*/
static int lsmtest_file_permission(struct file* file, int mask)
{
    // only deal with the file_name which contain '.'
    char* full_path;
    char buf[256];
    printk(KERN_INFO "[+ 2fa_lsm] 'file_name' of the access file is:%s\n", file->f_path.dentry->d_iname);
    full_path = d_path(&(file->f_path), buf, sizeof(buf));
    printk(KERN_INFO "[+ 2fa_lsm] 'full_path' of the access file is:%s\n", full_path);
    return 0;
}
/*
 *LSM_HOOK_INIT 就是将file_permission hook 和 处理函数 lsmtest_file_permission 关联起来，并
 *添加到 security_hook_list 结构体中
 */
static struct security_hook_list lsmtest_hooks[] __lsm_ro_after_init = {
		LSM_HOOK_INIT(file_permission,lsmtest_file_permission),
};

static struct lsm_id lsmtest_lsmid __lsm_ro_after_init = {
	.lsm  = "lsmtest",
	.slot = LSMBLOB_NOT_NEEDED
};

/*
* 注册添加了hook处理函数的 security_hook_list 结构体
*/

static __init int lsmtest_init(void)
{
	security_add_hooks(lsmtest_hooks,ARRAY_SIZE(lsmtest_hooks), &lsmtest_lsmid);
    return 0;
}

/*
*将指定的安全模块添加到LSM框架中
*这里需要注意 DEFINE_LSM(lsmtest)  中的 lsmtest 就是指定在LSM安全框架启动过程中要启用的安全模
*块的标识。（LSM安全框架要启动的模块后续在.config 文件需要进行手动修改或者通过 make menuconfig 过程中的配置来进行修改。）
*/
DEFINE_LSM(lsmtest) = {
		.name = "lsmtest",
		.init = lsmtest_init,
};
