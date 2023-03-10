#include <linux/lsm_hooks.h>
#include <linux/sysctl.h>
#include <linux/string.h>
#include <linux/cred.h>
#include "2fa.h"

/*
*lsm_2fa_file_open 函数的就是hook处理函数
*在这里需要注意的是 lsm_2fa_file_open 的函数头需要和 include/linux/lsm_hooks.h 文件
*中对应hook的函数头保持一致（在这里就是和 ’file_open‘ hook的函数头对应） 
*/
static int lsm_2fa_file_open(struct file* file)
{
    char* full_path;
    char buf[256];
    uid_t uid;

    full_path = d_path(&(file->f_path), buf, sizeof(buf));
    uid = current_uid().val;

    return check_permission(full_path, uid);
}
/*
 *LSM_HOOK_INIT 就是将file_open hook 和 处理函数 lsm_2fa_file_open 关联起来，并
 *添加到 security_hook_list 结构体中
 */
static struct security_hook_list lsm_2fa_hooks[] __lsm_ro_after_init = {
		LSM_HOOK_INIT(file_open,lsm_2fa_file_open),
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
