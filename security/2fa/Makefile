# obj-$(CONFIG_PROC_2FA) := 2fa_m.o
# 2fa_m-objs := 2fa_module.o 2fa.o utils.o otp/rfc6238.o otp/rfc4226.o otp/base32.o 
obj-$(CONFIG_SECURITY_LSM2FA) := 2faall.o    #将对应的模块编译进内核(obj-y 生成 build-in.a)或者编译成第三方模块（obj-m 生成 xxx.ko）
2faall-y := lsm_2fa.o 2fa.o utils.o otp/rfc6238.o otp/rfc4226.o otp/base32.o

# all:
# 		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

# clean:
# 		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
