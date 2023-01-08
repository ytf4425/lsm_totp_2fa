obj-$(CONFIG_PROC_2FA)	+= 2fa_proc.o
2fa_proc-$(CONFIG_PROC_2FA) := proc_file.o 2fa.o otp/rfc6238.o otp/rfc4226.o otp/base32.o

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
