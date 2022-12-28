obj-m := 2fa_m.o
2fa_m-objs := 2fa_module.o 2fa.o utils.o otp/rfc6238.o otp/rfc4226.o otp/base32.o 

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
