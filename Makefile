obj-m := 2fa.o
2fa-objs := 2fa_module.o otp/rfc6238.o otp/rfc4226.o otp/base32.o

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
