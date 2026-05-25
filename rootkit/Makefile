.PHONY: all clean load unload reload dmesg info

obj-m += rootkit.o

KERNEL_DIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean

load:
	sudo insmod ./rootkit.ko

unload:
	sudo rmmod rootkit
