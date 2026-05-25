.PHONY: all clean load unload reload report dmesg info

obj-m += secmon.o

secmon-y += main.o
secmon-y += hidden_process_check.o
secmon-y += module_check.o
secmon-y += syscall_check.o
secmon-y += kernel_protection_check.o

KERNEL_DIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean

load:
	sudo insmod ./secmon.ko

unload:
	sudo rmmod secmon

reload: unload load

report:
	cat /proc/secmon_report

dmesg:
	sudo dmesg | tail -50

info:
	modinfo ./secmon.ko
