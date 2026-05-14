MODULE_NAME := secmon

KERNEL_DIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
SYSCALL_TABLE_ADDR := $(shell sudo grep -w "sys_call_table" /proc/kallsyms 2>/dev/null | awk '{print $$1}' | head -n1)

obj-m += $(MODULE_NAME).o

$(MODULE_NAME)-y += main.o
$(MODULE_NAME)-y += hidden_process_check.o
$(MODULE_NAME)-y += module_check.o
$(MODULE_NAME)-y += syscall_check.o

.PHONY: all clean load unload reload report

all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

clean: unload
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean

load: all
	@if [ -z "$(SYSCALL_TABLE_ADDR)" ] || [ "$(SYSCALL_TABLE_ADDR)" = "0000000000000000" ]; then \
		echo "INFO: sys_call_table address was not found, loading without syscall_table_addr"; \
		sudo insmod $(MODULE_NAME).ko; \
	else \
		echo "INFO: sys_call_table address: 0x$(SYSCALL_TABLE_ADDR)"; \
		sudo insmod $(MODULE_NAME).ko syscall_table_addr=0x$(SYSCALL_TABLE_ADDR); \
	fi

unload:
	sudo rmmod $(MODULE_NAME) || true

reload: unload load

report:
	cat /proc/secmon_report
