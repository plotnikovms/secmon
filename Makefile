MODULE_NAME := secmon

KERNEL_DIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
SYSCALL_TABLE_ADDR := $(shell sudo grep -w "sys_call_table" /proc/kallsyms 2>/dev/null | awk '{print $$1}' | head -n1)
KERNEL_TEXT_START := $(shell sudo grep -w "_stext" /proc/kallsyms 2>/dev/null | awk '{print $$1}' | head -n1)
KERNEL_TEXT_END := $(shell sudo grep -w "_etext" /proc/kallsyms 2>/dev/null | awk '{print $$1}' | head -n1)

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
		echo "INFO: sys_call_table address was not found"; \
		SYSCALL_ARG=""; \
	else \
		echo "INFO: sys_call_table address: 0x$(SYSCALL_TABLE_ADDR)"; \
		SYSCALL_ARG="syscall_table_addr=0x$(SYSCALL_TABLE_ADDR)"; \
	fi; \
	if [ -z "$(KERNEL_TEXT_START)" ] || [ "$(KERNEL_TEXT_START)" = "0000000000000000" ]; then \
		echo "INFO: _stext address was not found"; \
		TEXT_START_ARG=""; \
	else \
		echo "INFO: _stext address: 0x$(KERNEL_TEXT_START)"; \
		TEXT_START_ARG="kernel_text_start=0x$(KERNEL_TEXT_START)"; \
	fi; \
	if [ -z "$(KERNEL_TEXT_END)" ] || [ "$(KERNEL_TEXT_END)" = "0000000000000000" ]; then \
		echo "INFO: _etext address was not found"; \
		TEXT_END_ARG=""; \
	else \
		echo "INFO: _etext address: 0x$(KERNEL_TEXT_END)"; \
		TEXT_END_ARG="kernel_text_end=0x$(KERNEL_TEXT_END)"; \
	fi; \
	sudo insmod $(MODULE_NAME).ko $$SYSCALL_ARG $$TEXT_START_ARG $$TEXT_END_ARG

unload:
	sudo rmmod $(MODULE_NAME) || true

reload: unload load

report:
	cat /proc/secmon_report
