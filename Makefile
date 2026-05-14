.PHONY: all kernel userspace clean load unload reload report run

all: kernel userspace

kernel:
	$(MAKE) -C kernel

userspace:
	$(MAKE) -C userspace

clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C userspace clean

load:
	$(MAKE) -C kernel load

unload:
	$(MAKE) -C kernel unload

reload:
	$(MAKE) -C kernel reload

report:
	$(MAKE) -C kernel report

run: all
	sudo ./userspace/secmon_userspace
