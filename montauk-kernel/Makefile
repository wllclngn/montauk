# SPDX-License-Identifier: GPL-2.0
#
# Makefile for montauk kernel module
#

# Module name
obj-m := montauk.o

# Source files
montauk-y := montauk_main.o montauk_table.o montauk_hooks.o montauk_netlink.o

# Kernel build directory (default: running kernel)
KDIR ?= /lib/modules/$(shell uname -r)/build

# Extra compiler flags
ccflags-y := -DDEBUG

# Build targets
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# Install to system modules directory
install:
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install
	depmod -a

# Load module
load:
	insmod montauk.ko

# Unload module
unload:
	rmmod montauk

# Reload (unload + load)
reload: unload load

# Show module info
info:
	modinfo montauk.ko

# Check if module is loaded
status:
	@lsmod | grep montauk || echo "montauk module not loaded"
	@dmesg | tail -20 | grep montauk || true

.PHONY: all clean install load unload reload info status
