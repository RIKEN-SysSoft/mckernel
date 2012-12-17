KDIR ?= /lib/modules/`uname -r `/build

obj-m += mcctrl.o

mcctrl-objs := driver.o control.o ikc.o syscall.o

IHK_BASE=$(src)/../../../ihk
EXTRA_CFLAGS = -I$(IHK_BASE)/linux/include -I$(IHK_BASE)/ikc/include -I$(IHK_BASE)/include -I$(src)/../include
KBUILD_EXTRA_SYMBOLS = $(IHK_BASE)/linux/core/Module.symvers

.PHONY: clean install

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(RM) .*.cmd *.mod.c *.o *.ko* Module.symvers modules.order -r .tmp*

install:
