
#ifeq ($(K),"current")
KDIR=/lib/modules/`uname -r `/build
#else
#KDIR=../target
#endif


obj-m += mcctrl.o

mcctrl-objs := driver.o control.o ikc.o syscall.o

AALBASE ?= $(src)/../../../aal
EXTRA_CFLAGS = -I$(AALBASE)/host/include -I$(AALBASE)/host/driver/knf -I$(AALBASE)/include -I$(AALBASE)/ikc/include -I$(src)/../include

.PHONY: clean install

modules:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(RM) .*.cmd *.mod.c *.o *.ko* Module.symvers modules.order -r .tmp*

install:
