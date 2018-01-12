obj-m += hello.o

hello-y = driver.o

.PHONY: clean install modules

modules:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(RM) .*.cmd *.mod.c *.o *.ko* Module.symvers modules.order -r .tmp*

