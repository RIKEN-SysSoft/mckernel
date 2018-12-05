# Makefile COPYRIGHT FUJITSU LIMITED 2018
CC = gcc
obj-m += test_driver.o

KERN_DIR=/usr/src/kernels/`uname -r`/

TARGET=modules CT_001 CT_002 CT_003 CT_004 CT_005 CT_006 CT_007 CT_008 CT_009 CT_010

CPPFLAGS = 
LDFLAGS = 


all: $(TARGET)

modules:
	$(MAKE) -C $(KERN_DIR) M=$(PWD) modules

CT_001: CT_001.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_002: CT_002.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_003: CT_003.c
	$(CC) -o $@ $^ $(LDFLAGS) -pthread

CT_004: CT_004.c
	$(CC) -o $@ $^ $(LDFLAGS) -pthread

CT_005: CT_005.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_006: CT_006.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_007: CT_007.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_008: CT_008.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_009: CT_009.c
	$(CC) -o $@ $^ $(LDFLAGS) -pthread

CT_010: CT_010.c
	$(CC) -o $@ $^ $(LDFLAGS) -pthread

test: all
	./run.sh

clean:
	rm -f $(TARGET) *.o 
	$(MAKE) -C $(KERN_DIR) M=$(PWD) clean
