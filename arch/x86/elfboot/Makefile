CFLAGS=-c -Wall -O
CFLAGS_TEST=-DTEST

all: elfboot

elfboot: elfboot.bin
	cp $^ $@
	truncate -s $(shell expr '(' `stat -c '%s' $^` + 4095 ')' / 4096 '*' 4096) $@

elfboot.bin: elfboot.elf
	$(OBJCOPY) -O binary $^ $@

elfboot.elf: head.o elfboot.raw.o raw.lds
	$(LD) $(LDFLAGS_RAW) -T raw.lds -o $@ $^

elfboot_test: elfboot.test.o test_main.o
	$(CC) -o $@ $^

elfboot.raw.o: elfboot.c
	$(CC) $(CFLAGS) -o $@ $^

elfboot.test.o: elfboot.c
	$(CC) $(CFLAGS) $(CFLAGS_TEST) -o $@ $^

clean:
	$(RM) elfboot *.bin *.elf elfboot_test *.o

disas:
	$(OBJDUMP) -b binary -m i386:x86-64 -D elfboot.bin
