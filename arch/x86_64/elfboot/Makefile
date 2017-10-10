DEST=$(O)/elfboot
CFLAGS=-c -Wall -O
CFLAGS_TEST=-DTEST

all: $(DEST) $(DEST)/elfboot

$(DEST)/elfboot: $(DEST)/elfboot.bin
	cp $^ $@
	truncate -s $(shell expr '(' `stat -c '%s' $^` + 4095 ')' / 4096 '*' 4096) $@

$(DEST)/elfboot.bin: $(DEST)/elfboot.elf
	$(OBJCOPY) -O binary $^ $@

$(DEST)/elfboot.elf: $(DEST)/head.o $(DEST)/elfboot.raw.o raw.lds
	$(LD) $(LDFLAGS_RAW) -T raw.lds -o $@ $^

$(DEST)/elfboot_test: $(DEST)/elfboot.test.o $(DEST)/test_main.o
	$(CC) -o $@ $^

$(DEST)/head.o: head.S
	$(CC) $(CFLAGS) -o $@ $^

$(DEST)/elfboot.raw.o: elfboot.c
	$(CC) $(CFLAGS) -o $@ $^

$(DEST)/elfboot.test.o: elfboot.c
	$(CC) $(CFLAGS) $(CFLAGS_TEST) -o $@ $^

clean:
	$(RM) $(DEST)/elfboot *.bin $(DEST)/*.elf $(DEST)/elfboot_test *.o

disas:
	$(OBJDUMP) -b binary -m i386:x86-64 -D $(DEST)/elfboot.bin

$(DEST):
	@mkdir -p $(DEST)
