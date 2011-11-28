DEST=$(O)/kboot
OBJS=$(DEST)/main.o $(DEST)/data.o
CFLAGS=-mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mcmodel=large

$(if $(O),,$(error Specify the target directory))

$(DEST)/kboot.elf: $(DEST) $(DEST)/kernel.lds $(OBJS)
	@$(LD) $(LDFLAGS) -o $@ -T $(DEST)/kernel.lds -nostdlib $(OBJS)

$(DEST)/%.o: %.c
	@$(CC) $(CFLAGS) -c -o $@ -O3 $<

$(DEST)/data.o: data.S
	@$(CC) -c -o $@ -O3 -DKIMAGE='"$(KIMAGE)"' $^

$(DEST)/kernel.lds: kernel.lds.S
	$(if $(LOAD_PA),,$(error Specify the loading physical address))
	@$(CC) -E -P -DLOAD_PA=$(LOAD_PA) -o $@ $<

$(DEST):
	@mkdir -p $(DEST)

clean:
	@$(RM) $(DEST)/*

.PHONY: clean

