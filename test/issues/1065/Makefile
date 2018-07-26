CC = gcc
MCK_DIR=/home/satoken/ppos

MCEXEC=$(MCK_DIR)/bin/mcexec
TARGET= file_map print_maps static_print_maps call_execve print_maps_and_cmdline config

CPPFLAGS = 
LDFLAGS = 

all: $(TARGET)

file_map: file_map.c
	$(CC) -o $@ $^ $(LDFLAGS)

print_maps: print_maps.c
	$(CC) -o $@ $^ $(LDFLAGS)

print_maps_and_cmdline: print_maps_and_cmdline.c
	$(CC) -o $@ $^ $(LDFLAGS)

static_print_maps: print_maps.c
	$(CC) -o $@ $^ $(LDFLAGS) -static

call_execve: call_execve.c
	$(CC) -o $@ $^ $(LDFLAGS)

config:
	@echo "MCEXEC=$(MCEXEC)" > ./config

init:
	ln -nfs ./dummy_file ./lnk_to_dummy

test: init all
	./CT_001.sh
	./CT_002.sh
	./CT_003.sh
	./CT_004.sh
	./CT_005.sh
	./CT_006.sh
	./CT_007.sh
	./CT_008.sh

clean:
	rm -f $(TARGET) *.o ./lnk_to_dummy

