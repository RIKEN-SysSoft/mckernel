include $(HOME)/.mck_test_config.mk
CC = gcc
TARGET=set_thp_and_exec check_thp mmap_large shm_large mmap_hugetlbfs

CPPFLAGS =
LDFLAGS =

all: $(TARGET)

set_thp_and_exec: set_thp_and_exec.c
	$(CC) -o $@ $^ $(LDFLAGS)

check_thp: check_thp.c
	$(CC) -o $@ $^ $(LDFLAGS)

mmap_large: mmap_large.c
	$(CC) -o $@ $^ $(LDFLAGS)

shm_large: shm_large.c
	$(CC) -o $@ $^ $(LDFLAGS)

mmap_hugetlbfs: mmap_hugetlbfs.c
	$(CC) -o $@ $^ $(LDFLAGS)

test: all
	@sh ./C1181.sh $(ARCH)

clean:
	rm -f $(TARGET) *.o CT*.txt

