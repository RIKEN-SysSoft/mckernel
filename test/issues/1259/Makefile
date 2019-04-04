XPMEM_DIR=$(HOME)/usr
CPPFLAGS=-I$(XPMEM_DIR)/include
LDFLAGS=-L$(XPMEM_DIR)/lib -Wl,-rpath -Wl,$(XPMEM_DIR)/lib -lxpmem

all: C1259
test: C1259
	./C1259.sh
clean:
	rm -f C1259 C1259.o

