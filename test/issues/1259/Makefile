XPMEM_DIR=$(HOME)/usr
CPPFLAGS=-I$(XPMEM_DIR)/include
LDFLAGS=-L$(XPMEM_DIR)/lib -Wl,-rpath -Wl,$(XPMEM_DIR)/lib -lxpmem

TARGET=huge_page_xpmem multi_vmr_xpmem XTP_001 XTP_002 XTP_003 XTP_004 XTP_005 XTP_006 XTP_007 XTP_008 XTP_009 XTP_010 XTP_011

all: $(TARGET)
test: all
	bash ./C1259.sh
clean:
	rm -f $(TARGET) C*.log

