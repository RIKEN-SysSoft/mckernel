CC = gcc
MCK_DIR=/opt/ppos
XPMEM_DIR=/opt/xpmem

MCEXEC=$(MCK_DIR)/bin/mcexec
TARGET=CT_001 CT_002 CT_003 CT_004 CT_005 CT_006 CT_007 CT_008 CT_009 CT_010 CT_011 rusage012

CPPFLAGS = -I$(XPMEM_DIR)/include
LDFLAGS = -L$(XPMEM_DIR)/lib -lxpmem

all: $(TARGET)

CT_001: CT_001.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_002: CT_002.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_003: CT_003.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_004: CT_004.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_005: CT_005.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_006: CT_006.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_007: CT_007.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_008: CT_008.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_009: CT_009.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_010: CT_010.c
	$(CC) -o $@ $^ $(LDFLAGS)

CT_011: CT_011.c
	$(CC) -o $@ $^ $(LDFLAGS)

test: all
	$(MCEXEC) ./CT_001
	$(MCEXEC) ./CT_002
	$(MCEXEC) ./CT_003
	$(MCEXEC) ./CT_004
	$(MCEXEC) ./CT_005
	$(MCEXEC) ./CT_006
	@sleep 2
	$(MCEXEC) ./CT_007
	$(MCEXEC) ./CT_008
	$(MCEXEC) ./CT_009
	$(MCEXEC) ./CT_010
	$(MCEXEC) ./CT_011
	$(MCEXEC) ./rusage012

clean:
	rm -f $(TARGET) *.o 

