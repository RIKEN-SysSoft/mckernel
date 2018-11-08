CC = gcc
MCK_DIR=/opt/ppos

MCEXEC=$(MCK_DIR)/bin/mcexec
TARGET=CT_001 CT_002 CT_003 CT_004 CT_005 CT_006 CT_007 CT_008 CT_009 CT_010

CPPFLAGS = 
LDFLAGS = 

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

test: all
	$(MCEXEC) ./CT_001
	$(MCEXEC) ./CT_002
	$(MCEXEC) ./CT_003
	$(MCEXEC) ./CT_004
	$(MCEXEC) ./CT_005
	$(MCEXEC) ./CT_006
	$(MCEXEC) ./CT_007
	$(MCEXEC) ./CT_008
	$(MCEXEC) ./CT_009
	$(MCEXEC) ./CT_010
	stdbuf -i0 -o0 -e0 $(MCEXEC) ./test_mck -s rt_sigaction -n 4

clean:
	rm -f $(TARGET) *.o 

