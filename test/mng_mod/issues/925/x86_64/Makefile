CC = gcc
MCK_DIR=/home/satoken/ppos
XPMEM_DIR=/home/satoken/usr

MCEXEC=$(MCK_DIR)/bin/mcexec
TARGET=CT_001 CT_002 CT_003 CT_004 CT_005 CT_006 CT_007 CT_008 CT_009 CT_010 CT_011

CPPFLAGS = -I$(XPMEM_DIR)/include
LDFLAGS = -L$(XPMEM_DIR)/lib -lxpmem

all: $(TARGET)

CT_001: CT_001.o
	$(CC) -o $@ $^ -static $(LDFLAGS)
CT_001.o: CT_001.c
	$(CC) $(CPPFLAGS) -c $<

CT_002: CT_002.o
	$(CC) -o $@ $^ -static $(LDFLAGS)
CT_002.o: CT_002.c
	$(CC) $(CPPFLAGS) -c $<

CT_003: CT_003.o
	$(CC) -o $@ $^ -static $(LDFLAGS)
CT_003.o: CT_003.c
	$(CC) $(CPPFLAGS) -c $<

CT_004: CT_004.o
	$(CC) -o $@ $^ -static $(LDFLAGS)
CT_004.o: CT_004.c
	$(CC) $(CPPFLAGS) -c $<

CT_005: CT_005.o
	$(CC) -o $@ $^ -static $(LDFLAGS)
CT_005.o: CT_005.c
	$(CC) $(CPPFLAGS) -c $<

CT_006: CT_006.o
	$(CC) -o $@ $^ -static $(LDFLAGS)
CT_006.o: CT_006.c
	$(CC) $(CPPFLAGS) -c $<

CT_007: CT_007.o
	$(CC) -o $@ $^ -static $(LDFLAGS)
CT_007.o: CT_007.c
	$(CC) $(CPPFLAGS) -c $<

CT_008: CT_008.o
	$(CC) -o $@ $^ -static $(LDFLAGS)
CT_008.o: CT_008.c
	$(CC) $(CPPFLAGS) -c $<

CT_009: CT_009.o
	$(CC) -o $@ $^ -static $(LDFLAGS)
CT_009.o: CT_009.c
	$(CC) $(CPPFLAGS) -c $<

CT_010: CT_010.o
	$(CC) -o $@ $^ -static $(LDFLAGS)
CT_010.o: CT_010.c
	$(CC) $(CPPFLAGS) -c $<

CT_011: CT_011.o
	$(CC) -o $@ $^ -static $(LDFLAGS)
CT_011.o: CT_011.c
	$(CC) $(CPPFLAGS) -c $<

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

clean:
	rm -f $(TARGET) *.o 

