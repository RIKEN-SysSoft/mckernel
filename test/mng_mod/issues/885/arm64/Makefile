## Makefile COPYRIGHT FUJITSU LIMITED 2018 ##
CC = gcc
TARGET=CT_001 CT_002 CT_003 CT_004 CT_005 CT_006 CT_007 CT_008 CT_009 CT_010 CT_011

CPPFLAGS = 
LDFLAGS = -pthread

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
	./run.sh

clean:
	rm -f $(TARGET) *.o 

