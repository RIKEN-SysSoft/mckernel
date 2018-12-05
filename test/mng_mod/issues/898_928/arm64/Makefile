# Makefile COPYRIGHT FUJITSU LIMITED 2018
CC = gcc
MCK_DIR=/opt/ppos
TARGET=ihklib001_lin CT_001 CT_002 CT_003 CT_004 CT_005 CT_006 CT_007 CT_008 CT_009

CPPFLAGS = -I$(MCK_DIR)/include
LDFLAGS = -L$(MCK_DIR)/lib -lihk -Wl,-rpath -Wl,$(MCK_DIR)/lib -lbfd

all: $(TARGET)

CT_001: CT_001.c
	$(CC) -o $@ $(CPPFLAGS) $(LDFLAGS) $^

CT_002: CT_002.c
	$(CC) -o $@ $(CPPFLAGS) $(LDFLAGS) $^

CT_003: CT_003.c
	$(CC) -o $@ $(CPPFLAGS) $(LDFLAGS) $^

CT_004: CT_004.c
	$(CC) -o $@ $(CPPFLAGS) $(LDFLAGS) $^

CT_005: CT_005.c
	$(CC) -o $@ $(CPPFLAGS) $(LDFLAGS) $^

CT_006: CT_006.c
	$(CC) -o $@ $(CPPFLAGS) $(LDFLAGS) $^

CT_007: CT_007.c
	$(CC) -o $@ $(CPPFLAGS) $(LDFLAGS) $^

CT_008: CT_008.c
	$(CC) -o $@ $(CPPFLAGS) $(LDFLAGS) $^

CT_009: CT_009.c
	$(CC) -o $@ $(CPPFLAGS) $(LDFLAGS) $^

ihklib001_lin: ihklib001_lin.c
	$(CC) -o $@ $(CPPFLAGS) $(LDFLAGS) $^

test:: $(TARGET)
	./run.sh

clean:
	rm -f $(TARGET)

