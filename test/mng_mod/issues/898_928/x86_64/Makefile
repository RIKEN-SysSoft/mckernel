CC = gcc
MCK_DIR=/home/satoken/ppos
TARGET=CT_001 CT_002 CT_003 CT_004 CT_005 CT_006 CT_007 CT_008 CT_009

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


test:: $(TARGET)
	-sudo ./CT_001
	-sudo ./CT_002
	-sudo ./CT_003
	-sudo ./CT_004
	#-sudo ./CT_005
	-sudo ./CT_006
	-sudo ./CT_007
	-sudo ./CT_008
	-sudo ./CT_009

clean:
	rm -f $(TARGET)

