include $(HOME)/.mck_test_config.mk

CC = gcc
TARGET=perf_tool.o processing CT_001 CT_002 CT_003 CT_004

CPPFLAGS =
LDFLAGS =

all: $(TARGET)

CT_001: CT_001.c perf_tool.o
	$(CC) -o $@ $^ $(LDFLAGS)

CT_002: CT_002.c perf_tool.o
	$(CC) -o $@ $^ $(LDFLAGS)

CT_003: CT_003.c perf_tool.o
	$(CC) -o $@ $^ $(LDFLAGS) -I$(MCK_DIR)/include -L$(MCK_DIR)/lib -Wl,--rpath=$(MCK_DIR)/lib -l ihk 

CT_004: CT_004.c perf_tool.o
	$(CC) -o $@ $^ $(LDFLAGS) -I$(MCK_DIR)/include -L$(MCK_DIR)/lib -Wl,--rpath=$(MCK_DIR)/lib -l ihk

perf_tool.o: perf_tool.c perf_tool.h

processing: processing.c perf_tool.o


test: all
	@echo "#!/bin/sh" > ./processing.sh
	@echo "$(BIN)/mcexec ./processing" >> ./processing.sh
	@sh ./C1001.sh

clean:
	rm -f $(TARGET) *.o processing.sh

