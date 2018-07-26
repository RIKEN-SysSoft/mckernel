CC = gcc
MCK_DIR=/home/satoken/ppos

MCEXEC=$(MCK_DIR)/bin/mcexec
TARGET=config

CPPFLAGS = 
LDFLAGS = 

all: $(TARGET)

config:
	@echo "MCEXEC=$(MCEXEC)" > ./config

test: all
	./CT_001.sh
	./CT_002.sh
	./CT_003.sh
	./CT_004.sh
	./CT_005.sh

clean:
	rm -f $(TARGET) *.o

