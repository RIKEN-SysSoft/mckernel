include $(HOME)/.mck_test_config.mk

CFLAGS=-g -O0 -Wall -I$(MCK_DIR)/include
LDFLAGS=-L$(MCK_DIR)/lib64 -lihk -lnuma -Wl,-rpath=$(MCK_DIR)/lib64

TARGET=check_mempol_il

all: $(TARGET)

test: all
	./C959.sh
clean:
	rm -f $(TARGET) *.o *.txt

