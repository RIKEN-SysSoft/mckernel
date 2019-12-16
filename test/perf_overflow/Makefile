# Makefile COPYRIGHT FUJITSU LIMITED 2019
CC := ${CROSS_COMPILE}gcc

CFLAGS += -Wall -O0 -ggdb3

TARGET := perf_overflow
SRC := $(wildcard *.c)
OBJ := $(SRC:.c=.o)
DEP := $(SRC:.c=.d)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP -c $<

.PHONY: clean
clean:
	$(RM) $(OBJ) $(DEP) $(TARGET)

-include $(DEP)
