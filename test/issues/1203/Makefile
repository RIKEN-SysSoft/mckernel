TARGET = C1203T01 C1203T02
SCRIPT = ./C1203.sh
C1203T02: LDFLAGS = -B /usr/share/libhugetlbfs -Wl,--hugetlbfs-align
CFLAGS = -Wall

all: $(TARGET)

test: all
	bash $(SCRIPT)

clean:
	rm -f $(TARGET) *.o
