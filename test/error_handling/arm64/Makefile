CC = gcc
TARGET=exec

all: $(TARGET)

exec: exec.c
	$(CC) -o $@ $^ $(LDFLAGS)

test: all
	./run.sh

clean:
	rm -f $(TARGET) *.o 

