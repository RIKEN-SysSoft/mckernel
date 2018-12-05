CC = gcc

TARGET=CT02 CT02m

all: $(TARGET)

CT02: CT02.c
	$(CC) -o CT02 CT02.c

CT02m: CT02m.c
	$(CC) -o CT02m CT02m.c

test: all
	./CT02

clean:
	rm -f $(TARGET)

