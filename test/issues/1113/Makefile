CC = gcc

TARGET=hello print_maps fork_execve static_print_maps

all: $(TARGET)

hello: hello.c
	$(CC) -o $@ $^

print_maps: print_maps.c
	$(CC) -o $@ $^

fork_execve: fork_execve.c
	$(CC) -o $@ $^

static_print_maps: print_maps.c
	$(CC) -static -o $@ $^

test: all
	@sh ./C1113.sh

clean:
	rm -f $(TARGET) *.o CT*.txt

