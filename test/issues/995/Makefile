CC = gcc

TARGET=put_args call_execve

all: $(TARGET)

put_args: put_args.c
	$(CC) -o $@ $^

call_execve: call_execve.c
	$(CC) -o $@ $^

test: all
	@ln -nfs ./put_args ./syml_put_args
	@echo "#!./syml_put_args" > test_01.sh
	@echo "#!`pwd`/syml_put_args" > test_02.sh
	@chmod +x ./test_01.sh
	@chmod +x ./test_02.sh
	@sh ./C995.sh

clean:
	rm -f $(TARGET) *.o ./syml_put_args ./test_01.sh ./test_02.sh

