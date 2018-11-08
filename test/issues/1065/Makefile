CC = gcc
TARGET= file_map

CPPFLAGS = 
LDFLAGS = 

all: $(TARGET)

file_map: file_map.c
	$(CC) -o $@ $^ $(LDFLAGS)

init:
	@echo "This is Test file for mmap" > ./dummy_file
	@ln -nfs ./dummy_file ./lnk_to_dummy

test: init all
	@sh ./C1065.sh

clean:
	rm -f $(TARGET) *.o ./dummy_file ./lnk_to_dummy

