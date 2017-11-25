CC=gcc
MCEXEC=../../../../mic/mcexec
TARGET=943 944 945 946 960 961
all:: $(TARGET)

943: 943.c
	$(CC) -o 943 $<

944: 944.c
	$(CC) -o 944 $<

945: 945.c
	$(CC) -o 945 $<

946: 946.c
	$(CC) -o 946 $<

960: 960.c
	$(CC) -o 960 $<

961: 961.c
	$(CC) -o 961 $<

test:: $(TARGET)
	-$(MCEXEC) ./943
	-$(MCEXEC) ./944
	-$(MCEXEC) ./945
	-$(MCEXEC) ./946
	-$(MCEXEC) ./960
	-$(MCEXEC) ./961

clean::
	rm -f $(TARGET)
