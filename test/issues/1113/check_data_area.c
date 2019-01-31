#include <stdio.h>
#include <stdlib.h>

#define INIT_DATA 0xaaaaaaaa

unsigned long data_area = INIT_DATA;

int main(int argc, char *argv[])
{
	unsigned long chk_data = 0;

	if (argc > 1) {
		chk_data = atoi(argv[1]);
	}

	if (data_area != INIT_DATA) {
		printf("[ NG ] initialized data_area is INVALID\n");
		return -1;
	}

	data_area = chk_data;

	if (data_area != chk_data) {
		printf("[ NG ] upddated data_area is INVALID\n");
		return -1;
	}

	printf("[ OK ] data area is fine\n");
	return 0;
}
