#include <stdio.h>
#include <stdlib.h>
#include <linux/kernel.h>
#include <sys/sysinfo.h>
#include <errno.h>

int main(void)
{
	struct sysinfo *info;
	int ret = 0, rc = 0;
	unsigned long assigned_mem = (20UL << 30);
	unsigned long _totalram, _freeram;
	unsigned int _mem_unit;

	info = malloc(sizeof(struct sysinfo));
	rc = sysinfo(info);
	if (rc) {
		perror("sysinfo fail: ");
		ret = -1;
		goto out;
	}

	_totalram = info->totalram;
	_freeram = info->freeram;
	_mem_unit = info->mem_unit;

	// Check totalram
	if (0.95 * assigned_mem < _totalram &&
			_totalram < assigned_mem) {
		printf("[OK] totalram: %ld\n", _totalram);
	}
	else {
		printf("[NG] unexpected totalram: %ld\n", _totalram);
		printf("  expected range: %ld - %ld\n",
			(unsigned long)(0.95 * assigned_mem),
			assigned_mem);
		ret = -1;
		goto out;
	}

	// Check freeram
	if (0.95 * _totalram < _freeram &&
			_freeram < _totalram) {
		printf("[OK] freeram: %ld\n", _freeram);
	}
	else {
		printf("[NG] unexpected freeram: %ld\n", _freeram);
		ret = -1;
		goto out;
	}

	// Check mem_unit
	if (_mem_unit == 1) {
		printf("[OK] mem_unit: %ld\n", _mem_unit);
	}
	else {
		printf("[NG] unexpected mem_unit: %ld\n", _mem_unit);
		ret = -1;
		goto out;
	}

	free(info);
out:
	return ret;
}
