/* 309.c COPYRIGHT FUJITSU LIMITED 2018 */
#include "test_mck.h"
#include "testsuite.h"

static const size_t shift = PAGE_SHIFT;
static const size_t contshift = CONT_PAGE_SHIFT;

SETUP_EMPTY(TEST_SUITE, TEST_NUMBER)

RUN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	return do_3xx(shift, contshift, 2, 0, 0, 0);
}

TEARDOWN_FUNC(TEST_SUITE, TEST_NUMBER)
{
	teardown_3xx();
}