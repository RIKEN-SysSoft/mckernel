BEGIN { id = -1; }
/Node .*, zone\s*(Normal|DMA32)/ { id = substr($2, 1, length($2) - 1); }
{
    if ($0 ~ keyword && id != -1) {
	printf("id: %d, nr_free_pages: %ld\n", id, $2);
	id = -1;
    }
}

