{
    id = substr($2, 1, length($2) - 1);
    size = $4;
    sizes[id] += size;
}

END {
    for (i = 0; i <= id; i++) {
	if (sizes[i] * page_size > 2 * 1024 * 1024 * 1024) {
	    print i;
	}
    }
}
