#ifndef _HT_H_
#define _HT_H_

#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>

#define HTS 100

typedef unsigned long key_ht_t;

typedef struct hash_data {
	LIST_ENTRY(hash_data) entries;
	key_ht_t key;
	void *data;
} hash_data_t;

LIST_HEAD(listhead, hash_data) head;

typedef struct hash_entry {
	struct listhead head;
} hash_entry_t;

typedef hash_entry_t hash_table_t[HTS];

void ht_init(hash_table_t ht);
void *ht_search(hash_table_t ht, key_ht_t key);
int ht_insert(hash_table_t ht, key_ht_t key, void *data);

#endif // _HT_H_
