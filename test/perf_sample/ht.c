#include "ht.h"

static unsigned int hash(key_ht_t key)
{
	return key%HTS;
}

void ht_init(hash_table_t ht)
{
	int i;

	for (i = 0; i < HTS; i++)
		LIST_INIT(&ht[i].head);
}

void *ht_search(hash_table_t ht, key_ht_t key)
{
	hash_data_t *hd;
	unsigned int i;

	i = hash(key);

	//printf("searching for key %lx in bin %u\n", key, i);

	for (hd = ht[i].head.lh_first; hd != NULL; hd = hd->entries.le_next) {
		if (hd->key == key)
			return hd->data;
	}

	return NULL;
}

int ht_insert(hash_table_t ht, key_ht_t key, void *data)
{
	hash_data_t *hd;
	unsigned int i;

	i = hash(key);

	hd = (hash_data_t *) malloc(sizeof(hash_data_t));
	hd->key = key;
	hd->data = data;

	//printf("inserting key %lx data %p into bin %u\n", key, data, i);

	LIST_INSERT_HEAD(&ht[i].head, hd, entries);

	return 0;
}

