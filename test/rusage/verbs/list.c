/*
 * list.c
 *
 *  Created on: 2011/10/19
 *      Author: simin
 */

#include <stdio.h>
#include "list.h"
#include <stdlib.h>

void* list_get(list_t *list, int idx) {
	int i;
	list_element_t *e;

	if (list->cnt <= 0 || idx < 0 || idx >= list->cnt)
		return NULL;

	e = list->head;
	for (i = 0; i < idx; i++)
		e = e->next;

	return e->data;
}

void list_add(list_t *list, void *data) {
	list_element_t *e;
	e = malloc(sizeof(list_element_t));
	e->data = data;
	e->next = NULL;

	if(list->tail != NULL)
		list->tail->next = e;
	list->tail = e;

	if (list->cnt == 0)
		list->head = list->tail;

	list->cnt++;
}

void* list_remove(list_t *list, int idx) {
	int i;
	list_element_t *e, *pe, *ne;
	void *data;
	e = pe = ne = NULL;

	if (list->cnt <= 0 || idx < 0 || idx >= list->cnt)
		return NULL;

	e = list->head;
	i = 0;
	if(idx > 0){
		while(i++ < idx-1){
			e = e->next;
		}
		pe = e;
		i--;
	}
	while(i++ < idx)
		e = e->next;
	if(idx < list->cnt)
		ne = e->next;

	if(pe != NULL)
		pe->next = ne;
	else
		list->head = ne;
	if(ne == NULL)
		list->tail = pe;

	list->cnt--;

	data = e->data;
	free(e);

	return data;
}

void* list_pop(list_t *list){
	return list_remove(list, list->cnt-1);
}
