/*
 * list.h
 *
 *  Created on: 2011/10/19
 *      Author: simin
 */

#ifndef LIST_H_
#define LIST_H_

typedef struct list_element_t{
	void  *data;
	struct list_element_t *next;
}list_element_t;

typedef struct list_t{
	list_element_t *head;
	list_element_t *tail;
	int cnt;
}list_t;

extern void* list_get(list_t *list, int idx);
extern void list_add(list_t *list, void *e);
extern void* list_remove(list_t *list, int idx);
extern void* list_pop(list_t *list);
#endif /* LIST_H_ */
