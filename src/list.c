/*
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

    Author: Richard Withnell
    github.com/richardwithnell
 */

#include "list.h"

/**
 *
 */
uint32_t list_init(List* l)
{
    l->front = l->back = (Litem*)0;
    l->size = 0;
    return 1;
}

/**
 *
 */
uint32_t list_empty(List* l)
{
    return l->front == (Litem*)0;
}

/**
 *
 */
uint32_t list_size(List* l)
{
    return l->size;
}

/**
 *
 */
List* list_copy(List* old_list)
{
    List* new_list = (List*)0;
    Litem* li;

    if((new_list = malloc(sizeof(List)))) {
        return (List*)0;
    }

    list_init(new_list);

    li = old_list->front;

    while(li) {
        Litem* new_item = (Litem*)0;

        if((new_item = malloc(sizeof(Litem)))) {
            list_destroy(new_list);
            return (List*)0;
        }

        if((new_item->data = malloc(sizeof(li->data)))) {
            list_destroy(new_list);
            return (List*)0;
        }

        memcpy(new_item->data, li->data, sizeof(*(li->data)));

        list_put(new_list, new_item);
        li = li->next;
    }

    return new_list;
}

/**
 *
 */
void list_destroy(List* l)
{
    Litem* li = (Litem*)0;

    if(!l) {
        return;
    }

    li = l->front;
    while(li) {
        Litem* next = li->next;
        free(li);
        li = next;
    }
    free(l);
}

/**
 *
 */
void list_put(List* l, Litem* new_item)
{
    if(!l || !new_item) {
        return;
    }
    new_item->next = (Litem*)0;
    if (list_empty(l)) {
        l->front = new_item;
    } else {
        l->back->next = new_item;
    }
    l->back = new_item;
    l->size++;
}

/**
 *
 */
Litem* list_remove(List* l, uint32_t index)
{
    uint32_t i = 0;
    Litem* curr;
    Litem* prev;

    if(!l) {
        return (Litem*)0;
    }

    if(index >= l->size || l->size <= 0) {
        return (Litem*)0;
    }

    if(index == 0) {
        curr = l->front;
        l->front = curr->next;
    } else {
        curr = l->front;
        for(; i < index; i++) {
            prev = curr;
            curr = curr->next;
        }
        if(curr) {
            prev->next = curr->next;
        }
    }

    if(index == l->size - 1) {
        l->back = prev;
    }

    l->size--;
    return curr;
}

/**
 *
 */
Litem* list_get(List* l, uint32_t index)
{
    uint32_t i = 0;
    Litem* li;

    if(!l) {
        return (Litem*)0;
    }

    if(index > l->size || l->size <= 0) {
        return (Litem*)0;
    }

    li = l->front;

    for(; i < index; i++) {
        li = li->next;
    }

    return (Litem*)li;
}

/* end file: list.c */
