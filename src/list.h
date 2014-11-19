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

#ifndef MPD_LIST
#define MPD_LIST

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct litem {
    struct litem *next;
    struct litem *prev;
    void *data;
} Litem;

typedef struct list {
        Litem *front, *back;
        uint32_t size;
} List;


uint32_t list_size(List *l);
uint32_t list_init(List *l);
uint32_t list_empty(List *l);
void list_put(List *l, Litem *new_item);
void list_destroy(List *l);
Litem * list_remove(List *l, uint32_t index);
Litem * list_get(List *l, uint32_t index);


#define list_for_each(item, list) \
    Litem * item; for(item = list->front; item != 0; item = item->next) \



#endif
