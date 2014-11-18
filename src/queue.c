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

#include "queue.h"


/**
*
*/
int
queue_init(Queue *q)
{
    q->front = q->back = (Qitem *)0;
    q->size = 0;
	return 0;
}


/**
*
*/
int
queue_empty(Queue *q)
{
    return (q->front == (Qitem *)0);
}


/**
*
*/
int
queue_size(Queue *q)
{
    return q->size;
}


/**
*
*/
void
queue_put(Queue *q, Qitem *new_item)
{
    new_item->next = (Qitem *)0;
    if (queue_empty(q)) {
            q->front = new_item;
    } else {
            q->back->next = new_item;
    }
    q->back = new_item;
    q->size++;
}


/**
*
*/
Qitem *
queue_get(Queue *q)
{
    Qitem *p = q->front;

    if (!queue_empty(q)) {
        q->front = q->front->next;
        if (q->front == (Qitem *)0) q->back = (Qitem *)0;
    }
    if(p) q->size--;
    return p;
}

/* end file: queue.c */
