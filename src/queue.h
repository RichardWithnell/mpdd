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

/* file: queue.h -- definitions for queue manipulation routines. */

#ifndef MPD_QUEUE_DEFINED
#define MPD_QUEUE_DEFINED

typedef struct qitem
{
	/* next must always be first; can cast to any struct with this first */
	struct qitem* next;
	void* data;
} Qitem;

typedef struct queue
{
	Qitem* front, * back;
	int size;
} Queue;

int queue_size(Queue* q);
int queue_init(Queue* q);
int queue_empty(Queue* q);
void queue_put(Queue* q, Qitem* new_item);
Qitem* queue_get(Queue* q);

#endif

/* end file: queue.h */
