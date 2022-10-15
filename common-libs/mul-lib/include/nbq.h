/*
 *  nbq.h Non-blocking queue headers
 *  Copyright (C) 2012, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#ifndef __C_NBQ_H__
#define __C_NBQ_H__

struct nbq_elem {
    void *udata;
    struct nbq_elem *next;
};

struct nbq {
    struct nbq_elem *head;
    struct nbq_elem *tail;
    volatile uint32_t sched;
    uint32_t pad;
};

void nbq_init(struct nbq *q);
struct nbq *nbq_alloc(void);
int nbq_enqueue(struct nbq *q, void *udata);
void *nbq_dequeue(struct nbq *q);
void nbq_iterate(struct nbq *q, void (*iter)(void *arg), void *arg);

#endif 
