/*
 * nbq.c - Non-blocking queuing library for single producer/consumer pair
 * Copyright (C) 2012-2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "compiler.h"
#include "c_util.h"
#include "clog.h"
#include "nbq.h"

int
nbq_enqueue(struct nbq *q, void *udata)
{
    struct nbq_elem *prev = q->tail;
    struct nbq_elem *tmp  = calloc(1, sizeof(struct nbq_elem));
    if (!tmp) return -1;

    prev->next = tmp;
    prev->udata = udata;
    q->tail = tmp;
    mb();
    return 0;
}

void
nbq_iterate(struct nbq *q, void (*iter)(void *arg), void *arg)
{
    struct nbq_elem *tmp;

    if (!arg) return;
    tmp = q->head;
    while (tmp != q->tail) {
        iter(tmp->udata);
        tmp = tmp->next;
    }
}

void *
nbq_dequeue(struct nbq *q)
{
    void *udata;
    struct nbq_elem *prev;

    if (q->head == q->tail) return NULL;

    prev = q->head;

    q->head = prev->next;
    udata = prev->udata;
    mb();

    free(prev);

    return udata;
}

void
nbq_init(struct nbq *q)
{
    struct nbq_elem *tmp  = calloc(1, sizeof(struct nbq_elem));
    if (!tmp) return;

    q->tail = tmp;
    q->head = tmp;
    mb();
}
