/*
 *  cbuf.c: Buffer handling infra 
 *  Copyright (C) 2012, Dipjyoti Saikia
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
#include <string.h>
#include <assert.h>
#include "cbuf.h"

void
cbuf_list_head_init(struct cbuf_head *head)
{
    head->next = NULL;
    head->len  = 0;
} 

void
cbuf_list_queue_tail(struct cbuf_head *head,
                     struct cbuf *buf)
{
    struct cbuf *curr;
    struct cbuf **prev = &head->next;

    while ((curr = *prev)) {
        prev = &curr->next;
    }

    buf->next = NULL;
    *prev = buf;
    head->len++;
} 

void
cbuf_list_queue(struct cbuf_head *head,
                struct cbuf *buf)
{
    buf->next  = head->next;
    head->next = buf;    
    head->len++;
} 

struct cbuf *
cbuf_list_dequeue(struct cbuf_head *head)
{
    struct cbuf *curr;
    struct cbuf **prev = &head->next;

    if ((curr = *prev)) {
        *prev = curr->next;
        head->len--;
    }

    return curr;
} 

int
cbuf_list_count(struct cbuf_head *head)
{
    struct cbuf *curr = head->next;
    int len = 0;

    while (curr) {
        len++;
        curr = curr->next; 
    }

    return len;
} 

void
cbuf_list_rm_inline_bufs(struct cbuf_head *head)
{
    struct cbuf *curr, *new;
    struct cbuf **prev = &head->next; 

    head->len = 0;
    while ((curr = *prev)) {
        if (curr->nofree) {
            new = cbuf_realloc_headroom(curr, 0, 0);
            new->next = curr->next;
            *prev = new;
            curr = new;
        } 
        
        prev = &curr->next;
        head->len++;
    }
} 

void
cbuf_list_purge(struct cbuf_head *head)
{
    struct cbuf *curr = head->next;
    struct cbuf *prev = NULL;

    while (curr) {
        prev = curr;
        curr = curr->next; 
        head->len--;
        free_cbuf(prev);
    }

    assert(head->len == 0);
    head->next = NULL;

} 

static void
init_cbuf(struct cbuf *b, size_t alloc_len)
{
    b->data = (unsigned char *)(b + 1);
    b->tail = b->data;
    b->end = (unsigned char *)b + alloc_len;
    b->len = 0;
    b->nofree = 0;
    b->next = NULL;
}

struct cbuf *
alloc_cbuf(size_t len)
{
    struct cbuf *b;
    size_t      alloc_len = CBUF_ALIGN_SZ(len + CBUF_SZ);

    b = malloc(alloc_len);
    assert(b);

    init_cbuf(b, alloc_len);

    return b;
}

struct cbuf *
zalloc_cbuf(size_t len)
{
    struct cbuf *b;
    size_t      alloc_len = CBUF_ALIGN_SZ(len + CBUF_SZ);

    b = calloc(1, alloc_len);
    assert(b);

    init_cbuf(b, alloc_len);

    return b;
}

void *
cbuf_put(struct cbuf *b, size_t len)
{
    void *tmp = b->tail;

    assert(b->tail+len <= b->end);

    b->tail += len;
    b->len  += len;

    return tmp;
}

void *
cbuf_pull(struct cbuf *b, size_t len)
{
    assert(b->data + len <= b->end);

    b->data += len;
    b->len -= len;

    return (void *)(b->data);
}

void *
cbuf_push(struct cbuf *b, size_t len)
{
    assert(cbuf_headroom(b) >= len);

    b->data -= len;
    b->len += len;

    return (void *)(b->data);
}

size_t
cbuf_headroom(struct cbuf *b)
{
    int room;

    assert(b && b->data);

    room = (b->data - (unsigned char *)b) + CBUF_SZ;
    if (room < 0) return 0;

    return room;
}

struct cbuf *
cbuf_realloc_tailroom(struct cbuf *b, size_t room, int do_free)
{
    struct cbuf *old = b;

    if (room > cbuf_tailroom(b)) {
        b = alloc_cbuf(old->len + room);
        memcpy(b->data, old->data, old->len);
        cbuf_put(b, old->len);
        if (do_free) 
            free_cbuf(old);
    }

    return b;
}

struct cbuf *
cbuf_realloc_headroom(struct cbuf *b, size_t room, int do_free)
{
    struct cbuf *old = b;

    if (1 /*room > cbuf_headroom(b)*/) {
        b = alloc_cbuf(old->len + room);
        cbuf_put(b, old->len + room);
        cbuf_pull(b, room);
        memcpy(b->data, old->data, old->len);
        if (do_free) 
            free_cbuf(old);
    }

    return b;
}

void
free_cbuf(struct cbuf *b)
{
    if (!b->nofree)
        free(b);
}
