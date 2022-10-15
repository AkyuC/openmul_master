#include <stdlib.h> 
#include <string.h> 
#include "mul_patricia.h"


/*
 * Private function used to return whether
 * or not bit 'i' is set in 'key'.
 */
static __inline
unsigned long
check_bit(int i, unsigned long key)
{
    return key & (1 << (31-i));
}


/*
 * Count the number of masks (and therefore entries)
 * in the Patricia trie.
 */
static int __attribute__((unused)) 
mul_pat_count(struct pat_tree *t, int b)
{
    int count;
    
    if (t->pat_bit <= b) return 0;

    count = t->pat_mask_len;
    
    count += mul_pat_count(t->pat_left,  t->pat_bit);
    count += mul_pat_count(t->pat_right, t->pat_bit);

    return count;
}


/*
 * Private function used for inserting a node recursively.
 */
static struct pat_tree *
mul_pat_insert_rec(struct pat_tree *h, struct pat_tree *n, int d, struct pat_tree *p)
{
    if ((h->pat_bit >= d) || (h->pat_bit <= p->pat_bit)) {
        n->pat_bit = d;
        n->pat_left = check_bit(d, n->pat_key) ? h : n;
        n->pat_right = check_bit(d, n->pat_key) ? n : h;
        return n;
    }

    if (check_bit(h->pat_bit, n->pat_key))
        h->pat_right = mul_pat_insert_rec(h->pat_right, n, d, h);
    else
        h->pat_left = mul_pat_insert_rec(h->pat_left, n, d, h);
    return h;
}


/*
 * Patricia trie insert.
 *
 * 1) Go down to leaf.
 * 2) Determine longest prefix match with leaf node.
 * 3) Insert new internal node at appropriate location and
 *    attach new external node.
 */
struct pat_tree *
mul_pat_insert(struct pat_tree *n, struct pat_tree *head)
{
    struct pat_tree *t;
    struct pat_tree_mask *buf, *pm;
    int i, copied;

    if (!head || !n || !n->pat_mask)
        return 0;

    /*
     * Make sure the key matches the mask.
     */
    n->pat_key &= n->pat_mask->pm_mask;

    /*
     * Find closest matching leaf node.
     */
    t = head;
    do {
        i = t->pat_bit;
        t = check_bit(t->pat_bit, n->pat_key) ? t->pat_right : t->pat_left;
    } while (i < t->pat_bit);

    /*
     * If the keys are the same we need to check the masks.
     */
    if (n->pat_key == t->pat_key) {
        /*
         * If we have a duplicate mask, replace the entry
         * with the new one.
         */
        for (i = 0; i < t->pat_mask_len; i++) {
            if (n->pat_mask->pm_mask == t->pat_mask[i].pm_mask) {
                t->pat_mask[i].pm_data = n->pat_mask->pm_data;
                free(n->pat_mask);
                free(n);
                n = 0;
                return t;
            }
        }
        
        /*
         * Allocate space for a new set of masks.
         */
        buf = (struct pat_tree_mask *)malloc(
               sizeof(struct pat_tree_mask)*(t->pat_mask_len+1));

        /*
         * Insert the new mask in the proper order from least
         * to greatest mask.
         */
        copied = 0;
        for (i = 0, pm = buf; i < t->pat_mask_len; pm++) {
            if (n->pat_mask->pm_mask > t->pat_mask[i].pm_mask) {
                bcopy(t->pat_mask + i, pm, sizeof(struct pat_tree_mask));
                i++;
            }
            else {
                bcopy(n->pat_mask, pm, sizeof(struct pat_tree_mask));
                n->pat_mask->pm_mask = 0xffffffff;
                copied = 1;
            }
        }
        if (!copied) {
            bcopy(n->pat_mask, pm, sizeof(struct pat_tree_mask));
        }
        free(n->pat_mask);
        free(n);
        n = 0;
        t->pat_mask_len++;

        /*
         * Free old masks and point to new ones.
         */
        free(t->pat_mask);
        t->pat_mask = buf;
        
        return t;
    }

    /*
     * Find the first bit that differs.
     */
    for (i = 1; i < 32 && check_bit(i, n->pat_key) == check_bit(i, t->pat_key); i++); 

    /*
     * Recursive step.
     */
    if (check_bit(head->pat_bit, n->pat_key))
        head->pat_right = mul_pat_insert_rec(head->pat_right, n, i, head);
    else
        head->pat_left = mul_pat_insert_rec(head->pat_left, n, i, head);
    
    return n;
}


/*
 * Remove an entry given a key in a Patricia trie.
 */
int
mul_pat_remove(struct pat_tree *n, struct pat_tree *head)
{
    struct pat_tree *p, *g, *pt, *pp, *t;
    struct pat_tree_mask *buf, *pm;
    int i;

    if (!n || !n->pat_mask)
        return 0;

    /*
     * Search for the target node, while keeping track of the
     * parent and grandparent nodes.
     */
    g = p = t = head;
    do {
        i = t->pat_bit;
        g = p;
        p = t;
        t = check_bit(t->pat_bit, n->pat_key) ? t->pat_right : t->pat_left;
    } while (i < t->pat_bit);

    /*
     * For removal, we need an exact match.
     */
    if (t->pat_key != n->pat_key)
        return 0;

    /*
     * If there is only 1 mask, we can remove the entire node.
     */
    if (t->pat_mask_len == 1) {
        /*
         * Don't allow removal of the default entry.
         */
        if (t->pat_bit == 0)
            return 0;
        
        /*
         * Must match on the mask.
         */
        if (t->pat_mask->pm_mask != n->pat_mask->pm_mask)
            return 0;
        
        /*
         * Search for the node that points to the parent, so
         * we can make sure it doesn't get lost.
         */
        pp = pt = p;
        do {
            i = pt->pat_bit;
            pp = pt;
            pt = check_bit(pt->pat_bit, p->pat_key) ? pt->pat_right : pt->pat_left;
        } while (i < pt->pat_bit);

        if (check_bit(pp->pat_bit, p->pat_key))
            pp->pat_right = t;
        else
            pp->pat_left = t;

        /*
         * Point the grandparent to the proper node.
         */
        if (check_bit(g->pat_bit, n->pat_key))
            g->pat_right = check_bit(p->pat_bit, n->pat_key) ?
                p->pat_left : p->pat_right;
        else
            g->pat_left = check_bit(p->pat_bit, n->pat_key) ?
                p->pat_left : p->pat_right;
    
        /*
         * Delete the target's data and copy in its parent's
         * data, but not the bit value.
         */
        if (t->pat_mask->pm_data)
            free(t->pat_mask->pm_data);
        free(t->pat_mask);
        if (t != p) {
            t->pat_key = p->pat_key;
            t->pat_mask = p->pat_mask;
            t->pat_mask_len = p->pat_mask_len;
        }
        free(p);

        return 1;
    }

    /*
     * Multiple masks, so we need to find the one to remove.
     * Return if we don't match on any of them.
     */
    for (i = 0; i < t->pat_mask_len; i++)
        if (n->pat_mask->pm_mask == t->pat_mask[i].pm_mask)
            break;
    if (i >= t->pat_mask_len)
        return 0;
    
    /*
     * Allocate space for a new set of masks.
     */
    buf = (struct pat_tree_mask *)malloc(
           sizeof(struct pat_tree_mask)*(t->pat_mask_len - 1));

    for (i = 0, pm = buf; i < t->pat_mask_len; i++) {
        if (n->pat_mask->pm_mask != t->pat_mask[i].pm_mask) {
            bcopy(t->pat_mask + i, pm++, sizeof(struct pat_tree_mask));
        }
    }
        
    /*
     * Free old masks and point to new ones.
     */
    t->pat_mask_len--;
    free(t->pat_mask);
    t->pat_mask = buf;
    return 1;
}


/*
 * Find an entry given a key in a Patricia trie.
 */
struct pat_tree *
mul_pat_search(unsigned long key, struct pat_tree *head)
{
    struct pat_tree *p = 0, *t = head;
    int i;
    
    if (!t)
        return 0;

    /*
     * Find closest matching leaf node.
     */
    do {
        /*
         * Keep track of most complete match so far.
         */
        if (t->pat_key == (key & t->pat_mask->pm_mask)) {
            p = t;
        }
        
        i = t->pat_bit;
        t = check_bit(t->pat_bit, key) ? t->pat_right : t->pat_left;
    } while (i < t->pat_bit);

    /*
     * Compare keys (and masks) to see if this
     * is really the node we want.
     */
    return (t->pat_key == (key & t->pat_mask->pm_mask)) ? t : p;
}

