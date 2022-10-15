/*
 *  mul_patricia.h - Patricia header
 *  Copyright (C) 2012-2014, Dipjyoti Saikia <dipjyoti.saikia@gmail.com>
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
#ifndef _PATRICIA_H_
#define _PATRICIA_H_

/*
 * Patricia tree mask.
 * Each node in the tree can contain multiple masks, so this
 * structure is where the mask and data are kept.
 */
struct pat_tree_mask {
    unsigned long pm_mask;
    void *pm_data;
};


/*
 * Patricia tree node data structure.
 */
struct pat_tree {
    unsigned long pat_key;                /* Node key         */
    struct pat_tree_mask *pat_mask;       /* Node masks       */
    unsigned char pat_mask_len;           /* Number of masks  */
    char pat_bit;                         /* Bit to check     */
    struct pat_tree *pat_left;            /* Left pointer     */
    struct pat_tree *pat_right;           /* Right pointer    */
};


extern struct pat_tree *mul_pat_insert(struct pat_tree *n, struct pat_tree *head);
extern int           mul_pat_remove(struct pat_tree *n, struct pat_tree *head);
extern struct pat_tree *mul_pat_search(unsigned long key, struct pat_tree *head);

#endif /* _PATRICIA_H_ */
