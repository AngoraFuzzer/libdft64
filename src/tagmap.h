/*-
 * Copyright (c) 2010, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Columbia University nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __TAGMAP_H__
#define __TAGMAP_H__

#include "pin.H"
#include "tag_traits.h"
#include <utility>

#define FLAG_TYPE uint8_t

// Code tag mask
#define FUNC_ENTRY_MASK 0x1
#define FUNC_EXIT_MASK 0x2
#define LOOP_ENTRY_MASK 0x3
#define LOOP_BODY_MASK 0x4
#define LOOP_EXIT_MASK 0x8

// Data tag mask
#define POINTER_MASK 0x1
#define ACCESS_MASK 0x2
#define READ_MASK 0x4
#define WRITE_MASK 0x8
#define ARRAY_ELEMENT_MASK 0x10

#define VALUE_ID 0

/*
 * the bitmap size in bytes
 */
#define PAGE_SIZE 4096
#define PAGE_BITS 12
#define TOP_DIR_SZ 0x800000
#define PAGETABLE_SZ 0X1000
#define PAGETABLE_BITS 24

#define BYTE_MASK 0x01U     /* byte mask; 1 bit */
#define WORD_MASK 0x0003U   /* word mask; 2 sequential bits */
#define LONG_MASK 0x000FU   /* long mask; 4 sequential bits */
#define QUAD_MASK 0x00FFU   /* quad mask; 8 sequential bits */
#define _3BYTE_MASK 0x0007U /* 3 bytes mask; 3 sequential bits */
#define _5BYTE_MASK 0x001FU /* 5 bytes mask; 5 sequential bits */
#define _6BYTE_MASK 0x003FU /* 6 bytes mask; 6 sequential bits */
#define _7BYTE_MASK 0x007FU /* 7 bytes mask; 7 sequential bits */
#define OFFSET_MASK 0x00000FFFU
#define PAGETABLE_OFFSET_MASK 0x00FFFFFFU

#define VIRT2PAGETABLE(addr) ((addr) >> PAGETABLE_BITS)
#define VIRT2PAGETABLE_OFFSET(addr)                                            \
  (((addr)&PAGETABLE_OFFSET_MASK) >> PAGE_BITS)

#define VIRT2PAGE(addr) VIRT2PAGETABLE_OFFSET(addr)
#define VIRT2OFFSET(addr) ((addr)&OFFSET_MASK)

#define ALIGN_OFF_MAX 8 /* max alignment offset */
#define ASSERT_FAST 32  /* used in comparisons  */

#define TEST_MASK(src, mask) ((src & (mask)) == (mask))
#define SET_MASK(src, mask) (src | mask)
#define CLR_MASK(src, mask) (src & (~(mask)))

/* for eflag */
#define OVERFLOW_BITS 11
#define OVERFLOW_MASK (1 << OVERFLOW_BITS)

extern void libdft_die();

/* XXX: Latest Intel Pin(3.7) does not support std::array :( */
// typedef std::array<tag_t, PAGE_SIZE> tag_page_t;
// typedef std::array<tag_page_t*, PAGETABLE_SZ> tag_table_t;
// typedef std::array<tag_table_t*, TOP_DIR_SZ> tag_dir_t;
/* For file taint */
typedef struct {
  tag_t tag[PAGE_SIZE];
} tag_page_t;
typedef struct {
  tag_page_t *page[PAGETABLE_SZ];
} tag_table_t;
typedef struct {
  tag_table_t *table[TOP_DIR_SZ];
} tag_dir_t;

void tagmap_setb(ADDRINT addr, tag_t const &tag);
tag_t tagmap_getb(ADDRINT addr);
tag_t tagmap_getb_reg(THREADID tid, unsigned int reg_idx, unsigned int off);
tag_t tagmap_getn(ADDRINT addr, unsigned int size);
tag_t tagmap_getn_reg(THREADID tid, unsigned int reg_idx, unsigned int n);
void tagmap_clrb(ADDRINT addr);
void tagmap_clrn(ADDRINT, UINT32);

#endif /* __TAGMAP_H__ */
