/*-
 * Copyright (c) 2010, Columbia University
 * All rights reserved.
 *
 * This software was developed by Vasileios P. Kemerlis <vpk@cs.columbia.edu>
 * at Columbia University, New York, NY, USA, in June 2010.
 *
 * Georgios Portokalidis <porto@cs.columbia.edu> contributed to the
 * optimized implementation of tagmap_setn() and tagmap_clrn()
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
#include <err.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "tagmap.h"
#include "pin.H"
#include "branch_pred.h"

/*
 * tagmap
 *
 * the tagmap is the core data structure in libdft:.
 * It keeps the tag information for the virtual address space
 * of a process. For the 32-bit x86 architecture, it is implemented
 * using a BITMAP_SZ MB bitmap.
 *
 * Every byte that is addressable in the 32-bit virtual address
 * space is represented using one bit on the tagmap.
 */
//uint8_t *bitmap = NULL;
//TAG_TYPE ***directory = NULL;

/* For File taint */
tag_dir_t tag_dir;
const EWAHBoolArray<uint32_t> tag_traits<EWAHBoolArray<uint32_t>>::cleared_val = EWAHBoolArray<uint32_t>{};
const EWAHBoolArray<uint32_t> tag_traits<EWAHBoolArray<uint32_t>>::set_val = EWAHBoolArray<uint32_t>{};

template<>
EWAHBoolArray<uint32_t> tag_combine(EWAHBoolArray<uint32_t> & lhs, EWAHBoolArray<uint32_t> & rhs) {
	EWAHBoolArray<uint32_t> result;
	lhs.logicalor(rhs, result);
	return result;
}

template<>
std::string tag_sprint(EWAHBoolArray<uint32_t> const & tag) {
    std::stringstream ss;
    if(tag.numberOfOnes())
    	ss << tag;
    else
	return "{}";
    return ss.str();

}

template<>
bool tag_count(EWAHBoolArray<uint32_t> const & tag) {
	if(tag.numberOfOnes()){
		return 1;
	}else{
		return 0;
	}
}

/*
 * initialize the tagmap; allocate space
 *
 * returns:	0 on success, 1 on error 
 */
int
tagmap_alloc(void)
{
	/*
	 * allocate space for the bitmap;
	 * in GNU/Linux this will result in invoking mmap(2)
	 * since the requested size is greater than 128 KB
	 */

	//MODIFIED: allocate space for the directory structure
/*	if (unlikely((directory = (TAG_TYPE ***)calloc(TOP_DIR_SZ,sizeof(TAG_TYPE **))) == NULL))
		return 1;
	//initialize structure
	memset(directory, 0, TOP_DIR_SZ * sizeof(TAG_TYPE **));*/

	/* return with success */
	return 0;
}

/*
 * dispose the tagmap; deallocate its space
 */
void
tagmap_free(void)
{
	/* deallocate the bitmap space */
/*	unsigned int i;
	for (i=0; i<TOP_DIR_SZ; i++)
		if (directory[i])
			free(directory[i]);
	free(directory);*/
}

void 
alloc_pagetable(ADDRINT addr)
{
/*	if (!directory[VIRT2PAGETABLE(addr)]){
		if (unlikely((directory[VIRT2PAGETABLE(addr)] = (TAG_TYPE **)calloc(PAGETABLE_SZ,sizeof(TAG_TYPE*)))==NULL)){
			warn("%s:%u, ,malloc failed %lx", __func__, __LINE__,addr);
			exit(1);
		}
		memset(directory[VIRT2PAGETABLE(addr)], 0, PAGETABLE_SZ * sizeof(TAG_TYPE*));
	}*/
}

void inline static alloc_tag_page(ADDRINT addr)
{
/*	alloc_pagetable(addr);
	if (!directory[VIRT2PAGETABLE(addr)][VIRT2PAGE(addr)]){
		if (unlikely((directory[VIRT2PAGETABLE(addr)][VIRT2PAGE(addr)] = (TAG_TYPE *)calloc(PAGE_SIZE,sizeof(TAG_TYPE)))==NULL)){
			warn("%s:%u, ,malloc failed %lx", __func__, __LINE__,addr);
			exit(1);
		}
		memset(directory[VIRT2PAGETABLE(addr)][VIRT2PAGE(addr)], 0, PAGE_SIZE * sizeof(TAG_TYPE));
	}*/
}

/*
 * test wether a address is tagged or not
 *
 * @addr:	the virtual address
 *
 * returns: 0 means no tag, other means tagged
 */

/* 
	Below defined functions are for 
	taint spread from file
*/
/*
	Set taint at addr
*/
void PIN_FAST_ANALYSIS_CALL
tagmap_setb_with_tag(size_t addr, tag_t const & tag)
{
    tag_dir_setb(tag_dir, addr, tag);
}

/*
	Clear taint at addr
*/
void PIN_FAST_ANALYSIS_CALL
file_tagmap_clrb(ADDRINT addr){
	tagmap_setb_with_tag(addr, tag_traits<tag_t>::cleared_val);
}

/* 
	Clean n taint starting from addr
*/
void PIN_FAST_ANALYSIS_CALL
file_tagmap_clrn(ADDRINT addr, UINT32 n){
	//LOG(StringFromAddrint(addr) + "  " + decstr(n) + "\n");
	ADDRINT i;
	for(i=addr;i<addr+n;i++){
	//	LOG(StringFromAddrint(i) + "  ");
		file_tagmap_clrb(i);
	}
	//LOG("\n");
}

/* 
	Get taint at addr
*/
tag_t file_tagmap_getb(ADDRINT addr){
	return tag_dir_getb(tag_dir, addr);
}

bool file_tag_testb(ADDRINT addr){
        if (addr > 0x7fffffffffff)
                return 0;
        return 1;
}