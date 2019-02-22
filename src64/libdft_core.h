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

#ifndef __LIBDFT_CORE_H__
#define __LIBDFT_CORE_H__

#define OP_0		0			/* 0th (1st) operand index */
#define OP_1		1			/* 1st (2nd) operand index */
#define OP_2		2			/* 2nd (3rd) operand index */
#define OP_3		3			/* 3rd (4th) operand index */
#define OP_4		4			/* 4th (5th) operand index */
#define R32_ALIGN	12			/* alignment offset for 
						   mapping 32-bit PIN registers
						   to VCPU registers */
#define VCPU_MASK32	0x0F			/* 32-bit VCPU mask */
#define VCPU_MASK16	0x03			/* 16-bit VCPU mask */
#define VCPU_MASK8	0x01			/* 8-bit VCPU mask */
#define MEM_64BIT_LEN   64
#define MEM_LONG_LEN	32			/* long size (32-bit) */
#define MEM_WORD_LEN	16			/* word size (16-bit) */
#define MEM_BYTE_LEN	8			/* byte size (8-bit) */
#define BIT2BYTE(len)	((len) >> 3)		/* scale change; macro */
#define MAX_32BIT_VALUE 0xffffffff
#define MAX_64BIT_VALUE 0xffffffffffffffff

#define EFLAGS_DF(eflags)	((eflags & 0x0400))
/* core API */
void ins_inspect(INS);
//FLAG_TYPE ct(TAG_TYPE, TAG_TYPE);

/* REG INDEX API*/
size_t REG_INDX(REG);
REG VCPU_INDX(size_t);

#define DEBUG

#endif /* __LIBDFT_CORE_H__ */


