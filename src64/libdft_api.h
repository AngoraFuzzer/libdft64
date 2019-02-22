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

#ifndef __LIBDFT_API_H__
#define __LIBDFT_API_H__

#include <sys/syscall.h>

#include <unistd.h>

#include "tagmap.h"


#include "pin.H"


#include <set>
#include <vector>
#include <map>
#include <iostream>
#include <fstream>


//#define CPUID_FEATURE_INFO_EDX_MASK (0xf87ffffe) /* turn off FPU, MMX FXSR SSE SSE2 */
#define CPUID_FEATURE_INFO_EDX_MASK (0xf87f76ee) /* turn off FPU, MMX FXSR SSE SSE2 */
#define CPUID_FEATURE_INFO_ECX_MASK (0xc007cdec) /* turn off FPU, MMX FXSR SSE SSE2 */

#define MAX_ARG_PAGES 32
#define ARG_STACK_SIZE MAX_ARG_PAGES*PAGE_SIZE

#define SYSCALL_MAX	__NR_sched_getattr+1	/* max syscall number */
#define SYSCALL_ARG_NUM	6			/* syscall arguments */
#define SYSCALL_ARG0	0			/* 1st argument in syscall */
#define SYSCALL_ARG1	1			/* 2nd argument in syscall */
#define SYSCALL_ARG2	2			/* 3rd argument in syscall */
#define SYSCALL_ARG3	3			/* 4th argument in syscall */
#define SYSCALL_ARG4	4			/* 5th argument in syscall */
#define SYSCALL_ARG5	5			/* 6th argument in syscall */
#define THREAD_CTX_BLK	128			/* block of thread contexts */

#define DFT_REG_RDI     3
#define DFT_REG_RSI     4
#define DFT_REG_RBP     5
#define DFT_REG_RSP     6
#define DFT_REG_RBX     7
#define DFT_REG_RDX     8
#define DFT_REG_RCX     9
#define DFT_REG_RAX     10
#define DFT_REG_R8		11
#define DFT_REG_R9		12
#define DFT_REG_R10		13
#define DFT_REG_R11		14
#define DFT_REG_R12		15
#define DFT_REG_R13		16
#define DFT_REG_R14		17
#define DFT_REG_R15		18
#define DFT_REG_XMM0    19
#define DFT_REG_XMM1    20
#define DFT_REG_XMM2    21
#define DFT_REG_XMM3    22
#define DFT_REG_XMM4    23
#define DFT_REG_XMM5    24
#define DFT_REG_XMM6    25
#define DFT_REG_XMM7    26
#define DFT_REG_XMM8    27
#define DFT_REG_XMM9    28
#define DFT_REG_XMM10   29
#define DFT_REG_XMM11   30
#define DFT_REG_XMM12   31
#define DFT_REG_XMM13   32
#define DFT_REG_XMM14   33
#define DFT_REG_XMM15   34
#define DFT_REG_ST0             35
#define DFT_REG_ST1             36
#define DFT_REG_ST2             37
#define DFT_REG_ST3             38
#define DFT_REG_ST4             39
#define DFT_REG_ST5             40
#define DFT_REG_ST6             41
#define DFT_REG_ST7             42
#define REG_NUM                 43
#define XMM_NUM                 35
#define DFT_REG_HELPER1 0
#define DFT_REG_HELPER2 1
#define DFT_REG_HELPER3	2
#define GRP_NUM			43			/* general purpose registers */
#define TAGS_PER_GPR	16			/* general purpose registers */

#define MAX_NUM_32BIT	0xffffffff
#define MAX_NUM_64BIT	0xffffffffffffffff
#define MAX_NUM			MAX_NUM_64BIT
//#define VM_LOW_BOUND	0x09048000
//#define VM_HIGH_BOUND	0xc0000000

/* all run-time data structure are defined as *_ctx_t,
   static data structure are defined as *_desc(in other head files)*/
/*
 * virtual CPU (VCPU) context definition;
 * x86/x86_32/i386 arch
 */

/* Cmp.out File */
extern std::ofstream out;
extern std::ofstream out_lea;
extern std::ofstream reward_taint;


extern int limit_offset;
extern bool mmap_type;

/* Flag to start taint */
extern int flag;


typedef struct{
	string name;
	ADDRINT laddr;
	BOOL isMain;
} img_ctx_t;

typedef std::map<ADDRINT, img_ctx_t* > img_map_t;

typedef std::set<ADDRINT> ARRAY_SET_T;
typedef std::map<ADDRINT, std::set<ADDRINT>* > ARRAY_MAP_T;
typedef struct {
	/*
	 * general purpose registers (GPRs)
	 */
	//TAG_TYPE gpr[GRP_NUM + 1];
	tag_t gpr_file[GRP_NUM+1][TAGS_PER_GPR];
} vcpu_ctx_t;

#define LOOP_CTX_TYPE 1
#define FUNC_CTX_TYPE 2

/*
 * system call context definition
 *
 * only up to SYSCALL_ARGS (i.e., 6) are saved
 */
typedef struct {
	int 	nr;			/* syscall number */
	ADDRINT arg[SYSCALL_ARG_NUM];	/* arguments */
	ADDRINT ret;			/* return value */
	void	*aux;			/* auxiliary data */
/* 	ADDRINT errno; */		/* error code */
} syscall_ctx_t;

#define TYPE_IMM 0
#define TYPE_REG 1
#define TYPE_MEM 2
typedef struct{
	UINT8 type;
	UINT64 value;
	union{
		REG reg;
		UINT64 addr;
	};
//	TAG_TYPE *ptag;
} opnd_t;


#define NOCHECK			0			/*setup at ADD,ADC,SUB,SBB before, and check after*/
#define CHECK			1

/* thread context definition */
typedef struct {
	vcpu_ctx_t	    vcpu;		/* VCPU context */
	syscall_ctx_t	syscall_ctx;	/* syscall context */
	UINT32			syscall_nr;
} thread_ctx_t;

/* instruction (ins) descriptor */
typedef struct {
	void (* pre)(INS ins);		/* pre-ins instrumentation callback */
	void (* post)(INS ins);		/* post-ins instrumentation callback */
} ins_desc_t;


/* libdft API */
int libdft_init(int, char**);
void libdft_start(void);
void libdft_die(void);

/* ins API */
int ins_set_pre(ins_desc_t*, void (*)(INS));
int ins_clr_pre(ins_desc_t*);
int ins_set_post(ins_desc_t*, void (*)(INS));
int ins_clr_post(ins_desc_t*);

/* REG API */
size_t REG64_INDX(REG);
size_t REG32_INDX(REG);
size_t REG16_INDX(REG);
size_t REG8_INDX(REG);

/* dump API */
//void write_stack_array(ADDRINT, ADDRINT, ARRAY_SET_T* );
//void write_heap_array(heap_desc_t*, ADDRINT, ARRAY_SET_T*);
//img_ctx_t* locate_img(ADDRINT);


#endif /* __LIBDFT_API_H__ */
