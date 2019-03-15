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

#include "pin.H"

#include "def.h"
#include "tagmap.h"

/*
 * all run-time data structure are defined as *_ctx_t,
 *  static data structure are defined as *_desc(in other head files)
 */

/*
 * virtual CPU (VCPU) context definition;
 * x86/x86_32/i386 arch
 */
typedef struct {
  // general purpose registers (GPRs)
  tag_t gpr[GRP_NUM + 1][TAGS_PER_GPR];
} vcpu_ctx_t;

/*
 * system call context definition
 *
 * only up to SYSCALL_ARGS (i.e., 6) are saved
 */
typedef struct {
  int nr;                       /* syscall number */
  ADDRINT arg[SYSCALL_ARG_NUM]; /* arguments */
  ADDRINT ret;                  /* return value */
  void *aux;                    /* auxiliary data */
  /* 	ADDRINT errno; */       /* error code */
} syscall_ctx_t;

/* thread context definition */
typedef struct {
  vcpu_ctx_t vcpu;           /* VCPU context */
  syscall_ctx_t syscall_ctx; /* syscall context */
  UINT32 syscall_nr;
} thread_ctx_t;

/* instruction (ins) descriptor */
typedef struct {
  void (*pre)(INS ins);  /* pre-ins instrumentation callback */
  void (*post)(INS ins); /* post-ins instrumentation callback */
} ins_desc_t;

/* libdft API */
int libdft_init(void);
void libdft_die(void);

/* ins API */
int ins_set_pre(ins_desc_t *, void (*)(INS));
int ins_clr_pre(ins_desc_t *);
int ins_set_post(ins_desc_t *, void (*)(INS));
int ins_clr_post(ins_desc_t *);

#endif /* __LIBDFT_API_H__ */
