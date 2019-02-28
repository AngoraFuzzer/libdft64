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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <map>
#include <set>
#include <vector>
#include <string>
#include <assert.h>
#include <sys/stat.h>
#include <iostream>
#include <fstream>

#include "libdft_api.h"
#include "libdft_core.h"
#include "syscall_desc.h"
#include "tagmap.h"
#include "branch_pred.h"
#include "libdft_log.h"


/* Cmp.out file offset */
std::ofstream out;
std::ofstream out_lea;

std::ofstream reward_taint;


/* Flag to start taint */
int flag = 0;
int limit_offset;
bool mmap_type;
/* threads context counter */
static size_t tctx_ct = 0;

/* threads context */
thread_ctx_t *threads_ctx = NULL;

/* IMG context */
img_map_t *img_map = NULL;

/* exec entry */
ADDRINT EXEC_ENTRY = 0;

//PIN_MUTEX ArrayLock;
//PIN_MUTEX MergeLock;

FILE* fMergeLog;

/* heap descriptors */


/* syscall descriptors */
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

/* library call descriptors */

/* ins descriptors */
ins_desc_t ins_desc[XED_ICLASS_LAST];

/*extern KNOB<std::string> KnobImgDesc;
extern KNOB<std::string> KnobLoopDesc;
extern KNOB<std::string> KnobTaintDesc;

std::set<ADDRINT> accessed_func_sets;
std::map<ADDRINT, bool> to_store;
std::map<UINT256_T, bool> to_store_heap;
std::map<pair<int,int>, int> file_offsets;


static void get_path(string *loadpath)
{
	int pid;

	*loadpath = KnobImgDesc.Value();
	if ((*loadpath)[loadpath->length()]!='/')
		*loadpath += '/';
	pid = PIN_GetPid();
	*loadpath += std::to_string(pid);
	*loadpath += "/";
	mkdir(loadpath->c_str(), S_IRWXU);
};

static void read_funcs(const std::string &fname, FLAG_TYPE mask, ADDRINT laddr)
{
	ssize_t read;
	char* line;
	size_t len = 0;
	UINT64 entry;
	TAG_TYPE* ptag;
	FILE* pfile = fopen(fname.c_str(),"r");

	assert(pfile!=NULL);

	while ((read = getline(&line, &len, pfile))!=-1){
		sscanf(line, "0x%lx\n",&entry);
		entry = entry + laddr;
		//LOG("accessed_func " + StringFromAddrint(entry) + "\n");
		if (TEST_MASK(mask, FUNC_ENTRY_MASK)){
			accessed_func_sets.insert(entry);
			to_store[entry] = 0;
		}
		ptag = tagmap_get_ref(entry);
		ptag->cflag = SET_MASK(ptag->cflag,mask);
		free(line);
	}
	free(line);

	fclose(pfile);
}

img_ctx_t* locate_img(ADDRINT faddr)
{
	ADDRINT laddr;
	std::set<ADDRINT>::iterator sort_it;
	img_ctx_t *img_ctx;
	std::set<ADDRINT> sorted_set;
	img_map_t::iterator map_iter;

	for (map_iter = img_map->begin(); map_iter != img_map->end(); map_iter++){
		sorted_set.insert(map_iter->first);
	}

	laddr = 0;
	for (sort_it=sorted_set.begin(); sort_it!=sorted_set.end(); sort_it++){
		if (faddr > *sort_it)
			laddr = *sort_it;
		else
			break;
	}
	if (laddr == 0)
		return NULL;
	img_ctx = (*img_map)[laddr];
	return img_ctx;
}

static void read_loops(const std::string &fname, ADDRINT laddr)
{
	ssize_t read;
	char* line;
	size_t len = 0;
	UINT64 addr, loop_head;
	TAG_TYPE* ptag;
	UINT64 sid = 0x2000;//start of loop id;
	UINT64 offset, count;
	FILE* pfile = fopen(fname.c_str(),"r");

	assert(pfile!=NULL);

	while ((read = getline(&line, &len, pfile))!=-1){
		sscanf(line, "0x%lx 0x%lx\n",&addr, &count);
		addr = addr + laddr;
		ptag = tagmap_get_ref(addr);
		ptag->cflag = SET_MASK(ptag->cflag,LOOP_ENTRY_MASK);
		ptag->sid = sid;
		loop_head = addr;
		free(line);
		for (offset = 0; offset < count; offset++){
			assert((read = getline(&line, &len, pfile))!=-1);
			sscanf(line, "0x%lx\n", &addr);
			addr = addr + laddr;
			ptag = tagmap_get_ref(addr);
			ptag->cflag = SET_MASK(ptag->cflag,LOOP_BODY_MASK);
			ptag->body_sid = sid;
			ptag->loop_head = loop_head;
			free(line);
		}
		sid++;
	}
	fclose(pfile);
}

static void read_heap_taint(const std::string &fname)
{
}

static void write_heap_taint(const std::string &fname, const std::string &fcstack)
{
	heap_desc_map_t::iterator desc_iter;
	heap_desc_t* heap_desc;
	UINT256_T md5;
	UINT32 i;
	TAG_TYPE *ptag;
	std::vector<ADDRINT>::iterator calliter;
	img_ctx_t* img_ctx;
	FILE *pfile_taint = fopen(fname.c_str(),"w");
	FILE *pfile_stack = fopen(fcstack.c_str(),"w");

	for (desc_iter = heap_desc_map.begin(); desc_iter!=heap_desc_map.end(); desc_iter++)
	{
		md5 = desc_iter->first;
		heap_desc = desc_iter->second;
		if (heap_desc->dlength == 0)
			continue;

		if(to_store_heap[md5] == 0)
			continue;

		for (i=0;i<4;i++)
			fprintf(pfile_taint,"%lx",md5.d[i]);
		int ct = 0;
		ptag = heap_desc->dtags;
	        
		for(i=0; i< heap_desc->dlength; i++){
			if(ptag[i].istaint > 0 )
				ct++;
		}
		fprintf(pfile_taint, ",%x\n", ct);
		for (i=0; i< heap_desc->dlength; i++){
			std::string s = "{}";
			Taint<std::string>* t = ptag[i].file_taint;
			s = t->gettaint();
			if(ptag[i].istaint)
				fprintf(pfile_taint, "0x%x:0x%lx, size=%x, flag=%x, size_file=%x, file=%s\n",i, ptag[i].base_addr, ptag[i].size,ptag[i].dflag, ptag[i].istaint, s.c_str());
		}

		fprintf(pfile_stack, "MD5 = ");
		for (i=0;i<4;i++)
			fprintf(pfile_stack,"%lx",md5.d[i]);
		fprintf(pfile_stack, "\n");
		i = 0;
		for (calliter = heap_desc->callstack.begin(); calliter != heap_desc->callstack.end(); calliter++)
		{
			img_ctx = locate_img(*calliter);
			assert(img_ctx!=NULL);
			fprintf(pfile_stack, "%d:%lx,%s\n",i, *calliter-img_ctx->laddr, img_ctx->name.c_str());
			i++;
		}
	}
}

static void read_stack_taint(const std::string &fname, ADDRINT laddr)
{
	ssize_t read;
	  char* line;
	  UINT32 dlen;
	  size_t len;
	  UINT32 i, dummy;
	  UINT64 addr;
	  TAG_TYPE *ptag;
	  TAG_TYPE *ctag;

	FILE* pfile;

	pfile = fopen(fname.c_str(),"r");
	  if (pfile == NULL)
	  return;

	  while ((read = getline(&line, &len, pfile))!=-1){
	  sscanf(line, "%lx,%x\n",&addr, &dlen);
	  addr = addr + laddr;
	  ctag = tagmap_get_ref(addr);
	  ptag = (TAG_TYPE*)malloc(sizeof(TAG_TYPE)*dlen);
	  for (i=0;i<dlen;i++){
	  assert((read = getline(&line, &len, pfile))!=-1);
	  sscanf(line, "%x:%x-%x,%x\n",&dummy, &(ptag[i].base_addr),&(ptag[i].size),&(ptag[i].dflag));
	  }
	  }
	  fclose(pfile);
	//Clean up the old taint file
	pfile = fopen(fname.c_str(),"w");
	fclose(pfile)
}


static void write_file_offsets(const std::string &fpath){
	std::string storepath;
	std::map<pair<int,int>,int>::iterator it;
	FILE *pfile_taint = fopen(fpath.c_str(),"w");
	for(it = file_offsets.begin();it!=file_offsets.end();it++){
		fprintf(pfile_taint, "%d,%d:%d\n", it->first.first,it->first.second,it->second);
	}
	fclose(pfile_taint);
}

static void write_stack_taint(const std::string &fpath)
{
	std::set<ADDRINT>::iterator it;
	ADDRINT faddr;
	TAG_TYPE *ptag;
	TAG_TYPE *ctag;
	UINT32 i;
	img_ctx_t *img_ctx;
	std::string storepath;
	FILE *pfile;
	ADDRINT laddr;

	for (it = accessed_func_sets.begin(); it!=accessed_func_sets.end(); ++it)
	{
		faddr = *it;
	//	LOG(StringFromAddrint(faddr) + " " + to_string(to_store[faddr]) + "\n");
		if(to_store[faddr] == 0){
			continue;
		}
		ctag = tagmap_get_ref(faddr);
		img_ctx = locate_img(faddr);
		assert(img_ctx!=NULL);
		laddr = img_ctx->laddr;
		LOG(img_ctx->name + " " + StringFromAddrint(faddr-laddr) + " ");
		for(int i=0;i<to_store[faddr].size();i++){
			LOG(to_string(to_store[faddr][i]) + " ");
		}
		LOG("\n");
		storepath = fpath + img_ctx->name;
		mkdir(storepath.c_str(), S_IRWXU);
		storepath += "/stack_taint.raw";
		pfile = fopen(storepath.c_str(), "a+");
		if (ctag->dlength > 0){
			//Dump function and number of taint
			fprintf(pfile, "%lx,%x\n",faddr - laddr, ctag->dlength);
			ptag = (TAG_TYPE*)ctag->dtags;
			for (i=0;i<ctag->dlength;i++){
				ADDRINT addr = faddr - i;
				std::string s = "{}";
	//			LOG(StringFromAddrint(addr) + "\n");
	//			LOG(ptag[i].file_taint->gettaint() + "\n");
//				if(file_tag_testb(addr)){
					Taint<std::string>* t = ptag[i].file_taint;
					s = t->gettaint();
//					//LOG(StringFromAddrint(addr) + " " + s + "\n");
//				}
				//index:base-size,dflag
				//if (TEST_MASK(ptag[i].dflag, ACCESS_MASK)) //remove when real
				fprintf(pfile, "-0x%x:-0x%lx, size=%x, flag=%x, size_file=%x, file=%s\n",i, ptag[i].base_addr, ptag[i].size,ptag[i].dflag, ptag[i].istaint, s.c_str());
			}
		}
		fclose(pfile);
	}
}

static inline void write_array(FILE* pfile, ADDRINT root, ARRAY_SET_T* praw)
{
	ARRAY_SET_T::iterator iter;

	for (iter = praw->begin(); iter!=praw->end(); iter++)
	{
		std::string s = "{}";
		if(file_tag_testb(*iter)){
			tag_t t = file_tagmap_getb(*iter);
			int no = t.numberOfOnes();
			if(no <= limit_offset && no > 0)
				s = tag_sprint(t);
		//	LOG(StringFromAddrint(*iter) + " " + s + "\n");
		}

		if (*iter >= root)
			fprintf(pfile, "0x%lx,%s ",*iter-root,s.c_str());
		else
			fprintf(pfile, "-0x%lx,%s ",root-*iter,s.c_str());
	}
	fprintf(pfile,"\n");
}

void write_stack_array(ADDRINT func_entry, ADDRINT root, ARRAY_SET_T *praw)
{
	img_ctx_t *img_ctx;
	std::string loadpath;
	FILE* pfile;

	img_ctx = locate_img(func_entry);
	assert(img_ctx!=NULL);
	get_path(&loadpath);
	loadpath += img_ctx->name;
	mkdir(loadpath.c_str(), S_IRWXU);
	loadpath += "/stack_array.raw";
	PIN_MutexLock(&ArrayLock);
	pfile = fopen(loadpath.c_str(),"a+");
	fprintf(pfile, "%lx\n",func_entry - img_ctx->laddr);
	write_array(pfile, root, praw);
	fclose(pfile);
	PIN_MutexUnlock(&ArrayLock);
}

void write_heap_array(heap_desc_t* pdesc, ADDRINT root, ARRAY_SET_T *praw)
{
	FILE* pfile;
	std::string loadpath;
	int i;

	get_path(&loadpath);
	loadpath += "heap_array.raw";

	PIN_MutexLock(&ArrayLock);
	pfile = fopen(loadpath.c_str(),"a+");
	for (i=0;i<4;i++)
		fprintf(pfile,"%lx",pdesc->md5.d[i]);
	fprintf(pfile,"\n");
	write_array(pfile, root, praw);
	fclose(pfile);
	PIN_MutexUnlock(&ArrayLock);
}
*/

/*
 * thread start callback (analysis function)
 *
 * allocate space for the syscall context and VCPUs (i.e., thread context)
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @flags:	OS specific flags for the new thread
 * @v:		callback value
 */
	static void
thread_alloc(THREADID tid, CONTEXT *ctx, INT32 flags, VOID *v)
{
	/* store the old threads context */
	thread_ctx_t *tctx_prev = threads_ctx;

	/*
	 * we need more thread contexts; optimized branch (not so frequent);
	 *
	 * NOTE: in case the tid is greater than tctx_ct + THREAD_CTX_BLK we
	 * need to loop in order to allocate enough thread contexts
	 */
	while (unlikely(tid >= tctx_ct)) {
		/* reallocate space; optimized branch */
			if (unlikely((threads_ctx = (thread_ctx_t *)realloc(threads_ctx,
							(tctx_ct + THREAD_CTX_BLK) * sizeof(thread_ctx_t)))
					== NULL)) {
				/* failed; this is fatal we need to terminate */

				/* cleanup */
				free(tctx_prev);

				/* error message */
				fprintf(stderr,"%s:%u", __func__, __LINE__);
	
				/* die */
				libdft_die();
			}

		/* success; patch the counter */
		tctx_ct		+= THREAD_CTX_BLK;
	}
	/*threads_ctx[tid].lowest_rsp = PIN_GetContextReg(ctx,LEVEL_BASE::REG_RSP);
	threads_ctx[tid].highest_rsp = 0x7fffffffffff;
	threads_ctx[tid].rid = 0;
	threads_ctx[tid].vcpu.gpr[DFT_REG_RSP].isPointer = TRUE;
	threads_ctx[tid].vcpu.gpr[DFT_REG_RSP].base_addr = threads_ctx[tid].lowest_rsp;
	INIT_LIST_HEAD(&(threads_ctx[tid].rt_stack_head));*/
}

/* 
 * syscall enter notification (analysis function)
 *
 * save the system call context and invoke any pre-syscall callback
 * functions that have been registered
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @std:	syscall standard (e.g., Linux IA-32, IA-64, etc)
 * @v:		callback value
 */
	static void
sysenter_save(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{
	/* get the syscall number */
	size_t syscall_nr = PIN_GetSyscallNumber(ctx, std);

	/* unknown syscall; optimized branch */
	if (unlikely(syscall_nr >= SYSCALL_MAX)) {
		fprintf(stderr,"%s:%u: unknown syscall(num=%lu)",
				__func__, __LINE__, syscall_nr);
		/* syscall number is set to -1; hint for the sysexit_save() */
		threads_ctx[tid].syscall_ctx.nr = -1;
		/* no context save and no pre-syscall callback invocation */
		return;
	}

	/* pass the system call number to sysexit_save() */
	threads_ctx[tid].syscall_ctx.nr = syscall_nr;

	/*
	 * check if we need to save the arguments for that syscall
	 *
	 * we save only when we have a callback registered or the syscall
	 * returns a value in the arguments
	 */
	if (syscall_desc[syscall_nr].save_args |
			syscall_desc[syscall_nr].retval_args) {
		/*
		 * dump only the appropriate number of arguments
		 * or yet another lame way to avoid a loop (vpk)
		 */
		switch (syscall_desc[syscall_nr].nargs) {
			/* 6 */
			case SYSCALL_ARG5 + 1:
				threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG5] =
					PIN_GetSyscallArgument(ctx,
							std,
							SYSCALL_ARG5);
				/* 5 */
			case SYSCALL_ARG4 + 1:
				threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG4] =
					PIN_GetSyscallArgument(ctx,
							std,
							SYSCALL_ARG4);
				/* 4 */
			case SYSCALL_ARG3 + 1:
				threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG3] =
					PIN_GetSyscallArgument(ctx,
							std,
							SYSCALL_ARG3);
				/* 3 */
			case SYSCALL_ARG2 + 1:
				threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG2] =
					PIN_GetSyscallArgument(ctx,
							std,
							SYSCALL_ARG2);
				/* 2 */
			case SYSCALL_ARG1 + 1:
				threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG1] =
					PIN_GetSyscallArgument(ctx,
							std,
							SYSCALL_ARG1);
				/* 1 */
			case SYSCALL_ARG0 + 1:
				threads_ctx[tid].syscall_ctx.arg[SYSCALL_ARG0] =
					PIN_GetSyscallArgument(ctx,
							std,
							SYSCALL_ARG0);
				/* default */
			default:
				/* nothing to do */
				break;
		}

		/* 
		 * dump the architectural state of the processor;
		 * saved as "auxiliary" data
		 */
		threads_ctx[tid].syscall_ctx.aux = ctx;

		/* call the pre-syscall callback (if any); optimized branch */
		if (unlikely(syscall_desc[syscall_nr].pre != NULL))
			syscall_desc[syscall_nr].pre(tid,&threads_ctx[tid].syscall_ctx);
	}
}

/* 
 * syscall exit notification (analysis function)
 *
 * save the system call context and invoke any post-syscall callback
 * functions that have been registered
 *
 * NOTE: it performs tag cleanup for the syscalls that have side-effects in
 * their arguments
 *
 * @tid:	thread id
 * @ctx:	CPU context
 * @std:	syscall standard (e.g., Linux IA-32, IA-64, etc)
 * @v:		callback value
 */
	static void
sysexit_save(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v)
{
	/* iterator */
	size_t i;

	/* get the syscall number */
	int syscall_nr = threads_ctx[tid].syscall_ctx.nr;

	/* unknown syscall; optimized branch */
	if (unlikely(syscall_nr < 0)) {
		fprintf(stderr,"%s:%u: unknown syscall(num=%d)",
				__func__, __LINE__, syscall_nr);
		/* no context save and no pre-syscall callback invocation */
		return;
	}

	/*
	 * return value of a syscall is store in EAX, usually it is not a pointer
	 * So need to clean the tag of EAX, if it is, the post function should
	 * retag EAX
	 */
	//threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX].dflag = 0;

	/*
	 * check if we need to save the arguments for that syscall
	 *
	 * we save only when we have a callback registered or the syscall
	 * returns a value in the arguments
	 */
	if (syscall_desc[syscall_nr].save_args |
			syscall_desc[syscall_nr].retval_args) {
		/* dump only the appropriate number of arguments */
		threads_ctx[tid].syscall_ctx.ret =
			PIN_GetSyscallReturn(ctx, std);

		/* 
		 * dump the architectural state of the processor;
		 * saved as "auxiliary" data
		 */
		threads_ctx[tid].syscall_ctx.aux = ctx;

		/* thread_ctx[tid].syscall_ctx.errno =
		   PIN_GetSyscallErrno(ctx, std); */

		/* call the post-syscall callback (if any) */
		if (syscall_desc[syscall_nr].post != NULL){
			syscall_desc[syscall_nr].post(tid,&threads_ctx[tid].syscall_ctx);
		}
		else {
			/* default post-syscall handling */

			/* 
			 * the syscall failed; typically 0 and positive
			 * return values indicate success
			 */
			if (threads_ctx[tid].syscall_ctx.ret < 0)
				/* no need to do anything */
				return;

			/* traverse the arguments map */
			for (i = 0; i < syscall_desc[syscall_nr].nargs; i++)
				/* analyze each argument */
				if (unlikely(syscall_desc[syscall_nr].map_args[i] > 0)) 
					/* sanity check -- probably non needed */
					if (likely(
								(void *)threads_ctx[tid].syscall_ctx.arg[i] != NULL))
						/* 
						 * argument i is changed by the system call;
						 * the length of the change is given by
						 * map_args[i]
						 */
						file_tagmap_clrn(threads_ctx[tid].syscall_ctx.arg[i], syscall_desc[syscall_nr].map_args[i]);
		}
	}
}

/*
 * trace inspection (instrumentation function)
 *
 * traverse the basic blocks (BBLs) on the trace and
 * inspect every instruction for instrumenting it
 * accordingly
 *
 * @trace:      instructions trace; given by PIN
 */
	static void
trace_inspect(TRACE trace, VOID *v)
{
	/* iterators */
	BBL bbl;
	INS ins;
	xed_iclass_enum_t ins_indx;

	/* traverse all the BBLs in the trace */
	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		/* traverse all the instructions in the BBL */
		for (ins = BBL_InsHead(bbl);
				INS_Valid(ins);
				ins = INS_Next(ins)) {
			/*
			 * use XED to decode the instruction and
			 * extract its opcode
			 */
			ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);

			/* 
			 * invoke the pre-ins insrumentation callback;
			 * optimized branch
			 */
			if (unlikely(ins_desc[ins_indx].pre != NULL))
				ins_desc[ins_indx].pre(ins);

			/* analyze the instruction */
		//        LOG(INS_Disassemble(ins)+ " " + StringFromAddrint(INS_Address(ins)) + "\n");
			ins_inspect(ins);

			/* 
			 * invoke the post-ins insrumentation callback;
			 * optimized branch
			 */
			if (unlikely(ins_desc[ins_indx].post != NULL))
				ins_desc[ins_indx].post(ins);

		}
	}
}


/*
 * initialize thread contexts
 *
 * allocate space for the thread contexts and
 * register a thread start callback
 *
 * returns: 0 on success, 1 on error
 */
	static inline int
thread_ctx_init(void)
{
	/* allocate space for the thread contexts; optimized branch
	 * 
	 * NOTE: allocation is performed in blocks of THREAD_CTX_BLK
	 */
	threads_ctx = new thread_ctx_t[THREAD_CTX_BLK]();

	if (unlikely(threads_ctx == NULL)) { 
////	if (unlikely((threads_ctx = (thread_ctx_t *)calloc(THREAD_CTX_BLK,
//						sizeof(thread_ctx_t))) == NULL)) { 
		/* error message */
		fprintf(stderr,"%s:%u", __func__, __LINE__);
		/* failed */
		libdft_die();
		return 1;
	}

	/* initialize the context counter */
	tctx_ct = THREAD_CTX_BLK;

	/* 
	 * thread start hook;
	 * keep track of the threads and allocate space for the per-thread
	 * logistics (i.e., syscall context, VCPU, etc)
	 */
	PIN_AddThreadStartFunction(thread_alloc, NULL);

	/* success */
	return 0;
}

/*	static void
img_inspect(IMG img, VOID *v)
{
	ADDRINT low_addr;
	std::string loadpath;
	std::vector<std::string> splitted;
	img_ctx_t *img_ctx;

	if (IMG_Invalid() == img)
		return;
	low_addr = IMG_LowAddress(img);
	img_ctx = new img_ctx_t();
	(*img_map)[low_addr] = img_ctx;
	SplitString(IMG_Name(img), splitted, "/");

	img_ctx->name = splitted.back();
	img_ctx->isMain = FALSE;
	img_ctx->laddr = low_addr;

	if (IMG_IsMainExecutable(img)){
		//LOG("mainEXE " + StringFromAddrint(low_addr) + "\n");
		EXEC_ENTRY = IMG_Entry(img);
		img_ctx->isMain = TRUE;
		img_ctx->name = "mainEXE";
	}

	loadpath = KnobImgDesc.Value();
	if (loadpath[loadpath.length()]!='/')
		loadpath += '/';

	loadpath = loadpath + img_ctx->name;
	read_funcs(loadpath+"/funcs.raw", FUNC_ENTRY_MASK, low_addr);
	read_loops(loadpath+"/loops.raw", low_addr);
}

void forkAfter(THREADID tid, const CONTEXT *ctxt, VOID *v)
{
	std::string loadpath;

	fclose(fMergeLog);
	get_path(&loadpath);
	loadpath += "merge.raw";
	fMergeLog = fopen(loadpath.c_str(),"w");
}
*/
void finish(INT32 code, VOID *v)
{
	//std::string loadpath;

	//free_callback();
	//get_path(&loadpath);
	//printf("Finish with %s\n",loadpath.c_str());
	// Cmp.out close file and flush the stream
	out.flush();
	out.close();
	out_lea.flush();
	out_lea.close();
	reward_taint.flush();
	reward_taint.close();
	// End
//	write_stack_taint(loadpath);
//	write_heap_taint((loadpath+"heap.taint"),(loadpath+"heap.callstack"));
//	write_file_offsets(loadpath+"file.taint");
//	PIN_MutexFini(&ArrayLock);
//	PIN_MutexFini(&HeapLock);
//	PIN_MutexFini(&MergeLock);
	//fclose(fMergeLog);
}


/*
 * initialization of the core tagging engine;
 * it must be called before using everything else
 *
 * @argc:	argc passed in main
 * @argv:	argv passed in main
 *
 * returns: 0 on success, 1 on error
 */
	int
libdft_init(int argc, char **argv)
{
	std::string loadpath;

	std::ios::sync_with_stdio(false);

	/* initialize symbol processing */
	PIN_InitSymbolsAlt(IFUNC_SYMBOLS);

	/* initialize PIN; optimized branch */
	if (unlikely(PIN_Init(argc, argv)))
		/* PIN initialization failed */
		return 1;

//	PIN_MutexInit(&ArrayLock);
//	PIN_MutexInit(&HeapLock);
//	PIN_MutexInit(&MergeLock);
//	get_path(&loadpath);
//	loadpath += "merge.raw";
//	fMergeLog = fopen(loadpath.c_str(),"w");
//	loadpath = "";
//	get_path(&loadpath);
//	loadpath += "reward.taint";
//	reward_taint.open(loadpath.c_str(), std::ios::binary | std::ios::trunc | std::ios::out );
	/* initialize thread contexts; optimized branch */
	if (unlikely(thread_ctx_init()))
		/* thread contexts failed */
		return 1;

	/* initialize the tagmap; optimized branch */
	if (unlikely(tagmap_alloc()))
		/* tagmap initialization failed */
		return 1;

	//PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, forkAfter, NULL);

	/*
	 * syscall hooks; store the context of every syscall
	 * and invoke registered callbacks (if any)
	 */

	/* register sysenter_save() to be called before every syscall */
	PIN_AddSyscallEntryFunction(sysenter_save, NULL);

	/* register sysexit_save() to be called after every syscall */
	PIN_AddSyscallExitFunction(sysexit_save, NULL);

	/* initialize the ins descriptors */
	(void)memset(ins_desc, 0, sizeof(ins_desc));

	//img_map = new img_map_t();
	/* Find the executable entry */
	//IMG_AddInstrumentFunction(img_inspect, NULL);

	/*Register library image instrumentation*/
	//IMG_AddInstrumentFunction(libcall_img_inspect, 0);

	/* Register library trace instrumentation*/
	//TRACE_AddInstrumentFunction(libcall_trace_inspect, NULL);

	/* register trace_ins() to be called for every trace */
	TRACE_AddInstrumentFunction(trace_inspect, NULL);

	PIN_AddFiniFunction(finish, 0);

	/* success */
	return 0;
}

/*
 * start the execution of the application inside the
 * tag-aware VM; this call be invoked even with
 * running applications (i.e., dynamically)
 */
	void
libdft_start(void)
{
	/* start PIN */
	PIN_StartProgram();
}

/*
 * stop the execution of the application inside the
 * tag-aware VM; the execution of the application
 * is not interrupted
 *
 * NOTE: it also performs the appropriate cleanup
 */
	void
libdft_die(void)
{
	/*
	 * deallocate the resources needed for the tagmap
	 * and threads context
	 */
//	delete[] threads_ctx;
	free(threads_ctx);
	tagmap_free();
	LOG("died\n");
	/*
	 * detach PIN from the application;
	 * the application will continue to execute natively
	 */
	PIN_Detach();
}

/*
 * add a new pre-ins callback into an instruction descriptor
 *
 * @desc:       the ins descriptor
 * @pre:        function pointer to the pre-ins handler
 *
 * returns:     0 on success, 1 on error
 */
	int
ins_set_pre(ins_desc_t *desc, void (* pre)(INS))
{
	/* sanity checks */
	if (unlikely((desc == NULL) | (pre == NULL)))
		/* return with failure */
		return 1;

	/* update the pre-ins callback */
	desc->pre = pre;

	/* success */
	return 0;
}

/*
 * add a new post-ins callback into an instruction descriptor
 *
 * @desc:       the ins descriptor
 * @pre:        function pointer to the post-ins handler
 *
 * returns:     0 on success, 1 on error
 */
	int
ins_set_post(ins_desc_t *desc, void (* post)(INS))
{
	/* sanity checks */
	if (unlikely((desc == NULL) | (post == NULL)))
		/* return with failure */
		return 1;

	/* update the post-ins callback */
	desc->post = post;

	/* success */
	return 0;
}

/*
 * remove the pre-ins callback from an instruction descriptor
 *
 * @desc:       the ins descriptor
 *
 * returns:     0 on success, 1 on error
 */
	int
ins_clr_pre(ins_desc_t *desc)
{
	/* sanity check */
	if (unlikely(desc == NULL))
		/* return with failure */
		return 1;

	/* clear the pre-ins callback */
	desc->pre = NULL;

	/* return with success */
	return 0;
}

/*
 * remove the post-ins callback from an instruction descriptor
 *
 * @desc:       the ins descriptor
 *
 * returns:     0 on success, 1 on error
 */
	int
ins_clr_post(syscall_desc_t *desc)
{
	/* sanity check */
	if (unlikely(desc == NULL))
		/* return with failure */
		return 1;

	/* clear the post-ins callback */
	desc->post = NULL;

	/* return with success */
	return 0;
}