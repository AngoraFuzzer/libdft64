#include <err.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>
#include <set>
#include <map>
#include <algorithm>

#include "pin.H"
#include "libdft_api.h"
#include "libdft_core.h"
#include "tagmap.h"
#include "branch_pred.h"
#include "libdft_log.h"

/* threads context */
extern thread_ctx_t  *threads_ctx;
extern ADDRINT EXEC_ENTRY;

//extern PIN_MUTEX MergeLock;
//extern PIN_MUTEX HeapLock;
//extern FILE* fMergeLog;

//ADDRINT DEBUG_IP;
//rt_ctx_t* TRACK_PFUNC;

/* File Taint */
extern tag_dir_t tag_dir;

extern int flag;
extern int limit_offset;
extern std::map<ADDRINT, bool> to_store;
extern std::map<pair<int,int>, int> file_offsets;


#define RTAG(tid) threads_ctx[tid].vcpu.gpr_file

#define R8TAG(tid, RIDX) \
{RTAG(tid)[(RIDX)][0]}
#define R16TAG(tid,RIDX) \
{RTAG(tid)[(RIDX)][0], RTAG(tid)[(RIDX)][1]}
#define R32TAG(tid,RIDX) \
{RTAG(tid)[(RIDX)][0], RTAG(tid)[(RIDX)][1], RTAG(tid)[(RIDX)][2], RTAG(tid)[(RIDX)][3]}
#define R64TAG(tid,RIDX) \
{RTAG(tid)[(RIDX)][0], RTAG(tid)[(RIDX)][1], RTAG(tid)[(RIDX)][2], RTAG(tid)[(RIDX)][3], RTAG(tid)[(RIDX)][4],  RTAG(tid)[(RIDX)][5], RTAG(tid)[(RIDX)][6], RTAG(tid)[(RIDX)][7]}
#define R128TAG(tid,RIDX) \
{RTAG(tid)[(RIDX)][0], RTAG(tid)[(RIDX)][1], RTAG(tid)[(RIDX)][2], RTAG(tid)[(RIDX)][3], RTAG(tid)[(RIDX)][4],  RTAG(tid)[(RIDX)][5], RTAG(tid)[(RIDX)][6], RTAG(tid)[(RIDX)][7], RTAG(tid)[(RIDX)][8],RTAG(tid)[(RIDX)][9],RTAG(tid)[(RIDX)][10],RTAG(tid)[(RIDX)][11],RTAG(tid)[(RIDX)][12],RTAG(tid)[(RIDX)][13],RTAG(tid)[(RIDX)][14],RTAG(tid)[(RIDX)][15]}



#define MTAG(ADDR) \
        tag_dir_getb(tag_dir, (ADDR))
#define M8TAG(ADDR) \
{tag_dir_getb(tag_dir, (ADDR))}
#define M16TAG(ADDR) \
{MTAG(ADDR), MTAG(ADDR+1)}      
#define M32TAG(ADDR) \
{MTAG(ADDR), MTAG(ADDR+1), MTAG(ADDR+2), MTAG(ADDR+3)}  
#define M64TAG(ADDR) \
{MTAG(ADDR), MTAG(ADDR+1), MTAG(ADDR+2), MTAG(ADDR+3), MTAG(ADDR+4), MTAG(ADDR+5), MTAG(ADDR+6), MTAG(ADDR+7)}  
#define M128TAG(ADDR) \
{MTAG(ADDR), MTAG(ADDR+1), MTAG(ADDR+2), MTAG(ADDR+3), MTAG(ADDR+4), MTAG(ADDR+5), MTAG(ADDR+6), MTAG(ADDR+7),  MTAG(ADDR+8),  MTAG(ADDR+9), MTAG(ADDR+10), MTAG(ADDR+11),  MTAG(ADDR+12),  MTAG(ADDR+13),  MTAG(ADDR+14), MTAG(ADDR+15)}  

/* XXX: Latest Intel Pin (3.7) doesn't support INT2STR */
#define INT2STR( x ) static_cast< std::ostringstream & >( \
        ( std::ostringstream() << std::dec << x ) ).str()

UINT32 get_reg_size(REG reg){
        if(REG_is_xmm(reg)){
                return 16;
        }else if(REG_is_gr64(reg)){
                return 8;
        }else if(REG_is_gr32(reg)){
                return 4;
        }else if(REG_is_gr16(reg)){
                return 2;
        }else{
                return 1;
        }
}


size_t REG_INDX(REG reg)
{
        if (reg == REG_INVALID())
                return GRP_NUM;
        switch (reg) {
                case REG_RDI:
                case REG_EDI:
                case REG_DI:
                case REG_DIL:
                        return DFT_REG_RDI;
                        break;
                case REG_RSI:
                case REG_ESI:
                case REG_SI:
                case REG_SIL:
                        return DFT_REG_RSI;
                        break;
                case REG_RBP:
                case REG_EBP:
                case REG_BP:
                case REG_BPL:
                        return DFT_REG_RBP;
                        break;
                case REG_RSP:
                case REG_ESP:
                case REG_SP:
                case REG_SPL:
                        return DFT_REG_RSP;
                        break;
                case REG_RAX:
                case REG_EAX:
                case REG_AX:
                case REG_AH:
                case REG_AL:
                        return DFT_REG_RAX;
                        break;
                case REG_RBX:
                case REG_EBX:
                case REG_BX:
                case REG_BH:
                case REG_BL:
                        return DFT_REG_RBX;
                        break;
                case REG_RCX:
                case REG_ECX:
                case REG_CX:
                case REG_CH:
                case REG_CL:
                        return DFT_REG_RCX;
                        break;
                case REG_RDX:
                case REG_EDX:
                case REG_DX:
                case REG_DH:
                case REG_DL:
                        return DFT_REG_RDX;
                        break;
                case REG_R8:
                case REG_R8D:
                case REG_R8W:
                case REG_R8B:
                        return DFT_REG_R8;
                        break;
                case REG_R9:
                case REG_R9D:
                case REG_R9W:
                case REG_R9B:
                        return DFT_REG_R9;
                        break;
                case REG_R10:
                case REG_R10D:
                case REG_R10W:
                case REG_R10B:
                        return DFT_REG_R10;
                        break;
                case REG_R11:
                case REG_R11D:
                case REG_R11W:
                case REG_R11B:
                        return DFT_REG_R11;
                        break;
                case REG_R12:
                case REG_R12D:
                case REG_R12W:
                case REG_R12B:
                        return DFT_REG_R12;
                        break;
                case REG_R13:
                case REG_R13D:
                case REG_R13W:
                case REG_R13B:
                        return DFT_REG_R13;
                        break;
                case REG_R14:
                case REG_R14D:
                case REG_R14W:
                case REG_R14B:
                        return DFT_REG_R14;
                        break;
                case REG_R15:
                case REG_R15D:
                case REG_R15W:
                case REG_R15B:
                        return DFT_REG_R15;
                        break;
                case REG_XMM0:
                        return DFT_REG_XMM0;
                        break;
                case REG_XMM1:
                        return DFT_REG_XMM1;
                        break;
                case REG_XMM2:
                        return DFT_REG_XMM2;
                        break;
                case REG_XMM3:
                        return DFT_REG_XMM3;
                        break;
                case REG_XMM4:
                        return DFT_REG_XMM4;
                        break;
                case REG_XMM5:
                        return DFT_REG_XMM5;
                        break;
                case REG_XMM6:
                        return DFT_REG_XMM6;
                        break;
                case REG_XMM7:
                        return DFT_REG_XMM7;
                        break;
                case REG_XMM8:
                        return DFT_REG_XMM8;
                        break;
                case REG_XMM9:
                        return DFT_REG_XMM9;
                        break;
                case REG_XMM10:
                        return DFT_REG_XMM10;
                        break;
                case REG_XMM11:
                        return DFT_REG_XMM11;
                        break;
                case REG_XMM12:
                        return DFT_REG_XMM12;
                        break;
                case REG_XMM13:
                        return DFT_REG_XMM13;
                        break;
                case REG_XMM14:
                        return DFT_REG_XMM14;
                        break;
                case REG_XMM15:
                        return DFT_REG_XMM15;
                        break;
                case REG_MM0:
                case REG_ST0:
                        return DFT_REG_ST0;
                        break;
                case REG_MM1:
                case REG_ST1:
                        return DFT_REG_ST1;
			break;
                case REG_MM2:
                case REG_ST2:
                        return DFT_REG_ST2;
                        break;
                case REG_MM3:
                case REG_ST3:
                        return DFT_REG_ST3;
                        break;
                case REG_MM4:
                case REG_ST4:
                        return DFT_REG_ST4;
                        break;
                case REG_MM5:
                case REG_ST5:
                        return DFT_REG_ST5;
                        break;
                case REG_MM6:
                case REG_ST6:
                        return DFT_REG_ST6;
                        break;
                case REG_MM7:
                case REG_ST7:
                        return DFT_REG_ST7;
                        break;

                default:
                        break;
        }
        /* nothing */
        return GRP_NUM;

}

inline REG VCPU_INDX(size_t indx)
{
        REG reg;

        if ((indx >= 3)&&(indx < GRP_NUM))
                reg = (REG)(indx);
        else
                reg = REG_INVALID();
        return reg;

}


void get_array_mem(ADDRINT addr, int size, std::vector<tag_t> &tag){
        switch (size){
                case 1:{
                               tag_t temp[] = M8TAG(addr);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                       }
                case 2:{
                               tag_t temp[] = M16TAG(addr);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                       }
                case 4:{
                               tag_t temp[] = M32TAG(addr);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                       }
                case 8:{
                               tag_t temp[] = M64TAG(addr);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                       }
                case 16:{
                               tag_t temp[] = M128TAG(addr);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                        }
                default:
                     
return;                                                                                                                                                                                                                                                               
        }
}


void get_array_reg(THREADID tid, uint32_t reg, int size, std::vector<tag_t> &tag){                                                             
        switch (size){
                case 1:{
                               tag_t temp[] = R8TAG(tid, reg);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                       }
                case 2:{
                               tag_t temp[] = R16TAG(tid, reg);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                       }
                case 4:{
                               tag_t temp[] = R32TAG(tid, reg);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                       }
                case 8:{
                               tag_t temp[] = R64TAG(tid, reg);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                       }
                case 16:{
                               tag_t temp[] = R128TAG(tid, reg);
                               for(int i=0;i<size;i++){
                                       tag[i] = temp[i];
                               }
                               break;
                        }
                default:{
                                return;
                        }
        }
        return;
}

vector<std::string> splitted;
void split( std::string const& original, char separator )
{
        std::string::const_iterator start = original.begin();
        std::string::const_iterator end = original.end();
        std::string::const_iterator next = std::find( start, end, separator );
        while ( next != end ) {
                splitted.push_back( std::string( start, next ) );
                start = next + 1;
                next = std::find( start, end, separator );
        }
        splitted.push_back( std::string( start, next ) );
}
/* Printing Log of CMP */
vector<string> output(21,"{}");
void print_log(){
        splitted.clear();
        for(size_t i=3;i<19;i++){
                split(output[i],',');
                if((int)splitted.size() > limit_offset){
                        splitted.clear();
                        return;
                }
                splitted.clear();
        }
        //LOG("IN PRINT LOG\n");
        for(size_t i=0;i<21;i++){
                out << output[i];
                out << " ";
        }
        out << std::endl;
        out << flush;
}
/* Printing Log of LEA */
vector<string> output_lea(10,"{}");
void print_lea_log(){
        splitted.clear();
        for(size_t i=2;i<10;i++){
                split(output_lea[i],',');
                if((int)splitted.size() > limit_offset){
                        splitted.clear();
                        return;
                }
                splitted.clear();
        }
        //LOG("IN PRINT LOG\n");
        for(size_t i=0;i<10;i++){
                out_lea << output_lea[i];
                out_lea << " ";
        }
        out_lea << std::endl;
        out_lea << flush;
}


static void PIN_FAST_ANALYSIS_CALL
_cdqe(THREADID tid)
{
    tag_t src_tag[] = R64TAG(tid, DFT_REG_RAX);
    RTAG(tid)[DFT_REG_RAX][4] = src_tag[0];
    RTAG(tid)[DFT_REG_RAX][5] = src_tag[1];
    RTAG(tid)[DFT_REG_RAX][6] = src_tag[2];
    RTAG(tid)[DFT_REG_RAX][7] = src_tag[3];
}

static void PIN_FAST_ANALYSIS_CALL
_cwde(THREADID tid)
{
    tag_t src_tag[] = R16TAG(tid, DFT_REG_RAX);
    RTAG(tid)[DFT_REG_RAX][2] = src_tag[0];
    RTAG(tid)[DFT_REG_RAX][3] = src_tag[1];
}


/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 16-bit 
 * register and an 8-bit register as t[dst] = t[upper(src)]
 *
 * NOTE: special case for MOVSX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_opwb_u(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];
	
    /* update the destination (xfer) */
    threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
    threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 16-bit 
 * register and an 8-bit register as t[dst] = t[lower(src)]
 *
 * NOTE: special case for MOVSX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_opwb_l(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
        tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];

	/* update the destination (xfer) */
	threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_opqb_u(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];

	/* update the destination (xfer) */
    for(size_t i = 0; i < 8; i++)
        threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_oplb_u(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];

	/* update the destination (xfer) */
    for(size_t i = 0; i < 4; i++)
        threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_opqb_l(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];

	/* update the destination (xfer) */
    for (size_t i = 0; i < 8; i++)
            threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_oplb_l(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];

	/* update the destination (xfer) */
    for (size_t i = 0; i < 4; i++)
            threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_opqw(THREADID tid, uint32_t dst, uint32_t src)
{
        /* temporary tag values */
    tag_t src_low_tag = threads_ctx[tid].vcpu.gpr_file[src][0];
    tag_t src_high_tag = threads_ctx[tid].vcpu.gpr_file[src][1];

    /* update the destination (xfer) */
        threads_ctx[tid].vcpu.gpr_file[dst][0] = src_low_tag;
        threads_ctx[tid].vcpu.gpr_file[dst][1] = src_high_tag;
        threads_ctx[tid].vcpu.gpr_file[dst][2] = src_low_tag;
        threads_ctx[tid].vcpu.gpr_file[dst][3] = src_high_tag;
        threads_ctx[tid].vcpu.gpr_file[dst][4] = src_low_tag;
        threads_ctx[tid].vcpu.gpr_file[dst][5] = src_high_tag;
        threads_ctx[tid].vcpu.gpr_file[dst][6] = src_low_tag;
        threads_ctx[tid].vcpu.gpr_file[dst][7] = src_high_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_opql(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag values */
    tag_t src_tag[] = R32TAG(tid, src);
	

    for (size_t i = 0; i < 8; i++)
	    RTAG(tid)[dst][i] = src_tag[i%4];
}


static void PIN_FAST_ANALYSIS_CALL
_movsx_r2r_oplw(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag values */
    tag_t src_low_tag = threads_ctx[tid].vcpu.gpr_file[src][0];
    tag_t src_high_tag = threads_ctx[tid].vcpu.gpr_file[src][1];
	
    /* update the destination (xfer) */
	threads_ctx[tid].vcpu.gpr_file[dst][0] = src_low_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][1] = src_high_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][2] = src_low_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][3] = src_high_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_opwb(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t src_tag[] = M8TAG(src);
	
    /* update the destination (xfer) */ 
	RTAG(tid)[dst][0] = src_tag[0];
	RTAG(tid)[dst][1] = src_tag[0];
}

static void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_opqb(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t src_tag = tag_dir_getb(tag_dir, src);
	
    /* update the destination (xfer) */
    for (size_t i = 0; i < 8; i++)
	    RTAG(tid)[dst][i] = src_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_oplb(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t src_tag = tag_dir_getb(tag_dir, src);
	
    /* update the destination (xfer) */
    for (size_t i = 0; i < 4; i++)
	    RTAG(tid)[dst][i] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_opqw(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t src_tags[] = M16TAG(src);
	
    /* update the destination (xfer) */
    for (size_t i = 0; i < 8; i++)
	    RTAG(tid)[dst][i] = src_tags[i%2];
}


static void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_opql(THREADID tid, uint32_t dst, ADDRINT src)
{
        /* temporary tag value */
    tag_t src_tags[] = M32TAG(src);

    /* update the destination (xfer) */
    for (size_t i = 0; i < 8; i++)
            RTAG(tid)[dst][i] = src_tags[i%4];
}


static void PIN_FAST_ANALYSIS_CALL
_movsx_m2r_oplw(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t src_tags[] = M16TAG(src);
	
    /* update the destination (xfer) */
    for (size_t i = 0; i < 4; i++)
	    RTAG(tid)[dst][i] = src_tags[i%2];
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 16-bit 
 * register and an 8-bit register as t[dst] = t[upper(src)]
 *
 * NOTE: special case for MOVZX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_opwb_u(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];
	
    /* update the destination (xfer) */
	threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 16-bit 
 * register and an 8-bit register as t[dst] = t[lower(src)]
 *
 * NOTE: special case for MOVZX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source register index (VCPU)
 */
static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_opwb_l(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];
	
    /* update the destination (xfer) */
	threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_opqb_u(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];
	
    /* update the destination (xfer) */
	threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_oplb_u(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];
	
    /* update the destination (xfer) */
	threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_opqb_l(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];
	
    /* update the destination (xfer) */
    for (size_t i = 0; i < 8; i++)
	    threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_oplb_l(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];
	
    /* update the destination (xfer) */
    for (size_t i = 0; i < 4; i++)
	    threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_opqw(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
	tag_t src_tags[] = {threads_ctx[tid].vcpu.gpr_file[src][0], threads_ctx[tid].vcpu.gpr_file[src][1]};

	/* update the destination (xfer) */
    for(size_t i = 0; i < 8; i++)
	    threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tags[i%2];
}


static void PIN_FAST_ANALYSIS_CALL
_movzx_r2r_oplw(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
	tag_t src_tags[] = {threads_ctx[tid].vcpu.gpr_file[src][0], threads_ctx[tid].vcpu.gpr_file[src][1]};

	/* update the destination (xfer) */
    for(size_t i = 0; i < 4; i++)
	    threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tags[i%2];
}

/*
 * tag propagation (analysis function)
 *
 * propagate and extend tag between a 16-bit 
 * register and an 8-bit memory location as
 * t[dst] = t[src]
 *
 * NOTE: special case for MOVZX instruction
 *
 * @thread_ctx:	the thread context
 * @dst:	destination register index (VCPU)
 * @src:	source memory address
 */
static void PIN_FAST_ANALYSIS_CALL
_movzx_m2r_opwb(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t src_tag = M8TAG(src);
	/* update the destination (xfer) */ 
	threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
	threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movzx_m2r_opqb(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
	tag_t src_tag = tag_dir_getb(tag_dir, src);
	//LOG("movzx byte " + tag_sprint(src_tag) + " " + StringFromAddrint(src) + " " + decstr(dst) + "\n");	
	/* update the destination (xfer) */
    for (size_t i = 0; i < 8; i++)
	    threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_movzx_m2r_oplb(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
	tag_t src_tag = tag_dir_getb(tag_dir, src);
	//LOG("movzx byte " + tag_sprint(src_tag) + " " + StringFromAddrint(src) + " " + decstr(dst) + "\n");	
	/* update the destination (xfer) */
    for (size_t i = 0; i < 4; i++)
	    threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_movzx_m2r_opqw(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t src_tags[] = {tag_dir_getb(tag_dir, src), tag_dir_getb(tag_dir, src+1)};

	/* update the destination (xfer) */
    for( size_t i = 0; i < 8; i++)
        threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tags[i%2];
}


static void PIN_FAST_ANALYSIS_CALL
_movzx_m2r_oplw(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t src_tags[] = {tag_dir_getb(tag_dir, src), tag_dir_getb(tag_dir, src+1)};

	/* update the destination (xfer) */
    for( size_t i = 0; i < 4; i++)
        threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tags[i%2];
}

static ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opq_fast(THREADID tid, uint32_t dst_val, uint32_t src,
							uint32_t src_val)
{
	/* save the tag value of dst in the scratch register */
    tag_t save_tags[] = R64TAG(tid, DFT_REG_RAX);
    for (size_t i = 0; i < 8; i++)
        RTAG(tid)[DFT_REG_HELPER1][i] = save_tags[i];

	/* update */
    tag_t src_tags[] = R64TAG(tid, src);

    for (size_t i = 0; i < 8; i++){
        RTAG(tid)[DFT_REG_RAX][i] = src_tags[i];
    }
	/* compare the dst and src values */
	return (dst_val == src_val);
}


static ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opl_fast(THREADID tid, uint32_t dst_val, uint32_t src,
							uint32_t src_val)
{
	/* save the tag value of dst in the scratch register */
    tag_t save_tags[] = R32TAG(tid, DFT_REG_RAX);
    for (size_t i = 0; i < 4; i++)
        RTAG(tid)[DFT_REG_HELPER1][i] = save_tags[i];

	/* update */
    tag_t src_tags[] = R32TAG(tid, src);

    for (size_t i = 0; i < 4; i++){
        RTAG(tid)[DFT_REG_RAX][i] = src_tags[i];
    }
	/* compare the dst and src values */
	return (dst_val == src_val);
}


static void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opq_slow(THREADID tid, uint32_t dst, uint32_t src)
{
	/* restore the tag value from the scratch register */
    tag_t saved_tags[] = {threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][0], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][1],
                            threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][2], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][3],
			  threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][4], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][5], 
			 threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][6], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][7]};
    for (size_t i = 0; i < 8; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = saved_tags[i];

	/* update */
    tag_t src_tags[] = {threads_ctx[tid].vcpu.gpr_file[src][0], threads_ctx[tid].vcpu.gpr_file[src][1],
                        threads_ctx[tid].vcpu.gpr_file[src][2], threads_ctx[tid].vcpu.gpr_file[src][3],
			threads_ctx[tid].vcpu.gpr_file[src][4],	threads_ctx[tid].vcpu.gpr_file[src][5],
			threads_ctx[tid].vcpu.gpr_file[src][6], threads_ctx[tid].vcpu.gpr_file[src][7]};
    for (size_t i = 0; i < 8; i++){
        threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tags[i];
    }
}


static void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opl_slow(THREADID tid, uint32_t dst, uint32_t src)
{
	/* restore the tag value from the scratch register */
    tag_t saved_tags[] = {threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][0], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][1],
                            threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][2], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][3]};
    for (size_t i = 0; i < 4; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = saved_tags[i];

	/* update */
    tag_t src_tags[] = {threads_ctx[tid].vcpu.gpr_file[src][0], threads_ctx[tid].vcpu.gpr_file[src][1],
                            threads_ctx[tid].vcpu.gpr_file[src][2], threads_ctx[tid].vcpu.gpr_file[src][3]};
    for (size_t i = 0; i < 4; i++){
        threads_ctx[tid].vcpu.gpr_file[dst][i] = src_tags[i];
    }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opw_fast(THREADID tid, uint16_t dst_val, uint32_t src,
						uint16_t src_val)
{
	/* save the tag value of dst in the scratch register */
    tag_t save_tags[] = R32TAG(tid, DFT_REG_RAX);
    for (size_t i = 0; i < 4; i++)
        RTAG(tid)[DFT_REG_HELPER1][i] = save_tags[i];

    tag_t src_tags[] = R16TAG(tid, src);
    RTAG(tid)[DFT_REG_RAX][0] = src_tags[0];
    RTAG(tid)[DFT_REG_RAX][1] = src_tags[1];

	/* compare the dst and src values */
	return (dst_val == src_val);
}


static void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2r_opw_slow(THREADID tid, uint32_t dst, uint32_t src)
{
	/* restore the tag value from the scratch register */

    tag_t saved_tags[] = {threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][0], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][1],
                            threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][2], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][3]};
    for (size_t i = 0; i < 4; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = saved_tags[i];

	/* update */
    tag_t src_tags[] = {threads_ctx[tid].vcpu.gpr_file[src][0], threads_ctx[tid].vcpu.gpr_file[src][1]};
    threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tags[0];
    threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tags[1];
}

static ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_m2r_opq_fast(THREADID tid, uint32_t dst_val, ADDRINT src)
{
	/* save the tag value of dst in the scratch register */

    tag_t save_tags[] = {threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][0], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][1],
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][2], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][3], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][4],
	threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][5], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][6], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][7]};
    for (size_t i = 0; i < 8; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][i] = save_tags[i];

    tag_t src_tags[] = {tag_dir_getb(tag_dir, src), tag_dir_getb(tag_dir, src+1),
        tag_dir_getb(tag_dir, src+2), tag_dir_getb(tag_dir, src+3), tag_dir_getb(tag_dir, src+4),
	tag_dir_getb(tag_dir, src+5), tag_dir_getb(tag_dir, src+6), tag_dir_getb(tag_dir, src+7)};
    for (size_t i = 0; i < 8; i++){
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = src_tags[i];
     }

	return (dst_val == *(uint32_t *)src);
}


static ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_m2r_opl_fast(THREADID tid, uint32_t dst_val, ADDRINT src)
{
	/* save the tag value of dst in the scratch register */

    tag_t save_tags[] = {threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][0], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][1],
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][2], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][3]};
    for (size_t i = 0; i < 4; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][i] = save_tags[i];

    tag_t src_tags[] = {tag_dir_getb(tag_dir, src), tag_dir_getb(tag_dir, src+1),
        tag_dir_getb(tag_dir, src+2), tag_dir_getb(tag_dir, src+3)};
    for (size_t i = 0; i < 4; i++){
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = src_tags[i];
     }

	return (dst_val == *(uint32_t *)src);
}


static void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2m_opq_slow(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t saved_tags[] = R64TAG(tid, DFT_REG_HELPER1);
    for (size_t i = 0; i < 8; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = saved_tags[i];

	/* update */
    tag_t src_tags[] = R64TAG(tid, src);
    for (size_t i = 0; i < 8; i++){
        tag_dir_setb(tag_dir, dst + i, src_tags[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2m_opl_slow(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t saved_tags[] = R32TAG(tid, DFT_REG_HELPER1);
    for (size_t i = 0; i < 4; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = saved_tags[i];

	/* update */
    tag_t src_tags[] = R32TAG(tid, src);
    for (size_t i = 0; i < 4; i++){
        tag_dir_setb(tag_dir, dst + i, src_tags[i]);
    }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL
_cmpxchg_m2r_opw_fast(THREADID tid, uint16_t dst_val, ADDRINT src)
{
	/* save the tag value of dst in the scratch register */

    tag_t save_tags[] = {threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][0], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][1],
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][2], threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][3]};

    for (size_t i = 0; i < 4; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][i] = save_tags[i];

    tag_t src_tags[] = {tag_dir_getb(tag_dir, src), tag_dir_getb(tag_dir, src+1)};
    for (size_t i = 0; i < 2; i++){
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = src_tags[i];
    }
	
	/* compare the dst and src values; the original values the tag bits */
	return (dst_val == *(uint16_t *)src);
}

static void PIN_FAST_ANALYSIS_CALL
_cmpxchg_r2m_opw_slow(THREADID tid, ADDRINT dst, uint32_t src)
{
	/* restore the tag value from the scratch register */
    tag_t saved_tags[] = {threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][0], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][1],
                            threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][2], threads_ctx[tid].vcpu.gpr_file[DFT_REG_HELPER1][3]};

    for (size_t i = 0; i < 4; i++)
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = saved_tags[i];

	/* update */
    tag_t src_tags[] = {threads_ctx[tid].vcpu.gpr_file[src][0], threads_ctx[tid].vcpu.gpr_file[src][1]};
    for (size_t i = 0; i < 2; i++){
        tag_dir_setb(tag_dir, dst + i, src_tags[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opb_ul(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
    tag_t tmp_tag = threads_ctx[tid].vcpu.gpr_file[dst][1];

    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];

	/* swap */
    threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
    threads_ctx[tid].vcpu.gpr_file[src][0] = tmp_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opb_lu(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
    tag_t tmp_tag = threads_ctx[tid].vcpu.gpr_file[dst][0];

    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];

	/* swap */
    threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
    threads_ctx[tid].vcpu.gpr_file[src][1] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opb_u(THREADID tid, uint32_t dst, uint32_t src)
{
	/* temporary tag value */
    tag_t tmp_tag = threads_ctx[tid].vcpu.gpr_file[dst][1];

    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];

	/* swap */
    threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
    threads_ctx[tid].vcpu.gpr_file[src][1] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opb_l(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t tmp_tag = threads_ctx[tid].vcpu.gpr_file[dst][0];

    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];

	/* swap */
    threads_ctx[tid].vcpu.gpr_file[dst][0] = src_tag;
    threads_ctx[tid].vcpu.gpr_file[src][0] = tmp_tag;
}


static void PIN_FAST_ANALYSIS_CALL
_xchg_r2r_opw(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t dst_tag[] = R16TAG(tid, dst);
    
    tag_t src_tag[] = R16TAG(tid, src);

	/* swap */
    RTAG(tid)[dst][0] = src_tag[0];
    RTAG(tid)[dst][1] = src_tag[1];
    RTAG(tid)[src][0] = dst_tag[0];
    RTAG(tid)[src][1] = dst_tag[1];
}

static void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opb_u(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t tmp_tag = RTAG(tid)[dst][1];
    
    tag_t src_tag = M8TAG(src);

	/* swap */
    threads_ctx[tid].vcpu.gpr_file[dst][1] = src_tag;
    tag_dir_setb(tag_dir, src, tmp_tag);
}
static void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opb_l(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t tmp_tag = RTAG(tid)[dst][0];
    
    tag_t src_tag = M8TAG(src);

	/* swap */
    RTAG(tid)[dst][0] = src_tag;
    tag_dir_setb(tag_dir, src, tmp_tag);
}

static void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opw(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t tmp_tag[] = R16TAG(tid, dst);
    
    tag_t src_tag[] = M16TAG(src);

	/* swap */
    RTAG(tid)[dst][0] = src_tag[0];
    RTAG(tid)[dst][1] = src_tag[1];
    tag_dir_setb(tag_dir, src, tmp_tag[0]);
    tag_dir_setb(tag_dir, src+1, tmp_tag[1]);
}

static void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opq(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t tmp_tag[] = R64TAG(tid, dst);
    tag_t src_tag[] = M64TAG(src);

	/* swap */
    RTAG(tid)[dst][0] = src_tag[0];
    RTAG(tid)[dst][1] = src_tag[1];
    RTAG(tid)[dst][2] = src_tag[2];
    RTAG(tid)[dst][3] = src_tag[3];
    RTAG(tid)[dst][4] = src_tag[4];
    RTAG(tid)[dst][5] = src_tag[5];
    RTAG(tid)[dst][6] = src_tag[6];
    RTAG(tid)[dst][7] = src_tag[7];

    tag_dir_setb(tag_dir, src, tmp_tag[0]);
    tag_dir_setb(tag_dir, src+1, tmp_tag[1]);
    tag_dir_setb(tag_dir, src+2, tmp_tag[2]);
    tag_dir_setb(tag_dir, src+3, tmp_tag[3]);
    tag_dir_setb(tag_dir, src+4, tmp_tag[4]);
    tag_dir_setb(tag_dir, src+5, tmp_tag[5]);
    tag_dir_setb(tag_dir, src+6, tmp_tag[6]);
    tag_dir_setb(tag_dir, src+7, tmp_tag[7]);
}

static void PIN_FAST_ANALYSIS_CALL
_xchg_m2r_opl(THREADID tid, uint32_t dst, ADDRINT src)
{
	/* temporary tag value */
    tag_t tmp_tag[] = R32TAG(tid, dst);
    tag_t src_tag[] = M32TAG(src);

	/* swap */
    RTAG(tid)[dst][0] = src_tag[0];
    RTAG(tid)[dst][1] = src_tag[1];
    RTAG(tid)[dst][2] = src_tag[2];
    RTAG(tid)[dst][3] = src_tag[3];

    tag_dir_setb(tag_dir, src, tmp_tag[0]);
    tag_dir_setb(tag_dir, src+1, tmp_tag[1]);
    tag_dir_setb(tag_dir, src+2, tmp_tag[2]);
    tag_dir_setb(tag_dir, src+3, tmp_tag[3]);
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opb_ul(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t tmp_tag = threads_ctx[tid].vcpu.gpr_file[dst][1];

    threads_ctx[tid].vcpu.gpr_file[dst][1] = tag_combine(threads_ctx[tid].vcpu.gpr_file[dst][1], threads_ctx[tid].vcpu.gpr_file[src][0]);
    threads_ctx[tid].vcpu.gpr_file[src][0] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opb_lu(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t tmp_tag = threads_ctx[tid].vcpu.gpr_file[dst][0];

    threads_ctx[tid].vcpu.gpr_file[dst][0] = tag_combine(threads_ctx[tid].vcpu.gpr_file[dst][0], threads_ctx[tid].vcpu.gpr_file[src][1]);
    threads_ctx[tid].vcpu.gpr_file[src][1] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opb_u(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t tmp_tag = threads_ctx[tid].vcpu.gpr_file[dst][1];

    threads_ctx[tid].vcpu.gpr_file[dst][1] = tag_combine(threads_ctx[tid].vcpu.gpr_file[dst][1], threads_ctx[tid].vcpu.gpr_file[src][1]);
    threads_ctx[tid].vcpu.gpr_file[src][1] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opb_l(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t tmp_tag = threads_ctx[tid].vcpu.gpr_file[dst][0];

    threads_ctx[tid].vcpu.gpr_file[dst][0] = tag_combine(threads_ctx[tid].vcpu.gpr_file[dst][0], threads_ctx[tid].vcpu.gpr_file[src][0]);
    threads_ctx[tid].vcpu.gpr_file[src][0] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_r2r_opw(THREADID tid, uint32_t dst, uint32_t src)
{

    tag_t dst_tag[] = {threads_ctx[tid].vcpu.gpr_file[dst][0], threads_ctx[tid].vcpu.gpr_file[dst][1]};
    tag_t src_tag[] = {threads_ctx[tid].vcpu.gpr_file[src][0], threads_ctx[tid].vcpu.gpr_file[src][1]};

    threads_ctx[tid].vcpu.gpr_file[dst][0] = tag_combine(dst_tag[0], src_tag[0]);
    threads_ctx[tid].vcpu.gpr_file[dst][1] = tag_combine(dst_tag[1], src_tag[1]);
    threads_ctx[tid].vcpu.gpr_file[src][0] = dst_tag[0];
    threads_ctx[tid].vcpu.gpr_file[src][1] = dst_tag[1];
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_m2r_opb_u(THREADID tid, uint32_t src, ADDRINT dst)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][1];
    tag_t dst_tag = tag_dir_getb(tag_dir, dst);

    threads_ctx[tid].vcpu.gpr_file[src][1] = dst_tag;
    tag_dir_setb(tag_dir, dst, tag_combine(dst_tag, src_tag));
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_m2r_opb_l(THREADID tid, uint32_t src, ADDRINT dst)
{
    tag_t src_tag = threads_ctx[tid].vcpu.gpr_file[src][0];
    tag_t dst_tag = tag_dir_getb(tag_dir, dst);

    threads_ctx[tid].vcpu.gpr_file[src][0] = dst_tag;
    tag_dir_setb(tag_dir, dst, tag_combine(dst_tag, src_tag));
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_m2r_opw(THREADID tid, uint32_t src, ADDRINT dst)
{
    tag_t src_tag[] = R16TAG(tid, src);
    tag_t dst_tag[] = M16TAG(dst);

    threads_ctx[tid].vcpu.gpr_file[src][0] = dst_tag[0];
    threads_ctx[tid].vcpu.gpr_file[src][1] = dst_tag[1];

    tag_dir_setb(tag_dir, dst, tag_combine(dst_tag[0], src_tag[0]));
    tag_dir_setb(tag_dir, dst+1, tag_combine(dst_tag[1], src_tag[1]));
}

static void PIN_FAST_ANALYSIS_CALL
_xadd_m2r_opq(THREADID tid, uint32_t src, ADDRINT dst)
{
    tag_t src_tag[] = R64TAG(tid, src);
    tag_t dst_tag[] = M64TAG(dst);

    threads_ctx[tid].vcpu.gpr_file[src][0] = dst_tag[0];
    threads_ctx[tid].vcpu.gpr_file[src][1] = dst_tag[1];
    threads_ctx[tid].vcpu.gpr_file[src][2] = dst_tag[2];
    threads_ctx[tid].vcpu.gpr_file[src][3] = dst_tag[3];
    threads_ctx[tid].vcpu.gpr_file[src][4] = dst_tag[4];
    threads_ctx[tid].vcpu.gpr_file[src][5] = dst_tag[5];
    threads_ctx[tid].vcpu.gpr_file[src][6] = dst_tag[6];
    threads_ctx[tid].vcpu.gpr_file[src][7] = dst_tag[7];

    tag_dir_setb(tag_dir, dst, tag_combine(dst_tag[0], src_tag[0]));
    tag_dir_setb(tag_dir, dst+1, tag_combine(dst_tag[1], src_tag[1]));
    tag_dir_setb(tag_dir, dst+2, tag_combine(dst_tag[2], src_tag[2]));
    tag_dir_setb(tag_dir, dst+3, tag_combine(dst_tag[3], src_tag[3]));
    tag_dir_setb(tag_dir, dst+4, tag_combine(dst_tag[4], src_tag[4]));
    tag_dir_setb(tag_dir, dst+5, tag_combine(dst_tag[5], src_tag[5]));
    tag_dir_setb(tag_dir, dst+6, tag_combine(dst_tag[6], src_tag[6]));
    tag_dir_setb(tag_dir, dst+7, tag_combine(dst_tag[7], src_tag[7]));
}


static void PIN_FAST_ANALYSIS_CALL
_xadd_m2r_opl(THREADID tid, uint32_t src, ADDRINT dst)
{
    tag_t src_tag[] = R32TAG(tid, src);
    tag_t dst_tag[] = M32TAG(dst);

    threads_ctx[tid].vcpu.gpr_file[src][0] = dst_tag[0];
    threads_ctx[tid].vcpu.gpr_file[src][1] = dst_tag[1];
    threads_ctx[tid].vcpu.gpr_file[src][2] = dst_tag[2];
    threads_ctx[tid].vcpu.gpr_file[src][3] = dst_tag[3];

    tag_dir_setb(tag_dir, dst, tag_combine(dst_tag[0], src_tag[0]));
    tag_dir_setb(tag_dir, dst+1, tag_combine(dst_tag[1], src_tag[1]));
    tag_dir_setb(tag_dir, dst+2, tag_combine(dst_tag[2], src_tag[2]));
    tag_dir_setb(tag_dir, dst+3, tag_combine(dst_tag[3], src_tag[3]));

}

static void PIN_FAST_ANALYSIS_CALL
_lea_r2r_opw(ADDRINT ins_address, THREADID tid,
		uint32_t dst,
		uint32_t base,
		uint32_t index)
{
    tag_t base_tag[] = R16TAG(tid, base);
    tag_t idx_tag[] = R16TAG(tid, index);
    for(size_t i = 0 ;i<10;i++){
      output_lea[i] = "{}";
    }
    output_lea[0] = "16";
    output_lea[1] = "baseidx";
    int fl = 0;
    for (size_t i = 0; i < 2; i++){
        if(tag_count(idx_tag[i])){
                if(fl == 0){
                        output_lea[2] = StringFromAddrint(ins_address);
                        fl = 1;
                }
        }
        output_lea[i+2] = tag_sprint(idx_tag[i]);
    }
    if(fl == 1){
        print_lea_log();
    }


    RTAG(tid)[dst][0] = tag_combine(base_tag[0], idx_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(base_tag[1], idx_tag[1]);
}

static void PIN_FAST_ANALYSIS_CALL
_lea_r2r_opq(ADDRINT ins_address, THREADID tid,
		uint32_t dst,
		uint32_t base,
		uint32_t index)
{
    tag_t base_tag[] = R64TAG(tid, base);
    tag_t idx_tag[] = R64TAG(tid, index);

    for(size_t i = 0 ;i<10;i++){
      output_lea[i] = "{}";
    }
    output_lea[0] = "64";
    output_lea[1] = "baseidx";
    int fl = 0;
    for (size_t i = 0; i < 8; i++){
        if(tag_count(idx_tag[i])){
                if(fl == 0){
                        output_lea[2] = StringFromAddrint(ins_address);
                        fl = 1;
                }
        }
        output_lea[i+2] = tag_sprint(idx_tag[i]);
    }
    if(fl == 1){
        print_lea_log();
    }

    RTAG(tid)[dst][0] = tag_combine(base_tag[0], idx_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(base_tag[1], idx_tag[1]);
    RTAG(tid)[dst][2] = tag_combine(base_tag[2], idx_tag[2]);
    RTAG(tid)[dst][3] = tag_combine(base_tag[3], idx_tag[3]);
    RTAG(tid)[dst][4] = tag_combine(base_tag[4], idx_tag[4]);
    RTAG(tid)[dst][5] = tag_combine(base_tag[5], idx_tag[5]);
    RTAG(tid)[dst][6] = tag_combine(base_tag[6], idx_tag[6]);
    RTAG(tid)[dst][7] = tag_combine(base_tag[7], idx_tag[7]);
}


static void PIN_FAST_ANALYSIS_CALL
_lea_r2r_opl(ADDRINT ins_address, THREADID tid,
		uint32_t dst,
		uint32_t base,
		uint32_t index)
{
    tag_t base_tag[] = R32TAG(tid, base);
    tag_t idx_tag[] = R32TAG(tid, index);
    for(size_t i = 0 ;i<10;i++){
      output_lea[i] = "{}";
    }
    output_lea[0] = "32";
    output_lea[1] = "baseidx";
    int fl = 0;
    for (size_t i = 0; i < 4; i++){
        if(tag_count(idx_tag[i])){
                if(fl == 0){
                        output_lea[2] = StringFromAddrint(ins_address);
                        fl = 1;
                }
        }
        output_lea[i+2] = tag_sprint(idx_tag[i]);
    }
    if(fl == 1){
        print_lea_log();
    }

    RTAG(tid)[dst][0] = tag_combine(base_tag[0], idx_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(base_tag[1], idx_tag[1]);
    RTAG(tid)[dst][2] = tag_combine(base_tag[2], idx_tag[2]);
    RTAG(tid)[dst][3] = tag_combine(base_tag[3], idx_tag[3]);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opb_u(THREADID tid, uint32_t src)
{
    tag_t tmp_tag = RTAG(tid)[src][1];

    RTAG(tid)[DFT_REG_RAX][0] = tag_combine(RTAG(tid)[DFT_REG_RAX][0], tmp_tag);
    RTAG(tid)[DFT_REG_RAX][1] = tag_combine(RTAG(tid)[DFT_REG_RAX][1], tmp_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opb_l(THREADID tid, uint32_t src)
{
    tag_t tmp_tag = RTAG(tid)[src][0];

    RTAG(tid)[DFT_REG_RAX][0] = tag_combine(RTAG(tid)[DFT_REG_RAX][0], tmp_tag);
    RTAG(tid)[DFT_REG_RAX][1] = tag_combine(RTAG(tid)[DFT_REG_RAX][1], tmp_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opw(THREADID tid, uint32_t src)
{
    tag_t tmp_tag[] = {RTAG(tid)[src][0], RTAG(tid)[src][1]};
    tag_t dst1_tag[] = {RTAG(tid)[DFT_REG_RDX][0], RTAG(tid)[DFT_REG_RDX][1]};
    tag_t dst2_tag[] = {RTAG(tid)[DFT_REG_RAX][0], RTAG(tid)[DFT_REG_RAX][1]};

    RTAG(tid)[DFT_REG_RDX][0] = tag_combine(dst1_tag[0], tmp_tag[0]);
    RTAG(tid)[DFT_REG_RDX][1] = tag_combine(dst1_tag[1], tmp_tag[1]);
    
    RTAG(tid)[DFT_REG_RAX][0] = tag_combine(dst2_tag[0], tmp_tag[0]);
    RTAG(tid)[DFT_REG_RAX][1] = tag_combine(dst2_tag[1], tmp_tag[1]);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opq(THREADID tid, uint32_t src)
{ 
    tag_t tmp_tag[] = R64TAG(tid, src);
    tag_t dst1_tag[] = R64TAG(tid, DFT_REG_RDX);
    tag_t dst2_tag[] = R64TAG(tid, DFT_REG_RAX);

    for (size_t i = 0; i < 8; i++)
    {
        RTAG(tid)[DFT_REG_RDX][i] = tag_combine(dst1_tag[i], tmp_tag[i]);
        RTAG(tid)[DFT_REG_RAX][i] = tag_combine(dst2_tag[i], tmp_tag[i]);
    }
}


static void PIN_FAST_ANALYSIS_CALL
r2r_ternary_opl(THREADID tid, uint32_t src)
{ 
    tag_t tmp_tag[] = R32TAG(tid, src);
    tag_t dst1_tag[] = R32TAG(tid, DFT_REG_RDX);
    tag_t dst2_tag[] = R32TAG(tid, DFT_REG_RAX);

    for (size_t i = 0; i < 4; i++)
    {
        RTAG(tid)[DFT_REG_RDX][i] = tag_combine(dst1_tag[i], tmp_tag[i]);
        RTAG(tid)[DFT_REG_RAX][i] = tag_combine(dst2_tag[i], tmp_tag[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opb(THREADID tid, ADDRINT src)
{
    tag_t tmp_tag = MTAG(src);
    tag_t dst_tag[] = R16TAG(tid, DFT_REG_RAX);

    RTAG(tid)[DFT_REG_RAX][0] = tag_combine(dst_tag[0], tmp_tag);
    RTAG(tid)[DFT_REG_RAX][1] = tag_combine(dst_tag[1], tmp_tag);
}

static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opw(THREADID tid, ADDRINT src)
{
    tag_t tmp_tag[] = M16TAG(src);
    tag_t dst1_tag[] = R16TAG(tid, DFT_REG_RDX);
    tag_t dst2_tag[] = R16TAG(tid, DFT_REG_RAX);

    for (size_t i = 0; i < 2; i++)
    {
        RTAG(tid)[DFT_REG_RDX][i] = tag_combine(dst1_tag[i], tmp_tag[i]);
        RTAG(tid)[DFT_REG_RAX][i] = tag_combine(dst2_tag[i], tmp_tag[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opq(THREADID tid, ADDRINT src)
{
    tag_t tmp_tag[] = M64TAG(src);
    tag_t dst1_tag[] = R64TAG(tid, DFT_REG_RDX);
    tag_t dst2_tag[] = R64TAG(tid, DFT_REG_RAX);

    for (size_t i = 0; i < 8; i++)
    {
        RTAG(tid)[DFT_REG_RDX][i] = tag_combine(dst1_tag[i], tmp_tag[i]);
        RTAG(tid)[DFT_REG_RAX][i] = tag_combine(dst2_tag[i], tmp_tag[i]);
    }
}


static void PIN_FAST_ANALYSIS_CALL
m2r_ternary_opl(THREADID tid, ADDRINT src)
{
    tag_t tmp_tag[] = M32TAG(src);
    tag_t dst1_tag[] = R32TAG(tid, DFT_REG_RDX);
    tag_t dst2_tag[] = R32TAG(tid, DFT_REG_RAX);

    for (size_t i = 0; i < 4; i++)
    {
        RTAG(tid)[DFT_REG_RDX][i] = tag_combine(dst1_tag[i], tmp_tag[i]);
        RTAG(tid)[DFT_REG_RAX][i] = tag_combine(dst2_tag[i], tmp_tag[i]);
    }
}

static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opb_ul(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = RTAG(tid)[src][0];
    tag_t dst_tag = RTAG(tid)[dst][1];

    RTAG(tid)[dst][1] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opb_lu(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = RTAG(tid)[src][1];
    tag_t dst_tag = RTAG(tid)[dst][0];

    RTAG(tid)[dst][0] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opb_u(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = RTAG(tid)[src][1];
    tag_t dst_tag = RTAG(tid)[dst][1];

    RTAG(tid)[dst][1] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opb_l(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag = RTAG(tid)[src][0];
    tag_t dst_tag = RTAG(tid)[dst][0];

    RTAG(tid)[dst][0] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opw(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag[] = R16TAG(tid, src);
    tag_t dst_tag[] = R16TAG(tid, dst);

    RTAG(tid)[dst][0] = tag_combine(dst_tag[0], src_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(dst_tag[1], src_tag[1]);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opx(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag[] = R128TAG(tid, src);
    tag_t dst_tag[] = R128TAG(tid, dst);


    RTAG(tid)[dst][0] = tag_combine(dst_tag[0], src_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(dst_tag[1], src_tag[1]);
    RTAG(tid)[dst][2] = tag_combine(dst_tag[2], src_tag[2]);
    RTAG(tid)[dst][3] = tag_combine(dst_tag[3], src_tag[3]);
    RTAG(tid)[dst][4] = tag_combine(dst_tag[4], src_tag[4]);
    RTAG(tid)[dst][5] = tag_combine(dst_tag[5], src_tag[5]);
    RTAG(tid)[dst][6] = tag_combine(dst_tag[6], src_tag[6]);
    RTAG(tid)[dst][7] = tag_combine(dst_tag[7], src_tag[7]);
    RTAG(tid)[dst][8] = tag_combine(dst_tag[8], src_tag[8]);
    RTAG(tid)[dst][9] = tag_combine(dst_tag[9], src_tag[9]);
    RTAG(tid)[dst][10] = tag_combine(dst_tag[10], src_tag[10]);
    RTAG(tid)[dst][11] = tag_combine(dst_tag[11], src_tag[11]);
    RTAG(tid)[dst][12] = tag_combine(dst_tag[12], src_tag[12]);
    RTAG(tid)[dst][13] = tag_combine(dst_tag[13], src_tag[13]);
    RTAG(tid)[dst][14] = tag_combine(dst_tag[14], src_tag[14]);
    RTAG(tid)[dst][15] = tag_combine(dst_tag[15], src_tag[15]);

}

static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opq(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag[] = R64TAG(tid, src);
    tag_t dst_tag[] = R64TAG(tid, dst);


    RTAG(tid)[dst][0] = tag_combine(dst_tag[0], src_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(dst_tag[1], src_tag[1]);
    RTAG(tid)[dst][2] = tag_combine(dst_tag[2], src_tag[2]);
    RTAG(tid)[dst][3] = tag_combine(dst_tag[3], src_tag[3]);
    RTAG(tid)[dst][4] = tag_combine(dst_tag[4], src_tag[4]);
    RTAG(tid)[dst][5] = tag_combine(dst_tag[5], src_tag[5]);
    RTAG(tid)[dst][6] = tag_combine(dst_tag[6], src_tag[6]);
    RTAG(tid)[dst][7] = tag_combine(dst_tag[7], src_tag[7]);
}

static void PIN_FAST_ANALYSIS_CALL
r2r_binary_opl(THREADID tid, uint32_t dst, uint32_t src)
{
    tag_t src_tag[] = R32TAG(tid, src);
    tag_t dst_tag[] = R32TAG(tid, dst);


    RTAG(tid)[dst][0] = tag_combine(dst_tag[0], src_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(dst_tag[1], src_tag[1]);
    RTAG(tid)[dst][2] = tag_combine(dst_tag[2], src_tag[2]);
    RTAG(tid)[dst][3] = tag_combine(dst_tag[3], src_tag[3]);
}

static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opb_u(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag = MTAG(src);
    tag_t dst_tag = RTAG(tid)[dst][1];

    RTAG(tid)[dst][1] = tag_combine(src_tag, dst_tag);
}

static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opb_l(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag = MTAG(src);
    tag_t dst_tag = RTAG(tid)[dst][0];

    RTAG(tid)[dst][0] = tag_combine(src_tag, dst_tag);
}

static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opw(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M16TAG(src);
    tag_t dst_tag[] = R16TAG(tid, dst);

    RTAG(tid)[dst][0] = tag_combine(src_tag[0], dst_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(src_tag[1], dst_tag[1]);
}

static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opx(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M128TAG(src);
    tag_t dst_tag[] = R128TAG(tid, dst);

    RTAG(tid)[dst][0] = tag_combine(src_tag[0], dst_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(src_tag[1], dst_tag[1]);
    RTAG(tid)[dst][2] = tag_combine(src_tag[2], dst_tag[2]);
    RTAG(tid)[dst][3] = tag_combine(src_tag[3], dst_tag[3]);
    RTAG(tid)[dst][4] = tag_combine(src_tag[4], dst_tag[4]);
    RTAG(tid)[dst][5] = tag_combine(src_tag[5], dst_tag[5]);
    RTAG(tid)[dst][6] = tag_combine(src_tag[6], dst_tag[6]);
    RTAG(tid)[dst][7] = tag_combine(src_tag[7], dst_tag[7]);
    RTAG(tid)[dst][8] = tag_combine(src_tag[8], dst_tag[8]);
    RTAG(tid)[dst][9] = tag_combine(src_tag[9], dst_tag[9]);
    RTAG(tid)[dst][10] = tag_combine(src_tag[10], dst_tag[10]);
    RTAG(tid)[dst][11] = tag_combine(src_tag[11], dst_tag[11]);
    RTAG(tid)[dst][12] = tag_combine(src_tag[12], dst_tag[12]);
    RTAG(tid)[dst][13] = tag_combine(src_tag[13], dst_tag[13]);
    RTAG(tid)[dst][14] = tag_combine(src_tag[14], dst_tag[14]);
    RTAG(tid)[dst][15] = tag_combine(src_tag[15], dst_tag[15]);


}

static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opq(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M64TAG(src);
    tag_t dst_tag[] = R64TAG(tid, dst);

    RTAG(tid)[dst][0] = tag_combine(src_tag[0], dst_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(src_tag[1], dst_tag[1]);
    RTAG(tid)[dst][2] = tag_combine(src_tag[2], dst_tag[2]);
    RTAG(tid)[dst][3] = tag_combine(src_tag[3], dst_tag[3]);
    RTAG(tid)[dst][4] = tag_combine(src_tag[4], dst_tag[4]);
    RTAG(tid)[dst][5] = tag_combine(src_tag[5], dst_tag[5]);
    RTAG(tid)[dst][6] = tag_combine(src_tag[6], dst_tag[6]);
    RTAG(tid)[dst][7] = tag_combine(src_tag[7], dst_tag[7]);

}

static void PIN_FAST_ANALYSIS_CALL
m2r_binary_opl(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M32TAG(src);
    tag_t dst_tag[] = R32TAG(tid, dst);

    RTAG(tid)[dst][0] = tag_combine(src_tag[0], dst_tag[0]);
    RTAG(tid)[dst][1] = tag_combine(src_tag[1], dst_tag[1]);
    RTAG(tid)[dst][2] = tag_combine(src_tag[2], dst_tag[2]);
    RTAG(tid)[dst][3] = tag_combine(src_tag[3], dst_tag[3]);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opb_u(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag = RTAG(tid)[src][1];
    tag_t dst_tag = MTAG(dst);

    tag_t res_tag = tag_combine(dst_tag, src_tag);
    tag_dir_setb(tag_dir, dst, res_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opb_l(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag = RTAG(tid)[src][0];
    tag_t dst_tag = MTAG(dst);

    tag_t res_tag = tag_combine(dst_tag, src_tag);
    tag_dir_setb(tag_dir, dst, res_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opw(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag[] = R16TAG(tid, src);
    tag_t dst_tag[] = M16TAG(dst);

    tag_t res_tag[] = {tag_combine(dst_tag[0], src_tag[0]), tag_combine(dst_tag[1], src_tag[1])};
    tag_dir_setb(tag_dir, dst, res_tag[0]);
    tag_dir_setb(tag_dir, dst+1, res_tag[1]);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opq(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag[] = R64TAG(tid, src);
    tag_t dst_tag[] = M64TAG(dst);

    tag_t res_tag[] = {tag_combine(dst_tag[0], src_tag[0]), tag_combine(dst_tag[1], src_tag[1]), 
        tag_combine(dst_tag[2], src_tag[2]), tag_combine(dst_tag[3], src_tag[3]), tag_combine(dst_tag[4], src_tag[4]), tag_combine(dst_tag[5], src_tag[5]), tag_combine(dst_tag[6], src_tag[6]), tag_combine(dst_tag[7], src_tag[7])};

    tag_dir_setb(tag_dir, dst, res_tag[0]);
    tag_dir_setb(tag_dir, dst+1, res_tag[1]);
    tag_dir_setb(tag_dir, dst+2, res_tag[2]);
    tag_dir_setb(tag_dir, dst+3, res_tag[3]);
    tag_dir_setb(tag_dir, dst+4, res_tag[4]);
    tag_dir_setb(tag_dir, dst+5, res_tag[5]);
    tag_dir_setb(tag_dir, dst+6, res_tag[6]);
    tag_dir_setb(tag_dir, dst+7, res_tag[7]);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_binary_opl(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag[] = R32TAG(tid, src);
    tag_t dst_tag[] = M32TAG(dst);

    tag_t res_tag[] = {tag_combine(dst_tag[0], src_tag[0]), tag_combine(dst_tag[1], src_tag[1]), 
        tag_combine(dst_tag[2], src_tag[2]), tag_combine(dst_tag[3], src_tag[3])};

    tag_dir_setb(tag_dir, dst, res_tag[0]);
    tag_dir_setb(tag_dir, dst+1, res_tag[1]);
    tag_dir_setb(tag_dir, dst+2, res_tag[2]);
    tag_dir_setb(tag_dir, dst+3, res_tag[3]);
}

static void PIN_FAST_ANALYSIS_CALL
r_clrl4(THREADID tid)
{
    for (size_t i = 0; i < 8; i++)
    {
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RDX][i] = tag_traits<tag_t>::cleared_val;
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RCX][i] = tag_traits<tag_t>::cleared_val;
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RBX][i] = tag_traits<tag_t>::cleared_val;
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = tag_traits<tag_t>::cleared_val;
    }
}

static void PIN_FAST_ANALYSIS_CALL
r_clrl2(THREADID tid)
{
    for (size_t i = 0; i < 8; i++)
    {
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RDX][i] = tag_traits<tag_t>::cleared_val;
        threads_ctx[tid].vcpu.gpr_file[DFT_REG_RAX][i] = tag_traits<tag_t>::cleared_val;
    }
}

static void PIN_FAST_ANALYSIS_CALL
r_clrx(THREADID tid, uint32_t reg)
{
    for (size_t i = 0; i < 16; i++)
    {
        threads_ctx[tid].vcpu.gpr_file[reg][i] = tag_traits<tag_t>::cleared_val;
    }
}


static void PIN_FAST_ANALYSIS_CALL
r_clrq(THREADID tid, uint32_t reg)
{
    for (size_t i = 0; i < 8; i++)
    {
        threads_ctx[tid].vcpu.gpr_file[reg][i] = tag_traits<tag_t>::cleared_val;
    }
}

static void PIN_FAST_ANALYSIS_CALL
r_clrl(THREADID tid, uint32_t reg)
{
    for (size_t i = 0; i < 4; i++)
    {
        threads_ctx[tid].vcpu.gpr_file[reg][i] = tag_traits<tag_t>::cleared_val;
    }
}

static void PIN_FAST_ANALYSIS_CALL
r_clrw(THREADID tid, uint32_t reg)
{
    for (size_t i = 0; i < 2; i++)
    {
        threads_ctx[tid].vcpu.gpr_file[reg][i] = tag_traits<tag_t>::cleared_val;
    }
}

static void PIN_FAST_ANALYSIS_CALL
r_clrb_u(THREADID tid, uint32_t reg)
{
    threads_ctx[tid].vcpu.gpr_file[reg][1] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL
r_clrb_l(THREADID tid, uint32_t reg)
{
    threads_ctx[tid].vcpu.gpr_file[reg][0] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opb_ul(THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag = RTAG(tid)[src][0];

     RTAG(tid)[dst][1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opb_lu(THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag = RTAG(tid)[src][1];

     RTAG(tid)[dst][0] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opb_u(THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag = RTAG(tid)[src][1];

     RTAG(tid)[dst][1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opb_l(THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag = RTAG(tid)[src][0];

     RTAG(tid)[dst][0] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opw(THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R16TAG(tid, src);

     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
}

static void PIN_FAST_ANALYSIS_CALL
r2r_lea_idx_xfer_opw(ADDRINT ins_address, THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R16TAG(tid, src);
   
    for(size_t i = 0 ;i<10;i++){
      output_lea[i] = "{}";
    }
    output_lea[0] = "16";
    output_lea[1] = "onlyidx";
    int fl = 0;
    for (size_t i = 0; i < 2; i++){
	if(tag_count(src_tag[i])){
		if(fl == 0){
	      		output_lea[2] = StringFromAddrint(ins_address);
			fl = 1;
		}
	}
        output_lea[i+2] = tag_sprint(src_tag[i]);
    }
    if(fl == 1){
        print_lea_log();
    }
 

     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
}

static void PIN_FAST_ANALYSIS_CALL
r2r_lea_base_xfer_opw(ADDRINT ins_address, THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R16TAG(tid, src);
   

     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
}

static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opq(THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R64TAG(tid, src);

     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
     RTAG(tid)[dst][2] = src_tag[2];
     RTAG(tid)[dst][3] = src_tag[3];
     RTAG(tid)[dst][4] = src_tag[4];
     RTAG(tid)[dst][5] = src_tag[5];
     RTAG(tid)[dst][6] = src_tag[6];
     RTAG(tid)[dst][7] = src_tag[7];

}

static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opx(THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R128TAG(tid, src);

     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
     RTAG(tid)[dst][2] = src_tag[2];
     RTAG(tid)[dst][3] = src_tag[3];
     RTAG(tid)[dst][4] = src_tag[4];
     RTAG(tid)[dst][5] = src_tag[5];
     RTAG(tid)[dst][6] = src_tag[6];
     RTAG(tid)[dst][7] = src_tag[7];
     RTAG(tid)[dst][8] = src_tag[8];
     RTAG(tid)[dst][9] = src_tag[9];
     RTAG(tid)[dst][10] = src_tag[10];
     RTAG(tid)[dst][11] = src_tag[11];
     RTAG(tid)[dst][12] = src_tag[12];
     RTAG(tid)[dst][13] = src_tag[13];
     RTAG(tid)[dst][14] = src_tag[14];
     RTAG(tid)[dst][15] = src_tag[15];

}


static void PIN_FAST_ANALYSIS_CALL
r2r_xfer_opl(THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R32TAG(tid, src);

     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
     RTAG(tid)[dst][2] = src_tag[2];
     RTAG(tid)[dst][3] = src_tag[3];
}

static void PIN_FAST_ANALYSIS_CALL
r2r_lea_idx_xfer_opq(ADDRINT ins_address, THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R64TAG(tid, src);

    for(size_t i = 0 ;i<10;i++){
      output_lea[i] = "{}";
    }
    output_lea[0] = "64";
    output_lea[1] = "onlyidx";
    int fl = 0;
    for (size_t i = 0; i < 8; i++){
        if(tag_count(src_tag[i])){
                if(fl == 0){
                        output_lea[2] = StringFromAddrint(ins_address);
                        fl = 1;
                }
        }
        output_lea[i+2] = tag_sprint(src_tag[i]);
    }
    if(fl == 1){
        print_lea_log();
    }


     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
     RTAG(tid)[dst][2] = src_tag[2];
     RTAG(tid)[dst][3] = src_tag[3];
     RTAG(tid)[dst][4] = src_tag[4];
     RTAG(tid)[dst][5] = src_tag[5];
     RTAG(tid)[dst][6] = src_tag[6];
     RTAG(tid)[dst][7] = src_tag[7];
}


static void PIN_FAST_ANALYSIS_CALL
r2r_lea_idx_xfer_opl(ADDRINT ins_address, THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R32TAG(tid, src);
    for(size_t i = 0 ;i<10;i++){
      output_lea[i] = "{}";
    }
    output_lea[0] = "32";
    output_lea[1] = "onlyidx";
    int fl = 0;
    for (size_t i = 0; i < 4; i++){
        if(tag_count(src_tag[i])){
                if(fl == 0){
                        output_lea[2] = StringFromAddrint(ins_address);
                        fl = 1;
                }
        }
        output_lea[i+2] = tag_sprint(src_tag[i]);
    }
    if(fl == 1){
        print_lea_log();
    }

 
     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
     RTAG(tid)[dst][2] = src_tag[2];
     RTAG(tid)[dst][3] = src_tag[3];
}

static void PIN_FAST_ANALYSIS_CALL
r2r_lea_base_xfer_opq(ADDRINT ins_address, THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R64TAG(tid, src);

 
     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
     RTAG(tid)[dst][2] = src_tag[2];
     RTAG(tid)[dst][3] = src_tag[3];
     RTAG(tid)[dst][4] = src_tag[4];
     RTAG(tid)[dst][5] = src_tag[5];
     RTAG(tid)[dst][6] = src_tag[6];
     RTAG(tid)[dst][7] = src_tag[7];
}


static void PIN_FAST_ANALYSIS_CALL
r2r_lea_base_xfer_opl(ADDRINT ins_address, THREADID tid, uint32_t dst, uint32_t src)
{
     tag_t src_tag[] = R32TAG(tid, src);

 
     RTAG(tid)[dst][0] = src_tag[0];
     RTAG(tid)[dst][1] = src_tag[1];
     RTAG(tid)[dst][2] = src_tag[2];
     RTAG(tid)[dst][3] = src_tag[3];
}

static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opb_u(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag = MTAG(src);

    RTAG(tid)[dst][1] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opb_l(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag = MTAG(src);

    RTAG(tid)[dst][0] = src_tag;
}

static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opw(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M16TAG(src);

    RTAG(tid)[dst][0] = src_tag[0];
    RTAG(tid)[dst][1] = src_tag[1];
}

static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opq_h(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M64TAG(src);

    for (size_t i = 0; i < 8; i++)
        RTAG(tid)[dst][i+8] = src_tag[i];
}

static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opq(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M64TAG(src);

    for (size_t i = 0; i < 8; i++)
        RTAG(tid)[dst][i] = src_tag[i];
}

static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opx(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M128TAG(src);

    for (size_t i = 0; i < 16; i++)
        RTAG(tid)[dst][i] = src_tag[i];
}

static void PIN_FAST_ANALYSIS_CALL
m2r_xfer_opl(THREADID tid, uint32_t dst, ADDRINT src)
{
    tag_t src_tag[] = M32TAG(src);

    for (size_t i = 0; i < 4; i++)
        RTAG(tid)[dst][i] = src_tag[i];
}

static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opbn(THREADID tid, ADDRINT dst, ADDRINT count, 
        ADDRINT eflags)
{
    tag_t src_tag = RTAG(tid)[DFT_REG_RAX][0];
	if (likely(EFLAGS_DF(eflags) == 0)) {
		/* EFLAGS.DF = 0 */

        for (size_t i = 0; i < count; i++)
        {
            tag_dir_setb(tag_dir, dst+i, src_tag);

        }
	}
	else {
		/* EFLAGS.DF = 1 */

        for (size_t i = 0; i < count; i++)
        {
            size_t dst_addr = dst - count + 1 + i;
            tag_dir_setb(tag_dir, dst_addr, src_tag);

        }
	}
}
static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opb_u(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag = RTAG(tid)[src][1];

    tag_dir_setb(tag_dir, dst, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opb_l(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag = RTAG(tid)[src][0];

    tag_dir_setb(tag_dir, dst, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opwn(THREADID tid,
		ADDRINT dst,
		ADDRINT count,
		ADDRINT eflags)
{
    tag_t src_tag[] = R16TAG(tid, DFT_REG_RAX);
	if (likely(EFLAGS_DF(eflags) == 0)) {
		/* EFLAGS.DF = 0 */

        for (size_t i = 0; i < (count << 1); i++)
        {
            tag_dir_setb(tag_dir, dst+i, src_tag[i%2]);

        }
	}
	else {
		/* EFLAGS.DF = 1 */

        for (size_t i = 0; i < (count << 1); i++)
        {
            size_t dst_addr = dst - (count << 1) + 1 + i;
            tag_dir_setb(tag_dir, dst_addr, src_tag[i%2]);

        }
	}
}

static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opw(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag[] = R16TAG(tid, src);

    tag_dir_setb(tag_dir, dst, src_tag[0]);
    tag_dir_setb(tag_dir, dst+1, src_tag[1]);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opqn(THREADID tid,
		ADDRINT dst,
		ADDRINT count,
		ADDRINT eflags)
{
    tag_t src_tag[] = R64TAG(tid, DFT_REG_RAX);
	if (likely(EFLAGS_DF(eflags) == 0)) {
		/* EFLAGS.DF = 0 */

        for (size_t i = 0; i < (count << 2); i++)
        {
            tag_dir_setb(tag_dir, dst+i, src_tag[i%8]);

        }
	}
	else {
		/* EFLAGS.DF = 1 */

        for (size_t i = 0; i < (count << 2); i++)
        {
            size_t dst_addr = dst - (count << 2) + 1 + i;
            tag_dir_setb(tag_dir, dst_addr, src_tag[i%8]);

        }
	}
}


static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opln(THREADID tid,
		ADDRINT dst,
		ADDRINT count,
		ADDRINT eflags)
{
    tag_t src_tag[] = R32TAG(tid, DFT_REG_RAX);
	if (likely(EFLAGS_DF(eflags) == 0)) {
		/* EFLAGS.DF = 0 */

        for (size_t i = 0; i < (count << 2); i++)
        {
            tag_dir_setb(tag_dir, dst+i, src_tag[i%4]);

        }
	}
	else {
		/* EFLAGS.DF = 1 */

        for (size_t i = 0; i < (count << 2); i++)
        {
            size_t dst_addr = dst - (count << 2) + 1 + i;
            tag_dir_setb(tag_dir, dst_addr, src_tag[i%4]);

        }
	}
}

static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opq_h(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag[] = R128TAG(tid, src);

    for (size_t i = 0; i < 8; i++)
        tag_dir_setb(tag_dir, dst + i, src_tag[i+8]);
}


static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opq(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag[] = R64TAG(tid, src);

    for (size_t i = 0; i < 8; i++)
        tag_dir_setb(tag_dir, dst + i, src_tag[i]);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opx(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag[] = R128TAG(tid, src);

    for (size_t i = 0; i < 16; i++)
        tag_dir_setb(tag_dir, dst + i, src_tag[i]);
}

static void PIN_FAST_ANALYSIS_CALL
r2m_xfer_opl(THREADID tid, ADDRINT dst, uint32_t src)
{
    tag_t src_tag[] = R32TAG(tid, src);

    for (size_t i = 0; i < 4; i++)
        tag_dir_setb(tag_dir, dst + i, src_tag[i]);
}

static void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opw(ADDRINT dst, ADDRINT src)
{
    tag_t src_tag[] = M16TAG(src);

    for (size_t i = 0; i < 2; i++)
        tag_dir_setb(tag_dir, dst + i, src_tag[i]);
}

static void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opb(ADDRINT dst, ADDRINT src)
{
    tag_t src_tag = MTAG(src);

    tag_dir_setb(tag_dir, dst, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opq(ADDRINT dst, ADDRINT src)
{
    tag_t src_tag[] = M64TAG(src);

    for (size_t i = 0; i < 8; i++)
        tag_dir_setb(tag_dir, dst + i, src_tag[i]);
}


static void PIN_FAST_ANALYSIS_CALL
m2m_xfer_opl(ADDRINT dst, ADDRINT src)
{
    tag_t src_tag[] = M32TAG(src);

    for (size_t i = 0; i < 4; i++)
        tag_dir_setb(tag_dir, dst + i, src_tag[i]);
}

static ADDRINT PIN_FAST_ANALYSIS_CALL
rep_predicate(BOOL first_iteration)
{
	/* return the flag; typically this is true only once */
	return first_iteration; 
}

static void PIN_FAST_ANALYSIS_CALL
m2r_restore_opw(THREADID tid, ADDRINT src)
{
    for (size_t i = 0; i < 8; i++)
    {
        if (i == DFT_REG_RSP) continue;
        size_t offset = (i < DFT_REG_RSP)?(i << 1):((i-1) << 1);
        tag_t src_tag[] = M16TAG(src + offset);
        RTAG(tid)[DFT_REG_RDI+i][0] = src_tag[0];
        RTAG(tid)[DFT_REG_RDI+i][1] = src_tag[1];


    }
}

static void PIN_FAST_ANALYSIS_CALL
m2r_restore_opl(THREADID tid, ADDRINT src)
{
    for (size_t i = 0; i < 8; i++)
    {
        if (i == DFT_REG_RSP) continue;
        size_t offset = (i < DFT_REG_RSP)?(i << 2):((i-1) << 2);
        tag_t src_tag[] = M32TAG(src + offset);
        RTAG(tid)[DFT_REG_RDI+i][0] = src_tag[0];
        RTAG(tid)[DFT_REG_RDI+i][1] = src_tag[1];
        RTAG(tid)[DFT_REG_RDI+i][2] = src_tag[2];
        RTAG(tid)[DFT_REG_RDI+i][3] = src_tag[3];

    }
}

static void PIN_FAST_ANALYSIS_CALL
r2m_save_opw(THREADID tid, ADDRINT dst)
{
    for (int i = DFT_REG_RDI; i < DFT_REG_XMM0; i++)
    {
        if (i == DFT_REG_RSP) continue;
        size_t offset = (i < DFT_REG_RSP)?(i << 1):((i-1) << 1);
        tag_t src_tag[] = R16TAG(tid, i);

        tag_dir_setb(tag_dir, dst + offset, src_tag[0]);
        tag_dir_setb(tag_dir, dst + offset + 1, src_tag[1]);



    }
}

static void PIN_FAST_ANALYSIS_CALL
r2m_save_opl(THREADID tid, ADDRINT dst)
{
    for (int i = DFT_REG_RDI; i < DFT_REG_XMM0; i++)
    {
        if (i == DFT_REG_RSP) continue;
        size_t offset = (i < DFT_REG_RSP)?(i << 2):((i-1) << 2);
        tag_t src_tag[] = R32TAG(tid, i);

        for (size_t j = 0; j < 4; j++)
            tag_dir_setb(tag_dir, dst + offset + j, src_tag[j]);


    }
}


static void PIN_FAST_ANALYSIS_CALL
file_cmp_r2r(THREADID tid, ADDRINT ins_address, uint32_t reg_dest, uint64_t reg_dest_val, uint32_t reg_src, uint64_t reg_src_val, uint32_t size_dest){
	std::vector<tag_t> dest_tag(size_dest);
	std::vector<tag_t> src_tag(size_dest);
	get_array_reg(tid, reg_dest, size_dest, dest_tag);
	get_array_reg(tid, reg_src, size_dest, src_tag);
	for(int i=0;i<21;i++){
		output[i] = "{}";
	}
	int fl = 0;
	for(size_t i=0;i<size_dest;i++){
		if(tag_count(dest_tag[i])){
			if(fl == 0){
				output[2] = StringFromAddrint(ins_address);
				fl = 1;
			}
		}
		output[i+3] = tag_sprint(dest_tag[i]);
		if(tag_count(src_tag[i])){
			output[2] = StringFromAddrint(ins_address);
			fl = 1;
		}
		output[i+11] = tag_sprint(src_tag[i]);
	}
	if(fl == 1){
		switch(size_dest){
			case 8:
				output[19] = hexstr(reg_dest_val);
				output[20] = hexstr(reg_src_val);
				break;
			case 4:
				output[19] = hexstr((uint32_t)reg_dest_val);
				output[20] = hexstr((uint32_t)reg_src_val);
				break;
			case 2:
				output[19] = hexstr((uint16_t)reg_dest_val);
				output[20] = hexstr((uint16_t)reg_src_val);
				break;
			case 1:
				output[19] = hexstr((uint8_t)reg_dest_val);
				output[20] = hexstr((uint8_t)reg_src_val);
				break;
		}

		output[0] = INT2STR(size_dest*8);
		output[1] = "reg reg";
		print_log();
	}
}

static void PIN_FAST_ANALYSIS_CALL
file_cmp_m2r(THREADID tid, ADDRINT ins_address, uint32_t reg_dest, uint64_t reg_dest_val, ADDRINT src_addr, uint32_t size_dest){
	std::vector<tag_t> dest_tag(size_dest);
	std::vector<tag_t> src_tag(size_dest);
	get_array_reg(tid, reg_dest, size_dest, dest_tag);
	if(!file_tag_testb(src_addr)){
		return;
	}
	get_array_mem(src_addr, size_dest, src_tag);
	for(int i=0;i<21;i++){
		output[i] = "{}";
	}
	int fl = 0;
	for(size_t i=0;i<size_dest;i++){
		if(tag_count(dest_tag[i])){
			if(fl == 0){
				output[2] = StringFromAddrint(ins_address);
				fl = 1;
			}
		}
		output[i+3] = tag_sprint(dest_tag[i]);
		if(tag_count(src_tag[i])){
			output[2] = StringFromAddrint(ins_address);
			fl = 1;
		}
		output[i+11] = tag_sprint(src_tag[i]);
	}
	if(fl == 1){
		switch(size_dest){
			case 8:
				output[19] = hexstr(reg_dest_val);
				output[20] = hexstr(*(uint64_t *)src_addr);
				break;
			case 4:
				output[19] = hexstr((uint32_t)reg_dest_val);
				output[20] = hexstr(*(uint32_t *)src_addr);
				break;
			case 2:
				output[19] = hexstr((uint16_t)reg_dest_val);
				output[20] = hexstr(*(uint16_t *)src_addr);
				break;
			case 1:
				output[19] = hexstr((uint8_t)reg_dest_val);
				output[20] = hexstr(*(uint8_t *)src_addr);
				break;
		}
		output[0] = INT2STR(size_dest*8);
		output[1] = "reg mem";
		print_log();
	}
}

static void PIN_FAST_ANALYSIS_CALL
file_cmp_i2r(THREADID tid, ADDRINT ins_address, uint32_t reg_dest, uint64_t reg_dest_val, uint32_t imm_src_val, uint32_t size_dest){
	std::vector<tag_t> dest_tag(size_dest);
	std::vector<tag_t> src_tag(size_dest);
	get_array_reg(tid, reg_dest, size_dest, dest_tag);
	for(int i=0;i<21;i++){
		output[i] = "{}";
	}
	//LOG(StringFromAddrint(ins_address) + "\n");
	int fl = 0;
	for(size_t i=0;i<size_dest;i++){
		if(tag_count(dest_tag[i])){
			if(fl == 0){
				output[2] = StringFromAddrint(ins_address);
				fl = 1;
			}
		}
		output[i+3] = tag_sprint(dest_tag[i]);
	}
	if(fl == 1){
		switch(size_dest){
			case 8:
			case 4:
				output[19] = hexstr((uint32_t)reg_dest_val);
				output[20] = hexstr((uint32_t)imm_src_val);
				break;
			case 2:
				output[19] = hexstr((uint16_t)reg_dest_val);
				output[20] = hexstr((uint16_t)imm_src_val);
				break;
			case 1:
				output[19] = hexstr((uint8_t)reg_dest_val);
				output[20] = hexstr((uint8_t)imm_src_val);
				break;
		}	
		output[0] = INT2STR(size_dest*8);
		output[1] = "reg imm";
		print_log();
	}
}


static void PIN_FAST_ANALYSIS_CALL
file_cmp_r2m(THREADID tid, ADDRINT ins_address, ADDRINT dest_addr, uint32_t reg_src, uint64_t reg_src_val, uint32_t size_dest){
	std::vector<tag_t> dest_tag(size_dest);
	std::vector<tag_t> src_tag(size_dest);
	if(!file_tag_testb(dest_addr)){
		return;
	}
	get_array_mem(dest_addr, size_dest, dest_tag);
	get_array_reg(tid, reg_src, size_dest, src_tag);
	for(int i=0;i<21;i++){
		output[i] = "{}";
	}
	int fl = 0;
	for(size_t i=0;i<size_dest;i++){
		if(tag_count(dest_tag[i])){
			if(fl == 0){
				output[2] = StringFromAddrint(ins_address);
				fl = 1;
			}
		}
		output[i+3] = tag_sprint(dest_tag[i]);
		if(tag_count(src_tag[i])){
			if(fl == 0){
				output[2] = StringFromAddrint(ins_address);
				fl = 1;
			}
		}
		output[i+11] = tag_sprint(src_tag[i]);
	}
	if(fl == 1){
		switch(size_dest){
			case 8:
				output[19] = hexstr(*(uint64_t *)dest_addr);
				output[20] = hexstr(reg_src_val);
				break;
			case 4:
				output[19] = hexstr(*(uint32_t *)dest_addr);
				output[20] = hexstr((uint32_t)reg_src_val);
				break;
			case 2:
				output[19] = hexstr(*(uint16_t *)dest_addr);
				output[20] = hexstr((uint16_t)reg_src_val);
				break;
			case 1:
				output[19] = hexstr(*(uint8_t *)dest_addr);
				output[20] = hexstr((uint8_t)reg_src_val);
				break;
		}
		output[0] = INT2STR(size_dest*8);
		output[1] = "mem reg";
		print_log();
	}
}


static void PIN_FAST_ANALYSIS_CALL
file_cmp_m2m(ADDRINT ins_address, ADDRINT dest_addr, ADDRINT src_addr, uint32_t size_dest){
	std::vector<tag_t> dest_tag(size_dest);
	std::vector<tag_t> src_tag(size_dest);
	if(!file_tag_testb(dest_addr) ||!file_tag_testb(src_addr)){
		return;
	}
	get_array_mem(dest_addr, size_dest, dest_tag);
	get_array_mem(src_addr, size_dest, src_tag);
	for(int i=0;i<21;i++){
		output[i] = "{}";
	}
	int fl = 0;
	for(size_t i=0;i<size_dest;i++){
		if(dest_tag[i].numberOfOnes() > 0 && dest_tag[i].numberOfOnes() <= (uint32_t)limit_offset){
			for(tag_t::const_iterator it = dest_tag[i].begin();it != dest_tag[i].end();it++){
	                                //file_offsets[make_pair(*it,1)] = 1;
			//file_offsets[*it] = 1;

			}
         //               LOG(tag_sprint(dest_tag[i]) + " CMPS" );
			if(fl == 0){
				output[2] = StringFromAddrint(ins_address);
				fl = 1;
			}
		}
		output[i+3] = tag_sprint(dest_tag[i]);
		if(src_tag[i].numberOfOnes() > 0 && src_tag[i].numberOfOnes() <= (uint32_t)limit_offset){
			for(tag_t::const_iterator it = src_tag[i].begin();it != src_tag[i].end();it++){
                                //file_offsets[make_pair(*it,1)] = 1;

				//file_offsets[*it] = 1;
			}
           //             LOG(tag_sprint(src_tag[i]) + " CMPS" );
			if(fl == 0){
				output[2] = StringFromAddrint(ins_address);
				fl = 1;
			}
		}
		output[i+11] = tag_sprint(src_tag[i]);
	}
	if(fl == 1){
                switch(size_dest){
                        case 8:
                        case 4:
                                output[19] = hexstr(*(uint32_t *)dest_addr);
                                output[20] = hexstr(*(uint32_t *)src_addr);
                                break;
                        case 2:
                                output[19] = hexstr(*(uint16_t *)dest_addr);
                                output[20] = hexstr(*(uint16_t *)src_addr);
                                break;
                        case 1:
                                output[19] = hexstr(*(uint8_t *)dest_addr);
                                output[20] = hexstr(*(uint8_t *)src_addr);
                                break;
                }

		output[0] = INT2STR(size_dest*8);
		output[1] = "mem mem";
             //   LOG("\n");
		print_log();
	}
}


static void PIN_FAST_ANALYSIS_CALL
file_cmp_i2m(ADDRINT ins_address, ADDRINT dest_addr, uint32_t imm_src_val, uint32_t size_dest){
	std::vector<tag_t> dest_tag(size_dest);

	if(!file_tag_testb(dest_addr)){
		return;
	}
	get_array_mem(dest_addr, size_dest, dest_tag);
	for(int i=0;i<21;i++){
		output[i] = "{}";
	}
	int fl = 0;
	for(size_t i=0;i<size_dest;i++){
		if(tag_count(dest_tag[i])){
			if(fl == 0){
				output[2] = StringFromAddrint(ins_address);
				fl = 1;
			}
		}
		output[i+3] = tag_sprint(dest_tag[i]);
	}
	if(fl == 1){
		switch(size_dest){
			case 8:
			case 4:
				output[19] = hexstr(*(uint32_t *)dest_addr);
				break;
			case 2:
				output[19] = hexstr(*(uint16_t *)dest_addr);
				break;
			case 1:
				output[19] = hexstr(*(uint8_t *)dest_addr);
				break;
		}
		output[20] = hexstr(imm_src_val);
		output[0] = INT2STR(size_dest*8);
		output[1] = "mem imm";
		print_log();
	}
}



   /* 
static void PIN_FAST_ANALYSIS_CALL
cal(THREADID tid,ADDRINT ins_address, char *str, uint64_t rsp_val){
   
    std::string s(str);
    LOG(s + " " + StringFromAddrint(ins_address) + " " + hexstr(rsp_val) + "\n"); 
    std::vector<tag_t> dest_tag(8);
    get_array_reg(tid, 3, 8, dest_tag);
    for(int i=0;i<2;i++){
	LOG("RDI " + tag_sprint(dest_tag[i]) + " " );
    }
    LOG("\n");
    get_array_reg(tid, 4, 8, dest_tag);
    for(int i=0;i<2;i++){
	LOG("RSI " + tag_sprint(dest_tag[i]) + " " );
    }
    LOG("\n");
    get_array_reg(tid, 5, 8, dest_tag);
    for(int i=0;i<2;i++){
	LOG("RBP " + tag_sprint(dest_tag[i]) + " " );
    }
    LOG("\n");
    get_array_reg(tid, 6, 8, dest_tag);
    for(int i=0;i<2;i++){
	LOG("RSP " + tag_sprint(dest_tag[i]) + " " );
    }
    LOG("\n");
    get_array_reg(tid, 7, 8, dest_tag);
    for(int i=0;i<2;i++){
	LOG("RBX " + tag_sprint(dest_tag[i]) + " " );
    }
    LOG("\n");
    get_array_reg(tid, 8, 8, dest_tag);
    for(int i=0;i<2;i++){
	LOG("RDX " + tag_sprint(dest_tag[i]) + " " );
    }
    LOG("\n");
    get_array_reg(tid, 9, 8, dest_tag);
    for(int i=0;i<2;i++){
	LOG("RCX " + tag_sprint(dest_tag[i]) + " " );
    }
    LOG("\n");
    get_array_reg(tid, 10, 8, dest_tag);
    for(int i=0;i<2;i++){
	LOG("RAX " + tag_sprint(dest_tag[i]) + " " );
    }
    LOG("\n");
    stringstream ss1;
    tag_t t = threads_ctx[tid].vcpu.gpr_file[3][0];
    t.set(1);
    ss1 << RTAG[3][0];
	LOG("TAG:" + ss1.str() +"\n");
}*/
/*
 * instruction inspection (instrumentation function)
 *
 * analyze every instruction and instrument it
 * for propagating the tag bits accordingly
 *
 * @ins:	the instruction to be instrumented
 */
void
ins_inspect(INS ins)
{
	/* 
	 * temporaries;
	 * source, destination, base, and index registers
	 */
	REG reg_dst, reg_src, reg_base, reg_indx;

	/* use XED to decode the instruction and extract its opcode */
	xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
	/* sanity check */
	if (unlikely(ins_indx <= XED_ICLASS_INVALID || 
				ins_indx >= XED_ICLASS_LAST)) {
		LOG(string(__func__) + ": unknown opcode (opcode=" +
				decstr(ins_indx) + ")\n");

		/* done */
		return;
	}
/*	char *cstr;
        cstr = new char [INS_Disassemble(ins).size()+1];
        strcpy(cstr, INS_Disassemble(ins).c_str());

				INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)cal,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_INST_PTR,
								IARG_PTR, cstr,
								IARG_REG_VALUE, REG_RSP,
								IARG_END);*/


// 	LOG(StringFromAddrint(INS_Address(ins)) + ": " + INS_Disassemble(ins) + "\n");
	switch (ins_indx) {
		case XED_ICLASS_ADC:
		case XED_ICLASS_ADD:
		case XED_ICLASS_AND:
		case XED_ICLASS_OR:
		case XED_ICLASS_XOR:
		case XED_ICLASS_SBB:
		case XED_ICLASS_SUB:
			if (INS_OperandIsImmediate(ins, OP_1))
				break;

			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_dst)) {
					switch (ins_indx) {
						case XED_ICLASS_XOR:
						case XED_ICLASS_SUB:
						case XED_ICLASS_SBB:
							if (reg_dst == reg_src) 
							{
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrq,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_END);
								break;
							}
						default:
							INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_binary_opq,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_src),
							IARG_END);
					}
				}
				else if (REG_is_gr32(reg_dst)) {
					switch (ins_indx) {
						case XED_ICLASS_XOR:
						case XED_ICLASS_SUB:
						case XED_ICLASS_SBB:
							if (reg_dst == reg_src) 
							{
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrl,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_END);
								break;
							}
						default:
							INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_binary_opl,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_src),
							IARG_END);
					}
				}
				else if (REG_is_gr16(reg_dst)) {
					switch (ins_indx) {
						case XED_ICLASS_XOR:
						case XED_ICLASS_SUB:
						case XED_ICLASS_SBB:
							if (reg_dst == reg_src) 
							{
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrw,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_END);
								break;
							}
						default:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r2r_binary_opw,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_UINT32, REG_INDX(reg_src),
								IARG_END);
					}
				}
				else {
					switch (ins_indx) {
						case XED_ICLASS_XOR:
						case XED_ICLASS_SUB:
						case XED_ICLASS_SBB:
							if (reg_dst == reg_src) 
							{
						if (REG_is_Upper8(reg_dst))
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrb_u,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_END);
						else 
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrb_l,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_END);
								break;
							}
						default:
					if (REG_is_Lower8(reg_dst) &&
							REG_is_Lower8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_Upper8(reg_dst) &&
							REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if (REG_is_Lower8(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opb_lu,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opb_ul,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					}
				}
			}
			else if (INS_OperandIsMemory(ins, OP_1)) {
				reg_dst = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_Upper8(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else 
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
			}
			else {
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_binary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_binary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr16(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_binary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_binary_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_binary_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
			}

			break;
		case XED_ICLASS_BSF:
		case XED_ICLASS_BSR:
		case XED_ICLASS_MOV:
			if (INS_OperandIsImmediate(ins, OP_1) ||
				(INS_OperandIsReg(ins, OP_1) &&
				REG_is_seg(INS_OperandReg(ins, OP_1)))) {
				if (INS_OperandIsMemory(ins, OP_0)) {
					switch (INS_OperandWidth(ins, OP_0)) {
						case MEM_64BIT_LEN:
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)file_tagmap_clrn,
							IARG_FAST_ANALYSIS_CALL,
							IARG_MEMORYWRITE_EA,
							IARG_UINT32, 8,
							IARG_END);
							break;
						case MEM_LONG_LEN:
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)file_tagmap_clrn,
							IARG_FAST_ANALYSIS_CALL,
							IARG_MEMORYWRITE_EA,
							IARG_UINT32, 4,
							IARG_END);
							break;
						case MEM_WORD_LEN:
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)file_tagmap_clrn,
							IARG_FAST_ANALYSIS_CALL,
							IARG_MEMORYWRITE_EA,
							IARG_UINT32, 2,
							IARG_END);

							break;
						case MEM_BYTE_LEN:
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)file_tagmap_clrn,
							IARG_FAST_ANALYSIS_CALL,
							IARG_MEMORYWRITE_EA,
							IARG_UINT32, 1,
							IARG_END);

							break;
						default:
						LOG(string(__func__) +
						": unhandled operand width (" +
						INS_Disassemble(ins) + ")\n");


							return;
					}
				}
				else if (INS_OperandIsReg(ins, OP_0)) {
					reg_dst = INS_OperandReg(ins, OP_0);
					if (REG_is_gr64(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrq,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
					else if (REG_is_gr32(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrl,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
					else if (REG_is_gr16(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrw,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
					else if (REG_is_Upper8(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrb_u,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
					else
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r_clrb_l,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
				}
			}
			else if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr8(reg_dst)) {
					if (REG_is_Lower8(reg_dst) &&
							REG_is_Lower8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_Upper8(reg_dst) &&
							REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if (REG_is_Lower8(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opb_lu,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opb_ul,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
			}
			else if (INS_OperandIsMemory(ins, OP_1)) {
				reg_dst = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_Upper8(reg_dst)) 
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
			}
			else {
				reg_src = INS_OperandReg(ins, OP_1);

				if (REG_is_gr64(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr16(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else 
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
			}

			break;
		case XED_ICLASS_CMOVB:
		case XED_ICLASS_CMOVBE:
		case XED_ICLASS_CMOVL:
		case XED_ICLASS_CMOVLE:
		case XED_ICLASS_CMOVNB:
		case XED_ICLASS_CMOVNBE:
		case XED_ICLASS_CMOVNL:
		case XED_ICLASS_CMOVNLE:
		case XED_ICLASS_CMOVNO:
		case XED_ICLASS_CMOVNP:
		case XED_ICLASS_CMOVNS:
		case XED_ICLASS_CMOVNZ:
		case XED_ICLASS_CMOVO:
		case XED_ICLASS_CMOVP:
		case XED_ICLASS_CMOVS:
		case XED_ICLASS_CMOVZ:
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);

				if (REG_is_gr64(reg_dst))
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else 
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
			}
			else {
				reg_dst = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_dst))
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else
					INS_InsertPredicatedCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
			}

			break;
		case XED_ICLASS_CBW:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2r_xfer_opb_ul,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_AH),
				IARG_UINT32, REG_INDX(REG_AL),
				IARG_END);

			break;
		case XED_ICLASS_CWD:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2r_xfer_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_DX),
				IARG_UINT32, REG_INDX(REG_AX),
				IARG_END);

			break;
		case XED_ICLASS_CWDE:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)_cwde,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_END);
			break;
		case XED_ICLASS_CDQ:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2r_xfer_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_EDX),
				IARG_UINT32, REG_INDX(REG_EAX),
				IARG_END);

			break;
		case XED_ICLASS_CDQE:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)_cdqe,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_END);
			break;
		case XED_ICLASS_CQO:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2r_xfer_opq,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_EDX),
				IARG_UINT32, REG_INDX(REG_EAX),
				IARG_END);

			break;
		case XED_ICLASS_MOVSX:
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr16(reg_dst)) {
					if (REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_opwb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_opwb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_gr16(reg_src)){
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_opqw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_oplw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);

				}
				else if (REG_is_Upper8(reg_src)){
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_opqb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_oplb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else{
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_opqb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_r2r_oplb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
			}
			else {
				reg_dst = INS_OperandReg(ins, OP_0);
				if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_m2r_opwb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_WORD_LEN)){
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_m2r_opqw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_m2r_oplw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);

				}
				else{
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_m2r_opqb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movsx_m2r_oplb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);

				}
			}
			break;
		case XED_ICLASS_MOVSXD:
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_movsx_r2r_opql,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_UINT32, REG_INDX(reg_src),
					IARG_END);
			}
			else {
				reg_dst = INS_OperandReg(ins, OP_0);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)_movsx_m2r_opql,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}
			break;
		case XED_ICLASS_MOVZX:
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				
				if (REG_is_gr16(reg_dst)) {
					if (REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_opwb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_opwb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_gr16(reg_src)){
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_opqw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_oplw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_Upper8(reg_src)){
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_opqb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_oplb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else{
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_opqb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_r2r_oplb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
			}
			else {
				reg_dst = INS_OperandReg(ins, OP_0);
				
				if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_m2r_opwb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_WORD_LEN)){
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_m2r_opqw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_m2r_oplw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				}
				else{
					if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_m2r_opqb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
					else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_movzx_m2r_oplb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				}
			}
			break;
		case XED_ICLASS_DIV:
		case XED_ICLASS_IDIV:
		case XED_ICLASS_MUL:
			if (INS_OperandIsMemory(ins, OP_0))
				switch (INS_MemoryWriteSize(ins)) {
					case BIT2BYTE(MEM_64BIT_LEN):
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_END);
						break;
					case BIT2BYTE(MEM_LONG_LEN):
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_END);
						break;
					case BIT2BYTE(MEM_WORD_LEN):
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_END);

						break;
					case BIT2BYTE(MEM_BYTE_LEN):
					default:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_END);
						break;
				}
			else {
				reg_src = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr16(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else 
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
			}
			break;
		case XED_ICLASS_IMUL:
			if (INS_OperandIsImplicit(ins, OP_1)) {
				if (INS_OperandIsMemory(ins, OP_0))
				switch (INS_MemoryWriteSize(ins)) {
					case BIT2BYTE(MEM_64BIT_LEN):
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_END);
						break;
					case BIT2BYTE(MEM_LONG_LEN):
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_END);
						break;
					case BIT2BYTE(MEM_WORD_LEN):
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_END);

						break;
					case BIT2BYTE(MEM_BYTE_LEN):
					default:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_ternary_opb,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYREAD_EA,
						IARG_END);
						break;
				}
			else {
				reg_src = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				if (REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr16(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_ternary_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
			}
			else {
				if (INS_OperandIsImmediate(ins, OP_1))
					break;

				if (INS_MemoryOperandCount(ins) == 0) {
					reg_dst = INS_OperandReg(ins, OP_0);
					reg_src = INS_OperandReg(ins, OP_1);
				
					if (REG_is_gr32(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_binary_opl,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_src),
							IARG_END);
					else
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_binary_opw,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_src),
							IARG_END);
				}
				else {
					reg_dst = INS_OperandReg(ins, OP_0);
					if (REG_is_gr64(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)m2r_binary_opq,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_MEMORYREAD_EA,
							IARG_END);
					else if (REG_is_gr32(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)m2r_binary_opl,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_MEMORYREAD_EA,
							IARG_END);
					else
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)m2r_binary_opw,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_MEMORYREAD_EA,
							IARG_END);
				}
			}

			break;
		case XED_ICLASS_SETB:
		case XED_ICLASS_SETBE:
		case XED_ICLASS_SETL:
		case XED_ICLASS_SETLE:
		case XED_ICLASS_SETNB:
		case XED_ICLASS_SETNBE:
		case XED_ICLASS_SETNL:
		case XED_ICLASS_SETNLE:
		case XED_ICLASS_SETNO:
		case XED_ICLASS_SETNP:
		case XED_ICLASS_SETNS:
		case XED_ICLASS_SETNZ:
		case XED_ICLASS_SETO:
		case XED_ICLASS_SETP:
		case XED_ICLASS_SETS:
		case XED_ICLASS_SETZ:
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				
				if (REG_is_Upper8(reg_dst))	
					INS_InsertPredicatedCall(ins,
							IPOINT_BEFORE,
						(AFUNPTR)r_clrb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
				else 
					INS_InsertPredicatedCall(ins,
							IPOINT_BEFORE,
						(AFUNPTR)r_clrb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
			}
			else
				INS_InsertPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)file_tagmap_clrn,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, 1,
					IARG_END);

			break;
		case XED_ICLASS_STMXCSR:
			/* propagate tag accordingly */
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)file_tagmap_clrn,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_UINT32, 4,
				IARG_END);
		
			/* done */
			break;
		case XED_ICLASS_SMSW:
		case XED_ICLASS_STR:
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				
				if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
				else if(REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
				else if(REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
			}
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)file_tagmap_clrn,
					IARG_FAST_ANALYSIS_CALL,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, 2,
					IARG_END);

			break;

		case XED_ICLASS_LAR:
			reg_dst = INS_OperandReg(ins, OP_0);

			if (REG_is_gr16(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r_clrw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_END);
			else if (REG_is_gr32(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r_clrl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_END);
			else if (REG_is_gr64(reg_dst))
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r_clrq,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_END);
			break;
		case XED_ICLASS_RDPMC:
		case XED_ICLASS_RDTSC:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r_clrl2,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_END);

			break;
		case XED_ICLASS_CPUID:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r_clrl4,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_END);

			break;
		case XED_ICLASS_LAHF:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r_clrb_u,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_AH),
				IARG_END);

			break;
		case XED_ICLASS_CMPXCHG:
			//LOG("Compare class" +  INS_Disassemble(ins) + "\n");
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_dst)) {
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2r_opq_fast,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_REG_VALUE, REG_EAX,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_REG_VALUE, reg_dst,
						IARG_END);
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2r_opq_slow,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_gr32(reg_dst)) {
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2r_opl_fast,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_REG_VALUE, REG_EAX,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_REG_VALUE, reg_dst,
						IARG_END);
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2r_opl_slow,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_gr16(reg_dst)) {
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2r_opw_fast,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_REG_VALUE, REG_AX,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_REG_VALUE, reg_dst,
						IARG_END);
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2r_opw_slow,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else
				LOG(string(__func__) +
					": unhandled opcode (opcode=" +
					decstr(ins_indx) + ")\n");
			}
			else {
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_src)) {
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_m2r_opq_fast,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_REG_VALUE, REG_EAX,
						IARG_MEMORYREAD_EA,
						IARG_END);
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2m_opq_slow,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_gr32(reg_src)) {
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_m2r_opl_fast,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_REG_VALUE, REG_EAX,
						IARG_MEMORYREAD_EA,
						IARG_END);
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2m_opl_slow,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_gr16(reg_src)) {
					INS_InsertIfCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_m2r_opw_fast,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_REG_VALUE, REG_AX,
						IARG_MEMORYREAD_EA,
						IARG_END);
					INS_InsertThenCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_cmpxchg_r2m_opw_slow,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else
				LOG(string(__func__) +
					": unhandled opcode (opcode=" +
					decstr(ins_indx) + ")\n");
			}
			break;

		case XED_ICLASS_CMP:{
//				LOG(" CMP " + StringFromAddrint(INS_Address(ins)) + " " + INS_Disassemble(ins) + "\n");
				if(INS_OperandIsReg(ins, OP_0)){
					REG reg_dest = INS_OperandReg(ins, OP_0);
					uint32_t size = get_reg_size(reg_dest);
					if(INS_OperandIsReg(ins, OP_1)){
						REG reg_src = INS_OperandReg(ins, OP_1);
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(file_cmp_r2r),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_INST_PTR,
							IARG_UINT32, REG_INDX(reg_dest),
							IARG_REG_VALUE, reg_dest,
							IARG_UINT32, REG_INDX(reg_src),
							IARG_REG_VALUE, reg_src,
							IARG_UINT32, size,
							IARG_END);
					}else if(INS_OperandIsMemory(ins, OP_1)){
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(file_cmp_m2r),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_INST_PTR,
							IARG_UINT32, REG_INDX(reg_dest),
							IARG_REG_VALUE, reg_dest,
							IARG_MEMORYREAD_EA,
							IARG_UINT32, size,
							IARG_END);
					}else if(INS_OperandIsImmediate(ins, OP_1)){
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(file_cmp_i2r),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_INST_PTR,
							IARG_UINT32, REG_INDX(reg_dest),
							IARG_REG_VALUE, reg_dest,
							IARG_UINT32, INS_OperandImmediate(ins, OP_1),
							IARG_UINT32, size,
							IARG_END);
					}
				}else if(INS_OperandIsMemory(ins, OP_0)){
					uint32_t size = INS_OperandWidth(ins, OP_0)/MEM_BYTE_LEN;
					if(INS_OperandIsReg(ins, OP_1)){
						REG reg_src = INS_OperandReg(ins, OP_1);
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(file_cmp_r2m),
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_INST_PTR,
							IARG_MEMORYREAD_EA,
							IARG_UINT32, REG_INDX(reg_src),
							IARG_REG_VALUE, reg_src,
							IARG_UINT32, size,
							IARG_END);
					}else if(INS_OperandIsImmediate(ins, OP_1)){
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							AFUNPTR(file_cmp_i2m),
							IARG_FAST_ANALYSIS_CALL,
							IARG_INST_PTR,
							IARG_MEMORYREAD_EA,
							IARG_UINT32, INS_OperandImmediate(ins, OP_1),
							IARG_UINT32, size,
							IARG_END);
					}
				}
			break;	
		}
                case XED_ICLASS_CMPSB:{
//                      	LOG(INS_Disassemble(ins) + "\n");
	                INS_InsertCall(ins,
                                IPOINT_BEFORE,
                                AFUNPTR(file_cmp_m2m),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_INST_PTR,
                                IARG_MEMORYREAD2_EA,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, 1,
                                IARG_END);

                	break;
        	}
                case XED_ICLASS_CMPSW:{
//                        LOG(INS_Disassemble(ins) + "\n");
	                INS_InsertCall(ins,
                                IPOINT_BEFORE,
                                AFUNPTR(file_cmp_m2m),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_INST_PTR,
                                IARG_MEMORYREAD2_EA,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, 2,
                                IARG_END);

        	        break;
        	}
                case XED_ICLASS_CMPSD:{
//                        LOG(INS_Disassemble(ins) + "\n");
	                INS_InsertCall(ins,
                                IPOINT_BEFORE,
                                AFUNPTR(file_cmp_m2m),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_INST_PTR,
                                IARG_MEMORYREAD2_EA,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, 4,
                                IARG_END);

               		break;
        	}
               case XED_ICLASS_CMPSQ:{
//              	          LOG(INS_Disassemble(ins) + "\n");
	                INS_InsertCall(ins,
                                IPOINT_BEFORE,
                                AFUNPTR(file_cmp_m2m),
                                IARG_FAST_ANALYSIS_CALL,
                                IARG_INST_PTR,
                                IARG_MEMORYREAD2_EA,
                                IARG_MEMORYREAD_EA,
                                IARG_UINT32, 8,
                                IARG_END);

                	break;
        	}

		case XED_ICLASS_XCHG:
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_dst)) {
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 0,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_UINT32, 0,
						IARG_END);
				}
				else if (REG_is_gr32(reg_dst)) {
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 0,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_UINT32, 0,
						IARG_END);
				}
				else if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_r2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr8(reg_dst)) {
					if (REG_is_Lower8(reg_dst) &&
						REG_is_Lower8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_r2r_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_Upper8(reg_dst) &&
						REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_r2r_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if (REG_is_Lower8(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_r2r_opb_lu,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_r2r_opb_ul,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
			}
			else if (INS_OperandIsMemory(ins, OP_1)) {
				reg_dst = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (REG_is_Upper8(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
			}
			else {
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
				else if (REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
				else if (REG_is_gr16(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
				else if (REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xchg_m2r_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
			}

			break;
		case XED_ICLASS_XADD:
			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_dst)) {
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 0,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_UINT32, 0,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_gr32(reg_dst)) {
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, 0,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_UINT32, 0,
						IARG_END);
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_binary_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
				else if (REG_is_gr16(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr8(reg_dst)) {
					if (REG_is_Lower8(reg_dst) &&
						REG_is_Lower8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2r_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if(REG_is_Upper8(reg_dst) &&
						REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2r_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else if (REG_is_Lower8(reg_dst))
						
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2r_opb_lu,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
					else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_r2r_opb_ul,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				}
			}
			else {
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_gr64(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_m2r_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
				if (REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_m2r_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
				else if (REG_is_gr16(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_m2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
				else if (REG_is_Upper8(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_m2r_opb_u,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_xadd_m2r_opb_l,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_MEMORYWRITE_EA,
						IARG_END);
			}

			break;
		case XED_ICLASS_XLAT:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_xfer_opb_l,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_AL),
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_LODSB:
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_xfer_opb_l,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_AL),
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_LODSW:
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_xfer_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_AX),
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_LODSD:
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_xfer_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_EAX),
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_LODSQ:
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_xfer_opq,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_EAX),
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_STOSB:
			if (INS_RepPrefix(ins)) {
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)rep_predicate,
					IARG_FAST_ANALYSIS_CALL,
					IARG_FIRST_REP_ITERATION,
					IARG_END);
				INS_InsertThenPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opbn,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_REG_VALUE, INS_RepCountRegister(ins),
					IARG_REG_VALUE, INS_OperandReg(ins, OP_4),
					IARG_END);
			}
			else 
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opb_l,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG_INDX(REG_AL),
					IARG_END);

			break;
		case XED_ICLASS_STOSW:
			if (INS_RepPrefix(ins)) {
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)rep_predicate,
					IARG_FAST_ANALYSIS_CALL,
					IARG_FIRST_REP_ITERATION,
					IARG_END);
				INS_InsertThenPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opwn,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_REG_VALUE, INS_RepCountRegister(ins),
					IARG_REG_VALUE, INS_OperandReg(ins, OP_4),
					IARG_END);
			}
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG_INDX(REG_AX),
					IARG_END);

			break;
		case XED_ICLASS_STOSD:
			if (INS_RepPrefix(ins)) {
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)rep_predicate,
					IARG_FAST_ANALYSIS_CALL,
					IARG_FIRST_REP_ITERATION,
					IARG_END);
				INS_InsertThenPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opln,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_REG_VALUE, INS_RepCountRegister(ins),
					IARG_REG_VALUE, INS_OperandReg(ins, OP_4),
					IARG_END);
			}
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG_INDX(REG_EAX),
					IARG_END);

			break;
		case XED_ICLASS_STOSQ:
			if (INS_RepPrefix(ins)) {
				INS_InsertIfPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)rep_predicate,
					IARG_FAST_ANALYSIS_CALL,
					IARG_FIRST_REP_ITERATION,
					IARG_END);
				INS_InsertThenPredicatedCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opqn,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_REG_VALUE, INS_RepCountRegister(ins),
					IARG_REG_VALUE, INS_OperandReg(ins, OP_4),
					IARG_END);
			}
			else
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opq,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG_INDX(REG_EAX),
					IARG_END);

			break;

		case XED_ICLASS_MOVSQ:
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2m_xfer_opq,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_MOVSD:
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2m_xfer_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_MOVSW:
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2m_xfer_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_MOVSB:
			INS_InsertPredicatedCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2m_xfer_opb,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_SALC:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r_clrb_l,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_UINT32, REG_INDX(REG_AL),
				IARG_END);

			break;
		case XED_ICLASS_RCL:
		case XED_ICLASS_RCR:
		case XED_ICLASS_ROL:
		case XED_ICLASS_ROR:
		case XED_ICLASS_SHL:
		case XED_ICLASS_SAR:
		case XED_ICLASS_SHR:
		case XED_ICLASS_SHLD:
		case XED_ICLASS_SHRD:

			break;
		case XED_ICLASS_POP:
			if (INS_OperandIsReg(ins, OP_0)) {
				reg_dst = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);

				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
			}
			else if (INS_OperandIsMemory(ins, OP_0)) {
				if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_64BIT_LEN))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2m_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_END);

				else if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_LONG_LEN))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2m_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2m_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_END);
			}

			break;
		case XED_ICLASS_PUSH:
			if (INS_OperandIsReg(ins, OP_0)) {
				reg_src = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else if (REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
			}
			else if (INS_OperandIsMemory(ins, OP_0)) {
				if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_64BIT_LEN))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2m_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_END);
				else if (INS_MemoryWriteSize(ins) ==
						BIT2BYTE(MEM_LONG_LEN))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2m_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2m_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_MEMORYREAD_EA,
						IARG_END);
			}
			else {
				switch (INS_OperandWidth(ins, OP_0)) {
					case MEM_64BIT_LEN:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 8,
						IARG_END);
						break;
					case MEM_LONG_LEN:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 4,
						IARG_END);
						break;
					case MEM_WORD_LEN:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 2,
						IARG_END);

						break;
					case MEM_BYTE_LEN:
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 1,
						IARG_END);
						break;
					default:
						break;
				}
			}
			break;
		case XED_ICLASS_POPA:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_restore_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_POPAD:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)m2r_restore_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_MEMORYREAD_EA,
				IARG_END);

			break;
		case XED_ICLASS_PUSHA:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2m_save_opw,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_MEMORYWRITE_EA,
				IARG_END);

			break;
		case XED_ICLASS_PUSHAD:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)r2m_save_opl,
				IARG_FAST_ANALYSIS_CALL,
				IARG_THREAD_ID,
				IARG_MEMORYWRITE_EA,
				IARG_END);

			break;
		case XED_ICLASS_PUSHF:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)file_tagmap_clrn,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_UINT32, 2,
				IARG_END);

			break;
		case XED_ICLASS_PUSHFD:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)file_tagmap_clrn,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_UINT32, 4,
				IARG_END);

			break;
		case XED_ICLASS_PUSHFQ:
			INS_InsertCall(ins,
				IPOINT_BEFORE,
				(AFUNPTR)file_tagmap_clrn,
				IARG_FAST_ANALYSIS_CALL,
				IARG_MEMORYWRITE_EA,
				IARG_UINT32, 8,
				IARG_END);

			break;
		case XED_ICLASS_CALL_NEAR:
			if (INS_OperandIsImmediate(ins, OP_0)) {
				if (INS_OperandWidth(ins, OP_0) == MEM_64BIT_LEN)
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 8,
						IARG_END);
				else if (INS_OperandWidth(ins, OP_0) == MEM_LONG_LEN)
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 4,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 2,
						IARG_END);
			}
			else if (INS_OperandIsReg(ins, OP_0)) {
				reg_src = INS_OperandReg(ins, OP_0);
				if (REG_is_gr64(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 8,
						IARG_END);
				else if (REG_is_gr32(reg_src))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 4,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 2,
						IARG_END);
			}
			else {

				if (INS_OperandWidth(ins, OP_0) == MEM_64BIT_LEN)
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 8,
						IARG_END);
				else if (INS_OperandWidth(ins, OP_0) == MEM_LONG_LEN)
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 4,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)file_tagmap_clrn,
						IARG_FAST_ANALYSIS_CALL,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, 2,
						IARG_END);
			}

			break;
		case XED_ICLASS_LEAVE:
			reg_dst = INS_OperandReg(ins, OP_3);
			reg_src = INS_OperandReg(ins, OP_2);
			if (REG_is_gr64(reg_dst)) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opq,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_UINT32, REG_INDX(reg_src),
					IARG_END);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opq,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_src),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}
			else if (REG_is_gr32(reg_dst)) {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_UINT32, REG_INDX(reg_src),
					IARG_END);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opl,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_src),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}
			else {
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_UINT32, REG_INDX(reg_src),
					IARG_END);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opw,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_src),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}

			break;
		case XED_ICLASS_LEA:
			reg_base	= INS_MemoryBaseReg(ins);
			reg_indx	= INS_MemoryIndexReg(ins);
			reg_dst		= INS_OperandReg(ins, OP_0);
			
			if (reg_base == REG_INVALID() &&
					reg_indx == REG_INVALID()) {
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
				else 
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r_clrw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_END);
			}
			if (reg_base != REG_INVALID() &&
					reg_indx == REG_INVALID()) {
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_lea_base_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_base),
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_lea_base_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_base),
						IARG_END);
				else 
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_lea_base_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_base),
						IARG_END);
			}
			if (reg_base == REG_INVALID() &&
					reg_indx != REG_INVALID()) {
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_lea_idx_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_indx),
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_lea_idx_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_indx),
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2r_lea_idx_xfer_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_indx),
						IARG_END);
			}
			if (reg_base != REG_INVALID() &&
					reg_indx != REG_INVALID()) {
				if (REG_is_gr64(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_lea_r2r_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_base),
						IARG_UINT32, REG_INDX(reg_indx),
						IARG_END);
				else if (REG_is_gr32(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_lea_r2r_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_base),
						IARG_UINT32, REG_INDX(reg_indx),
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)_lea_r2r_opw,
						IARG_FAST_ANALYSIS_CALL,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_UINT32, REG_INDX(reg_base),
						IARG_UINT32, REG_INDX(reg_indx),
						IARG_END);
			}			
			break;
		case XED_ICLASS_MOVAPS:
		case XED_ICLASS_MOVDQA:
		case XED_ICLASS_MOVDQU:
			if (INS_MemoryOperandCount(ins) == 0) { 
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1); 
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2r_xfer_opx,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_END);				
			}else if(INS_OperandIsReg(ins, OP_0)){
				reg_dst = INS_OperandReg(ins, OP_0); 
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opx,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}else{
				reg_src = INS_OperandReg(ins, OP_1); 
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opx,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG_INDX(reg_src),
					IARG_END);
			}
			break;
		case XED_ICLASS_MOVD:
		case XED_ICLASS_MOVQ:
			if (INS_MemoryOperandCount(ins) == 0) { 
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1); 
				if(REG_is_xmm(reg_dst)){
					if(REG_is_gr64(reg_src))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_xfer_opq,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
					else
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_xfer_opl,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
				}else if(REG_is_xmm(reg_src)){
					if(REG_is_gr64(reg_dst))
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_xfer_opq,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
					else
						INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_xfer_opl,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_END);
				}		
			}
			else if(INS_OperandIsReg(ins, OP_0)){
				reg_dst = INS_OperandReg(ins, OP_0); 
				if (INS_MemoryReadSize(ins) == BIT2BYTE(MEM_64BIT_LEN))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
			}else{
				reg_src = INS_OperandReg(ins, OP_1); 
				if (INS_MemoryReadSize(ins) == BIT2BYTE(MEM_64BIT_LEN))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
				else
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)r2m_xfer_opl,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_MEMORYWRITE_EA,
						IARG_UINT32, REG_INDX(reg_src),
						IARG_END);
			}
			break;
		case XED_ICLASS_MOVLPD:
		case XED_ICLASS_MOVLPS:
			if (INS_OperandIsMemory(ins, OP_0)){
				reg_src = INS_OperandReg(ins, OP_1);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opq,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG_INDX(reg_src),
					IARG_END);
				
			}else{
				reg_dst = INS_OperandReg(ins, OP_0); 
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opq,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}
			break;
		case XED_ICLASS_MOVHPD:
		case XED_ICLASS_MOVHPS:
			if (INS_OperandIsMemory(ins, OP_0)){
				reg_src = INS_OperandReg(ins, OP_1);
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)r2m_xfer_opq_h,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_MEMORYWRITE_EA,
					IARG_UINT32, REG_INDX(reg_src),
					IARG_END);
				
			}else{
				reg_dst = INS_OperandReg(ins, OP_0); 
				INS_InsertCall(ins,
					IPOINT_BEFORE,
					(AFUNPTR)m2r_xfer_opq_h,
					IARG_FAST_ANALYSIS_CALL,
					IARG_THREAD_ID,
					IARG_UINT32, REG_INDX(reg_dst),
					IARG_MEMORYREAD_EA,
					IARG_END);
			}
			break;
		case XED_ICLASS_PXOR:
		case XED_ICLASS_POR:
		case XED_ICLASS_PSUBB:
		case XED_ICLASS_PSUBW:
		case XED_ICLASS_PSUBD:
			if (INS_OperandIsImmediate(ins, OP_1))
				break;

			if (INS_MemoryOperandCount(ins) == 0) {
				reg_dst = INS_OperandReg(ins, OP_0);
				reg_src = INS_OperandReg(ins, OP_1);
				if (REG_is_xmm(reg_dst)) {
					switch (ins_indx) {
						case XED_ICLASS_PXOR:
						case XED_ICLASS_PSUBB:
						case XED_ICLASS_PSUBW:
						case XED_ICLASS_PSUBD:
						case XED_ICLASS_SBB:
							if (reg_dst == reg_src) 
							{
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrx,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_END);
								break;
							}
						default:
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r2r_binary_opx,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_UINT32, REG_INDX(reg_src),
								IARG_END);
					}
				}else{
					switch (ins_indx) {
						case XED_ICLASS_PXOR:
						case XED_ICLASS_PSUBB:
						case XED_ICLASS_PSUBW:
						case XED_ICLASS_PSUBD:
						case XED_ICLASS_SBB:
							if (reg_dst == reg_src) 
							{
							INS_InsertCall(ins,
								IPOINT_BEFORE,
								(AFUNPTR)r_clrq,
								IARG_FAST_ANALYSIS_CALL,
								IARG_THREAD_ID,
								IARG_UINT32, REG_INDX(reg_dst),
								IARG_END);
								break;
							}
						default:
							INS_InsertCall(ins,
							IPOINT_BEFORE,
							(AFUNPTR)r2r_binary_opq,
							IARG_FAST_ANALYSIS_CALL,
							IARG_THREAD_ID,
							IARG_UINT32, REG_INDX(reg_dst),
							IARG_UINT32, REG_INDX(reg_src),
							IARG_END);
					}
				}
			}else if (INS_OperandIsMemory(ins, OP_1)) {
				reg_dst = INS_OperandReg(ins, OP_0);
				if (REG_is_xmm(reg_dst))
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opx,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);
				else{
					INS_InsertCall(ins,
						IPOINT_BEFORE,
						(AFUNPTR)m2r_binary_opq,
						IARG_FAST_ANALYSIS_CALL,
						IARG_THREAD_ID,
						IARG_UINT32, REG_INDX(reg_dst),
						IARG_MEMORYREAD_EA,
						IARG_END);

				}
           }
			break;

		case XED_ICLASS_CMPXCHG8B:
		case XED_ICLASS_ENTER:
			LOG(string(__func__) +
				": unhandled opcode (opcode=" +
				decstr(ins_indx) + ")\n");

			break;
		default:
			break;
	}
}
