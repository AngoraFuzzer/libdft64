#include "../config.h"
#include "pin.H"
#include "branch_pred.h"
#include "libdft_api.h"
#include "libdft_core.h"
#include "syscall_desc.h"
#include "tagmap.h"
#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

extern REG thread_ctx_ptr;
extern ins_desc_t ins_desc[XED_ICLASS_LAST];
extern syscall_desc_t syscall_desc[SYSCALL_MAX];

ADDRINT code_start_addr = 0;
ADDRINT code_end_addr = 0;

// FIXME: Make them thread local ?
int fuzzing_fd;
u32 stdin_offset;
int socket_fd = -1;
struct sockaddr_un socket_dst;
bool has_dst = false;

void sendData(void *data, int size) {

  if (sendto(socket_fd, data, size, 0, (struct sockaddr *)&socket_dst,
             sizeof(struct sockaddr_un)) < 0) {
    //fprintf(stderr, "failt to call sendto\n");
  }

}

void SocketInit() {
  socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (socket_fd < 0) {
    fprintf(stderr, "failt to creat socket fd\n");
    exit(1);
  }
  /* Construct name of socket to send to. */
  memset(&socket_dst, 0, sizeof(struct sockaddr_un));
  socket_dst.sun_family = AF_UNIX;
  char *dst_id_str = getenv(SOCKET_ENV_VAR);
  //fprintf(stderr, "dst: %s\n", dst_str);
  if (dst_id_str) {
    has_dst = true;
    snprintf(socket_dst.sun_path, sizeof(socket_dst.sun_path), "/tmp/angora_tracker_%s",
             dst_id_str);
    char data[] = "__STR__";
    sendData(data, sizeof(data));
  }

}

inline ADDRINT isExecutable(ADDRINT addr) {
  return (addr <= code_end_addr && addr >= code_start_addr);
}

VOID EntryPoint(VOID *v) {
  IMG img = APP_ImgHead();
  for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
    if (SEC_IsExecutable(sec) && SEC_Name(sec) == ".text") {
      ADDRINT sec_addr = SEC_Address(sec);
      UINT64 sec_size = SEC_Size(sec);
      if (sec_addr != 0) {
        code_start_addr = sec_addr;
        code_end_addr = sec_addr + sec_size;
        break;
      }
    }
  }
}

void combineTag(std::vector<tag_seg> &tag_all, const tag_t *tags, u32 off, u32 size) {

  if (!tags) return;

  for (size_t i = off; i < size; i++) {
#ifdef USE_TREE_TAG
    tag_combine_inplace(tag_all, TagSet::find(tags[i]));
#else
    tag_combine_inplace(tag_all, tags[i]);
#endif
  }

}

void sendCondStmt(u32 br_id, u32 cmp_id, u32 size,
                  u32 op0_val, u32 op1_val,
                  u32 op0_off, u32 op1_off,
                  const tag_t *op0_tags,
                  const tag_t *op1_tags) {

  std::vector<tag_seg> tag_all;
  u16 has_imm = 0;

  combineTag(tag_all, op0_tags, op0_off, size);

  u32 tag_size = tag_all.size();
  if (tag_size == 0) {
    has_imm = 1;
  }

  combineTag(tag_all, op1_tags, op1_off, size);

  if (tag_all.size() == tag_size) {
    if (tag_size > 0) {
      has_imm = 2;
    } else {
      has_imm = 0;
    }
  }

  u16 rg_size = tag_all.size();
  u64 delta = op0_val > op1_val ? op0_val - op1_val : op1_val - op0_val;

  fprintf(stderr, "br: %d, cmp: %d, size: %d, op (%d, %d), tag_size: %d\n",
          br_id, cmp_id, size, op0_val, op1_val, rg_size);

  CondStmt stmt = {
    br_id,
    cmp_id,
    0, // context
    0, // op
    has_imm,
    size,
    rg_size,
    delta
  };

  sendData(&stmt, sizeof(stmt));

  if (rg_size) {
    sendData(&tag_all[0], sizeof(tag_seg) * rg_size);
  }
  if (has_imm == 1) {
    sendData(&op0_val, size);
  } else if (has_imm == 2) {
    sendData(&op1_val, size);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2r_cmp_op(thread_ctx_t *thread_ctx,
                                              u32 br_id,
                                              u32 cmp_id,
                                              u32 size,
                                              u32 op0_idx,
                                              u32 op0_val, u32 op0_off, u32 op1_idx,
                                              u32 op1_val,
                                              u32 op1_off
                                              ) {

  // printf(" > ID: 0x%x, R[%d]: 0x%x, R[%d]: 0x%x, SIZE: %d (%d, %d) \n", br_id, op0_idx, op0_val,
  //        op1_idx, op1_val, size, op0_off, op1_off);

  const tag_t *op0_tags = thread_ctx->vcpu.gpr[op0_idx];
  const tag_t *op1_tags = thread_ctx->vcpu.gpr[op1_idx];
  sendCondStmt(br_id, cmp_id, size, op0_val, op1_val, op0_off, op1_off, op0_tags, op1_tags);

}

static void PIN_FAST_ANALYSIS_CALL r2m_cmp_op(thread_ctx_t *thread_ctx,
                                              u32 br_id,
                                              u32 cmp_id,
                                              u32 size,
                                              u32 op0_idx,
                                              u32 op0_val, u32 op0_off,
                                              ADDRINT op1_addr
                                              ) {
  u32 op1_val = *((u32*)op1_addr);
  // printf(" > ID: 0x%x, R[%d]: 0x%x, M[0x%x]: 0x%x, SIZE: %d (%d, %d) \n", br_id, op0_idx, op0_val,
  //        op1_addr, op1_val, size, op0_off, 0);

  const tag_t *op0_tags = thread_ctx->vcpu.gpr[op0_idx];
  const tag_t *op1_tags = tagmap_getb_as_ptr(op1_addr);
  sendCondStmt(br_id, cmp_id, size, op0_val, op1_val, op0_off, 0, op0_tags, op1_tags);
}

static void PIN_FAST_ANALYSIS_CALL r2i_cmp_op(thread_ctx_t *thread_ctx,
                                              u32 br_id, u32 cmp_id, u32 size, u32 op0_idx,
                                              u32 op0_val, u32 op0_off, u32 op1_val) {

  // printf(" > ID: 0x%x, R[%d]: 0x%x, I: 0x%x, SIZE: %d (%d, %d)\n", br_id, op0_idx, op0_val,
  //        op1_val, size, op0_off, 0);

  const tag_t *op0_tags = thread_ctx->vcpu.gpr[op0_idx];
  sendCondStmt(br_id, cmp_id, size, op0_val, op1_val, op0_off, 0, op0_tags, NULL);
}

static void PIN_FAST_ANALYSIS_CALL m2i_cmp_op(thread_ctx_t *thread_ctx,
                                              u32 br_id, u32 cmp_id, u32 size,
                                              ADDRINT op0_addr,
                                              u32 op1_val
                                              ) {
  u32 op0_val = *((u32*)op0_addr);
  // printf(" > ID: 0x%x, M[0x%x]: 0x%x, I: 0x%x, SIZE: %d (%d, %d)\n", br_id, op0_addr, op0_val,
  //        op1_val, size, 0, 0);

  const tag_t *op0_tags = tagmap_getb_as_ptr(op0_addr);
  sendCondStmt(br_id, cmp_id, size, op0_val, op1_val, 0, 0, op0_tags, NULL);
}

static void post_cmp_hook(INS ins) {
  if (!isExecutable(INS_Address(ins)))
    return;

  // Get the nearest conditional branch inst.
  // The result of cmp inst decides the branch taking or not.
  INS br_ins;
  u32 br_id = 0;

  for (br_ins = ins; INS_Valid(br_ins); br_ins = INS_Next(br_ins)) {

    if (INS_Category(br_ins) == XED_CATEGORY_COND_BR) {
      ADDRINT addr = INS_Address(br_ins);
      br_id = ADDR_PREFIX(addr);
      break;
    }

  }

  std::cout << "CMP: " << INS_Disassemble(ins) << "\n";
  if (br_id == 0) {
    std::cerr << "Can't find an conditional branch!" << std::endl;
    return;
  }

  //std::cout << "BR: " << INS_Disassemble(br_ins) << std::endl;

  ADDRINT cmp_id = INS_Address(ins);
  u32 arg_size = 0;

  if (INS_OperandIsReg(ins, OP_0)) {

    REG reg0 = INS_OperandReg(ins, OP_0);
    u32 reg0_off = 0;
    u32 reg0_idx = 0;

    if (REG_is_gr32(reg0)) {
      arg_size = 4;
      reg0_idx = REG32_INDX(reg0);
    } else if (REG_is_gr16(reg0)) {
      arg_size = 2;
      reg0_idx = REG16_INDX(reg0);
    } else if (REG_is_gr8(reg0)) {
      arg_size = 1;
      reg0_off = REG_is_Lower8(reg0) ? 0 : 1;
      reg0_idx = REG8_INDX(reg0);
    } else {
      // unknown register
      return;
    }

    if (INS_OperandIsReg(ins, OP_1)) {
      REG reg1 = INS_OperandReg(ins, OP_1);
      u32 reg1_off = 0;
      u32 reg1_idx = 0;
      switch (arg_size) {
      case 1:
        reg1_off = REG_is_Lower8(reg1) ? 0 : 1;
        reg1_idx = REG32_INDX(reg1);
        break;
      case 2:
        reg1_idx = REG16_INDX(reg1);
        break;
      case 4:
        reg1_idx = REG8_INDX(reg1);
        break;
      }

      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_cmp_op,
                     IARG_FAST_ANALYSIS_CALL, IARG_REG_VALUE, thread_ctx_ptr,
                     IARG_UINT32, br_id,
                     IARG_UINT32, cmp_id,
                     IARG_UINT32, arg_size,
                     IARG_UINT32, reg0_idx,
                     IARG_REG_VALUE, reg0,
                     IARG_UINT32, reg0_off,
                     IARG_UINT32, reg1_idx,
                     IARG_REG_VALUE, reg1,
                     IARG_UINT32, reg1_off,
                     IARG_END);

    } else if (INS_OperandIsMemory(ins, OP_1)) {

      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2m_cmp_op,
                     IARG_FAST_ANALYSIS_CALL,
                     IARG_REG_VALUE, thread_ctx_ptr,
                     IARG_UINT32, br_id,
                     IARG_UINT32, cmp_id,
                     IARG_UINT32, arg_size,
                     IARG_UINT32, reg0_idx,
                     IARG_REG_VALUE, reg0,
                     IARG_UINT32, reg0_off,
                     IARG_MEMORYREAD_EA,
                     IARG_END);

    } else if (INS_OperandIsImmediate(ins, OP_1)) {

      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2i_cmp_op,
                     IARG_FAST_ANALYSIS_CALL, IARG_REG_VALUE, thread_ctx_ptr,
                     IARG_UINT32, br_id,
                     IARG_UINT32, cmp_id,
                     IARG_UINT32, arg_size,
                     IARG_UINT32, reg0_idx,
                     IARG_REG_VALUE, reg0,
                     IARG_UINT32, reg0_off,
                     IARG_UINT32,
                     (u32)INS_OperandImmediate(ins, OP_1),
                     IARG_END);
    }

  } else if (INS_OperandIsMemory(ins, OP_0)) {

    arg_size = INS_OperandWidth(ins, OP_0) / 8;

    if (INS_OperandIsReg(ins, OP_1)) {
      REG reg1 = INS_OperandReg(ins, OP_1);
      u32 reg1_off = 0;
      u32 reg1_idx = 0;
      switch (arg_size) {
      case 1:
        reg1_off = REG_is_Lower8(reg1) ? 0 : 1;
        reg1_idx = REG32_INDX(reg1);
        break;
      case 2:
        reg1_idx = REG16_INDX(reg1);
        break;
      case 4:
        reg1_idx = REG8_INDX(reg1);
        break;
      }

      // reverse the order or operands
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2m_cmp_op,
                     IARG_FAST_ANALYSIS_CALL,
                     IARG_REG_VALUE, thread_ctx_ptr,
                     IARG_UINT32, br_id,
                     IARG_UINT32, cmp_id,
                     IARG_UINT32, arg_size,
                     IARG_UINT32, reg1_idx,
                     IARG_REG_VALUE, reg1,
                     IARG_UINT32, reg1_off,
                     IARG_MEMORYREAD_EA,
                     IARG_END);

    } else if (INS_OperandIsImmediate(ins, OP_1)) {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)m2i_cmp_op,
                     IARG_FAST_ANALYSIS_CALL,
                     IARG_REG_VALUE, thread_ctx_ptr,
                     IARG_UINT32, br_id,
                     IARG_UINT32, cmp_id,
                     IARG_UINT32, arg_size,
                     IARG_MEMORYREAD_EA,
                     IARG_UINT32,
                     (u32)INS_OperandImmediate(ins, OP_1),
                     IARG_END);

    }
  }
}

// static void post_conditional_branch_hook(INS ins) {
//   if (!isExecutable(INS_Address(ins))) return;
//   //std::cout << INS_Disassemble(ins) << "\t prev: "<<
//   INS_Disassemble(INS_Prev(ins))<< std::endl;
// }

// static void post_indirect_branch_hook(INS ins) {
//   if (unlikely(INS_IsIndirectBranchOrCall(ins))) {
//     // TODO: get the offset of the address if tainted
//   }
// }

static void post_open_hook(syscall_ctx_t *ctx) {
  if (unlikely((long)ctx->ret < 0))
    return;

  fprintf(stdout, "fuzzing input: %s --> %d \n", (char *)ctx->arg[SYSCALL_ARG0],  (int)ctx->ret);
  if (strstr((char *)ctx->arg[SYSCALL_ARG0], FUZZING_INPUT_FILE) != NULL) {
    //fprintf(stdout, "fuzzing input: %s --> %d \n", (char *)ctx->arg[SYSCALL_ARG0],  (int)ctx->ret);
    fuzzing_fd = (int)ctx->ret;
  }
}

static u32 stdin_read_off = 0;
static void post_read_hook(syscall_ctx_t *ctx) {
  /* read() was not successful; optimized branch */
  if (unlikely((long)ctx->ret <= 0))
    return;

  const int fd = ctx->arg[SYSCALL_ARG0];
  const size_t nr = ctx->ret;
  const ADDRINT buf = ctx->arg[SYSCALL_ARG1];
  /* taint-source */
  if (fd == fuzzing_fd) {
    u32 read_off = 0;
    if (fd == STDIN_FILENO) {
      // maintain it by ourself
      read_off = stdin_read_off;
      stdin_read_off += nr;
    } else {
      // low-level POSIX file descriptor I/O.
      read_off = lseek(fd, 0, SEEK_CUR);
      read_off -= nr;      // post
    }

    std::cout <<"readoff: "<< read_off << ", NR:" << nr << std::endl;

    /* set the tag markings */
    for (u32 i = 0; i < nr; i++) {
      //tag_t new_tag = std::set<uint32_t>{read_off + i};
#ifdef USE_TREE_TAG
      tagmap_setb_with_pos(buf + i, read_off + i);
#else
      tag_off from = read_off + i;
      tag_off to = from + 1;
      tag_t new_tag = std::vector<tag_seg>{{from, to}};
      tagmap_setb_with_tag(buf + i, new_tag);
#endif
      std::cout << hex << buf + i << ": " << tag_sprint(tagmap_getb(buf+i)) <<std::endl;
    }

  } else {
    /* clear the tag markings */
    tagmap_clrn(buf, nr);
  }
}

int main(int argc, char *argv[]) {

  PIN_InitSymbols();

  if (unlikely(PIN_Init(argc, argv))) {
    std::cerr
        << "Sth error in PIN_Init. Plz use the right command line options."
        << std::endl;
    return -1;
  }

  SocketInit();

  PIN_AddApplicationStartFunction(EntryPoint, 0);

  if (unlikely(libdft_init() != 0)) {
    std::cerr << "Sth error libdft_init." << std::endl;
    return -1;
  }

  // * TODO: IndirectBranch, including:
  // jmp, call, retn, retf
  // (void)ins_set_post(&ins_desc[XED_ICLASS_CALL_NEAR],
  //                    post_indirect_branch_hook);
  // (void)ins_set_post(&ins_desc[XED_ICLASS_CALL_NEAR],
  //                    post_indirect_branch_hook);
  //(void)ins_set_post(&ins_desc[XED_ICLASS_RET_NEAR], dta_instrument_ret);

  // * Conditional Branch, including:
  // j* series,

  // unsigned less: CF, (euqal by ZF)
  // CF=1
  // (void)ins_set_post(&ins_desc[XED_ICLASS_JB], post_conditional_branch_hook);
  // CF=1 or ZF=1
  // (void)ins_set_post(&ins_desc[XED_ICLASS_JBE],
  // post_conditional_branch_hook);
  // CF=0
  // (void)ins_set_post(&ins_desc[XED_ICLASS_JNB],
  // post_conditional_branch_hook);
  // CF=0 and ZF=0
  // (void)ins_set_post(&ins_desc[XED_ICLASS_JNBE],
  // post_conditional_branch_hook);

  // signed less: SF, OF
  // SF != OF
  // (void)ins_set_post(&ins_desc[XED_ICLASS_JL], post_conditional_branch_hook);
  // ZF = 1 or SF != OF
  // (void)ins_set_post(&ins_desc[XED_ICLASS_JLE],
  // post_conditional_branch_hook);
  // SF == OF
  // (void)ins_set_post(&ins_desc[XED_ICLASS_JNL],
  // post_conditional_branch_hook);
  // ZF = 0 and  SF == OF
  // (void)ins_set_post(&ins_desc[XED_ICLASS_JNLE],
  // post_conditional_branch_hook);

  // // equal or zero : ZF
  // (void)ins_set_post(&ins_desc[XED_ICLASS_JZ], post_conditional_branch_hook);
  // (void)ins_set_post(&ins_desc[XED_ICLASS_JNZ],
  // post_conditional_branch_hook);

  // overflow: OF
  // (void)ins_set_post(&ins_desc[XED_ICLASS_JO], post_conditional_branch_hook);
  // (void)ins_set_post(&ins_desc[XED_ICLASS_JNO],
  // post_conditional_branch_hook);

  // if SF is set
  // (void)ins_set_post(&ins_desc[XED_ICLASS_JS], post_conditional_branch_hook);
  // (void)ins_set_post(&ins_desc[XED_ICLASS_JNS],
  // post_conditional_branch_hook);

  // if PF is set
  // (void)ins_set_post(&ins_desc[XED_ICLASS_JP], post_conditional_branch_hook);
  // (void)ins_set_post(&ins_desc[XED_ICLASS_JNP],
  // post_conditional_branch_hook);

  // others: JRCXZ: Jump if RCX is 0

  // * Cmps
  (void)ins_set_post(&ins_desc[XED_ICLASS_CMP], post_cmp_hook);
  //(void)ins_set_post(&ins_desc[XED_ICLASS_TEST], post_cmp_hook);
  // * Compare string operands: CMPS, CMPSB ...
  //(void)ins_set_post(&ins_desc[XED_ICLASS_CMPS], post_cmp_hook);

  // * IO
  fuzzing_fd = STDIN_FILENO; // By default.

  (void)syscall_set_post(&syscall_desc[__NR_open], post_open_hook);
  //(void)syscall_set_post(&syscall_desc[__NR_creat], post_open_hook);
  (void)syscall_set_post(&syscall_desc[__NR_read], post_read_hook);

  PIN_StartProgram();

  return 0;
}
