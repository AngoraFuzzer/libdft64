#include "ins_clear_op.h"
#include "ins_helper.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

static void PIN_FAST_ANALYSIS_CALL r_clrl4(THREADID tid) {
  for (size_t i = 0; i < 8; i++) {
    RTAG[DFT_REG_RDX][i] = tag_traits<tag_t>::cleared_val;
    RTAG[DFT_REG_RCX][i] = tag_traits<tag_t>::cleared_val;
    RTAG[DFT_REG_RBX][i] = tag_traits<tag_t>::cleared_val;
    RTAG[DFT_REG_RAX][i] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r_clrl2(THREADID tid) {
  for (size_t i = 0; i < 8; i++) {
    RTAG[DFT_REG_RDX][i] = tag_traits<tag_t>::cleared_val;
    RTAG[DFT_REG_RAX][i] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r_clrb_l(THREADID tid, uint32_t reg) {
  RTAG[reg][0] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL r_clrb_u(THREADID tid, uint32_t reg) {
  RTAG[reg][1] = tag_traits<tag_t>::cleared_val;
}

static void PIN_FAST_ANALYSIS_CALL r_clrw(THREADID tid, uint32_t reg) {
  for (size_t i = 0; i < 2; i++) {
    RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r_clrl(THREADID tid, uint32_t reg) {
  for (size_t i = 0; i < 4; i++) {
    RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r_clrq(THREADID tid, uint32_t reg) {
  for (size_t i = 0; i < 8; i++) {
    RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r_clrx(THREADID tid, uint32_t reg) {
  for (size_t i = 0; i < 16; i++) {
    RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
  }
}

static void PIN_FAST_ANALYSIS_CALL r_clry(THREADID tid, uint32_t reg) {
  for (size_t i = 0; i < 16; i++) {
    RTAG[reg][i] = tag_traits<tag_t>::cleared_val;
  }
}

void ins_clear_op(INS ins) {
  if (INS_OperandIsMemory(ins, OP_0)) {
    INT32 n = INS_OperandWidth(ins, OP_0) / 8;
    M_CLEAR_N(n);
  } else {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      R_CALL(r_clrq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      R_CALL(r_clrl, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      R_CALL(r_clrw, reg_dst);
    } else if (REG_is_xmm(reg_dst)) {
      R_CALL(r_clrx, reg_dst);
    } else if (REG_is_mm(reg_dst)) {
      R_CALL(r_clrq, reg_dst);
    } else if (REG_is_ymm(reg_dst)) {
      R_CALL(r_clry, reg_dst);
    } else {
      if (REG_is_Upper8(reg_dst))
        R_CALL(r_clrb_u, reg_dst);
      else
        R_CALL(r_clrb_l, reg_dst);
    }
  }
}

void ins_clear_op_predicated(INS ins) {
  // one byte
  if (INS_MemoryOperandCount(ins) == 0) {
    REG reg_dst = INS_OperandReg(ins, OP_0);

    if (REG_is_Upper8(reg_dst))
      INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)r_clrb_u,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst), IARG_END);
    else
      INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)r_clrb_l,
                               IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                               IARG_UINT32, REG_INDX(reg_dst), IARG_END);
  } else
    INS_InsertPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)tagmap_clrn,
                             IARG_FAST_ANALYSIS_CALL, IARG_MEMORYWRITE_EA,
                             IARG_UINT32, 1, IARG_END);
}

void ins_clear_op_l2(INS ins) {
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_clrl2, IARG_FAST_ANALYSIS_CALL,
                 IARG_THREAD_ID, IARG_END);
}

void ins_clear_op_l4(INS ins) {
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r_clrl4, IARG_FAST_ANALYSIS_CALL,
                 IARG_THREAD_ID, IARG_END);
}