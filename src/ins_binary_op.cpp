#include "ins_binary_op.h"
#include "ins_helper.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_ul(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = RTAG[dst][1];

  RTAG[dst][1] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_lu(THREADID tid, uint32_t dst,
                                                     uint32_t src) {
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = RTAG[dst][0];

  RTAG[dst][0] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_u(THREADID tid, uint32_t dst,
                                                    uint32_t src) {
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = RTAG[dst][1];

  RTAG[dst][1] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opb_l(THREADID tid, uint32_t dst,
                                                    uint32_t src) {
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = RTAG[dst][0];

  RTAG[dst][0] = tag_combine(dst_tag, src_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opw(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 2; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opl(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 4; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opq(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 8; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opx(THREADID tid, uint32_t dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 16; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL r2r_binary_opy(THREADID tid, uint32_t dst,
                                                  uint32_t src) {

  tag_t *src_tags = RTAG[src];
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 32; i++)
    dst_tags[i] = tag_combine(dst_tags[i], src_tags[i]);
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opb_u(THREADID tid, uint32_t dst,
                                                    ADDRINT src) {
  tag_t src_tag = MTAG(src);
  tag_t dst_tag = RTAG[dst][1];

  RTAG[dst][1] = tag_combine(src_tag, dst_tag);
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opb_l(THREADID tid, uint32_t dst,
                                                    ADDRINT src) {
  tag_t src_tag = MTAG(src);
  tag_t dst_tag = RTAG[dst][0];

  RTAG[dst][0] = tag_combine(src_tag, dst_tag);
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opw(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 2; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opl(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 4; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opq(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 8; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opx(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 16; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL m2r_binary_opy(THREADID tid, uint32_t dst,
                                                  ADDRINT src) {
  tag_t *dst_tags = RTAG[dst];
  for (size_t i = 0; i < 32; i++)
    dst_tags[i] = tag_combine(dst_tags[i], MTAG(src + i));
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opb_u(THREADID tid, ADDRINT dst,
                                                    uint32_t src) {
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = MTAG(dst);

  tag_t res_tag = tag_combine(dst_tag, src_tag);
  tagmap_setb(dst, res_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opb_l(THREADID tid, ADDRINT dst,
                                                    uint32_t src) {
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = MTAG(dst);

  tag_t res_tag = tag_combine(dst_tag, src_tag);
  tagmap_setb(dst, res_tag);
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opw(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 2; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opl(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 4; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opq(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 8; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opx(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 16; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

static void PIN_FAST_ANALYSIS_CALL r2m_binary_opy(THREADID tid, ADDRINT dst,
                                                  uint32_t src) {
  tag_t *src_tags = RTAG[src];
  for (size_t i = 0; i < 32; i++)
    tagmap_setb(dst + i, tag_combine(MTAG(dst + i), src_tags[i]));
}

void ins_binary_op(INS ins) {
  if (INS_OperandIsImmediate(ins, OP_1))
    return;
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(r2r_binary_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(r2r_binary_opl, reg_dst, reg_src);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(r2r_binary_opw, reg_dst, reg_src);
    } else if (REG_is_xmm(reg_dst)) {
      R2R_CALL(r2r_binary_opx, reg_dst, reg_src);
    } else if (REG_is_ymm(reg_dst)) {
      R2R_CALL(r2r_binary_opy, reg_dst, reg_src);
    } else if (REG_is_mm(reg_dst)) {
      R2R_CALL(r2r_binary_opq, reg_dst, reg_src);
    } else {
      if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src))
        R2R_CALL(r2r_binary_opb_l, reg_dst, reg_src);
      else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src))
        R2R_CALL(r2r_binary_opb_u, reg_dst, reg_src);
      else if (REG_is_Lower8(reg_dst))
        R2R_CALL(r2r_binary_opb_lu, reg_dst, reg_src);
      else
        R2R_CALL(r2r_binary_opb_ul, reg_dst, reg_src);
    }
  } else if (INS_OperandIsMemory(ins, OP_1)) {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst)) {
      M2R_CALL(m2r_binary_opq, reg_dst);
    } else if (REG_is_gr32(reg_dst)) {
      M2R_CALL(m2r_binary_opl, reg_dst);
    } else if (REG_is_gr16(reg_dst)) {
      M2R_CALL(m2r_binary_opw, reg_dst);
    } else if (REG_is_xmm(reg_dst)) {
      M2R_CALL(m2r_binary_opx, reg_dst);
    } else if (REG_is_ymm(reg_dst)) {
      M2R_CALL(m2r_binary_opy, reg_dst);
    } else if (REG_is_mm(reg_dst)) {
      M2R_CALL(m2r_binary_opq, reg_dst);
    } else if (REG_is_Upper8(reg_dst)) {
      M2R_CALL(m2r_binary_opb_u, reg_dst);
    } else {
      M2R_CALL(m2r_binary_opb_l, reg_dst);
    }
  } else {
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(r2m_binary_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(r2m_binary_opl, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(r2m_binary_opw, reg_src);
    } else if (REG_is_xmm(reg_src)) {
      R2M_CALL(r2m_binary_opx, reg_src);
    } else if (REG_is_ymm(reg_src)) {
      R2M_CALL(r2m_binary_opy, reg_src);
    } else if (REG_is_mm(reg_src)) {
      R2M_CALL(r2m_binary_opq, reg_src);
    } else if (REG_is_Upper8(reg_src)) {
      R2M_CALL(r2m_binary_opb_u, reg_src);
    } else {
      R2M_CALL(r2m_binary_opb_l, reg_src);
    }
  }
}
