#include "ins_xchg_op.h"
#include "ins_helper.h"
#include "ins_xfer_op.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

static ADDRINT PIN_FAST_ANALYSIS_CALL _cmpxchg_r2r_opq_fast(THREADID tid,
                                                            uint32_t dst_val,
                                                            uint32_t src,
                                                            uint32_t src_val) {
  /* save the tag value of dst in the scratch register */
  tag_t save_tags[] = R64TAG(DFT_REG_RAX);
  for (size_t i = 0; i < 8; i++)
    RTAG[DFT_REG_HELPER1][i] = save_tags[i];

  /* update */
  tag_t src_tags[] = R64TAG(src);

  for (size_t i = 0; i < 8; i++) {
    RTAG[DFT_REG_RAX][i] = src_tags[i];
  }
  /* compare the dst and src values */
  return (dst_val == src_val);
}

static ADDRINT PIN_FAST_ANALYSIS_CALL _cmpxchg_r2r_opl_fast(THREADID tid,
                                                            uint32_t dst_val,
                                                            uint32_t src,
                                                            uint32_t src_val) {
  /* save the tag value of dst in the scratch register */
  tag_t save_tags[] = R32TAG(DFT_REG_RAX);
  for (size_t i = 0; i < 4; i++)
    RTAG[DFT_REG_HELPER1][i] = save_tags[i];

  /* update */
  tag_t src_tags[] = R32TAG(src);

  for (size_t i = 0; i < 4; i++) {
    RTAG[DFT_REG_RAX][i] = src_tags[i];
  }
  /* compare the dst and src values */
  return (dst_val == src_val);
}

static void PIN_FAST_ANALYSIS_CALL _cmpxchg_r2r_opq_slow(THREADID tid,
                                                         uint32_t dst,
                                                         uint32_t src) {
  /* restore the tag value from the scratch register */
  tag_t saved_tags[] = {RTAG[DFT_REG_HELPER1][0], RTAG[DFT_REG_HELPER1][1],
                        RTAG[DFT_REG_HELPER1][2], RTAG[DFT_REG_HELPER1][3],
                        RTAG[DFT_REG_HELPER1][4], RTAG[DFT_REG_HELPER1][5],
                        RTAG[DFT_REG_HELPER1][6], RTAG[DFT_REG_HELPER1][7]};
  for (size_t i = 0; i < 8; i++)
    RTAG[DFT_REG_RAX][i] = saved_tags[i];

  /* update */
  tag_t src_tags[] = {RTAG[src][0], RTAG[src][1], RTAG[src][2], RTAG[src][3],
                      RTAG[src][4], RTAG[src][5], RTAG[src][6], RTAG[src][7]};
  for (size_t i = 0; i < 8; i++) {
    RTAG[dst][i] = src_tags[i];
  }
}

static void PIN_FAST_ANALYSIS_CALL _cmpxchg_r2r_opl_slow(THREADID tid,
                                                         uint32_t dst,
                                                         uint32_t src) {
  /* restore the tag value from the scratch register */
  tag_t saved_tags[] = {RTAG[DFT_REG_HELPER1][0], RTAG[DFT_REG_HELPER1][1],
                        RTAG[DFT_REG_HELPER1][2], RTAG[DFT_REG_HELPER1][3]};
  for (size_t i = 0; i < 4; i++)
    RTAG[DFT_REG_RAX][i] = saved_tags[i];

  /* update */
  tag_t src_tags[] = {RTAG[src][0], RTAG[src][1], RTAG[src][2], RTAG[src][3]};
  for (size_t i = 0; i < 4; i++) {
    RTAG[dst][i] = src_tags[i];
  }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL _cmpxchg_r2r_opw_fast(THREADID tid,
                                                            uint16_t dst_val,
                                                            uint32_t src,
                                                            uint16_t src_val) {
  /* save the tag value of dst in the scratch register */
  tag_t save_tags[] = R32TAG(DFT_REG_RAX);
  for (size_t i = 0; i < 4; i++)
    RTAG[DFT_REG_HELPER1][i] = save_tags[i];

  tag_t src_tags[] = R16TAG(src);
  RTAG[DFT_REG_RAX][0] = src_tags[0];
  RTAG[DFT_REG_RAX][1] = src_tags[1];

  /* compare the dst and src values */
  return (dst_val == src_val);
}

static void PIN_FAST_ANALYSIS_CALL _cmpxchg_r2r_opw_slow(THREADID tid,
                                                         uint32_t dst,
                                                         uint32_t src) {
  /* restore the tag value from the scratch register */

  tag_t saved_tags[] = {RTAG[DFT_REG_HELPER1][0], RTAG[DFT_REG_HELPER1][1],
                        RTAG[DFT_REG_HELPER1][2], RTAG[DFT_REG_HELPER1][3]};
  for (size_t i = 0; i < 4; i++)
    RTAG[DFT_REG_RAX][i] = saved_tags[i];

  /* update */
  tag_t src_tags[] = {RTAG[src][0], RTAG[src][1]};
  RTAG[dst][0] = src_tags[0];
  RTAG[dst][1] = src_tags[1];
}

static ADDRINT PIN_FAST_ANALYSIS_CALL _cmpxchg_m2r_opq_fast(THREADID tid,
                                                            uint32_t dst_val,
                                                            ADDRINT src) {
  /* save the tag value of dst in the scratch register */

  tag_t save_tags[] = {RTAG[DFT_REG_RAX][0], RTAG[DFT_REG_RAX][1],
                       RTAG[DFT_REG_RAX][2], RTAG[DFT_REG_RAX][3],
                       RTAG[DFT_REG_RAX][4], RTAG[DFT_REG_RAX][5],
                       RTAG[DFT_REG_RAX][6], RTAG[DFT_REG_RAX][7]};
  for (size_t i = 0; i < 8; i++)
    RTAG[DFT_REG_HELPER1][i] = save_tags[i];

  tag_t src_tags[] = {tagmap_getb(src),     tagmap_getb(src + 1),
                      tagmap_getb(src + 2), tagmap_getb(src + 3),
                      tagmap_getb(src + 4), tagmap_getb(src + 5),
                      tagmap_getb(src + 6), tagmap_getb(src + 7)};
  for (size_t i = 0; i < 8; i++) {
    RTAG[DFT_REG_RAX][i] = src_tags[i];
  }

  return (dst_val == *(uint32_t *)src);
}

static ADDRINT PIN_FAST_ANALYSIS_CALL _cmpxchg_m2r_opl_fast(THREADID tid,
                                                            uint32_t dst_val,
                                                            ADDRINT src) {
  /* save the tag value of dst in the scratch register */

  tag_t save_tags[] = {RTAG[DFT_REG_RAX][0], RTAG[DFT_REG_RAX][1],
                       RTAG[DFT_REG_RAX][2], RTAG[DFT_REG_RAX][3]};
  for (size_t i = 0; i < 4; i++)
    RTAG[DFT_REG_HELPER1][i] = save_tags[i];

  tag_t src_tags[] = {tagmap_getb(src), tagmap_getb(src + 1),
                      tagmap_getb(src + 2), tagmap_getb(src + 3)};
  for (size_t i = 0; i < 4; i++) {
    RTAG[DFT_REG_RAX][i] = src_tags[i];
  }

  return (dst_val == *(uint32_t *)src);
}

static void PIN_FAST_ANALYSIS_CALL _cmpxchg_r2m_opq_slow(THREADID tid,
                                                         ADDRINT dst,
                                                         uint32_t src) {
  tag_t saved_tags[] = R64TAG(DFT_REG_HELPER1);
  for (size_t i = 0; i < 8; i++)
    RTAG[DFT_REG_RAX][i] = saved_tags[i];

  /* update */
  tag_t src_tags[] = R64TAG(src);
  for (size_t i = 0; i < 8; i++) {
    tagmap_setb(dst + i, src_tags[i]);
  }
}

static void PIN_FAST_ANALYSIS_CALL _cmpxchg_r2m_opl_slow(THREADID tid,
                                                         ADDRINT dst,
                                                         uint32_t src) {
  tag_t saved_tags[] = R32TAG(DFT_REG_HELPER1);
  for (size_t i = 0; i < 4; i++)
    RTAG[DFT_REG_RAX][i] = saved_tags[i];

  /* update */
  tag_t src_tags[] = R32TAG(src);
  for (size_t i = 0; i < 4; i++) {
    tagmap_setb(dst + i, src_tags[i]);
  }
}

static ADDRINT PIN_FAST_ANALYSIS_CALL _cmpxchg_m2r_opw_fast(THREADID tid,
                                                            uint16_t dst_val,
                                                            ADDRINT src) {
  /* save the tag value of dst in the scratch register */

  tag_t save_tags[] = {RTAG[DFT_REG_RAX][0], RTAG[DFT_REG_RAX][1],
                       RTAG[DFT_REG_RAX][2], RTAG[DFT_REG_RAX][3]};

  for (size_t i = 0; i < 4; i++)
    RTAG[DFT_REG_HELPER1][i] = save_tags[i];

  tag_t src_tags[] = {tagmap_getb(src), tagmap_getb(src + 1)};
  for (size_t i = 0; i < 2; i++) {
    RTAG[DFT_REG_RAX][i] = src_tags[i];
  }

  /* compare the dst and src values; the original values the tag bits */
  return (dst_val == *(uint16_t *)src);
}

static void PIN_FAST_ANALYSIS_CALL _cmpxchg_r2m_opw_slow(THREADID tid,
                                                         ADDRINT dst,
                                                         uint32_t src) {
  /* restore the tag value from the scratch register */
  tag_t saved_tags[] = {RTAG[DFT_REG_HELPER1][0], RTAG[DFT_REG_HELPER1][1],
                        RTAG[DFT_REG_HELPER1][2], RTAG[DFT_REG_HELPER1][3]};

  for (size_t i = 0; i < 4; i++)
    RTAG[DFT_REG_RAX][i] = saved_tags[i];

  /* update */
  tag_t src_tags[] = {RTAG[src][0], RTAG[src][1]};
  for (size_t i = 0; i < 2; i++) {
    tagmap_setb(dst + i, src_tags[i]);
  }
}

static void PIN_FAST_ANALYSIS_CALL _xchg_r2r_opb_ul(THREADID tid, uint32_t dst,
                                                    uint32_t src) {
  /* temporary tag value */
  tag_t tmp_tag = RTAG[dst][1];

  tag_t src_tag = RTAG[src][0];

  /* swap */
  RTAG[dst][1] = src_tag;
  RTAG[src][0] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL _xchg_r2r_opb_lu(THREADID tid, uint32_t dst,
                                                    uint32_t src) {
  /* temporary tag value */
  tag_t tmp_tag = RTAG[dst][0];

  tag_t src_tag = RTAG[src][1];

  /* swap */
  RTAG[dst][0] = src_tag;
  RTAG[src][1] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL _xchg_r2r_opb_u(THREADID tid, uint32_t dst,
                                                   uint32_t src) {
  /* temporary tag value */
  tag_t tmp_tag = RTAG[dst][1];

  tag_t src_tag = RTAG[src][1];

  /* swap */
  RTAG[dst][1] = src_tag;
  RTAG[src][1] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL _xchg_r2r_opb_l(THREADID tid, uint32_t dst,
                                                   uint32_t src) {
  tag_t tmp_tag = RTAG[dst][0];

  tag_t src_tag = RTAG[src][0];

  /* swap */
  RTAG[dst][0] = src_tag;
  RTAG[src][0] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL _xchg_r2r_opw(THREADID tid, uint32_t dst,
                                                 uint32_t src) {
  tag_t dst_tag[] = R16TAG(dst);

  tag_t src_tag[] = R16TAG(src);

  /* swap */
  RTAG[dst][0] = src_tag[0];
  RTAG[dst][1] = src_tag[1];
  RTAG[src][0] = dst_tag[0];
  RTAG[src][1] = dst_tag[1];
}

static void PIN_FAST_ANALYSIS_CALL _xchg_m2r_opb_u(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  /* temporary tag value */
  tag_t tmp_tag = RTAG[dst][1];

  tag_t src_tag = M8TAG(src);

  /* swap */
  RTAG[dst][1] = src_tag;
  tagmap_setb(src, tmp_tag);
}
static void PIN_FAST_ANALYSIS_CALL _xchg_m2r_opb_l(THREADID tid, uint32_t dst,
                                                   ADDRINT src) {
  /* temporary tag value */
  tag_t tmp_tag = RTAG[dst][0];

  tag_t src_tag = M8TAG(src);

  /* swap */
  RTAG[dst][0] = src_tag;
  tagmap_setb(src, tmp_tag);
}

static void PIN_FAST_ANALYSIS_CALL _xchg_m2r_opw(THREADID tid, uint32_t dst,
                                                 ADDRINT src) {
  /* temporary tag value */
  tag_t tmp_tag[] = R16TAG(dst);

  tag_t src_tag[] = M16TAG(src);

  /* swap */
  RTAG[dst][0] = src_tag[0];
  RTAG[dst][1] = src_tag[1];
  tagmap_setb(src, tmp_tag[0]);
  tagmap_setb(src + 1, tmp_tag[1]);
}

static void PIN_FAST_ANALYSIS_CALL _xchg_m2r_opq(THREADID tid, uint32_t dst,
                                                 ADDRINT src) {
  /* temporary tag value */
  tag_t tmp_tag[] = R64TAG(dst);
  tag_t src_tag[] = M64TAG(src);

  /* swap */
  RTAG[dst][0] = src_tag[0];
  RTAG[dst][1] = src_tag[1];
  RTAG[dst][2] = src_tag[2];
  RTAG[dst][3] = src_tag[3];
  RTAG[dst][4] = src_tag[4];
  RTAG[dst][5] = src_tag[5];
  RTAG[dst][6] = src_tag[6];
  RTAG[dst][7] = src_tag[7];

  tagmap_setb(src, tmp_tag[0]);
  tagmap_setb(src + 1, tmp_tag[1]);
  tagmap_setb(src + 2, tmp_tag[2]);
  tagmap_setb(src + 3, tmp_tag[3]);
  tagmap_setb(src + 4, tmp_tag[4]);
  tagmap_setb(src + 5, tmp_tag[5]);
  tagmap_setb(src + 6, tmp_tag[6]);
  tagmap_setb(src + 7, tmp_tag[7]);
}

static void PIN_FAST_ANALYSIS_CALL _xchg_m2r_opl(THREADID tid, uint32_t dst,
                                                 ADDRINT src) {
  /* temporary tag value */
  tag_t tmp_tag[] = R32TAG(dst);
  tag_t src_tag[] = M32TAG(src);

  /* swap */
  RTAG[dst][0] = src_tag[0];
  RTAG[dst][1] = src_tag[1];
  RTAG[dst][2] = src_tag[2];
  RTAG[dst][3] = src_tag[3];

  tagmap_setb(src, tmp_tag[0]);
  tagmap_setb(src + 1, tmp_tag[1]);
  tagmap_setb(src + 2, tmp_tag[2]);
  tagmap_setb(src + 3, tmp_tag[3]);
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opb_ul(THREADID tid, uint32_t dst,
                                                    uint32_t src) {
  tag_t tmp_tag = RTAG[dst][1];

  RTAG[dst][1] = tag_combine(RTAG[dst][1], RTAG[src][0]);
  RTAG[src][0] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opb_lu(THREADID tid, uint32_t dst,
                                                    uint32_t src) {
  tag_t tmp_tag = RTAG[dst][0];

  RTAG[dst][0] = tag_combine(RTAG[dst][0], RTAG[src][1]);
  RTAG[src][1] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opb_u(THREADID tid, uint32_t dst,
                                                   uint32_t src) {
  tag_t tmp_tag = RTAG[dst][1];

  RTAG[dst][1] = tag_combine(RTAG[dst][1], RTAG[src][1]);
  RTAG[src][1] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opb_l(THREADID tid, uint32_t dst,
                                                   uint32_t src) {
  tag_t tmp_tag = RTAG[dst][0];

  RTAG[dst][0] = tag_combine(RTAG[dst][0], RTAG[src][0]);
  RTAG[src][0] = tmp_tag;
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opw(THREADID tid, uint32_t dst,
                                                 uint32_t src) {

  tag_t dst_tag[] = {RTAG[dst][0], RTAG[dst][1]};
  tag_t src_tag[] = {RTAG[src][0], RTAG[src][1]};

  RTAG[dst][0] = tag_combine(dst_tag[0], src_tag[0]);
  RTAG[dst][1] = tag_combine(dst_tag[1], src_tag[1]);
  RTAG[src][0] = dst_tag[0];
  RTAG[src][1] = dst_tag[1];
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opl(THREADID tid, uint32_t dst,
                                                 uint32_t src) {
  tag_t dst_tag[] = R32TAG(dst);
  tag_t src_tag[] = R32TAG(src);
  for (size_t i = 0; i < 4; i++) {
    RTAG[dst][i] = tag_combine(dst_tag[i], src_tag[i]);
    RTAG[src][i] = dst_tag[i];
  }
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2r_opq(THREADID tid, uint32_t dst,
                                                 uint32_t src) {
  tag_t dst_tag[] = R64TAG(dst);
  tag_t src_tag[] = R64TAG(src);
  for (size_t i = 0; i < 8; i++) {
    RTAG[dst][i] = tag_combine(dst_tag[i], src_tag[i]);
    RTAG[src][i] = dst_tag[i];
  }
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2m_opb_u(THREADID tid, ADDRINT dst,
                                                   uint32_t src) {
  tag_t src_tag = RTAG[src][1];
  tag_t dst_tag = tagmap_getb(dst);

  RTAG[src][1] = dst_tag;
  tagmap_setb(dst, tag_combine(dst_tag, src_tag));
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2m_opb_l(THREADID tid, ADDRINT dst,
                                                   uint32_t src) {
  tag_t src_tag = RTAG[src][0];
  tag_t dst_tag = tagmap_getb(dst);

  RTAG[src][0] = dst_tag;
  tagmap_setb(dst, tag_combine(dst_tag, src_tag));
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2m_opw(THREADID tid, ADDRINT dst,
                                                 uint32_t src) {
  tag_t src_tag[] = R16TAG(src);
  tag_t dst_tag[] = M16TAG(dst);

  RTAG[src][0] = dst_tag[0];
  RTAG[src][1] = dst_tag[1];

  tagmap_setb(dst, tag_combine(dst_tag[0], src_tag[0]));
  tagmap_setb(dst + 1, tag_combine(dst_tag[1], src_tag[1]));
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2m_opl(THREADID tid, ADDRINT dst,
                                                 uint32_t src) {
  tag_t src_tag[] = R32TAG(src);
  tag_t dst_tag[] = M32TAG(dst);

  for (size_t i = 0; i < 4; i++) {
    tagmap_setb(dst + i, tag_combine(dst_tag[i], src_tag[i]));
    RTAG[src][i] = dst_tag[i];
  }
}

static void PIN_FAST_ANALYSIS_CALL _xadd_r2m_opq(THREADID tid, ADDRINT dst,
                                                 uint32_t src) {
  tag_t src_tag[] = R64TAG(src);
  tag_t dst_tag[] = M64TAG(dst);

  for (size_t i = 0; i < 8; i++) {
    tagmap_setb(dst + i, tag_combine(dst_tag[i], src_tag[i]));
    RTAG[src][i] = dst_tag[i];
  }
}

void ins_cmpxchg_op(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opq_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_EAX, IARG_UINT32, REG_INDX(reg_dst), IARG_REG_VALUE,
                       reg_dst, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opq_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                         REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                         IARG_END);
    } else if (REG_is_gr32(reg_dst)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opl_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_EAX, IARG_UINT32, REG_INDX(reg_dst), IARG_REG_VALUE,
                       reg_dst, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opl_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                         REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                         IARG_END);
    } else if (REG_is_gr16(reg_dst)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opw_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_AX, IARG_UINT32, REG_INDX(reg_dst), IARG_REG_VALUE,
                       reg_dst, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2r_opw_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                         REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                         IARG_END);
    } else {
      xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
      LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) +
          ")\n");
    }
  } else {
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_m2r_opq_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_EAX, IARG_MEMORYREAD_EA, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2m_opq_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                         IARG_MEMORYWRITE_EA, IARG_UINT32, REG_INDX(reg_src),
                         IARG_END);
    } else if (REG_is_gr32(reg_src)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_m2r_opl_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_EAX, IARG_MEMORYREAD_EA, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2m_opl_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                         IARG_MEMORYWRITE_EA, IARG_UINT32, REG_INDX(reg_src),
                         IARG_END);
    } else if (REG_is_gr16(reg_src)) {
      INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_m2r_opw_fast,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_REG_VALUE,
                       REG_AX, IARG_MEMORYREAD_EA, IARG_END);
      INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)_cmpxchg_r2m_opw_slow,
                         IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID,
                         IARG_MEMORYWRITE_EA, IARG_UINT32, REG_INDX(reg_src),
                         IARG_END);
    } else {
      xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
      LOG(std::string(__func__) + ": unhandled opcode (opcode=" + decstr(ins_indx) +
          ")\n");
    }
  }
}

void ins_xchg_op(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_xfer_opq,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32, 0,
                     IARG_UINT32, REG_INDX(reg_dst), IARG_END);
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_xfer_opq,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                     IARG_END);
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_xfer_opq,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_src), IARG_UINT32, 0, IARG_END);
    } else if (REG_is_gr32(reg_dst)) {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_xfer_opl,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32, 0,
                     IARG_UINT32, REG_INDX(reg_dst), IARG_END);
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_xfer_opl,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                     IARG_END);
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)r2r_xfer_opl,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_src), IARG_UINT32, 0, IARG_END);
    } else if (REG_is_gr16(reg_dst))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_r2r_opw,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                     IARG_END);
    else if (REG_is_gr8(reg_dst)) {
      if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src))
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_r2r_opb_l,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                       REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                       IARG_END);
      else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src))
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_r2r_opb_u,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                       REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                       IARG_END);
      else if (REG_is_Lower8(reg_dst))
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_r2r_opb_lu,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                       REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                       IARG_END);
      else
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_r2r_opb_ul,
                       IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                       REG_INDX(reg_dst), IARG_UINT32, REG_INDX(reg_src),
                       IARG_END);
    }
  } else if (INS_OperandIsMemory(ins, OP_1)) {
    reg_dst = INS_OperandReg(ins, OP_0);
    if (REG_is_gr64(reg_dst))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opq,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_dst), IARG_MEMORYREAD_EA, IARG_END);
    else if (REG_is_gr32(reg_dst))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opl,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_dst), IARG_MEMORYREAD_EA, IARG_END);
    else if (REG_is_gr16(reg_dst))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opw,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_dst), IARG_MEMORYREAD_EA, IARG_END);
    else if (REG_is_Upper8(reg_dst))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opb_u,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_dst), IARG_MEMORYREAD_EA, IARG_END);
    else
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opb_l,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_dst), IARG_MEMORYREAD_EA, IARG_END);
  } else {
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opq,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_src), IARG_MEMORYWRITE_EA, IARG_END);
    else if (REG_is_gr32(reg_src))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opl,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_src), IARG_MEMORYWRITE_EA, IARG_END);
    else if (REG_is_gr16(reg_src))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opw,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_src), IARG_MEMORYWRITE_EA, IARG_END);
    else if (REG_is_Upper8(reg_src))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opb_u,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_src), IARG_MEMORYWRITE_EA, IARG_END);
    else
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)_xchg_m2r_opb_l,
                     IARG_FAST_ANALYSIS_CALL, IARG_THREAD_ID, IARG_UINT32,
                     REG_INDX(reg_src), IARG_MEMORYWRITE_EA, IARG_END);
  }
}

void ins_xadd_op(INS ins) {
  REG reg_dst, reg_src;
  if (INS_MemoryOperandCount(ins) == 0) {
    reg_dst = INS_OperandReg(ins, OP_0);
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_dst)) {
      R2R_CALL(_xadd_r2r_opq, reg_dst, reg_src);
    } else if (REG_is_gr32(reg_dst)) {
      R2R_CALL(_xadd_r2r_opl, reg_dst, reg_src);
    } else if (REG_is_gr16(reg_dst)) {
      R2R_CALL(_xadd_r2r_opw, reg_dst, reg_src);
    } else if (REG_is_gr8(reg_dst)) {
      if (REG_is_Lower8(reg_dst) && REG_is_Lower8(reg_src))
        R2R_CALL(_xadd_r2r_opb_l, reg_dst, reg_src);
      else if (REG_is_Upper8(reg_dst) && REG_is_Upper8(reg_src))
        R2R_CALL(_xadd_r2r_opb_u, reg_dst, reg_src);
      else if (REG_is_Lower8(reg_dst))
        R2R_CALL(_xadd_r2r_opb_lu, reg_dst, reg_src);
      else
        R2R_CALL(_xadd_r2r_opb_ul, reg_dst, reg_src);
    }
  } else {
    reg_src = INS_OperandReg(ins, OP_1);
    if (REG_is_gr64(reg_src)) {
      R2M_CALL(_xadd_r2m_opq, reg_src);
    } else if (REG_is_gr32(reg_src)) {
      R2M_CALL(_xadd_r2m_opl, reg_src);
    } else if (REG_is_gr16(reg_src)) {
      R2M_CALL(_xadd_r2m_opw, reg_src);
    } else if (REG_is_Upper8(reg_src)) {
      R2M_CALL(_xadd_r2m_opb_u, reg_src);
    } else {
      R2M_CALL(_xadd_r2m_opb_l, reg_src);
    }
  }
}