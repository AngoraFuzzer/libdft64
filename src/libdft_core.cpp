#include "libdft_core.h"
#include "ins_helper.h"

#include "ins_binary_op.h"
#include "ins_clear_op.h"
#include "ins_movsx_op.h"
#include "ins_unitary_op.h"
#include "ins_xchg_op.h"
#include "ins_xfer_op.h"

/* threads context */
extern thread_ctx_t *threads_ctx;

static void PIN_FAST_ANALYSIS_CALL _cbw(THREADID tid) {
  tag_t *rtag = RTAG[DFT_REG_RAX];
  rtag[1] = rtag[0];
}

static void PIN_FAST_ANALYSIS_CALL _cwde(THREADID tid) {
  tag_t *rtag = RTAG[DFT_REG_RAX];
  rtag[2] = rtag[0];
  rtag[3] = rtag[1];
}

static void PIN_FAST_ANALYSIS_CALL _cdqe(THREADID tid) {
  tag_t *rtag = RTAG[DFT_REG_RAX];
  for (int i = 0; i < 4; i++)
    rtag[i + 4] = rtag[i];
}

static void PIN_FAST_ANALYSIS_CALL _cwd(THREADID tid) {
  tag_t *dstrtag = RTAG[DFT_REG_RDX];
  tag_t *srcrtag = RTAG[DFT_REG_RAX];
  dstrtag[0] = srcrtag[0];
  dstrtag[1] = srcrtag[1];
}

static void PIN_FAST_ANALYSIS_CALL _cdq(THREADID tid) {
  tag_t *dstrtag = RTAG[DFT_REG_RDX];
  tag_t *srcrtag = RTAG[DFT_REG_RAX];
  for (int i = 0; i < 4; i++)
    dstrtag[i] = srcrtag[i];
}

static void PIN_FAST_ANALYSIS_CALL _cqo(THREADID tid) {
  tag_t *dstrtag = RTAG[DFT_REG_RDX];
  tag_t *srcrtag = RTAG[DFT_REG_RAX];
  for (int i = 0; i < 8; i++)
    dstrtag[i] = srcrtag[i];
}

static void PIN_FAST_ANALYSIS_CALL m2r_restore_opw(THREADID tid, ADDRINT src) {
  for (size_t i = 0; i < 8; i++) {
    if (i == DFT_REG_RSP)
      continue;
    size_t offset = (i < DFT_REG_RSP) ? (i << 1) : ((i - 1) << 1);
    tag_t src_tag[] = M16TAG(src + offset);
    RTAG[DFT_REG_RDI + i][0] = src_tag[0];
    RTAG[DFT_REG_RDI + i][1] = src_tag[1];
  }
}

static void PIN_FAST_ANALYSIS_CALL m2r_restore_opl(THREADID tid, ADDRINT src) {
  for (size_t i = 0; i < 8; i++) {
    if (i == DFT_REG_RSP)
      continue;
    size_t offset = (i < DFT_REG_RSP) ? (i << 2) : ((i - 1) << 2);
    tag_t src_tag[] = M32TAG(src + offset);
    RTAG[DFT_REG_RDI + i][0] = src_tag[0];
    RTAG[DFT_REG_RDI + i][1] = src_tag[1];
    RTAG[DFT_REG_RDI + i][2] = src_tag[2];
    RTAG[DFT_REG_RDI + i][3] = src_tag[3];
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_save_opw(THREADID tid, ADDRINT dst) {
  for (int i = DFT_REG_RDI; i < DFT_REG_XMM0; i++) {
    if (i == DFT_REG_RSP)
      continue;
    size_t offset = (i < DFT_REG_RSP) ? (i << 1) : ((i - 1) << 1);
    tag_t src_tag[] = R16TAG(i);

    tagmap_setb(dst + offset, src_tag[0]);
    tagmap_setb(dst + offset + 1, src_tag[1]);
  }
}

static void PIN_FAST_ANALYSIS_CALL r2m_save_opl(THREADID tid, ADDRINT dst) {
  for (int i = DFT_REG_RDI; i < DFT_REG_XMM0; i++) {
    if (i == DFT_REG_RSP)
      continue;
    size_t offset = (i < DFT_REG_RSP) ? (i << 2) : ((i - 1) << 2);
    tag_t src_tag[] = R32TAG(i);

    for (size_t j = 0; j < 4; j++)
      tagmap_setb(dst + offset + j, src_tag[j]);
  }
}

static bool reg_eq(INS ins) {
  return (!INS_OperandIsImmediate(ins, OP_1) &&
          INS_MemoryOperandCount(ins) == 0 &&
          INS_OperandReg(ins, OP_0) == INS_OperandReg(ins, OP_1));
}

static void PIN_FAST_ANALYSIS_CALL r_cmp(THREADID tid, ADDRINT dst,
                                         uint64_t val) {
  if (!tag_is_empty(RTAG[dst][0])) {
    LOGD("r taint(%ld)!\n", val);
  }
}

static void PIN_FAST_ANALYSIS_CALL m_cmp(THREADID tid, ADDRINT dst) {
  if (!tag_is_empty(MTAG(dst))) {
    LOGD("m taint!\n");
  }
}

void ins_cmp_op(INS ins) {
  if (INS_OperandIsReg(ins, OP_0)) {
    REG reg_dst = INS_OperandReg(ins, OP_0);
    INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(r_cmp), IARG_FAST_ANALYSIS_CALL,
                   IARG_THREAD_ID, IARG_UINT32, REG_INDX(reg_dst),
                   IARG_REG_VALUE, reg_dst, IARG_END);
    // R_CALL(r_cmp, reg_dst);
  }
  if (INS_OperandIsReg(ins, OP_1)) {
    REG reg_src = INS_OperandReg(ins, OP_1);
    R_CALL(r_cmp, reg_src);
  }
  if (INS_MemoryOperandCount(ins) > 0) {
    M_CALL_R(m_cmp);
  }
}

VOID dasm(char *s) { LOGD("[ins] %s\n", s); }

/*
 * instruction inspection (instrumentation function)
 *
 * analyze every instruction and instrument it
 * for propagating the tag bits accordingly
 *
 * @ins:	the instruction to be instrumented
 */
void ins_inspect(INS ins) {

  /* use XED to decode the instruction and extract its opcode */
  xed_iclass_enum_t ins_indx = (xed_iclass_enum_t)INS_Opcode(ins);
  /* sanity check */
  if (unlikely(ins_indx <= XED_ICLASS_INVALID || ins_indx >= XED_ICLASS_LAST)) {
    LOG(std::string(__func__) + ": unknown opcode (opcode=" + decstr(ins_indx) +
        ")\n");
    /* done */
    return;
  }

  // LOGD("[ins] %s \n", INS_Disassemble(ins).c_str());
  /*
  char *cstr;
  cstr = new char[INS_Disassemble(ins).size() + 1];
  strcpy(cstr, INS_Disassemble(ins).c_str());
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dasm, IARG_PTR, cstr, IARG_END);
  */

  switch (ins_indx) {
  // **** bianry ****
  case XED_ICLASS_ADC:
  case XED_ICLASS_ADD:
  case XED_ICLASS_ADD_LOCK:
  case XED_ICLASS_ADDPD:
  case XED_ICLASS_ADDSD:
  case XED_ICLASS_ADDSS:
  case XED_ICLASS_AND:
  case XED_ICLASS_AND_LOCK:
  case XED_ICLASS_OR:
  case XED_ICLASS_OR_LOCK:
  case XED_ICLASS_POR:
    ins_binary_op(ins);
    break;
  case XED_ICLASS_XOR:
  case XED_ICLASS_SBB:
  case XED_ICLASS_SUB:
  case XED_ICLASS_PXOR:
  case XED_ICLASS_SUBSD:
  case XED_ICLASS_PSUBB:
  case XED_ICLASS_PSUBW:
  case XED_ICLASS_PSUBD:
  case XED_ICLASS_XORPS:
  case XED_ICLASS_XORPD:
    if (reg_eq(ins)) {
      ins_clear_op(ins);
    } else {
      ins_binary_op(ins);
    }
    break;
  case XED_ICLASS_DIV:
  case XED_ICLASS_IDIV:
  case XED_ICLASS_MUL:
    ins_unitary_op(ins);
    break;
  case XED_ICLASS_IMUL:
    if (INS_OperandIsImplicit(ins, OP_1)) {
      ins_unitary_op(ins);
    } else {
      ins_binary_op(ins);
      // if ternary // TODO
    }
    break;
  case XED_ICLASS_MULSD:
  case XED_ICLASS_MULPD:
  case XED_ICLASS_DIVSD:
    ins_binary_op(ins);

  // **** xfer ****
  case XED_ICLASS_BSF:
  case XED_ICLASS_BSR:
  case XED_ICLASS_TZCNT:
  case XED_ICLASS_MOV:
    if (INS_OperandIsImmediate(ins, OP_1) ||
        (INS_OperandIsReg(ins, OP_1) &&
         REG_is_seg(INS_OperandReg(ins, OP_1)))) {
      ins_clear_op(ins);
    } else {
      ins_xfer_op(ins);
    }
    break;

  case XED_ICLASS_MOVD:
  case XED_ICLASS_MOVQ:
  case XED_ICLASS_MOVAPS:
  case XED_ICLASS_MOVAPD:
  case XED_ICLASS_MOVDQU:
  case XED_ICLASS_MOVDQA:
  case XED_ICLASS_MOVUPS:
  case XED_ICLASS_MOVUPD:
  case XED_ICLASS_MOVSS:
  // only xmm, ymm
  case XED_ICLASS_VMOVD:
  case XED_ICLASS_VMOVQ:
  case XED_ICLASS_VMOVAPS:
  case XED_ICLASS_VMOVAPD:
  case XED_ICLASS_VMOVDQU:
  case XED_ICLASS_VMOVDQA:
  case XED_ICLASS_VMOVUPS:
  case XED_ICLASS_VMOVUPD:
  case XED_ICLASS_VMOVSS:
  case XED_ICLASS_MOVSD_XMM:
  case XED_ICLASS_CVTSI2SD:
  case XED_ICLASS_CVTSD2SI:
    ins_xfer_op(ins);
    break;
  case XED_ICLASS_MOVLPD:
  case XED_ICLASS_MOVLPS:
    ins_movlp(ins);
    break;
  // case XED_ICLASS_VMOVLPD:
  // case XED_ICLASS_VMOVLPS:
  case XED_ICLASS_MOVHPD:
  case XED_ICLASS_MOVHPS:
    ins_movhp(ins);
    break;
  // case XED_ICLASS_VMOVHPD:
  // case XED_ICLASS_VMOVHPS:
  // case XED_ICLASS_MOVHLPS:
  // case XED_ICLASS_VMOVHLPS:
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
    ins_xfer_op_predicated(ins);
    break;
  case XED_ICLASS_MOVBE:
    ins_movbe_op(ins);
    break;
  case XED_ICLASS_MOVSX:
  case XED_ICLASS_MOVZX:
    ins_movsx_op(ins);
    break;
  case XED_ICLASS_MOVSXD:
    ins_movsxd_op(ins);
    break;
  case XED_ICLASS_CBW:
    CALL(_cbw);
    break;
  case XED_ICLASS_CWD:
    CALL(_cwd);
    break;
  case XED_ICLASS_CWDE:
    CALL(_cwde);
    break;
  case XED_ICLASS_CDQ:
    CALL(_cdq);
    break;
  case XED_ICLASS_CDQE:
    CALL(_cdqe);
    break;
  case XED_ICLASS_CQO:
    CALL(_cqo);
    break;

  // ****** clear op ******
  // TODO: add rules with CMP
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
    ins_clear_op_predicated(ins);
    break;
  case XED_ICLASS_STMXCSR:
    ins_clear_op(ins);
    break;
  case XED_ICLASS_SMSW:
  case XED_ICLASS_STR:
  case XED_ICLASS_LAR:
    ins_clear_op(ins);
    break;
  case XED_ICLASS_RDPID:
  case XED_ICLASS_RDRAND:
    ins_clear_op(ins);
    break;
  case XED_ICLASS_RDPMC:
  case XED_ICLASS_RDTSC:
    ins_clear_op_l2(ins);
    break;
  case XED_ICLASS_CPUID:
    ins_clear_op_l4(ins);
    break;
  case XED_ICLASS_LAHF:
    ins_clear_op(ins);
    break;
  case XED_ICLASS_CMPXCHG:
  case XED_ICLASS_CMPXCHG_LOCK:
    ins_cmpxchg_op(ins);
    break;
  case XED_ICLASS_XCHG:
    ins_xchg_op(ins);
    break;
  case XED_ICLASS_XADD:
  case XED_ICLASS_XADD_LOCK:
    ins_xadd_op(ins);
    break;
  case XED_ICLASS_XLAT:
    M2R_CALL(m2r_xfer_opb_l, REG_AL);
    break;
  case XED_ICLASS_LODSB:
    M2R_CALL_P(m2r_xfer_opb_l, REG_AL);
    break;
  case XED_ICLASS_LODSW:
    M2R_CALL_P(m2r_xfer_opw, REG_AX);
    break;
  case XED_ICLASS_LODSD:
    M2R_CALL_P(m2r_xfer_opl, REG_EAX);
    break;
  case XED_ICLASS_LODSQ:
    M2R_CALL_P(m2r_xfer_opq, REG_RAX);
    break;
  case XED_ICLASS_STOSB:
    ins_stosb(ins);
    break;
  case XED_ICLASS_STOSW:
    ins_stosw(ins);
    break;
  case XED_ICLASS_STOSD:
    ins_stosd(ins);
    break;
  case XED_ICLASS_STOSQ:
    ins_stosq(ins);
    break;
  case XED_ICLASS_MOVSQ:
    M2M_CALL(m2m_xfer_opq);
    break;
  case XED_ICLASS_MOVSD:
    M2M_CALL(m2m_xfer_opl);
    break;
  case XED_ICLASS_MOVSW:
    M2M_CALL(m2m_xfer_opw);
    break;
  case XED_ICLASS_MOVSB:
    M2M_CALL(m2m_xfer_opb);
    break;
  case XED_ICLASS_SALC:
    ins_clear_op(ins);
    break;
  case XED_ICLASS_POP:
    ins_pop_op(ins);
    break;
  case XED_ICLASS_PUSH:
    ins_push_op(ins);
    break;
  case XED_ICLASS_POPA:
    M_CALL_R(m2r_restore_opw);
    break;
  case XED_ICLASS_POPAD:
    M_CALL_R(m2r_restore_opl);
    break;
  case XED_ICLASS_PUSHA:
    M_CALL_W(r2m_save_opw);
    break;
  case XED_ICLASS_PUSHAD:
    M_CALL_W(r2m_save_opl);
    break;
  case XED_ICLASS_PUSHF:
    M_CLEAR_N(2);
    break;
  case XED_ICLASS_PUSHFD:
    M_CLEAR_N(4);
    break;
  case XED_ICLASS_PUSHFQ:
    M_CLEAR_N(8);
    break;
  case XED_ICLASS_LEA:
    ins_lea(ins);
    break;
  case XED_ICLASS_PCMPEQB:
    ins_binary_op(ins);
    break;
  case XED_ICLASS_FNSTCW:
    M_CLEAR_N(2);
    break;
    // TODO
  case XED_ICLASS_XGETBV:
  case XED_ICLASS_PMOVMSKB:
  case XED_ICLASS_VPMOVMSKB:
  case XED_ICLASS_PUNPCKLBW:
  case XED_ICLASS_PUNPCKLWD:
  case XED_ICLASS_PSHUFD:
  case XED_ICLASS_PMINUB:
  case XED_ICLASS_PSLLDQ:
  case XED_ICLASS_PSRLDQ:
  case XED_ICLASS_VPCMPEQB:
  case XED_ICLASS_VPBROADCASTB:
  case XED_ICLASS_VZEROUPPER:
  case XED_ICLASS_BSWAP:
  case XED_ICLASS_UNPCKLPD:
  case XED_ICLASS_PSHUFB:
  case XED_ICLASS_VPTEST:
    // TODO: ternary
  case XED_ICLASS_VMULSD:
  case XED_ICLASS_VDIVSD:
  case XED_ICLASS_VPOR:
  case XED_ICLASS_VPXOR:
  case XED_ICLASS_VPSUBB:
  case XED_ICLASS_VPSUBW:
  case XED_ICLASS_VPSUBD:
  case XED_ICLASS_VPXORD:
  case XED_ICLASS_VPXORQ:
  case XED_ICLASS_VPAND:
  case XED_ICLASS_VPANDN:
  case XED_ICLASS_VPSLLDQ:
  case XED_ICLASS_VPCMPGTB:
  case XED_ICLASS_VPALIGNR:
  case XED_ICLASS_VPCMPISTRI:

    break;
  case XED_ICLASS_CMP:
    // ins_cmp_op(ins);
    break;
  case XED_ICLASS_CMPSB:
  case XED_ICLASS_CMPSW:
  case XED_ICLASS_CMPSD:
  case XED_ICLASS_CMPSQ:
  case XED_ICLASS_CMPSS: // FIXME, 3arg
  case XED_ICLASS_UCOMISS:
  case XED_ICLASS_UCOMISD:
  case XED_ICLASS_VPMINUB:
  case XED_ICLASS_PCMPISTRI:
    break;

  // Ignore
  case XED_ICLASS_JMP:
  case XED_ICLASS_JZ:
  case XED_ICLASS_JNZ:
  case XED_ICLASS_JB:
  case XED_ICLASS_JNB:
  case XED_ICLASS_JBE:
  case XED_ICLASS_JNBE:
  case XED_ICLASS_JL:
  case XED_ICLASS_JNL:
  case XED_ICLASS_JLE:
  case XED_ICLASS_JNLE:
  case XED_ICLASS_JS:
  case XED_ICLASS_JNS:
  case XED_ICLASS_JP:
  case XED_ICLASS_JNP:
  case XED_ICLASS_JO:
  case XED_ICLASS_JNO:
  case XED_ICLASS_RET_FAR:
  case XED_ICLASS_RET_NEAR:
  case XED_ICLASS_CALL_FAR:
  case XED_ICLASS_CALL_NEAR:
  case XED_ICLASS_LEAVE:
  case XED_ICLASS_SYSCALL:
  case XED_ICLASS_TEST:
  case XED_ICLASS_RCL:
  case XED_ICLASS_RCR:
  case XED_ICLASS_ROL:
  case XED_ICLASS_ROR:
  case XED_ICLASS_SHL:
  case XED_ICLASS_SAR:
  case XED_ICLASS_SHR:
  case XED_ICLASS_SHLD:
  case XED_ICLASS_SHRD:
  case XED_ICLASS_NEG:
  case XED_ICLASS_NOT:
  case XED_ICLASS_NOP:
  case XED_ICLASS_BT:
  case XED_ICLASS_BTS:
  case XED_ICLASS_BTS_LOCK:
  case XED_ICLASS_BTR:
  case XED_ICLASS_BTR_LOCK:
  case XED_ICLASS_BTC:
  case XED_ICLASS_DEC:
  case XED_ICLASS_DEC_LOCK:
  case XED_ICLASS_INC:
  case XED_ICLASS_INC_LOCK:
  case XED_ICLASS_XSAVEC:
  case XED_ICLASS_XRSTOR:
  case XED_ICLASS_PAUSE:
  case XED_ICLASS_LFENCE:
  case XED_ICLASS_PREFETCHW:
    break;

  default:
    // https://intelxed.github.io/ref-manual/xed-extension-enum_8h.html#ae7b9f64cdf123c5fda22bd10d5db9916
    // INT32 num_op = INS_OperandCount(ins);
    // INT32 ins_ext = INS_Extension(ins);
    // if (ins_ext != 0 && ins_ext != 10)
    LOGD("[uninstrumented] opcode=%d, %s\n", ins_indx,
         INS_Disassemble(ins).c_str());
    break;
  }
}
