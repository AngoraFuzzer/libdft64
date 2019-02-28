#include "hook.h"
#include <iostream>
#include <map>
#include <set>
#include <vector>

extern REG thread_ctx_ptr;

TagSet tag_set;

struct ArgList {
  u64 op1;
  u64 op2;
  const tag_t *lb1;
  const tag_t *lb2;
};

std::map<u32, std::vector<ArgList>> __angora_unique_map;
std::set<const tag_t *> __angora_unique_so;
std::map<u64, u32> __angora_cond_ctr_map;

bool is_dup_cond(u32 cmpid, ADDRINT op1_addr, ADDRINT op2_addr) {
  u64 op1 = *((u64 *)op1_addr);
  u64 op2 = *((u64 *)op2_addr);
  const tag_t *lb1 = tagmap_getb_as_ptr(op1_addr);
  const tag_t *lb2 = tagmap_getb_as_ptr(op2_addr);

  u32 id = cmpid;
  std::map<u32, std::vector<ArgList>>::iterator it =
      __angora_unique_map.find(id);
  if (it == __angora_unique_map.end()) {
    std::vector<ArgList> v;
    ArgList al = {op1, op2, lb1, lb2};
    v.push_back(al);
    __angora_unique_map.insert(std::pair<u32, std::vector<ArgList>>(id, v));
  } else {
    std::vector<ArgList>::iterator it2;
    for (it2 = it->second.begin(); it2 != it->second.end(); it2++) {
      if (it2->lb1 == lb1 && it2->lb2 == lb2 && it2->op1 == op1 &&
          it2->op2 == op2) {
        return true;
      }
    }
    ArgList al = {op1, op2, lb1, lb2};
    it->second.push_back(al);
  }
  return false;
}

static bool is_dup_so(const tag_t *t) {
  if (__angora_unique_so.count(t) > 0) {
    return true;
  } else {
    __angora_unique_so.insert(t);
    return false;
  }
}

static u32 get_cond_ctr(u32 cid, u32 context) {
  u64 key = cid;
  key = (key << 32) | context;
  u32 ctr = 1;
  if (__angora_cond_ctr_map.count(key) > 0) {
    ctr = __angora_cond_ctr_map[key] + 1;
    __angora_cond_ctr_map[key] = ctr;
  } else {
    __angora_cond_ctr_map.insert(std::pair<u64, u32>(key, 1));
  }
  return ctr;
}

void combineTag(std::vector<tag_seg> &tag_all, ADDRINT addr, u32 size) {
  for (size_t i = 0; i < size; i++) {
    const tag_t tag = tagmap_getb(addr + i);
    if (tag == tag_traits<tag_t>::cleared_val)
      continue;
    // FIXME:
    const std::vector<tag_seg> tag_i = TagSet::find(tag);
    tag_combine_inplace(tag_all, tag_i);
    // tag_set.frac_tagvec(tag_all);
  }
}

VOID CmpHandler(u16 Cond, u32 Cid, u32 Size, u16 Type, u32 Context,
                ADDRINT pArg1, ADDRINT pArg2) {

  u64 Arg1 = *((u64 *)pArg1);
  u64 Arg2 = *((u64 *)pArg2);

  u32 ctr = get_cond_ctr(Cid, Context);

  // fprintf(stderr, "[PIN][CMP] Cid: %d, Size: %d, Type: %d, Context: %d, Args
  // : (%lld, %lld)\n",
  //         Cid, Size, Type, Context, Arg1, Arg2);

  if (ctr > MAX_COND_CTR || is_dup_cond(Cid, pArg1, pArg2))
    return;

  std::vector<tag_seg> tags1, tags2;
  combineTag(tags1, pArg1, Size);
  combineTag(tags2, pArg2, Size);

  u32 tag1_size = tags1.size();
  u32 tag2_size = tags2.size();

  // fprintf(stderr, "[PIN][CMP] tag_size: %d, %d\n", tag1_size, tag2_size);

  if (tag1_size == 0 && tag2_size == 0)
    return;

  u64 delta = Arg1 > Arg2 ? Arg1 - Arg2 : Arg2 - Arg1;

  if (Type == COND_BOOL_TYPE)
    delta = 0;

  // FIXME:
  /*
  if (Lb1 == TT_SP_LABEL || Lb2 == TT_SP_LABEL) {
    Type = COND_LEN_TYPE;
  }
  */

  CondStmt stmt = {
      Cid,
      Context,
      ctr,
      0, // belong

      static_cast<u16>(Cond + 1),
      Type,
      Size,
      0,    // off_len
      Size, // val_len

      delta,
      0, // extra
  };

  if (tag1_size > 0) {
    stmt.off_len = tag1_size;
    // Lock
    OutWrite(&stmt, sizeof(stmt));
    OutWrite(&tags1[0], sizeof(tag_seg) * stmt.off_len);
    if (Size > 0)
      OutWrite((void *)pArg2, Size);
  }

  if (tag2_size > 0) {
    stmt.order |= COND_MORE_MASK;
    stmt.off_len = tag2_size;
    OutWrite(&stmt, sizeof(stmt));
    OutWrite(&tags2[0], sizeof(tag_seg) * stmt.off_len);
    if (Size > 0)
      OutWrite((void *)pArg1, Size);
  }
}

VOID SwHandler(u32 Cid, u32 Size, u32 Context, ADDRINT pCond, u32 Num,
               ADDRINT pArgs) {
  u32 ctr = get_cond_ctr(Cid, Context);

  // const tag_t *tag = tagmap_getb_as_ptr(pCond);
  if (ctr > MAX_COND_CTR)
    return;

  std::vector<tag_seg> tags;
  combineTag(tags, pCond, Size);
  u32 tag_size = tags.size();
  if (tag_size == 0)
    return;

  CondStmt stmt = {
      Cid,      Context,      ctr,
      0, // belong

      1,        COND_SW_TYPE, Size,
      tag_size, // off_len
      Size,     // val_len

      0,
      0, // extra
  };

  u64 *Args = (u64 *)pArgs;
  u64 Cond = *((u64 *)pCond);

  for (u32 i = 0; i < Num; i++) {
    stmt.order = (i << 16) | ctr;
    stmt.delta = Cond > Args[i] ? Cond - Args[i] : Args[i] - Cond;
    stmt.extra = Args[i];
    if (stmt.delta == 0) {
      stmt.condition = 3; // This cond is done.
    }
    OutWrite(&stmt, sizeof(stmt));
    OutWrite(&tags[0], sizeof(tag_seg) * tag_size);
    OutWrite(&Args[i], Size);
  }
}

VOID FnHandler(u32 Cid, u32 Size, u32 Context, ADDRINT pArg1, ADDRINT pArg2) {
  u32 ctr = get_cond_ctr(Cid, Context);
  if (ctr > MAX_COND_CTR)
    return;

  if (Size == 0) {
    u32 len1 = strnlen((const char *)pArg1, 20);
    u32 len2 = strnlen((const char *)pArg2, 20);
    Size = MIN(len1, len2);
  }

  std::vector<tag_seg> tags1, tags2;
  combineTag(tags1, pArg1, Size);
  combineTag(tags2, pArg2, Size);

  u32 tag1_size = tags1.size();
  u32 tag2_size = tags2.size();

  if (tag1_size == 0 && tag2_size == 0) {
    return;
  }

  CondStmt stmt = {
      Cid,
      Context,
      ctr,
      0, // belong

      0, // Cond
      COND_FN_TYPE,
      Size,
      0,    // off_len
      Size, // val_len

      0, // delta
      0, // extra
  };

  if (tag1_size > 0) {
    stmt.off_len = tag1_size;
    OutWrite(&stmt, sizeof(stmt));
    OutWrite(&tags1[0], sizeof(tag_seg) * stmt.off_len);
    if (Size > 0)
      OutWrite((void *)pArg2, Size);
  }

  if (tag2_size > 0) {
    stmt.order |= COND_MORE_MASK;
    stmt.off_len = tag2_size;
    OutWrite(&stmt, sizeof(stmt));
    OutWrite(&tags2[0], sizeof(tag_seg) * stmt.off_len);
    if (Size > 0)
      OutWrite((void *)pArg1, Size);
  }
}

VOID SoHandler(u32 Cid, u32 Size, u16 Type, u32 Context, ADDRINT pVal) {

  u32 ctr = get_cond_ctr(Cid, Context);
  if (ctr > MAX_COND_CTR)
    return;

  const tag_t *tag = tagmap_getb_as_ptr(pVal);
  if (is_dup_so(tag))
    return;

  std::vector<tag_seg> tags;
  combineTag(tags, pVal, Size);
  u32 tag_size = tags.size();
  if (tag_size == 0)
    return;

  u64 Val = *((u64 *)pVal);

  CondStmt stmt = {
      Cid,      Context, ctr,
      0, // belong

      0, // Cond
      Type,     Size,
      tag_size, // off_len
      0,        // val_len

      Val, // delta
      0,   // extra
  };

  if (Size == 1)
    stmt.extra = 0xff;
  else if (Size == 2)
    stmt.extra = 0xffff;
  else if (Size == 4)
    stmt.extra = 0xffffffff;
  else
    stmt.extra = 0xffffffffffffffff;
  stmt.delta = stmt.extra - stmt.delta;

  OutWrite(&stmt, sizeof(stmt));
  OutWrite(&tags[0], sizeof(tag_seg) * tag_size);
}

VOID EntryPoint(VOID *v) {

  for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
    // std::cerr << "IMG: " << IMG_Name(img) << std::endl;

    RTN cmp_rtn = RTN_FindByName(img, "__angora_trace_cmp_pin");
    RTN sw_rtn = RTN_FindByName(img, "__angora_trace_switch_pin");
    RTN fn_rtn = RTN_FindByName(img, "__angora_trace_fn_pin");
    RTN so_rtn = RTN_FindByName(img, "__angora_trace_so_val_pin");

    if (RTN_Valid(cmp_rtn)) {
      RTN_Open(cmp_rtn);
      RTN_InsertCall(
          cmp_rtn, IPOINT_BEFORE, (AFUNPTR)CmpHandler,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_FUNCARG_ENTRYPOINT_REFERENCE,
          5, IARG_FUNCARG_ENTRYPOINT_REFERENCE, 7, IARG_END);
      RTN_Close(cmp_rtn);
    }
    if (RTN_Valid(fn_rtn)) {
      RTN_Open(fn_rtn);
      RTN_InsertCall(
          fn_rtn, IPOINT_BEFORE, (AFUNPTR)FnHandler,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 4, IARG_END);
      RTN_Close(fn_rtn);
    }

    if (RTN_Valid(sw_rtn)) {
      RTN_Open(sw_rtn);
      RTN_InsertCall(
          sw_rtn, IPOINT_BEFORE, (AFUNPTR)SwHandler,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_REFERENCE,
          3, IARG_FUNCARG_ENTRYPOINT_VALUE, 5, IARG_FUNCARG_ENTRYPOINT_VALUE, 6,
          IARG_END);
      RTN_Close(sw_rtn);
    }

    if (RTN_Valid(so_rtn)) {
      RTN_Open(so_rtn);
      RTN_InsertCall(
          so_rtn, IPOINT_BEFORE, (AFUNPTR)SoHandler,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
          IARG_FUNCARG_ENTRYPOINT_VALUE, 2, IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
          IARG_FUNCARG_ENTRYPOINT_REFERENCE, 4, IARG_END);
      RTN_Close(so_rtn);
    }
  }
}

void MemRead(ADDRINT addr, uint32_t size) {
  const tag_t *tags = tagmap_getb_as_ptr(addr);
  tag_set.mem_read(tags, size);
};
VOID ShowIns(ADDRINT insAddr, std::string insDis) {
  std::cout << hex << insAddr << ":" << insDis << std::endl;
}

VOID MemInstruction(INS ins, VOID *v) {
  if (!is_tainted())
    return;

  /*
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ShowIns,
                 IARG_ADDRINT, INS_Address(ins),
                 IARG_PTR,
                 new string(INS_Disassemble(ins)),
                 IARG_END);
  */

  if (INS_IsMemoryRead(ins)) { // one of Oprand is memory read
    UINT32 refSize = INS_MemoryReadSize(ins);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)MemRead, IARG_MEMORYREAD_EA,
                   IARG_UINT32, refSize, IARG_END);
  }
  if (INS_HasMemoryRead2(ins)) { // The other Opreand is memory read, too
    UINT32 refSize = INS_MemoryReadSize(ins);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)MemRead, IARG_MEMORYREAD2_EA,
                   IARG_UINT32, refSize, IARG_END);
  }
}

VOID Fini(INT32 code, VOID *v) { OutFini(); }

int main(int argc, char *argv[]) {

  PIN_InitSymbols();

  if (unlikely(PIN_Init(argc, argv))) {
    std::cerr
        << "Sth error in PIN_Init. Plz use the right command line options."
        << std::endl;
    return -1;
  }

  if (unlikely(libdft_init() != 0)) {
    std::cerr << "Sth error libdft_init." << std::endl;
    return -1;
  }

  PIN_AddApplicationStartFunction(EntryPoint, 0);

  PIN_CALLBACK memIns = INS_AddInstrumentFunction(MemInstruction, 0);
  CALLBACK_SetExecutionPriority(memIns, CALL_ORDER_DEFAULT + 9);

  OutInit();
  PIN_AddFiniFunction(Fini, 0);

  hook_syscall();

  PIN_StartProgram();

  return 0;
}
