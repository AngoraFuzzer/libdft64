#include "common.h"
#include "hook.h"
#include <iostream>

TagSet tag_set;
extern REG thread_ctx_ptr;

void combineTag(std::vector<tag_seg> &tag_all, ADDRINT addr, u32 size) {
  //if (!tags || !tags[0]) return;
  for (size_t i = 0; i < size; i++) {
    const tag_t tag = tagmap_getb(addr + i);
    if (!tag) continue;
#ifdef USE_TREE_TAG
    const std::vector<tag_seg> tag_i = TagSet::find(tag);
    //std::cout << "tagI: " << hex << addr+i << ": "<< tag_sprint(tag_i) << "\n";
    tag_combine_inplace(tag_all, tag_i);
#else
    tag_combine_inplace(tag_all, tag);
#endif
  }
}

// FIXME: Make them thread local ?
void sendCondStmt(u32 cmpid, u32 brid1, u32 brid2,
                  u32 size, u32 type, u32 context,
                  uval op1_val, uval op2_val,
                  ADDRINT op1_addr, ADDRINT op2_addr) {

  std::vector<tag_seg> tags1, tags2;
  combineTag(tags1, op1_addr, size);
  combineTag(tags2, op2_addr, size);
  if (type != FN_TYPE) {
    tag_set.frac_tagvec(tags1);
    tag_set.frac_tagvec(tags2);
  }

  u32 tag1_size = tags1.size();
  u32 tag2_size = tags2.size();

  // FIXME: return early
  if (tag1_size == 0 && tag2_size == 0) {
    return;
  }

  bool is_swapped = false;
  if (tag1_size == 0 ||
      (tag1_size > tag2_size && tag2_size > 0)) {
    // swap tag1 tag2
    is_swapped = true;
    u32 tmp = tag1_size;
    tag1_size = tag2_size;
    tag2_size = tmp;
  }

  u64 extra = 0;

  if (type == SW_TYPE) {//case
    extra = op2_val;
  }
  uval delta = op1_val > op2_val ? op1_val - op2_val : op2_val - op1_val;

  CondStmt stmt = {
    cmpid,
    brid1,
    brid2,
    context,

    size,
    type,
    tag1_size,
    tag2_size,

    delta,
    extra
  };
  
  sendData(&stmt, sizeof(stmt));

  // fprintf(stderr, "tag size: (%d, %d), delta: %lld\n",
  //         tag1_size, tag2_size, delta);

  if (!is_swapped) {
    if (tags1.size() > 0)
      sendData(&tags1[0], sizeof(tag_seg) * tags1.size());
    if (tags2.size() > 0)
      sendData(&tags2[0], sizeof(tag_seg) * tags2.size());
    sendData((void*)op1_addr, size);
    sendData((void*)op2_addr, size);
  } else {
    if (tags2.size() > 0)
      sendData(&tags2[0], sizeof(tag_seg) * tags2.size());
    if (tags1.size() > 0)
      sendData(&tags1[0], sizeof(tag_seg) * tags1.size());
    sendData((void*)op2_addr, size);
    sendData((void*)op1_addr, size);
  }

}

VOID CmpHandler(u32 Cid, u32 Size, u32 Type,
                u32 Context, u32 Edge0, u32 Edge1,
                ADDRINT pArg1, ADDRINT pArg2) {
  uval Arg1 = *((uval*)pArg1);
  uval Arg2  = *((uval*)pArg2);

  // fprintf(stderr, "[PIN] Cid: %d, Size: %d, Type: %d, Context: %d, Args : (%lld, %lld), Edge: (%d, %d)\n",
  //         Cid, Size, Type, Context, Arg1, Arg2, Edge0, Edge1);

  sendCondStmt(Cid, Edge0, Edge1, Size, Type, Context, Arg1, Arg2, pArg1, pArg2);
}

VOID FnHandler(ADDRINT pArg1, ADDRINT pArg2, u32 Size) {
  if (Size == 0) {
    u32 len1 = strnlen((const char*)pArg1, 20);
    u32 len2 = strnlen((const char*)pArg2, 20);
    Size = MIN(len1, len2);
  }
  // fprintf(stderr, "[PIN] FN , Size : %d\n", Size);
  sendCondStmt(0, 0, 0, Size, FN_TYPE, 0, 0, 0, pArg1, pArg2);
}

VOID EntryPoint(VOID *v) {

  for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
    std::cerr << "IMG: " << IMG_Name(img) << std::endl;

    RTN cmp_rtn = RTN_FindByName(img, "__trace_cmp_pp");
    RTN fn_rtn = RTN_FindByName(img, "__trace_fn_pp");
    if (RTN_Valid(cmp_rtn) && RTN_Valid(fn_rtn)) {

      RTN_Open(cmp_rtn);
      RTN_InsertCall(cmp_rtn, IPOINT_BEFORE, (AFUNPTR)CmpHandler,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 3,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 4,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 5,
                     IARG_FUNCARG_ENTRYPOINT_REFERENCE, 6,
                     IARG_FUNCARG_ENTRYPOINT_REFERENCE, 8,
                     IARG_END);
      RTN_Close(cmp_rtn);

      RTN_Open(fn_rtn);
      RTN_InsertCall(fn_rtn, IPOINT_BEFORE, (AFUNPTR)FnHandler,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
                     IARG_END);
      RTN_Close(fn_rtn);
      //break;
    }
    /*
      // For debug 
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
      std::cerr << "  SEC: " << SEC_Name(sec) << std::endl;
      for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
        RTN_Open(rtn);
        std::cerr << "    RTN: " << RTN_Name(rtn) << std::endl;
        RTN_Close(rtn);
      }
    }
    */

    /*
    RTN d_rtn = RTN_FindByName(img, "main");
    if (RTN_Valid(d_rtn)) {
      RTN_Open(d_rtn);
      for (INS ins = RTN_InsHead(d_rtn); INS_Valid(ins); ins = INS_Next(ins)) {
        std::cerr << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << std::endl;
      }
      RTN_Close(d_rtn);
    }
    */
  }

}

void MemRead(ADDRINT addr, uint32_t size) {
  const tag_t *tags = tagmap_getb_as_ptr(addr);
  tag_set.mem_read(tags, size);
};

VOID Instruction(INS ins, VOID *v) {

  if (!is_tainted()) return;

  //std::cerr << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << std::endl;

  if(INS_IsMemoryRead(ins)){ // one of Oprand is memory read
    UINT32 refSize = INS_MemoryReadSize(ins);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)MemRead,
                     IARG_MEMORYREAD_EA,
                     IARG_UINT32, refSize,
                     IARG_END);
  }
  if(INS_HasMemoryRead2(ins)){ // The other Opreand is memory read, too
    UINT32 refSize = INS_MemoryReadSize(ins);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)MemRead,
                     IARG_MEMORYREAD2_EA,
                     IARG_UINT32, refSize,
                     IARG_END);
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

  PIN_CALLBACK cbIns = INS_AddInstrumentFunction(Instruction, 0);
  CALLBACK_SetExecutionPriority(cbIns, CALL_ORDER_DEFAULT + 9);

  // * IO
  hook_syscall();

  PIN_StartProgram();

  return 0;
}
