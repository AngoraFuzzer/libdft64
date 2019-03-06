#include "branch_pred.h"
#include "cond_stmt.h"
#include "debug.h"
#include "libdft_api.h"
#include "pin.H"
#include "syscall_desc.h"
#include "syscall_hook.h"
#include "tagset.h"
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <vector>
extern REG thread_ctx_ptr;
std::ostream *out = &cerr;

TagSet tag_set;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "",
                            "specify file name for output");

VOID TestGetHandler(void *p) {
  uint64_t v = *((uint64_t *)p);
  tag_t t = tagmap_getn((ADDRINT)p, 8);
  LOGD("[PIN][GET] addr: %p, v: %lu, taint: %s\n", p, v, tag_sprint(t).c_str());
}

VOID TestGetValHandler(THREADID tid, uint64_t v) {
  // DFT_REG_RDI
  tag_t t = tagmap_getn_reg(tid, DFT_REG_RDI, 8);
  LOGD("[PIN][GETVAL] v: %lu, taint: %s\n", v, tag_sprint(t).c_str());
}

VOID TestSetHandler(void *p, unsigned int v) {
  tag_t t = tag_alloc<tag_t>(v);
  tagmap_setb((ADDRINT)p, t);
  LOGD("[PIN][SET] addr: %p, taint: %d\n", p, v);
}

VOID EntryPoint(VOID *v) {

  for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img)) {
    RTN test_get_rtn = RTN_FindByName(img, "__libdft_get_taint");
    if (RTN_Valid(test_get_rtn)) {
      RTN_Open(test_get_rtn);
      RTN_InsertCall(test_get_rtn, IPOINT_BEFORE, (AFUNPTR)TestGetHandler,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
      RTN_Close(test_get_rtn);
    }

    RTN test_set_rtn = RTN_FindByName(img, "__libdft_set_taint");
    if (RTN_Valid(test_set_rtn)) {
      RTN_Open(test_set_rtn);
      RTN_InsertCall(test_set_rtn, IPOINT_BEFORE, (AFUNPTR)TestSetHandler,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                     IARG_FUNCARG_ENTRYPOINT_VALUE, 1, IARG_END);
      RTN_Close(test_set_rtn);
    }

    RTN test_getval_rtn = RTN_FindByName(img, "__libdft_getval_taint");
    if (RTN_Valid(test_getval_rtn)) {
      RTN_Open(test_getval_rtn);

      RTN_InsertCall(test_getval_rtn, IPOINT_BEFORE, (AFUNPTR)TestGetValHandler,
                     IARG_THREAD_ID, IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                     IARG_END);
      RTN_Close(test_getval_rtn);
    }

    /*
    RTN cmp_rtn = RTN_FindByName(img, "__angora_trace_cmp_pin");

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
    RTN sw_rtn = RTN_FindByName(img, "__angora_trace_switch_pin");
    RTN fn_rtn = RTN_FindByName(img, "__angora_trace_fn_pin");
    RTN so_rtn = RTN_FindByName(img, "__angora_trace_so_val_pin");

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
          3, IARG_FUNCARG_ENTRYPOINT_VALUE, 5, IARG_FUNCARG_ENTRYPOINT_VALUE,
    6, IARG_END); RTN_Close(sw_rtn);
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
    */
  }
}

VOID Fini(INT32 code, VOID *v) {
  const string fileName = KnobOutputFile.Value();
  if (!fileName.empty()) {
    delete out;
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

  if (unlikely(libdft_init() != 0)) {
    std::cerr << "Sth error libdft_init." << std::endl;
    return -1;
  }

  const string fileName = KnobOutputFile.Value();

  if (!fileName.empty()) {
    out = new std::ofstream(fileName.c_str());
  }

  PIN_AddApplicationStartFunction(EntryPoint, 0);

  // CALLBACK_SetExecutionPriority(memIns, CALL_ORDER_DEFAULT + 9);

  hook_file_syscall();

  PIN_StartProgram();

  return 0;
}
