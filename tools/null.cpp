#include "pin.H"
#include "../config.h"
#include "../src/branch_pred.h"

#include <cstring>
#include <iostream>
#include <sys/shm.h>
#include <stack>
#include <time.h>

static ADDRINT fork_func = 0;
static ADDRINT timer_func = 0;
RTN fork_point;

// In this function, we call the "AngoraStartForkServer" fucntion in forkserver.so
VOID StartFork(CONTEXT * ctxt, THREADID tid) {
  PIN_CallApplicationFunction(ctxt, tid, CALLINGSTD_DEFAULT, AFUNPTR(fork_func), NULL, PIN_PARG_END());
}

static void DTearly(CONTEXT * ctxt, THREADID tid) {
  PIN_CallApplicationFunction(ctxt, tid, CALLINGSTD_DEFAULT, AFUNPTR(timer_func), NULL, PIN_PARG_END());
  PIN_Detach();
}


VOID ImageLoad(IMG img, VOID *v) {
  std::cerr << "IMG: " << IMG_Name(img) << std::endl;

  if (IMG_Name(img).find("forkserver.so") != string::npos ||
      IMG_Name(img).find("forkserver_m32.so") != string::npos) {

    RTN rtn = RTN_FindByName (img, "AngoraStartForkServer");

    if (RTN_Valid(rtn)) {
      fork_func = RTN_Address(rtn);
      std::cerr << "[Fork] find fork func!" << RTN_Name(rtn) << std::endl;
    } else {
      return;
    }

    RTN rtn_timer = RTN_FindByName (img, "AngoraTimer");
    if (RTN_Valid(rtn_timer)) {
      timer_func = RTN_Address(rtn_timer);
      std::cerr << "[Fork] find timer func!" << RTN_Name(rtn_timer) << std::endl;
    }

    if (RTN_Valid(fork_point)) {

      std::cerr << "[Fork] find fork point!" << RTN_Name(fork_point) << std::endl;
      // it is main function
      RTN_Open(fork_point);

      RTN_InsertCall(fork_point, IPOINT_BEFORE, (AFUNPTR)StartFork,
                     IARG_CONTEXT, IARG_THREAD_ID, IARG_END);

      RTN_InsertCall(fork_point, IPOINT_AFTER, (AFUNPTR)DTearly,
                     IARG_CONTEXT, IARG_THREAD_ID, IARG_END);

      RTN_Close(fork_point);

    } else {
      // If there are none main routine, which means it has been stripped,
      // So we can't determine which address is the entrance
      fork_point = RTN_FindByName(img, "AngoraStartStub");
      if (RTN_Valid(fork_point)) {
        std::cerr << "[Fork] find fork point!" << RTN_Name(fork_point) << std::endl;
        RTN_Open(fork_point);
        RTN_InsertCall(fork_point, IPOINT_AFTER, (AFUNPTR)StartFork,
                       IARG_CONTEXT, IARG_THREAD_ID, IARG_END);
        RTN_InsertCall(fork_point, IPOINT_AFTER, (AFUNPTR)DTearly,
                       IARG_CONTEXT, IARG_THREAD_ID, IARG_END);

        RTN_Close(fork_point);
      }

    }

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

  //IMG_AddInstrumentFunction(ImageLoad, 0);
  PIN_StartProgram();
  return 0;

}
