#include "../config.h"
#include "../src/branch_pred.h"
#include "pin.H"

#include <cstring>
#include <iostream>
#include <stack>
#include <sys/shm.h>
#include <time.h>

enum {
  /* #define */ OP_0 = 0,			/* 0th (1st) operand index */
  /* #define */ OP_1 = 1,			/* 1st (2nd) operand index */
};

// ADDRINT code_start_addr = 0;
// ADDRINT code_end_addr = 0;

u8 branch_map[MAP_SIZE];
u8 *path_shm = branch_map;
CondStmt __cond_stmt = {0, 0, 0, 0, 0, 0, 0, 0};
CondStmt *cond_stmt = &__cond_stmt;

static u32 context = 0;
bool enable_fork = false;
static ADDRINT fork_func = 0;
RTN fork_point;

// PIN_FAST_ANALYSIS_CALL
VOID TrackCondBranch(u32 prefix, bool taken) {
  // std::cout << "ID:" << prefix << ": " << taken << "--> " << (prefix |
  // (u32)taken) << std::endl;
  // path_shm[prefix | (u32)taken]++;
  // FIXME: context might destroy prefix's last bit
  path_shm[(prefix ^ context) | (u32)taken]++;
}

VOID TrackIndBranch(u32 addr) {
  path_shm[addr ^ context]++;
}

/*
std::stack<u32> call_stack;
static void PIN_FAST_ANALYSIS_CALL PushCtx(u32 addr) {
  call_stack.push(addr);
  context ^= addr;
  // std::cout<<"push:" << addr << ", context: "<< context << std::endl;
}

static void PIN_FAST_ANALYSIS_CALL PopCtx() {
  u32 cur_call = call_stack.top();
  call_stack.pop();
  context ^= cur_call;
  //std::cout<<"pop:" << cur_call << ", context: "<< context << std::endl;
}
*/

// In this function, we call the "AngoraStartForkServer" fucntion in
// forkserver.so
VOID StartFork(CONTEXT *ctxt, THREADID tid) {
  PIN_CallApplicationFunction(ctxt, tid, CALLINGSTD_DEFAULT, AFUNPTR(fork_func),
                              NULL, PIN_PARG_END());
}

static void DTearly() { PIN_Detach(); }


static void PIN_FAST_ANALYSIS_CALL cmp_rr(u32 op0, u32 op1) {
  cond_stmt->delta = op0 > op1 ? op0 - op1 : op1 - op0;
}

static void PIN_FAST_ANALYSIS_CALL cmp_rm(u32 op0, ADDRINT op1_addr) {
  u32 op1 = *((u32*)op1_addr);
  cond_stmt->delta = op0 > op1 ? op0 - op1 : op1 - op0;
}

VOID ImageLoad(IMG img, VOID *v) {
  std::cerr << "IMG: " << IMG_Name(img) << std::endl;

  if (1|| IMG_IsMainExecutable(img)) {

    // std::cerr << "  ~EXE~ " << std::endl;

    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {

      std::cout << "  SEC: " << SEC_Name(sec) << std::endl;

      // TODO: the check for .text name might be too much, there could be other
      // executable segments we need to instrument but maybe not things like the
      // .plt or .fini/init
      if (1 || SEC_Name(sec) == ".text") {
        fork_point = RTN_FindByName(img, "main");

        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
          RTN_Open(rtn);
          std::cout << "    RTN: " << RTN_Name(rtn) << std::endl;

          // IPOINT_AFTER is implemented by instrumenting each return
          // instruction in a routine.  Pin tries to find all return
          // instructions, but success is not guaranteed.
          // RTN_InsertCall( rtn, IPOINT_AFTER, (AFUNPTR)InsCount,
          //                 IARG_UINT32, RTN_NumIns(rtn), IARG_END);

          for (INS ins = RTN_InsHead(rtn); INS_Valid(ins);
               ins = INS_Next(ins)) {

            //std::cout << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << std::endl;

            // * Branch-based:
            // Entry id: ( branch address[n-1 bits] | taken[1 bit] )
            // DirectBranch is fixed, so we must ensure they are conditional,
            // While IndirectBranch is not fixed, it will change.
            if (INS_Category(ins) == XED_CATEGORY_COND_BR) {

              ADDRINT addr = INS_Address(ins);
              u32 prefix = ADDR_PREFIX(addr);
              INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TrackCondBranch,
                             IARG_UINT32, prefix, IARG_BRANCH_TAKEN, IARG_END);

            } else if (INS_IsIndirectBranchOrCall(ins)) {

              u32 addr = ADDR_GET(INS_Address(ins));
              INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)TrackIndBranch,
                             IARG_UINT32, addr, IARG_END);

            } else if (INS_Opcode(ins) == XED_ICLASS_CMP) {
              // 32bit
              u32 addr = INS_Address(ins);
              //std::cout << "cmpaddr:  " << addr << ", " << cond_stmt->cmpid << std::endl;
              if (addr == cond_stmt->cmpid) {
                //std::cout << "cmp: find it .. " << std::endl;
                if (INS_OperandIsReg(ins, OP_0)) {
                  REG reg0 = INS_OperandReg(ins, OP_0);
                  if (INS_OperandIsReg(ins, OP_1)) {
                    REG reg1 = INS_OperandReg(ins, OP_1);
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)cmp_rr,
                        IARG_FAST_ANALYSIS_CALL, IARG_REG_VALUE, reg0,
                        IARG_REG_VALUE, reg1, IARG_END);

                  } else if (INS_OperandIsMemory(ins, OP_1)) {

                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)cmp_rm,
                        IARG_FAST_ANALYSIS_CALL, IARG_REG_VALUE, reg0,
                        IARG_MEMORYREAD_EA, IARG_END);

                  } else if (INS_OperandIsImmediate(ins, OP_1)) {

                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)cmp_rr,
                        IARG_FAST_ANALYSIS_CALL, IARG_REG_VALUE, reg0,
                        IARG_UINT32, (u32)INS_OperandImmediate(ins, OP_1),
                        IARG_END);
                  }

                } else if (INS_OperandIsMemory(ins, OP_0)) {

                  if (INS_OperandIsReg(ins, OP_1)) {
                    REG reg1 = INS_OperandReg(ins, OP_1);
                    // reverse the order or operands
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)cmp_rm,
                        IARG_FAST_ANALYSIS_CALL, IARG_REG_VALUE, reg1,
                        IARG_MEMORYREAD_EA, IARG_END);

                  } else if (INS_OperandIsImmediate(ins, OP_1)) {
                    INS_InsertCall(
                        ins, IPOINT_BEFORE, (AFUNPTR)cmp_rr,
                        IARG_FAST_ANALYSIS_CALL, IARG_MEMORYREAD_EA,
                        IARG_UINT32, (u32)INS_OperandImmediate(ins, OP_1),
                        IARG_END);
                  }
                }
              }
            }

            // Enable context:
            /*
            if (INS_IsCall(ins)) {

              ADDRINT addr = INS_Address(ins);
              u32 call_prefix = ADDR_PREFIX(addr);

              INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)PushCtx,
              IARG_UINT32, call_prefix, IARG_END);

              else if (INS_IsRet(ins)) {
              INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)PopCtx,
                             IARG_END);
            }

            }
            */
          }

          RTN_Close(rtn);
        }
      }
    }
  }

  if (IMG_Name(img).find("forkserver.so") != string::npos ||
      IMG_Name(img).find("forkserver_m32.so") != string::npos) {

    RTN rtn = RTN_FindByName(img, "AngoraStartForkServer");
    if (RTN_Valid(rtn)) {
      fork_func = RTN_Address(rtn);
      std::cerr << "[Fork] find fork func!" << RTN_Name(rtn) << std::endl;
    } else {
      return;
    }

    if (RTN_Valid(fork_point)) {

      std::cerr << "[Fork] find fork point!" << RTN_Name(fork_point)
                << std::endl;
      // it is main function
      RTN_Open(fork_point);
      RTN_InsertCall(fork_point, IPOINT_BEFORE, (AFUNPTR)StartFork,
                     IARG_CONTEXT, IARG_THREAD_ID, IARG_END);
      RTN_InsertCall(fork_point, IPOINT_AFTER, (AFUNPTR)DTearly, IARG_END);
      RTN_Close(fork_point);

    } else {
      // If there are none main routine, which means it has been stripped,
      // So we can't determine which address is the entrance
      fork_point = RTN_FindByName(img, "AngoraStartStub");
      if (RTN_Valid(fork_point)) {
        std::cerr << "[Fork] find fork point!" << RTN_Name(fork_point)
                  << std::endl;
        RTN_Open(fork_point);
        RTN_InsertCall(fork_point, IPOINT_AFTER, (AFUNPTR)StartFork,
                       IARG_CONTEXT, IARG_THREAD_ID, IARG_END);
        RTN_Close(fork_point);
      }
    }
  }
}

void SetupShm() {

  if (char *shm_id_str = getenv(SHM_ENV_VAR)) {
    int shm_id = std::atoi(shm_id_str);
    // std::cerr << "shm_id: " << shm_id << std::endl;
    path_shm = reinterpret_cast<u8 *>(shmat(shm_id, NULL, 0));
    if (path_shm == reinterpret_cast<void *>(-1)) {
      std::cerr << "failed to get shm addr from shmmat()" << std::endl;
      _exit(1);
    }
  }

  if (char *cond_stmt_id_str = getenv(COND_STMT_ENV_VAR)) {
    int cond_stmt_id = std::atoi(cond_stmt_id_str);
    cond_stmt = reinterpret_cast<CondStmt *>(shmat(cond_stmt_id, NULL, 0));
    if (cond_stmt == reinterpret_cast<void *>(-1)) {
      std::cerr << "failed to get cond stmt addr from shmmat()" << std::endl;
      _exit(1);
    }
  }
}

VOID FindIO(THREADID tid, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v) {
  size_t syscall_nr = PIN_GetSyscallNumber(ctx, std);
  // before open
  std::cout << "syscall is " << syscall_nr << std::endl;
}

VOID Fini(INT32 code, VOID *v) {
  // std::cout << "FiniFunc: " << ":" <<  TIME_SPAN << std::endl;
}

int main(int argc, char *argv[]) {

  PIN_InitSymbols();

  if (unlikely(PIN_Init(argc, argv))) {
    std::cerr
        << "Sth error in PIN_Init. Plz use the right command line options."
        << std::endl;
    return -1;
  }

  SetupShm();
  // PIN_SetSyntaxIntel();
  IMG_AddInstrumentFunction(ImageLoad, 0);
  // PIN_AddSyscallEntryFunction(FindIO, 0);
  // PIN_AddFiniFunction(Fini, 0);
  PIN_StartProgram();
  return 0;
}
