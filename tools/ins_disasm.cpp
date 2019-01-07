#include <stdio.h>
#include "pin.H"
#include <iostream>

// This function is called before every instruction is executed
// and prints the IP

VOID ShowIns(ADDRINT insAddr, std::string insDis) {
  std::cout << hex << insAddr <<  ":" << insDis << std::endl;
}

// Pin calls this function every time a new instruction is encountered
/*
VOID Instruction(INS ins, VOID *v)
{
  // Insert a call to printip before every instruction, and pass it the IP
  std::cout << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << std::endl;
  // INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ShowIns,
  //                IARG_ADDRINT, INS_Address(ins),
  //                IARG_PTR,
  //                new string(INS_Disassemble(ins)),
  //                IARG_END);

}
*/

VOID ImageLoad(IMG img, VOID *v) {
  std::cerr << "IMG: " << IMG_Name(img) << std::endl;

  if (IMG_IsMainExecutable(img)) {
    for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
      std::cout << "  SEC: " << SEC_Name(sec) << std::endl;
      if (SEC_Name(sec) == ".text") {
        for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
          RTN_Open(rtn);
          std::cout << "    RTN: " << RTN_Name(rtn) << std::endl;
          for (INS ins = RTN_InsHead(rtn); INS_Valid(ins);
               ins = INS_Next(ins)) {
            std::cout << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << std::endl;
          }
          RTN_Close(rtn);

        }
      }
    }
  }
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize pin
  PIN_InitSymbols();
  if (PIN_Init(argc, argv)) return 0;

  // Register Instruction to be called to instrument instructions
  //INS_AddInstrumentFunction(Instruction, 0);
  IMG_AddInstrumentFunction(ImageLoad, 0);
  // Start the program, never returns
  PIN_StartProgram();
  return 0;
}
