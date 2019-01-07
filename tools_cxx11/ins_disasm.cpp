#include <stdio.h>
#include "pin.H"
#include <iostream>


// This function is called before every instruction is executed
// and prints the IP
VOID ShowIns(ADDRINT insAddr, std::string insDis) {
  std::cout << hex << insAddr <<  ":" << insDis << std::endl;
}

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
  // Insert a call to printip before every instruction, and pass it the IP
  //std::cout << hex << INS_Address(ins) << ": " << INS_Disassemble(ins) << std::endl;
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ShowIns,
                 IARG_ADDRINT, INS_Address(ins), new string(INS_Disassemble(ins)), IARG_END);
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    PIN_ERROR("This Pintool prints the IPs of every instruction executed\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char * argv[])
{
    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
