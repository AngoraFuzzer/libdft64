#ifndef PIN_MODE_CONFIG_H
#define PIN_MODE_CONFIG_H

#include <unistd.h>
#include <stdint.h>
#include <signal.h>
#include <sys/wait.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef ADDR_PREFIX
#define ADDR_PREFIX(_addr) ((_addr << 1) % MAP_SIZE)
#define ADDR_GET(_addr) (_addr % MAP_SIZE)
#endif

/*
  enum:
XED_ICLASS_JB 	 // <  , unsigned
XED_ICLASS_JBE 	 // <= , unsigned
XED_ICLASS_JL 	 // <  , signed
XED_ICLASS_JLE 	 // <= , signed
XED_ICLASS_JMP 	
XED_ICLASS_JMP_FAR 	
XED_ICLASS_JNB 	
XED_ICLASS_JNBE 	
XED_ICLASS_JNL 	
XED_ICLASS_JNLE 	
XED_ICLASS_JNO 	
XED_ICLASS_JNP 	
XED_ICLASS_JNS 	
XED_ICLASS_JNZ 	
XED_ICLASS_JO 	
XED_ICLASS_JP 	
XED_ICLASS_JRCXZ 	
XED_ICLASS_JS 	
XED_ICLASS_JZ
*/

#include "../config.h"

#endif
