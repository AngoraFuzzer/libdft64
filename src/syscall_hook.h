
#ifndef __SYSCALL_HOOK_H__
#define __SYSCALL_HOOK_H__

#include "branch_pred.h"
#include "libdft_api.h"
#include "libdft_core.h"
#include "pin.H"
#include "syscall_desc.h"
#include "tagmap.h"

#include "string.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
/*
 * TODO:
 * 	- add ioctl() handler
 * 	- add nfsservctl() handler
 */

#define FUZZING_INPUT_FILE "cur_input"

bool is_tainted();
void hook_file_syscall();

#endif