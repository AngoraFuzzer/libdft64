#include "pin.H"

#include "branch_pred.h"
#include "libdft_api.h"
#include "libdft_core.h"
#include "syscall_desc.h"
//#include "tag_set.h"
#include "tagmap.h"

#include "string.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

void hook_syscall();
bool is_tainted();