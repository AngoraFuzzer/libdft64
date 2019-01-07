#include "../config.h"
#include "pin.H"
#include "branch_pred.h"
#include "libdft_api.h"
#include "libdft_core.h"
#include "syscall_desc.h"
#include "tagmap.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include "string.h"
#include "../../tag_set/tag_set.h"

void hook_syscall();
bool is_tainted();
