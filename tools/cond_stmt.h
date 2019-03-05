#ifndef __COND_STMT_H__
#define __COND_STMT_H__

#include "libdft_api.h"
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

struct CondArg {
  u64 op1;
  u64 op2;
  const tag_t *lb1;
  const tag_t *lb2;
};

#endif