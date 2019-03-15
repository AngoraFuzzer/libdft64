#ifndef __LIBDFT_DEF_H__
#define __LIBDFT_DEF_H__

#include <sys/syscall.h>
#define SYSCALL_ARG_NUM 6 /* syscall arguments */
#define SYSCALL_ARG0 0    /* 1st argument in syscall */
#define SYSCALL_ARG1 1    /* 2nd argument in syscall */
#define SYSCALL_ARG2 2    /* 3rd argument in syscall */
#define SYSCALL_ARG3 3    /* 4th argument in syscall */
#define SYSCALL_ARG4 4    /* 5th argument in syscall */
#define SYSCALL_ARG5 5    /* 6th argument in syscall */

#define THREAD_CTX_BLK 128 /* block of thread contexts */

#define DFT_REG_RDI 3
#define DFT_REG_RSI 4
#define DFT_REG_RBP 5
#define DFT_REG_RSP 6
#define DFT_REG_RBX 7
#define DFT_REG_RDX 8
#define DFT_REG_RCX 9
#define DFT_REG_RAX 10
#define DFT_REG_R8 11
#define DFT_REG_R9 12
#define DFT_REG_R10 13
#define DFT_REG_R11 14
#define DFT_REG_R12 15
#define DFT_REG_R13 16
#define DFT_REG_R14 17
#define DFT_REG_R15 18
#define DFT_REG_XMM0 19
#define DFT_REG_XMM1 20
#define DFT_REG_XMM2 21
#define DFT_REG_XMM3 22
#define DFT_REG_XMM4 23
#define DFT_REG_XMM5 24
#define DFT_REG_XMM6 25
#define DFT_REG_XMM7 26
#define DFT_REG_XMM8 27
#define DFT_REG_XMM9 28
#define DFT_REG_XMM10 29
#define DFT_REG_XMM11 30
#define DFT_REG_XMM12 31
#define DFT_REG_XMM13 32
#define DFT_REG_XMM14 33
#define DFT_REG_XMM15 34
#define DFT_REG_ST0 35
#define DFT_REG_ST1 36
#define DFT_REG_ST2 37
#define DFT_REG_ST3 38
#define DFT_REG_ST4 39
#define DFT_REG_ST5 40
#define DFT_REG_ST6 41
#define DFT_REG_ST7 42
#define DFT_REG_HELPER1 0
#define DFT_REG_HELPER2 1
#define DFT_REG_HELPER3 2
#define GRP_NUM 43      /* general purpose registers */
#define TAGS_PER_GPR 32 /* general purpose registers */

#define X64_ARG0_REG DFT_REG_RDI
#define X64_ARG1_REG DFT_REG_RSI
#define X64_ARG2_REG DFT_REG_RDX
#define X64_ARG3_REG DFT_REG_RCX
#define X64_ARG4_REG DFT_REG_R8
#define X64_ARG5_REG DFT_REG_R9
#define X64_RET_REG DFT_REG_RAX

#endif