#ifndef __LIBDFT_API_H__
#define __LIBDFT_API_H__
//#define AVERBOSE
//#define ADEBUG

#ifdef AVERBOSE
#define averbose_fprintf(...) fprintf(__VA_ARGS__)
#define averbose_printf(...) printf(__VA_ARGS__)
#else
#define averbose_fprintf(...)
#define averbose_printf(...)
#endif

#ifdef ADEBUG
#define adebug_fprintf(...) fprintf(__VA_ARGS__)
#define adebug_printf(...) printf(__VA_ARGS__)
#else
#define adebug_fprintf(...)
#define adebug_printf(...)
#endif
#endif
