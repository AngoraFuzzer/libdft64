
#ifndef __DEBUG_H__
#define __DEBUG_H__

#define DEBUG_INFO 1

#ifdef DEBUG_INFO
// #define DEBUG_PRINTF printf
#define LOGD(...)                                                              \
  do {                                                                         \
    printf(__VA_ARGS__);                                                       \
  } while (0)
#else
#define LOGD(...)                                                              \
  do {                                                                         \
  } while (0)
#endif

#define LOGE(...)                                                              \
  do {                                                                         \
    fprintf(stderr, __VA_ARGS__);                                              \
  } while (0)
#else

#endif