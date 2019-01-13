#ifndef _COMMON_H_
#define _COMMON_H_

#ifdef __cplusplus
extern "C" {
#endif

#define OSDynLoad_Acquire ((void (*)(char* rpl, unsigned int *handle))0x0102A3B4)
#define OSDynLoad_FindExport ((void (*)(unsigned int handle, int isdata, char *symbol, void *address))0x0102B828)
#define OSFatal ((void (*)(char* msg))0x01031618)
#define __os_snprintf ((int(*)(char* s, int n, const char * format, ... ))0x0102F160)

#define ADDRESS_main_entry_hook                     0x0101c56c

#define BUS_SPEED                       248625000
#define SECS_TO_TICKS(sec) (((unsigned long long)(sec)) * (BUS_SPEED/4))

#ifdef __cplusplus
}
#endif

#endif
