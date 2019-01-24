#include "os_types.h"
#include "elf_abi.h"
#include "gx2sploit/kexploit.h"
#include "structs.h"
#include "main_hook.h"
#include "common.h"

/* Install functions */
static void InstallMain(private_data_t *private_data);
static void thread_callback(int argc, void *argv);
void doBrowserShutdown(unsigned int coreinit_handle);

/* ****************************************************************** */
/*                               ENTRY POINT                          */
/* ****************************************************************** */
void __main(void) {
    /* Get coreinit handle and keep it in memory */
    unsigned int coreinit_handle;
    OSDynLoad_Acquire("coreinit.rpl", &coreinit_handle);

    /* Get our memory functions */
    unsigned int* functionPointer;
    void* (*p_memset)(void * dest, unsigned int value, unsigned int bytes);
    void  (*_Exit)(int);

    void* (*OSSleepTicks)(u64 ticks);
    OSDynLoad_FindExport(coreinit_handle, 0, "memset", &p_memset);
    OSDynLoad_FindExport(coreinit_handle, 0, "_Exit", &_Exit);
    OSDynLoad_FindExport(coreinit_handle, 0, "OSSleepTicks", &OSSleepTicks);

    void* (*MEMAllocFromDefaultHeapEx)(unsigned int size, unsigned int align);
    void  (*MEMFreeToDefaultHeap)(void *ptr);

    OSDynLoad_FindExport(coreinit_handle, 1, "MEMAllocFromDefaultHeapEx", &functionPointer);
    MEMAllocFromDefaultHeapEx = (void*(*)(unsigned int, unsigned int))*functionPointer;
    OSDynLoad_FindExport(coreinit_handle, 1, "MEMFreeToDefaultHeap", &functionPointer);
    MEMFreeToDefaultHeap = (void (*)(void *))*functionPointer;

    void (*OSExitThread)(int);
    int (*OSCreateThread)(void *thread, void *entry, int argc, void *args, unsigned int stack, unsigned int stack_size, int priority, unsigned short attr);
    int (*OSResumeThread)(void *thread);
    int (*OSIsThreadTerminated)(void *thread);

    OSDynLoad_FindExport(coreinit_handle, 0, "OSCreateThread", &OSCreateThread);
    OSDynLoad_FindExport(coreinit_handle, 0, "OSResumeThread", &OSResumeThread);
    OSDynLoad_FindExport(coreinit_handle, 0, "OSIsThreadTerminated", &OSIsThreadTerminated);
    OSDynLoad_FindExport(coreinit_handle, 0, "OSExitThread", &OSExitThread);

    //Allocate a stack for the thread
    void *stack = MEMAllocFromDefaultHeapEx(0x4000, 0x20);
    //
    // Create the thread variable
    void *thread = MEMAllocFromDefaultHeapEx(0x1000, 8);
    if(!thread || !stack) {
        OSFatal("Thread memory allocation failed. Exit and re-enter browser.");
    }

    // Use a stable thread.
    // create a detached thread with priority 0 and use core 1
    int ret = OSCreateThread(thread, thread_callback, 0, (void*)NULL, (unsigned int)stack+0x4000, 0x4000, 0, 0x1A);
    if (ret == 0) {
        OSFatal("Failed to create thread. Exit and re-enter browser.");
    }

    // Schedule it for execution
    OSResumeThread(thread);

    OSExitThread(0);
}

static void thread_callback(int argc, void *argv) {
    unsigned int coreinit_handle;
    OSDynLoad_Acquire("coreinit.rpl", &coreinit_handle);

    /* Get our memory functions */
    unsigned int* functionPointer;
    void* (*p_memset)(void * dest, unsigned int value, unsigned int bytes);
    void  (*_Exit)(int);
    OSDynLoad_FindExport(coreinit_handle, 0, "memset", &p_memset);
    OSDynLoad_FindExport(coreinit_handle, 0, "_Exit", &_Exit);

    private_data_t private_data;
    p_memset(&private_data, 0, sizeof(private_data_t));

    private_data.coreinit_handle = coreinit_handle;
    private_data.memset = p_memset;
    private_data.data_elf = (unsigned char *) main_hook_main_hook_elf; // use this address as temporary to load the elf

    OSDynLoad_FindExport(coreinit_handle, 1, "MEMAllocFromDefaultHeapEx", &functionPointer);
    private_data.MEMAllocFromDefaultHeapEx = (void*(*)(unsigned int, unsigned int))*functionPointer;
    OSDynLoad_FindExport(coreinit_handle, 1, "MEMFreeToDefaultHeap", &functionPointer);
    private_data.MEMFreeToDefaultHeap = (void (*)(void *))*functionPointer;

    OSDynLoad_FindExport(coreinit_handle, 0, "memcpy", &private_data.memcpy);
    OSDynLoad_FindExport(coreinit_handle, 0, "OSEffectiveToPhysical", &private_data.OSEffectiveToPhysical);
    OSDynLoad_FindExport(coreinit_handle, 0, "DCFlushRange", &private_data.DCFlushRange);
    OSDynLoad_FindExport(coreinit_handle, 0, "ICInvalidateRange", &private_data.ICInvalidateRange);
    OSDynLoad_FindExport(coreinit_handle, 0, "OSEffectiveToPhysical", &private_data.OSEffectiveToPhysical);

    doBrowserShutdown(private_data.coreinit_handle);
    run_kexploit(coreinit_handle);

    InstallMain(&private_data);

    Elf32_Ehdr *ehdr = (Elf32_Ehdr *) private_data.data_elf;
    unsigned int mainEntryPoint = ehdr->e_entry;

    //! Install our entry point hook
    unsigned int repl_addr = ADDRESS_main_entry_hook;
    unsigned int jump_addr = mainEntryPoint & 0x03fffffc;

    unsigned int bufferU32 = 0x48000003 | jump_addr;
    KernelWriteU32(repl_addr,bufferU32,coreinit_handle);

    // Place a function to set the IBAT0 inside free kernel space.
    // Register it as syscall 0x09
    unsigned int setIBAT0Addr = 0xFFF02344;
    unsigned int curAddr = setIBAT0Addr;
    KernelWriteU32FixedAddr(curAddr, 0x7C0006AC,coreinit_handle);
    curAddr+=4;
    KernelWriteU32FixedAddr(curAddr, 0x4C00012C,coreinit_handle);
    curAddr+=4;
    KernelWriteU32FixedAddr(curAddr, 0x7C7083A6,coreinit_handle);
    curAddr+=4;
    KernelWriteU32FixedAddr(curAddr, 0x7C9183A6,coreinit_handle);
    curAddr+=4;
    KernelWriteU32FixedAddr(curAddr, 0x7C0006AC,coreinit_handle);
    curAddr+=4;
    KernelWriteU32FixedAddr(curAddr, 0x4C00012C,coreinit_handle);
    curAddr+=4;
    KernelWriteU32FixedAddr(curAddr, 0x4E800020,coreinit_handle);
    curAddr+=4;

    // Setup as syscall 0x09
    kern_write((void*)(KERN_SYSCALL_TBL_1 + (0x09 * 4)), (uint32_t) setIBAT0Addr);
    kern_write((void*)(KERN_SYSCALL_TBL_2 + (0x09 * 4)), (uint32_t) setIBAT0Addr);
    kern_write((void*)(KERN_SYSCALL_TBL_3 + (0x09 * 4)), (uint32_t) setIBAT0Addr);
    kern_write((void*)(KERN_SYSCALL_TBL_4 + (0x09 * 4)), (uint32_t) setIBAT0Addr);
    kern_write((void*)(KERN_SYSCALL_TBL_5 + (0x09 * 4)), (uint32_t) setIBAT0Addr);

    // Exit!
    unsigned int sysapp_handle;
    void (*_SYSLaunchMiiStudio)(void) = 0;
    OSDynLoad_Acquire("sysapp.rpl", &sysapp_handle);
    OSDynLoad_FindExport(sysapp_handle, 0, "_SYSLaunchMiiStudio", &_SYSLaunchMiiStudio);

    _SYSLaunchMiiStudio();

    _Exit(0);
}

void wait(unsigned int coreinit_handle, unsigned int t) {
    void (*OSYieldThread)(void);
    OSDynLoad_FindExport(coreinit_handle, 0, "OSYieldThread", &OSYieldThread);

    while(t--) {
        OSYieldThread();
    }
}

void doBrowserShutdown(unsigned int coreinit_handle) {
    void*(*memset)(void *dest, uint32_t value, uint32_t bytes);
    void*(*OSAllocFromSystem)(uint32_t size, int align);
    void (*OSFreeToSystem)(void *ptr);

    int(*IM_SetDeviceState)(int fd, void *mem, int state, int a, int b);
    int(*IM_Close)(int fd);
    int(*IM_Open)();

    OSDynLoad_FindExport(coreinit_handle, 0, "memset", &memset);
    OSDynLoad_FindExport(coreinit_handle, 0, "OSAllocFromSystem", &OSAllocFromSystem);
    OSDynLoad_FindExport(coreinit_handle, 0, "OSFreeToSystem", &OSFreeToSystem);

    OSDynLoad_FindExport(coreinit_handle, 0, "IM_SetDeviceState", &IM_SetDeviceState);
    OSDynLoad_FindExport(coreinit_handle, 0, "IM_Close", &IM_Close);
    OSDynLoad_FindExport(coreinit_handle, 0, "IM_Open", &IM_Open);

    //Restart system to get lib access
    int fd = IM_Open();
    void *mem = OSAllocFromSystem(0x100, 64);
    memset(mem, 0, 0x100);
    //set restart flag to force quit browser
    IM_SetDeviceState(fd, mem, 3, 0, 0);
    IM_Close(fd);
    OSFreeToSystem(mem);
    //wait a bit for browser end
    wait(coreinit_handle, 0x3FFFF*0x4);
}

static int strcmp(const char *s1, const char *s2) {
    while(*s1 && *s2) {
        if(*s1 != *s2) {
            return -1;
        }
        s1++;
        s2++;
    }

    if(*s1 != *s2) {
        return -1;
    }
    return 0;
}

static unsigned int get_section(private_data_t *private_data, unsigned char *data, const char *name, unsigned int * size, unsigned int * addr, int fail_on_not_found) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *) data;

    if (   !data
            || !IS_ELF (*ehdr)
            || (ehdr->e_type != ET_EXEC)
            || (ehdr->e_machine != EM_PPC)) {
        OSFatal("Invalid elf file");
    }

    Elf32_Shdr *shdr = (Elf32_Shdr *) (data + ehdr->e_shoff);
    int i;
    for(i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = ((const char*)data) + shdr[ehdr->e_shstrndx].sh_offset + shdr[i].sh_name;
        if(strcmp(section_name, name) == 0) {
            if(addr)
                *addr = shdr[i].sh_addr;
            if(size)
                *size = shdr[i].sh_size;
            return shdr[i].sh_offset;
        }
    }

    if(fail_on_not_found)
        OSFatal((char*)name);

    return 0;
}

/* ****************************************************************** */
/*                         INSTALL MAIN CODE                          */
/* ****************************************************************** */
static void InstallMain(private_data_t *private_data) {
    // get .text section
    unsigned int main_text_addr = 0;
    unsigned int main_text_len = 0;
    unsigned int section_offset = get_section(private_data, private_data->data_elf, ".text", &main_text_len, &main_text_addr, 1);
    unsigned char *main_text = private_data->data_elf + section_offset;
    /* Copy main .text to memory */
    if(section_offset > 0) {
        KernelWrite((main_text_addr), (void *)main_text, main_text_len, private_data->coreinit_handle);
    }

    // get the .rodata section
    unsigned int main_rodata_addr = 0;
    unsigned int main_rodata_len = 0;
    section_offset = get_section(private_data, private_data->data_elf, ".rodata", &main_rodata_len, &main_rodata_addr, 0);
    if(section_offset > 0) {
        unsigned char *main_rodata = private_data->data_elf + section_offset;
        /* Copy main rodata to memory */
        KernelWrite((main_rodata_addr), (void *)main_rodata, main_rodata_len, private_data->coreinit_handle);
    }

    // get the .data section
    unsigned int main_data_addr = 0;
    unsigned int main_data_len = 0;
    section_offset = get_section(private_data, private_data->data_elf, ".data", &main_data_len, &main_data_addr, 0);
    if(section_offset > 0) {
        unsigned char *main_data = private_data->data_elf + section_offset;
        /* Copy main data to memory */
        KernelWrite((main_data_addr), (void *)main_data, main_data_len, private_data->coreinit_handle);
    }

    // get the .bss section
    unsigned int main_bss_addr = 0;
    unsigned int main_bss_len = 0;
    section_offset = get_section(private_data, private_data->data_elf, ".bss", &main_bss_len, &main_bss_addr, 0);
    if(section_offset > 0) {
        unsigned char *main_bss = private_data->data_elf + section_offset;
        /* Copy main data to memory */
        KernelWrite((main_bss_addr), (void *)main_bss, main_bss_len, private_data->coreinit_handle);
    }

}
