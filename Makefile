include $(DEVKITPPC)/base_tools

PATH := $(DEVKITPPC)/bin:$(PATH)
PREFIX ?= powerpc-eabi-
CC = $(PREFIX)gcc
AS = $(PREFIX)gcc
CFLAGS = -std=gnu99 -Os -fno-builtin
ASFLAGS = -mregnames -x assembler-with-cpp
LD = $(PREFIX)ld
GCC_VER := $(shell $(DEVKITPPC)/bin/powerpc-eabi-gcc -dumpversion)
LDFLAGS=-Ttext 1800000 -L$(DEVKITPPC)/lib/gcc/powerpc-eabi/$(GCC_VER) -lgcc
OBJDUMP ?= $(PREFIX)objdump
project	:=	.
root	:=	$(CURDIR)
build	:=  $(root)/bin

main_hook_elf := main_hook/main_hook.elf

all: clean setup main550

main_hook_elf.bin: $(main_hook_elf)
	@$(bin2o)
    
$(main_hook_elf):
	make -C main_hook
	
setup:
	mkdir -p $(root)/bin/

main550:
	make main FIRMWARE=550

main: main_hook_elf.bin
	$(CC) $(CFLAGS) -DVER=$(FIRMWARE) -c $(project)/launcher.c
	$(CC) $(CFLAGS) -DVER=$(FIRMWARE) -c $(project)/gx2sploit/kexploit.c
	$(AS) $(ASFLAGS) -DVER=$(FIRMWARE) -c $(project)/gx2sploit/syscalls.S
	$(AS) $(ASFLAGS) -DVER=$(FIRMWARE) -c $(project)/crt0.S
	cp -r $(root)/*.o $(build)
	rm $(root)/*.o
	$(LD) -s -o code$(FIRMWARE).bin $(build)/crt0.o `find $(build) -name "*.o" ! -name "crt0.o"` --oformat binary  $(LDFLAGS) 
	$(LD) -s -o code$(FIRMWARE).elf $(build)/crt0.o `find $(build) -name "*.o" ! -name "crt0.o"` $(LDFLAGS) 

clean:
	rm -rf $(build)
	rm -rf code550.h
	rm -rf main_hook_elf.h
	make clean -C main_hook