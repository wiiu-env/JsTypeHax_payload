# JsTypeHax payload
This is an example payload for the [JsTypeHax](https://github.com/wiiu-env/JsTypeHax).
It simply copies a given statically linked payload (`main_hook/main_hook.elf`)
into memory and installs a "main hook" to jump to this every time a application
starts.

## Usage
This payload meant to be used with [JsTypeHax](https://github.com/wiiu-env/JsTypeHax),
a browser exploit for the Wii U (FW 5.5.2 to 5.5.3). Copy the created `code550.bin`
into the JsTypeHax folder and run the exploit. Read the README of the JsTypeHax
repository for more information.

The browser will switch to Mii Maker and from now on load your payload **every time**
you switch to another application.  

Overwrite the address `0x0101c56c` (our main entry hook) with `0x4E800421`
(= `bctrl`) to override this behaviour. **Note** This address is not writeable
from user/kernel, you need to either set up a `DBAT` or disable memory translation
temporarily. Then disabling the memory translation, make sure to use physical addresses,
`OSEffectiveToPhysical` might help there.

## Building
Place the a project with Makefile into a subfolder `/main_hook` that creates a `main_hook.elf`.
Using a `.elf` directly requires changes on the Makefile. This repository provides
a generic `.elf` as submodule, see it's README for detailed information and usage.

Clone via `git init --recursive URL`.

In order to be able to compile this, you need to have installed
[devkitPPC](https://devkitpro.org/wiki/Getting_Started) with the following
pacman packages installed.

```
pacman -Syu devkitPPC
```

Make sure the following environment variables are set:
```
DEVKITPRO=/opt/devkitpro
DEVKITPPC=/opt/devkitpro/devkitPPC
```

The command `make` should produce a `code550.bin`, meant to be used with
[JsTypeHax](https://github.com/wiiu-env/JsTypeHax)

## Technical details

This payload:

- Creates a new stable thread, as the current one is really unstable
- Kill the browser and waits a bit.
- Performs a kernel exploit, and registers the syscalls `0x34/0x35` for `kern_read/kern_write`
- These can be used to register further, complete custom syscalls.
- Syscall `0x25` is registered to copy data with memory protection disabled.
(this is **not** available in the to be loaded `main_hook.elf` payload)
- Copies the embedded `main_hook.elf` to the address where it's statically linked to.
Currently these sections are supported. `.text`, `.rodata`, `.data` and `.bss`.
In theory this could be placed anywhere, but keep in mind that the memory area
may be cleared (like the codegen area, or the whole heap), and needs to be
executable in user mode (even after switching the application). It's recommended
to use `0x011DD000...0x011E0000`
- Afterwards the `main entry hook` is set up to jump to this position on every
application switch. You also may have to modify this if the jump turns out to be too big.
- A small function to modify IBAT0 is copied to kernel space and registers as syscall
`0x09`. This can used in the loaded `.elf`.
 The declaration of this function is `extern void SC_0x09_SETIBAT0(uint32_t upper, uint32_t lower);`.
- The payload is switching to Mii Maker
- The `main_hook.elf` will be called, (and every other time when switching the application
  until the hook it reverted.)

## What this payload offers to the loaded .elf
The loaded `main_hook.elf` can expect:

- To be called everytime the application switches. (Mii Maker has sd access!)
- Syscall 0x09 to be available. Declaration: `extern void SC_0x09_SETIBAT0(uint32_t upper, uint32_t lower);`
, call via asm.
This function can be used to set IBAT0 to allow the kernel to execute new created
syscall (the kernel has for example no access to `0x011DD000...0x011E0000`).
- Syscall 0x34 (kern_read) and 0x35 (kern_write) to be available. Use the following
functions to use them:
```
/* Read a 32-bit word with kernel permissions */
uint32_t __attribute__ ((noinline)) kern_read(const void *addr) {
    uint32_t result;
    asm volatile (
        "li 3,1\n"
        "li 4,0\n"
        "li 5,0\n"
        "li 6,0\n"
        "li 7,0\n"
        "lis 8,1\n"
        "mr 9,%1\n"
        "li 0,0x3400\n"
        "mr %0,1\n"
        "sc\n"
        "nop\n"
        "mr 1,%0\n"
        "mr %0,3\n"
        :	"=r"(result)
        :	"b"(addr)
        :	"memory", "ctr", "lr", "0", "3", "4", "5", "6", "7", "8", "9", "10",
        "11", "12"
    );

    return result;
}

/* Write a 32-bit word with kernel permissions */
void __attribute__ ((noinline)) kern_write(void *addr, uint32_t value) {
    asm volatile (
        "li 3,1\n"
        "li 4,0\n"
        "mr 5,%1\n"
        "li 6,0\n"
        "li 7,0\n"
        "lis 8,1\n"
        "mr 9,%0\n"
        "mr %1,1\n"
        "li 0,0x3500\n"
        "sc\n"
        "nop\n"
        "mr 1,%1\n"
        :
        :	"r"(addr), "r"(value)
        :	"memory", "ctr", "lr", "0", "3", "4", "5", "6", "7", "8", "9", "10",
        "11", "12"
    );
}
```

# Credits

- orboditilt: Putting everything together.
- Marionumber1: [gx2sploit](https://github.com/wiiudev/libwiiu/tree/master/kernel/gx2sploit), the used kernel exploit.
- dimok789: This is based on the [homebrew launcher installer](https://github.com/dimok789/homebrew_launcher/tree/master/installer)
- Kinnay: for the [KernelCopyData function](https://github.com/Kinnay/Wii-U-Debugger/blob/master/src/kernel.S)
