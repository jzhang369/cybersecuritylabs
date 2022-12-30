# Compiling and Linking - A Note on static, pie, and ASLR

A few concepts can get quite confusing when one explores compilation, linking, and software reverse engineering challenges. This note records a few samples, experiments, and observations I have used to demystify these confusions. 

### **Concepts**

This lab will focus on the following options when you compile a program using gcc. 

+ **ASLR**: Address Space Layout Randomization. It is worth noting that ASLR is a system option rather than a compiler option. You can use the following commands to disable and enable ASLR in a Linux system, respectively. Keep in mind that their effectivness will not survive a reboot. 
    - echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
    - echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
+ **gcc -static**: On systems that support dynamic linking, this overrides -pie and prevents linking with the shared libraries.
+ **gcc -no-pie**: Don't produce a dynamically linked position independent executable.
+ **gcc -static-pie**: Produce a static position independent executable on targets that support it.



#### **`add.h`**
``` c
extern int kid; 
extern int add(int, int); 
```

#### **`add.c`**
``` c
int kid = 0x11;
int foo(int a)
{
	return a + 0x88; 
}
int add(int first, int second)
{
	int result;
	kid = 0xFF; 
	result = first + second +  foo(second) + 0xFF; 
	return result; 
}
```

#### **`main.c`**
``` c
#include <stdio.h>
#include "add.h"
void main()
{
	int a = 0x11;
	int b = 0x22;
	int c = 0;
	c = add(a, b);
	printf("the address of main is 0x%p\n", (void *)&main); 
	printf("the address of add is 0x%p\n", (void *)&add); 
	printf("the address of kid is 0x%p\n", (void *)&kid); 
	printf("the address of printf is 0x%p\n", (void *)&printf); 
}
```

### **Componenets**

When you compile your code, an executable will be generated, which is the result of integrating three parts:

+ Part-1: The sections (.data, .text, .rela.text, .bss, and etc.) from the code you have written. For example, if you run ``gcc -c main.c``, you will have ``main.o``. 
+ Part-2: The sections (.data, .text, .rela.text, .bss, and etc.) from the static libraries you need to use. After linking, these sections will be merged into sections from your code. 
    - We use ``add.c`` to simulate a static-only library. You can get its relocatable object using ``gcc -c add.c``, resulting in ``add.o``. 
    - Depending on your compilation options, the ``libc.a`` static library archieve, which contains ``printf()``, can also be used. 
+ Part-3: The sections (.plt, .text) from dynamically linked shared libraries. Unless you explicitly use ``libc.a`` for ``printf()``, ``printf()`` will be coming from ``libc.so``.  


### **gcc -static**

```console
[jzhang@DESKTOP-DSVPHPI src]$gcc -c main.c add.c
```
This will generate two relocatable objects including main.o and add.o, both of which are static (i.e., neither of them is dynamically linked shared library). 

```console
[jzhang@DESKTOP-DSVPHPI src]$gcc -static -o run_static.o main.o add.o
```
This will generate a ``static`` executable. 

+ It will copy text of ``add.o`` and ``printf()`` in ``libc.a`` directly into ``run_static.o``. 
    - Therefore, the dynamic loader will not be used (i.e., it is an ELF executable). 
        ``` console
        [jzhang@DESKTOP-DSVPHPI src]$file run_static.o
        run_static.o: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=ebfce71acd201543a5a5c5a1be85e8500e73443e, for GNU/Linux 3.2.0, not stripped
        ```
    - You can also find that ``run_static.o`` is sizable; You can also use Ghidra to find the text for ``printf()``. 
+ The image base and the address of each instruction is also known priori to the loading time. Specifically, the image base is 0x400000.  
    ``` console
    [jzhang@DESKTOP-DSVPHPI src]$pwn checksec run_static.o
    [*] '/mnt/c/Users/junji/Documents/Tools/ghidra_10.1.4_PUBLIC/projects/test/note-compiling-and-linking/src/run_static.o'
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    Canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
    ```

Even if the ASLR is enabled, when you run ``run_static.o`` to print out the addresses, you will see these addresses are not changed at all. 

``` console
[jzhang@DESKTOP-DSVPHPI src]$cat /proc/sys/kernel/randomize_va_space
2
[jzhang@DESKTOP-DSVPHPI src]$./run_static.o
the address of main is 0x0x401cb5
the address of add is 0x0x401d66
the address of kid is 0x0x4c00f0
the address of printf is 0x0x410a10
[jzhang@DESKTOP-DSVPHPI src]$./run_static.o
the address of main is 0x0x401cb5
the address of add is 0x0x401d66
the address of kid is 0x0x4c00f0
the address of printf is 0x0x410a10
[jzhang@DESKTOP-DSVPHPI src]$./run_static.o
the address of main is 0x0x401cb5
the address of add is 0x0x401d66
the address of kid is 0x0x4c00f0
the address of printf is 0x0x410a10
```

### **gcc -no-pie**

``` console
[jzhang@DESKTOP-DSVPHPI src]$gcc -c main.c add.c
[jzhang@DESKTOP-DSVPHPI src]$gcc -no-pie -o run_no_pie.o main.o add.o
```
The first command yields a static library ``add.o``. The second command generates the executable, i.e., ``run_no_pie.o``. ``run_no_pie.o`` statically integrates sections from ``add.o``. The integrated sections will be *non-PIE*. Therefore, its image base and instruction addresses (i.e., part-1 and part-2) are fixed. However, the ``printf()``, now from the shared library ``libc.so``, will be dynamically loaded at runtime. In other words, the address of ``printf()`` (i.e., part-3) is unpredictable. 

+ ``run_no_pie.o`` will be dynamically linked. 
    ```console
    [jzhang@DESKTOP-DSVPHPI src]$file run_no_pie.o
    run_no_pie.o: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=79c0ecff38964a86316a589662bd597843040452, for GNU/Linux 3.2.0, not stripped
    ```
    ```console
    [jzhang@DESKTOP-DSVPHPI src]$ldd run_no_pie.o
        linux-vdso.so.1 (0x00007ffffaded000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f5908327000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f5908525000)
    ```
+ Its image base and address of each instruction for Part-1 and -2 are known and fixed. 

    ```console
    [jzhang@DESKTOP-DSVPHPI src]$pwn checksec run_no_pie.o
    [*] '/mnt/c/Users/junji/Documents/Tools/ghidra_10.1.4_PUBLIC/projects/test/note-compiling-and-linking/src/run_no_pie.o'
        Arch:     amd64-64-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x400000)
    ```

With ASLR enabled, we can run it multiple times, and you will see the address of ``main()`` ``add()``, and ``kid`` will be fixed but the address of ``printf()`` will be changed. 

``` console
[jzhang@DESKTOP-DSVPHPI src]$cat //proc/sys/kernel/randomize_va_space
2
[jzhang@DESKTOP-DSVPHPI src]$./run_no_pie.o
the address of main is 0x0x401126
the address of add is 0x0x4011d7
the address of kid is 0x0x404028
the address of printf is 0x0x7f45a5624c90
[jzhang@DESKTOP-DSVPHPI src]$./run_no_pie.o
the address of main is 0x0x401126
the address of add is 0x0x4011d7
the address of kid is 0x0x404028
the address of printf is 0x0x7f0628ff1c90
[jzhang@DESKTOP-DSVPHPI src]$./run_no_pie.o
the address of main is 0x0x401126
the address of add is 0x0x4011d7
the address of kid is 0x0x404028
the address of printf is 0x0x7f6d326efc90
[jzhang@DESKTOP-DSVPHPI src]$./run_no_pie.o
the address of main is 0x0x401126
the address of add is 0x0x4011d7
the address of kid is 0x0x404028
the address of printf is 0x0x7f218231bc90
```

With ASLR disabled, we can run it multiple times, and you will see the address of ``main()`` ``add()``, and ``kid`` will be fixed and the address of ``printf()`` will *not* be changed. 

``` console
[jzhang@DESKTOP-DSVPHPI src]$cat //proc/sys/kernel/randomize_va_space
0
[jzhang@DESKTOP-DSVPHPI src]$./run_no_pie.o
the address of main is 0x0x401126
the address of add is 0x0x4011d7
the address of kid is 0x0x404028
the address of printf is 0x0x7ffff7e2dc90
[jzhang@DESKTOP-DSVPHPI src]$./run_no_pie.o
the address of main is 0x0x401126
the address of add is 0x0x4011d7
the address of kid is 0x0x404028
the address of printf is 0x0x7ffff7e2dc90
[jzhang@DESKTOP-DSVPHPI src]$./run_no_pie.o
the address of main is 0x0x401126
the address of add is 0x0x4011d7
the address of kid is 0x0x404028
the address of printf is 0x0x7ffff7e2dc90
[jzhang@DESKTOP-DSVPHPI src]$./run_no_pie.o
the address of main is 0x0x401126
the address of add is 0x0x4011d7
the address of kid is 0x0x404028
the address of printf is 0x0x7ffff7e2dc90
```

*Security Implications:* When ASLR is enabled, although the address of ``printf()`` is unpredictable, the ``GOT`` belongs to the *non-pie* portion of the code. In other words, the address for each ``GOT`` entry is known. Specifically, you can find the address for the ``GOT`` entry of ``printf()`` using 

``` console
[jzhang@DESKTOP-DSVPHPI src]$objdump -R ./run_no_pie.o  | egrep printf
0000000000403fe8 R_X86_64_GLOB_DAT  printf@GLIBC_2.2.5
```

This will facilitate vulnerabilities that enable arbitrary memory write such as format-string-based vulnerability. One example can be found [here](https://guyinatuxedo.github.io/10-fmt_strings/backdoor17_bbpwn/index.html) [1].  


### **gcc -pie**

``` console
[jzhang@DESKTOP-DSVPHPI src]$gcc -c main.c add.c
[jzhang@DESKTOP-DSVPHPI src]$gcc -pie -o run_pie.o main.o add.o
```
Actually you do not have to specify the ``-pie`` option since ``gcc`` by default will attempt to compile it with ``-pie`` enabled. 

First, the resulted object ``run_pie.o`` is considered as a *shared object* rather than an executable. 

``` console
[jzhang@DESKTOP-DSVPHPI src]$file run_pie.o
run_pie.o: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=7030a67dd9e56f5c497f040fc270b4fb0a2c2eaa, for GNU/Linux 3.2.0, not stripped
```
Now the entire binary will be *pie*-enabled. But whether the memory mapping of this object is randomized depends on whether the ASLR is enabled. 

+ When ASLR is enabled, the memory layout is randomized. 

    ```console
    [jzhang@DESKTOP-DSVPHPI src]$cat //proc/sys/kernel/randomize_va_space
    2
    [jzhang@DESKTOP-DSVPHPI src]$./run_pie.o
    the address of main is 0x0x56409bb28139
    the address of add is 0x0x56409bb281ea
    the address of kid is 0x0x56409bb2b010
    the address of printf is 0x0x7fab7c1c0c90
    [jzhang@DESKTOP-DSVPHPI src]$./run_pie.o
    the address of main is 0x0x55fd4cbdb139
    the address of add is 0x0x55fd4cbdb1ea
    the address of kid is 0x0x55fd4cbde010
    the address of printf is 0x0x7fafaf46ac90
    [jzhang@DESKTOP-DSVPHPI src]$./run_pie.o
    the address of main is 0x0x55e7ba5b4139
    the address of add is 0x0x55e7ba5b41ea
    the address of kid is 0x0x55e7ba5b7010
    the address of printf is 0x0x7fc4d6d4cc90
    ```

- When ASLR is disabled, the memory layout is not randomizd even if *pie* isn enabled. 

    ```console
    [jzhang@DESKTOP-DSVPHPI src]$cat //proc/sys/kernel/randomize_va_space
    0
    [jzhang@DESKTOP-DSVPHPI src]$./run_pie.o
    the address of main is 0x0x555555555139
    the address of add is 0x0x5555555551ea
    the address of kid is 0x0x555555558010
    the address of printf is 0x0x7ffff7e2dc90
    [jzhang@DESKTOP-DSVPHPI src]$./run_pie.o
    the address of main is 0x0x555555555139
    the address of add is 0x0x5555555551ea
    the address of kid is 0x0x555555558010
    the address of printf is 0x0x7ffff7e2dc90
    [jzhang@DESKTOP-DSVPHPI src]$./run_pie.o
    the address of main is 0x0x555555555139
    the address of add is 0x0x5555555551ea
    the address of kid is 0x0x555555558010
    the address of printf is 0x0x7ffff7e2dc90
    ```

### **gcc -static-pie**

This option is a little bit misleading. Here the ``-static`` part actually means the text for ``printf()`` will be copied from ``libc.a`` to the binary. However, it is worth noting that this ``-pie`` part will *NOT* make the image base and the address of each instruction predictable. Intead, the ``-pie`` part makes the resulted object ``PIE``-enabled. When ASLR is enabled, the loading address will be randomized. Otherwise, it is predictable. 

``` console
[jzhang@DESKTOP-DSVPHPI src]$gcc -static-pie -o run_static_pie.o main.o add.o
[jzhang@DESKTOP-DSVPHPI src]$file run_static_pie.o
run_static_pie.o: ELF 64-bit LSB shared object, x86-64, version 1 (GNU/Linux), dynamically linked, BuildID[sha1]=939e5c9ca5bd52a9c7f6f089ae64fc987e24f80f, for GNU/Linux 3.2.0, not stripped
[jzhang@DESKTOP-DSVPHPI src]$pwn checksec run_static_pie.o
[!] Did not find any GOT entries
[*] '/mnt/c/Users/junji/Documents/Tools/ghidra_10.1.4_PUBLIC/projects/test/note-compiling-and-linking/src/run_static_pie.o'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[jzhang@DESKTOP-DSVPHPI src]$ls -al |egrep run_static_pie.o
-rwxrwxrwx 1 jzhang jzhang 917512 Aug  7 23:51 run_static_pie.o
```

- When ASLR is enabled, the memory layout is randomized. 
    ```console
    [jzhang@DESKTOP-DSVPHPI src]$cat //proc/sys/kernel/randomize_va_space
    2
    [jzhang@DESKTOP-DSVPHPI src]$./run_static_pie.o
    the address of main is 0x0x7fbd4853efe9
    the address of add is 0x0x7fbd4853f09a
    the address of kid is 0x0x7fbd48600010
    the address of printf is 0x0x7fbd4854dd40
    [jzhang@DESKTOP-DSVPHPI src]$./run_static_pie.o
    the address of main is 0x0x7f1d9345ffe9
    the address of add is 0x0x7f1d9346009a
    the address of kid is 0x0x7f1d93521010
    the address of printf is 0x0x7f1d9346ed40
    [jzhang@DESKTOP-DSVPHPI src]$./run_static_pie.o
    the address of main is 0x0x7f3c347defe9
    the address of add is 0x0x7f3c347df09a
    the address of kid is 0x0x7f3c348a0010
    the address of printf is 0x0x7f3c347edd40
    ```

- When ASLR is disabled, the memory layout is *not* randomized. 
    ``` console
    [jzhang@DESKTOP-DSVPHPI src]$cat //proc/sys/kernel/randomize_va_space
    0
    [jzhang@DESKTOP-DSVPHPI src]$./run_static_pie.o
    the address of main is 0x0x7ffff7f39fe9
    the address of add is 0x0x7ffff7f3a09a
    the address of kid is 0x0x7ffff7ffb010
    the address of printf is 0x0x7ffff7f48d40
    [jzhang@DESKTOP-DSVPHPI src]$./run_static_pie.o
    the address of main is 0x0x7ffff7f39fe9
    the address of add is 0x0x7ffff7f3a09a
    the address of kid is 0x0x7ffff7ffb010
    the address of printf is 0x0x7ffff7f48d40
    [jzhang@DESKTOP-DSVPHPI src]$./run_static_pie.o
    the address of main is 0x0x7ffff7f39fe9
    the address of add is 0x0x7ffff7f3a09a
    the address of kid is 0x0x7ffff7ffb010
    the address of printf is 0x0x7ffff7f48d40
    ```

### **Misc**

Some additional references are can be found at [2, 3, 4]. 

### **References**

[1] https://guyinatuxedo.github.io/10-fmt_strings/backdoor17_bbpwn/index.html

[2] https://eli.thegreenplace.net/2011/08/25/load-time-relocation-of-shared-libraries/

[3] https://eli.thegreenplace.net/2011/11/03/position-independent-code-pic-in-shared-libraries/

[4] https://eli.thegreenplace.net/2011/11/11/position-independent-code-pic-in-shared-libraries-on-x64
