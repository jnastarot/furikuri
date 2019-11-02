Furikuri
=============

[![License](https://img.shields.io/badge/license-BSD3-blue.svg)](https://github.com/jnastarot/enma_pe/blob/master/LICENSE) [![Build status](https://ci.appveyor.com/api/projects/status/4fa90sgo6c89fqcp?svg=true)](https://ci.appveyor.com/project/jnastarot/furikuri) [![Build Status](https://travis-ci.org/jnastarot/furikuri.svg?branch=master)](https://travis-ci.org/jnastarot/furikuri)
------


```
Furikuri is protection framework what targeting on shellcode and executable files 
Supported x32 and x64 archs
```
1. [Obfuscation techniques](#Obfuscation-techniques)
	* [Instruction mutation](#Instruction-mutation) 
    * [Junk generation](#Junk-generation) 
    * [Spaghetti code](#Spaghetti-code) 
    * [Bytecode obfuscation](#Bytecode-obfuscation) 
2. [Examples](#Examples)
3. [Compile](#Compile)
4. [Third party](#third-party)

Obfuscation techniques
-------------------------------------

##### Instruction mutation
 Mutation of original instruction into series of other equivalent instructions 

   example:

   ```
    mov rcx, rax
    mov rdx, [rsp + 38h]
    call SomeFunc
   ```
   becomes to :
   ```
    mov rdx, rax
    mov rcx, [rsp + 38h]
    push rcx
    mov rcx, rdx
    pop rdx
    call SomeFunc
   
   ```
------------------------

##### Junk generation
Inserting assembler instructions with out any payload between "original" instructions

   example:
   ```
    mov rcx, rax
    mov rdx, [rsp + 38h]
    call SomeFunc
   ```
   becomes to :
   ```
    mov rdx, rdx
    mov rdx, r8
    mov rcx, rax
    push r8
    mov r8, 12345678h
    pop r8
    mov rdx, [rsp + 38h]
    call SomeFunc
   ```
------------------------

##### Spaghetti code
Dividing original basic block of code on several but more smaller, through insertion `jmp` in middle of   block to start of second of "new" block

   example:
   ```
   mov r10, [rax+20h]
   mov eax, [rsp+98h]
   mov [rsp+40h], eax
   mov rax, [rsp+90h]
   mov [rsp+38h], rax
   mov eax, [rsp+88h]
   mov [rsp+30h], eax
   mov rax, [rsp+80h]
   mov [rsp+28h], rax
   mov [rsp+20h], r9d
   ```
   becomes to :
   ```
   mov r10, [rax+20h]
   mov eax, [rsp+98h]
   mov [rsp+40h], eax
   mov rax, [rsp+90h]
   mov [rsp+38h], rax
   jmp l1:
   ...
   ...
   ...
   
   l1 :
   mov eax, [rsp+88h]
   mov [rsp+30h], eax
   mov rax, [rsp+80h]
   mov [rsp+28h], rax
   mov [rsp+20h], r9d
   
   ```
------------------------

##### Bytecode obfuscation
Changes bytecode of instruction to another bytecode

   example:
   ```
    48 8B CA mov rcx,rdx
   ```
   becomes to :
   ```
    48 89 D1 mov rcx,rdx
   ```




Examples
--------------
[shellcode obfuscation](https://github.com/jnastarot/furikuri/tree/master/examples/shellcode%20obfuscation)<br>
[executable obfuscation](https://github.com/jnastarot/furikuri/tree/master/examples/executable%20obfuscation)

---
Compile 
-------------
* Windows
	1. Requirements 
	    * Git Bush
	    * Visual Studio 2019 (for now, but u can change runtime version and compile in on below versions)
	
	2. Clone repo and initialize submodules
	
	   ```
	   git clone https://github.com/jnastarot/furikuri.git
	   cd furikuri
	   git submodule update --init
	   ```
	
	3. Open `furikuri.sln` and build it in Visual Studio 
	
	   
	
* Linux

  TODO




Third Party
-----------------
[capstone](http://www.capstone-engine.org/)<br>
[enma pe](https://github.com/jnastarot/enma_pe)<br>
[fukutasm](https://github.com/jnastarot/fukutasm)<br>