---
search:
  exclude: true
---
# Binary Exploitation

![](0.png)

#####  Below you fill find my binary exploitation learning notes, the easier challenges are at the top, and the further down you go, the more we dig into advanced concepts.

[ Template Page ](0/0.md)



#####  Preparing the Tools 

  1. [Installing gdb gef](0/gdb.md)
  2. [Installing py pwntools](0/pwntools.md)
  3. [Installing GHIDRA](0/ghidra.md)



  * | 
  * | 
  * | 





#####  1) Beginner Reversing 

The basics of reversing with simple to understand examples

  1. [✅ Strings](1/strings.md)
  2. [✅ Helithumper RE](1/heli.md)
  3. [✅ CSAW 2019 Beleaf](1/beleaf.md) 


  * | grep strings chmod
  * | ghidra, pointers, scanf, puts, arrays, hexa to ascii
  * | ghidra, pointers, arrays, functions





#####  2) Stack Buffer Overflows 

These are the most common binary exploits, they are there because of insecure functions that do not set a limit to user input, allowing the user to overwrite other memory registers.

  1. [✅ CSAW 2018 Quals boi](2/boi.md)
  2. [✅ TAMU 2019 pwn1](2/pwn1.md)
  3. [✅ TW 2017 Just Do It!](2/just.md)
  4. [✅ CSAW 2016 Warmup](2/warm.md)
  5. [✅ CSAW 2018 Get it](2/get.md)
  6. [✅ TUCTF 2017 Vulnchat](2/vuln.md)



  * | gbof variable, db-gef,elf, little endian, ghidra, offsets 
  * | bof variable
  * | bof variable
  * | bof callfunction
  * | bof callfunction
  * | bof callfunction





#####  Assembly x86_64 

As i hit the shellcode buffer overflow binary challenges, i realized that i needed assembly skills, so this is a simple introduction to modern intel Assembly for the x86_64 (64bits) architecture. We make use of the [syscalls](https://chromium.googlesource.com/chromiumos/docs/+/HEAD/constants/syscalls.md#x86_64-64_bit) used to communicate with the Linux Kernel:

  1. [✅ Hello World](asm/1.md)
  2. [✅ Hello World Explained ](asm/2.md)
  3. [✅ Jumps, Calls](asm/3.md)
  4. [✅ User Input](asm/4.md)
  5. [✅ Math Operations](asm/5.md)
  6. [✅ Reading / Writing Files](asm/6.md)
  7. [✅ Spawning a shell](asm/7.md)





#####  2) Stack Buffer Overflows (Part 2)

  1. [✅ CSAW 2017 Pilot](2/pilot.md)
  2. [✅ Tamu 2019 pwn3](2/pwn3.md)
  3. [✅ Tuctf 2018 shella-easy](2/shella.md)
  4. [✅ BKP 2016 calc](2/calc.md)
  5. [✅ DCQuals 2019 speed](2/speed.md)
  6. [✅ DCQuals 2016 feed](2/feed.md)
  7. [✅ CSAW 2019 babyboi](2/bboi.md)
  8. [✅ CSAW 2017 SVC](2/svc.md)
  9. [✅ FB 2019 Overfloat](2/overf.md)
  10. [✅ hs 2019 storytime](2/hs.md)
  11. [✅ UTC 2019 shellme](2/shme.md)



  * | bof shellcode
  * | bof shellcode
  * | bof shellcode
  * | bof ROP Chain, ROP Gadgets
  * | bof ROP Chain, ROP Gadgets
  * | bof ROP Chain, ROP Gadgets
  * | bof dynamic
  * | bof dynamic
  * | bof dynamic
  * | bof dynamic
  * | bof dynamic





#####  3) Bad Seed 

  1. [✅ h3 time ](3/h3.md)
  2. [✅ hsctf 2019 tux talk ](3/tux.md)
  3. [✅ Sunshine 17 Prepared ](3/prep.md)



  * | time seed 
  * | time seed 
  * | time seed



